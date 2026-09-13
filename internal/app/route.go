package app

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"x-tunnel/internal/route"
)

// ======================== 分流运行时（客户端） ========================
//
// routeRuntime 是客户端分流引擎的进程级持有者：持有 route.Engine、DNS 嗅探
// 映射（IP→域名，对齐 warp-go dnsInterceptor）、以及 DIRECT 出口。SOCKS5/HTTP
// 接入点在 Match 判定时通过它取引擎；route_enabled=false 时 engine 为 nil，
// 走全量隧道（现状行为零回归）。
type routeRuntime struct {
	mu        sync.RWMutex
	engine    *route.Engine
	dnsMap    map[netip.Addr]dnsMapEntry
	tcpDialer *net.Dialer
}

type dnsMapEntry struct {
	domain string
	expiry time.Time
}

// dnsMapTTL 是 IP→域名映射的存活时间（对齐 warp-go dnsInterceptor 的 TTL）。
const dnsMapTTL = 10 * time.Minute

var routeRT = &routeRuntime{dnsMap: make(map[netip.Addr]dnsMapEntry)}

// setEngine 替换当前引擎（初始化/关闭时调用）；nil 表示禁用分流。
func (rt *routeRuntime) setEngine(e *route.Engine) {
	rt.mu.Lock()
	rt.engine = e
	rt.mu.Unlock()
}

// engineSnapshot 返回当前引擎（可能为 nil）。
func (rt *routeRuntime) engineSnapshot() *route.Engine {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.engine
}

// remember 记录 IP→域名映射（对齐 warp-go dnsInterceptor.remember）。
func (rt *routeRuntime) remember(ip netip.Addr, domain string) {
	if !ip.IsValid() || domain == "" {
		return
	}
	rt.mu.Lock()
	rt.dnsMap[ip.Unmap()] = dnsMapEntry{domain: domain, expiry: time.Now().Add(dnsMapTTL)}
	rt.mu.Unlock()
}

// mappedHost 反查 IP→域名映射；命中且未过期返回域名，否则返回 false。
func (rt *routeRuntime) mappedHost(ip netip.Addr) (string, bool) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	e, ok := rt.dnsMap[ip.Unmap()]
	if !ok || time.Now().After(e.expiry) {
		return "", false
	}
	return e.domain, true
}

// resolveHostForRoute 把 SOCKS5/HTTP 目标 host 拆为供 Match 使用的 (host, ip)：
//   - host 本身是域名 → host 直接用，ip 零值（geosite/domain 规则生效，geoip 跳过）
//   - host 是 IP 字面量 → 先查 DNS 嗅探映射还原域名（命中则 geosite/domain 生效；
//     否则 host 传 IP 字面量，route.Match 内部识别 IP 只走 geoip）
func (rt *routeRuntime) resolveHostForRoute(host string) (string, netip.Addr) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if domain, ok := rt.mappedHost(ip); ok {
			return domain, ip
		}
		return host, ip
	}
	return host, netip.Addr{}
}

// initRouteEngine 装配分流引擎并挂载到 routeRT。rulesPath/geoDir 为空时用
// 运行目录下的默认位置；规则文件缺失时由 route.NewEngine 写默认模板；
// GEO 库缺失仅 warning 降级 rules-only。
func (e *Engine) initRouteEngine() error {
	v := e.config.values
	rulesPath := v.RulesPath
	if rulesPath == "" {
		rulesPath = "rules.txt"
	}
	geoDir := v.GeoDir
	if geoDir == "" {
		geoDir = "geo"
	}

	engine, err := route.NewEngine(rulesPath, geoDir)
	if err != nil {
		return err
	}
	routeRT.setEngine(engine)
	e.routeEngine = engine

	// GEO 下载走隧道（round40 根因修复）：sidecar 在 VPN 外直连物理网，境内
	// 拉 GitHub（MetaCubeX release）必败 → GEO 库永远缺失 → geosite/geoip 规则
	// 全不命中。注入 SOCKS5 代理客户端：经本机 listener（如 127.0.0.1:11080）
	// → 隧道 → 服务端出网下载。sidecar 自身 connect 在 VPN 外，天然防环。
	if proxyURL := firstSOCKS5ListenAddr(v.ListenAddr); proxyURL != "" {
		if u, err := url.Parse(proxyURL); err == nil {
			route.SetDownloadProxy(&http.Client{
				Transport: &http.Transport{
					Proxy: http.ProxyURL(&url.URL{Scheme: "socks5", Host: u.Host}),
				},
			})
			log.Printf("[分流] GEO 下载走隧道代理 %s", u.Host)
		}
	}

	// 异步首次 GEO 下载。重试 3 次（间隔 5s）：启动期本机 SOCKS5 listener 可能
	// 还未 bind（下载经隧道代理），立即发必失败；重试窗口覆盖 listener 就绪。
	// 失败只 warning，不阻塞启动；后续可经 /v1/route/geo/update 手动重试。
	go func() {
		const attempts = 3
		var lastErr error
		for i := 1; i <= attempts; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			updated, err := engine.UpdateGeo(ctx)
			cancel()
			if err == nil {
				if updated {
					log.Printf("[分流] GEO 数据库已更新（第 %d 次尝试）", i)
				} else {
					log.Printf("[分流] GEO 数据库已就绪（已是最新）")
				}
				return
			}
			lastErr = err
			log.Printf("[分流] GEO 数据库下载失败（第 %d/%d 次，降级 rules-only）：%v", i, attempts, err)
			select {
			case <-e.ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
		_ = lastErr
	}()
	return nil
}

// firstSOCKS5ListenAddr 从监听地址列表（逗号分隔，可含 http:// / tcp:// 混合）
// 中取第一个 socks5:// 地址；无则返回空串。
func firstSOCKS5ListenAddr(listenAddr string) string {
	for _, raw := range strings.Split(listenAddr, ",") {
		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(trimmed, "socks5://") {
			return trimmed
		}
	}
	return ""
}

// ======================== Match 接入（SOCKS5/HTTP 共用） ========================

type routeAction int

const (
	routeProxy routeAction = iota
	routeDirect
	routeReject
)

// decideForTarget 对目标 host 做分流判定。host 需已 SplitHostPort 去端口；
// ip 为已解析地址（可为零值）。引擎未启用时恒 proxy。
//
// 兜底语义（round40 根因修复，对齐 warp-go decision.go 防被墙）：
//   - matched=true → 按规则 action 执行
//   - matched=false（规则全部未命中，如 GEO 库缺失/目标不在规则内）→ **proxy 走隧道**，
//     绝不直连——直接把未命中当 direct 会让「GEO 库下载失败」放大成「全部流量直连」
//     （round39 真机实锤：GEO 开启后所有网络直连、隧道空转），且被墙目标直连必失败。
func decideForTarget(host string, ip netip.Addr) routeAction {
	if routeRT.engineSnapshot() == nil {
		return routeProxy
	}
	action, matched := routeRT.match(host, ip)
	if !matched {
		return routeProxy
	}
	switch action {
	case route.ActionDirect:
		return routeDirect
	case route.ActionReject:
		return routeReject
	default:
		return routeProxy
	}
}

// shouldTunnelDNS 是 DNS 解析源专用判定（round45）：仅当域名**明确命中
// proxy 规则**时走隧道解析（境外视角防污染）；direct 命中、规则未命中、
// GEO 库未就绪一律返回 false（国内直连解析，保底可达）。
//
// 与 decideForTarget 的兜底语义刻意不同：TCP 未命中兜底 proxy（防被墙），
// DNS 未命中兜底直连解析——r43 曾共用 TCP 语义导致 GEO 库缺失时国内域名
// 全被推到隧道 DNS，隧道不稳即全断（r44 真机实锤）。
func shouldTunnelDNS(host string) bool {
	if routeRT.engineSnapshot() == nil {
		return false
	}
	action, matched := routeRT.match(host, netip.Addr{})
	return matched && action == route.ActionProxy
}

// match 对 (host, ip) 做分流判定；引擎为 nil 时恒返回 proxy。
func (rt *routeRuntime) match(host string, ip netip.Addr) (string, bool) {
	e := rt.engineSnapshot()
	if e == nil {
		return route.ActionProxy, false
	}
	action, _, matched := e.Match(host, ip)
	return action, matched
}

// ======================== DIRECT 出口 ========================

// directDialer 懒创建带超时的 TCP 拨号器（客户端 DIRECT 出口）。
func directDialer() *net.Dialer {
	routeRT.mu.Lock()
	defer routeRT.mu.Unlock()
	if routeRT.tcpDialer == nil {
		routeRT.tcpDialer = &net.Dialer{Timeout: cfg.DialTimeout}
	}
	return routeRT.tcpDialer
}

// directDialTCP 直连目标（绕过隧道）。sidecar 自身在 VPN 外，物理网络可用
// （VpnDataPathController 已 addDisallowedApplication(self) 防环）。
func directDialTCP(target string) (net.Conn, error) {
	return directDialer().Dial("tcp", target)
}

// handleDirectConnect 是 SOCKS5 CONNECT 的 DIRECT 出口：直连目标成功后回
// 0x00 再双向转发，失败回 SOCKS5 错误码 0x05。
func handleDirectConnect(c net.Conn, target string) {
	upstream, err := directDialTCP(target)
	if err != nil {
		log.Printf("[客户端] %s DIRECT 直连失败 %s: %v", clientSourceAddr(c), target, err)
		_ = writeSOCKS5Reply(c, 0x05) // 连接被拒绝
		_ = c.Close()
		return
	}
	if err := writeSOCKS5Reply(c, 0x00); err != nil {
		_ = upstream.Close()
		_ = c.Close()
		return
	}
	logClientConnEvent(c, "SOCKS5-DIRECT", target, 0, true)
	defer logClientConnEvent(c, "SOCKS5-DIRECT", target, 0, false)
	proxyConnDuplex(c, upstream)
}

// handleDirectHTTP 是 HTTP 代理的 DIRECT 出口。对 CONNECT 回 200 后转发；普通
// 请求把已 sanitize 的 req 完整写到直连连接（req.Body 即客户端原始流）。
func handleDirectHTTP(c net.Conn, target string, req *http.Request, buffered []byte) {
	upstream, err := directDialTCP(target)
	if err != nil {
		log.Printf("[客户端] %s DIRECT 直连失败 %s: %v", clientSourceAddr(c), target, err)
		_ = writeHTTPProxyResponse(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer upstream.Close()

	logClientConnEvent(c, "HTTP-DIRECT", target, 0, true)
	defer logClientConnEvent(c, "HTTP-DIRECT", target, 0, false)

	if req.Method == "CONNECT" {
		if err := writeHTTPProxyResponse(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if len(buffered) > 0 {
			if err := writeAll(upstream, buffered); err != nil {
				return
			}
		}
		proxyConnDuplex(c, upstream)
		return
	}
	// 普通请求：req 已 sanitize（AbsoluteURI 清空、header 去 hop-by-hop、加 Via）。
	if err := req.Write(upstream); err != nil {
		return
	}
	proxyConnDuplex(c, upstream)
}

// proxyConnDuplex 是 proxyConnStream 的泛化：双向拷贝任意两个读写关闭流。
func proxyConnDuplex(a io.ReadWriteCloser, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(b, a)
		if n > 0 {
			atomic.AddUint64(&runtimeBytesSentSeq, uint64(n))
		}
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(a, b)
		if n > 0 {
			atomic.AddUint64(&runtimeBytesReceivedSeq, uint64(n))
		}
		done <- struct{}{}
	}()
	<-done
	_ = a.Close()
	_ = b.Close()
	<-done
}

// rememberHostFromDNS 供 UDP DNS 嗅探调用（§2.2）。
func rememberHostFromDNS(ip netip.Addr, host string) {
	routeRT.remember(ip, host)
}

// trimDot 去除域名尾部点（DNS QNAME 的 FQDN 表示）。
func trimDot(s string) string {
	return strings.TrimSuffix(s, ".")
}
