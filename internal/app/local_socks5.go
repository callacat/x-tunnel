package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"
)

// round43：DNS 源分流的两个解析出口。
// tunnelDNSHost 境外域名走隧道解析（境外视角无污染）；directDNSHost 国内
// 域名直连解析（国内 CDN 视角）。与 Android VpnDataPathController 的
// GEO_DNS(223.5.5.5) 对应。
const (
	tunnelDNSHost = "1.1.1.1"
	directDNSHost = "223.5.5.5"
)

type ProxyConfig struct {
	Username, Password, Host string
}

type UDPAssociation struct {
	id            uint64
	tcpConn       net.Conn
	udpListener   *net.UDPConn
	clientUDPAddr *net.UDPAddr
	pool          *ECHPool

	mu        sync.Mutex
	closed    bool
	receiving bool
	active    bool
	channelID int
	target    string
	stream    *smux.Stream
	// round41：UDP DIRECT 出口——GEO 分流判定 direct 的 UDP 目标（如国内
	// DNS 223.5.5.5:53）经本机 socket 直发，不占隧道。nil = 走隧道（现状）。
	directConn *net.UDPConn
}

func parseAuthAndAddr(full string) (string, string, string, error) {
	u, p, h := "", "", full
	if strings.Contains(full, "@") {
		parts := strings.SplitN(full, "@", 2)
		auth := parts[0]
		h = strings.TrimSpace(parts[1])
		if auth == "" || h == "" || !strings.Contains(auth, ":") {
			return "", "", "", fmt.Errorf("认证格式必须是 user:pass@host:port")
		}
		ap := strings.SplitN(auth, ":", 2)
		u, p = ap[0], ap[1]
		if u == "" || p == "" {
			return "", "", "", fmt.Errorf("用户名和密码不能为空")
		}
	}
	if strings.TrimSpace(h) == "" {
		return "", "", "", fmt.Errorf("地址不能为空")
	}
	return h, u, p, nil
}

func startSOCKS5Listener(ctx context.Context, addr string) (*runtimeListener, error) {
	h, u, p, err := parseAuthAndAddr(strings.TrimPrefix(addr, "socks5://"))
	if err != nil {
		return nil, fmt.Errorf("[客户端] SOCKS5地址解析失败: %w", err)
	}
	l, err := net.Listen("tcp", h)
	if err != nil {
		return nil, fmt.Errorf("[客户端] SOCKS5监听失败: %w", err)
	}
	listener := newRuntimeListener("socks5", addr, "socks5://"+l.Addr().String(), l.Close)
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	log.Printf("[客户端] SOCKS5 代理: %s", h)
	cfgp := &ProxyConfig{u, p, h}
	go func() {
		defer listener.finish(nil)
		for {
			c, err := l.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			go handleSOCKS5(c, cfgp)
		}
	}()
	return listener, nil
}

func runSOCKS5Listener(ctx context.Context, addr string) error {
	listener, err := startSOCKS5Listener(ctx, addr)
	if err != nil {
		return err
	}
	<-listener.done
	return nil
}

func handleSOCKS5(c net.Conn, cfgp *ProxyConfig) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(cfg.DialTimeout))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil || buf[0] != 0x05 {
		return
	}
	methods := make([]byte, buf[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if cfgp.Username != "" {
		if !bytes.Contains(methods, []byte{0x02}) {
			_ = writeSOCKS5MethodSelection(c, 0xff)
			return
		}
		if err := writeSOCKS5MethodSelection(c, 0x02); err != nil {
			return
		}
		if err := handleSOCKS5UserPassAuth(c, cfgp); err != nil {
			return
		}
	} else {
		if !bytes.Contains(methods, []byte{0x00}) {
			_ = writeSOCKS5MethodSelection(c, 0xff)
			return
		}
		if err := writeSOCKS5MethodSelection(c, 0x00); err != nil {
			return
		}
	}

	req, reply, err := readLocalSOCKS5Request(c)
	if err != nil {
		if reply != 0 {
			_ = writeSOCKS5Reply(c, reply)
		}
		return
	}

	// 增强过滤逻辑：解析 host 判断是否为 IP，从而覆盖 ATYP=0x03 但内容为 IP 的情况
	host, _, _ := net.SplitHostPort(req.target)
	ip := net.ParseIP(host)

	if req.command == 0x01 {
		if ipStrategy == IPStrategyIPv4Only {
			if req.atyp == 0x04 || (ip != nil && ip.To4() == nil) {
				_ = writeSOCKS5Reply(c, 0x02)
				return
			}
		}
		if ipStrategy == IPStrategyIPv6Only {
			if req.atyp == 0x01 || (ip != nil && ip.To4() != nil) {
				_ = writeSOCKS5Reply(c, 0x02)
				return
			}
		}
	}

	_ = c.SetDeadline(time.Time{})

	switch req.command {
	case 0x01:
		handleSOCKS5Connect(c, req.target)
	case 0x03:
		handleSOCKS5UDP(c, cfgp)
	default:
		_ = writeSOCKS5Reply(c, 0x07)
	}
}

type localSOCKS5Request struct {
	command byte
	atyp    byte
	target  string
}

func readLocalSOCKS5Request(r io.Reader) (localSOCKS5Request, byte, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return localSOCKS5Request{}, 0, err
	}
	if head[2] != 0x00 {
		return localSOCKS5Request{}, 0x01, fmt.Errorf("SOCKS5 请求 RSV 必须为 0")
	}

	host, err := readLocalSOCKS5RequestHost(r, head[3])
	if err != nil {
		if head[3] != 0x01 && head[3] != 0x03 && head[3] != 0x04 {
			return localSOCKS5Request{}, 0x08, err
		}
		return localSOCKS5Request{}, 0, err
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(r, pb); err != nil {
		return localSOCKS5Request{}, 0, err
	}
	port := int(pb[0])<<8 | int(pb[1])
	if head[1] == 0x01 && port == 0 {
		return localSOCKS5Request{}, 0x04, fmt.Errorf("SOCKS5 CONNECT 目标端口不能为 0")
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	if head[1] == 0x01 {
		if err := validateHostPort(target); err != nil {
			return localSOCKS5Request{}, 0x04, fmt.Errorf("SOCKS5 CONNECT目标无效: %w", err)
		}
	}

	return localSOCKS5Request{
		command: head[1],
		atyp:    head[3],
		target:  target,
	}, 0, nil
}

func readLocalSOCKS5RequestHost(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case 0x03:
		b := make([]byte, 1)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		addr := make([]byte, b[0])
		if _, err := io.ReadFull(r, addr); err != nil {
			return "", err
		}
		return string(addr), nil
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	default:
		return "", fmt.Errorf("SOCKS5 地址类型不支持: %d", atyp)
	}
}

func writeSOCKS5MethodSelection(w io.Writer, method byte) error {
	return writeAll(w, []byte{0x05, method})
}

func writeSOCKS5UserPassReply(w io.Writer, status byte) error {
	return writeAll(w, []byte{0x01, status})
}

func writeSOCKS5Reply(w io.Writer, status byte) error {
	return writeAll(w, []byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func writeSOCKS5UDPAssociateReply(w io.Writer, addr *net.UDPAddr) error {
	if addr == nil {
		return errors.New("SOCKS5 UDP ASSOCIATE 响应地址为空")
	}
	if addr.Port <= 0 || addr.Port > 65535 {
		return fmt.Errorf("SOCKS5 UDP ASSOCIATE 响应端口无效: %d", addr.Port)
	}
	resp := []byte{0x05, 0x00, 0x00}
	if ip4 := addr.IP.To4(); ip4 != nil {
		resp = append(resp, 0x01)
		resp = append(resp, ip4...)
	} else {
		ip16 := addr.IP.To16()
		if ip16 == nil {
			return errors.New("SOCKS5 UDP ASSOCIATE 响应地址无效")
		}
		resp = append(resp, 0x04)
		resp = append(resp, ip16...)
	}
	resp = append(resp, byte(addr.Port>>8), byte(addr.Port))
	return writeAll(w, resp)
}

func handleSOCKS5UserPassAuth(c net.Conn, cfgp *ProxyConfig) error {
	b := make([]byte, 2)
	if _, err := io.ReadFull(c, b); err != nil {
		return err
	}
	if b[0] != 0x01 {
		if err := writeSOCKS5UserPassReply(c, 0x01); err != nil {
			return err
		}
		return fmt.Errorf("SOCKS5 用户名密码认证版本无效: %d", b[0])
	}
	u := make([]byte, b[1])
	if _, err := io.ReadFull(c, u); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, b[:1]); err != nil {
		return err
	}
	p := make([]byte, b[0])
	if _, err := io.ReadFull(c, p); err != nil {
		return err
	}
	if string(u) == cfgp.Username && string(p) == cfgp.Password {
		return writeSOCKS5UserPassReply(c, 0x00)
	}
	if err := writeSOCKS5UserPassReply(c, 0x01); err != nil {
		return err
	}
	return errors.New("认证失败")
}

func handleSOCKS5Connect(c net.Conn, target string) {
	// 分流判定（§1.2）：host 拆端口供 Match；ATYP=域名直用，IP 字面量先查
	// DNS 嗅探映射还原域名（§2.2），miss 则只走 geoip。
	host, _, _ := net.SplitHostPort(target)
	routeHost, routeIP := routeRT.resolveHostForRoute(host)
	switch decideForTarget(routeHost, routeIP) {
	case routeDirect:
		handleDirectConnect(c, target)
		return
	case routeReject:
		_ = writeSOCKS5Reply(c, 0x02)
		_ = c.Close()
		return
	}

	stream, _, decision, err := echPool.openTCPStream(target)
	if err != nil {
		log.Printf("[客户端] %s SOCKS5 打开失败 %s: %v", clientSourceAddr(c), target, err)
		_ = writeSOCKS5Reply(c, socks5ReplyForOpenError(err))
		_ = c.Close()
		return
	}
	if err := writeSOCKS5Reply(c, 0x00); err != nil {
		_ = stream.Close()
		_ = c.Close()
		return
	}
	logClientConnEvent(c, "SOCKS5", target, decision, true)
	defer logClientConnEvent(c, "SOCKS5", target, decision, false)
	proxyConnStream(c, stream)
}

func handleSOCKS5UDP(c net.Conn, cfgp *ProxyConfig) {
	host, _, _ := net.SplitHostPort(cfgp.Host)
	uAddr, _ := net.ResolveUDPAddr("udp", net.JoinHostPort(host, "0"))
	ul, err := net.ListenUDP("udp", uAddr)
	if err != nil {
		_ = c.Close()
		return
	}
	defer ul.Close()

	actual, ok := ul.LocalAddr().(*net.UDPAddr)
	if !ok || actual == nil {
		_ = c.Close()
		return
	}
	if err := writeSOCKS5UDPAssociateReply(c, actual); err != nil {
		_ = c.Close()
		return
	}

	assoc := &UDPAssociation{
		id:          atomic.AddUint64(&udpAssociationSeq, 1),
		tcpConn:     c,
		udpListener: ul,
		pool:        echPool,
		active:      true,
		channelID:   -1,
	}
	atomic.AddUint64(&udpAssociationActiveSeq, 1)
	log.Printf("[客户端] udp_assoc=%d SOCKS5-UDP 关联打开 listener=%s client=%s", assoc.id, actual.String(), clientSourceAddr(c))

	go assoc.loop()
	b := make([]byte, 1)
	for {
		if _, err := c.Read(b); err != nil {
			assoc.Close()
			return
		}
	}
}

func (a *UDPAssociation) loop() {
	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufPool.Put(bufPtr)

	for {
		n, addr, err := a.udpListener.ReadFromUDP(buf)
		if err != nil {
			return
		}
		a.mu.Lock()
		if a.clientUDPAddr == nil {
			a.clientUDPAddr = addr
		} else if a.clientUDPAddr.String() != addr.String() {
			a.mu.Unlock()
			continue
		}
		a.mu.Unlock()

		tgt, data, err := parseSOCKS5UDPPacket(buf[:n])
		if err == nil {
			h, ps, _ := net.SplitHostPort(tgt)
			if ip := net.ParseIP(h); ip != nil {
				if ipStrategy == IPStrategyIPv4Only && ip.To4() == nil {
					continue
				}
				if ipStrategy == IPStrategyIPv6Only && ip.To4() != nil {
					continue
				}
			}
			prt, err := strconv.Atoi(ps)
			if err != nil {
				continue
			}
			if _, ok := udpBlockPorts[prt]; ok {
				continue
			}
			a.send(tgt, data)
		}
	}
}

func (a *UDPAssociation) send(target string, data []byte) {
	// round45：DNS 源分流（r43 语义反转修正，r44 真机实锤全断根因）。
	// 目标 :53 的 DNS 查询先解出 QNAME，按域名规则判定解析源：
	//   - 明确命中 proxy 规则的域名（geosite:google / geolocation-!cn 等）→
	//     改写目标 1.1.1.1:53 走隧道解析（境外视角，防污染）
	//   - **其余全部（direct 命中 / 规则未命中 / GEO 库未就绪）→ 国内直连解析
	//     223.5.5.5**——保底可达。r43 把「未命中」也推到隧道 DNS，GEO 库缺失时
	//     国内域名全被改写走隧道；隧道 UDP DNS 一旦不稳（r44 实锤：assoc 开着
	//     5.9s 无回包）= 所有域名解析失败 = 完全断网。
	//   - 引擎未启用（GEO off）→ 保持客户端原目标不动（现状零回归）。
	host, portStr, _ := net.SplitHostPort(target)
	if portStr == "53" && routeRT.engineSnapshot() != nil {
		if qname, ok := sniffDNSQuery(data); ok && shouldTunnelDNS(qname) {
			// 明确 proxy 的境外域名：走隧道解析（无污染视角）。
			if rewritten := net.JoinHostPort(tunnelDNSHost, "53"); rewritten != target {
				target = rewritten
				host = tunnelDNSHost
			}
		} else if ok && host != directDNSHost {
			// direct 命中 / 未命中 / 库未就绪：国内直连解析（保底可达，r45）。
			target = net.JoinHostPort(directDNSHost, "53")
			host = directDNSHost
		}
	}
	// round41：UDP 分流判定。GEO 引擎启用且目标判定 direct（国内 DNS/国内 UDP
	// 服务）→ 本机 socket 直发（不占隧道）；其余/引擎未启用 → 走隧道（现状）。
	// DNS 响应同样会在 direct 路径上被嗅探（写 IP→域名映射）。
	routeHost, routeIP := routeRT.resolveHostForRoute(host)
	if decideForTarget(routeHost, routeIP) == routeDirect {
		a.sendDirect(target, data)
		return
	}

	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	needStart := !a.receiving
	if needStart {
		a.receiving = true
		a.target = target
	}
	stream := a.stream
	a.mu.Unlock()

	if needStart {
		s, id, decision, err := a.pool.openUDPStream(target)
		if err != nil {
			log.Printf("[客户端] %s SOCKS5-UDP 打开失败 %s: %v", clientSourceAddr(a.tcpConn), target, err)
			a.Close()
			return
		}
		a.mu.Lock()
		a.stream = s
		a.channelID = id
		stream = s
		a.mu.Unlock()
		log.Printf("[客户端] udp_assoc=%d 绑定目标 %s 通道 %d", a.id, target, decision)
		logClientConnEvent(a.tcpConn, "SOCKS5-UDP", target, decision, true)
		go func() {
			for {
				addrStr, payload, e := readUDPReply(s)
				if e != nil {
					a.Close()
					return
				}
				a.handleUDPResponse(addrStr, payload)
			}
		}()
	} else {
		if target != "" && target != a.target {
			log.Printf("[客户端] udp_assoc=%d 丢弃不同目标 %s，已绑定目标 %s", a.id, target, a.target)
			return
		}
	}
	if stream == nil {
		a.Close()
		return
	}
	if err := writeChunk(stream, data); err != nil {
		a.Close()
	}
}

// sendDirect 是 UDP 的 DIRECT 出口（round41）：目标地址解析后用独立本机
// UDP socket 直发，起一个 goroutine 读响应回写客户端（含 DNS 嗅探）。
// socket 按目标懒创建；目标变更时重建（UDPAssociation 本身绑定单目标，
// 上游 send 已挡不同 target，这里防御性处理）。
func (a *UDPAssociation) sendDirect(target string, data []byte) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	conn := a.directConn
	boundTo := a.target
	needStart := conn == nil || (boundTo != "" && boundTo != target)
	a.mu.Unlock()

	if needStart {
		raddr, err := net.ResolveUDPAddr("udp", target)
		if err != nil {
			log.Printf("[客户端] %s UDP-DIRECT 解析目标失败 %s: %v", clientSourceAddr(a.tcpConn), target, err)
			return
		}
		// 绑定与客户端 listener 同一地址族（v4 目标绑 v4 通配，避免HappyEyeballs问题）。
		laddr := &net.UDPAddr{Port: 0}
		if raddr.IP.To4() == nil {
			laddr.IP = net.IPv6unspecified
		}
		nc, err := net.ListenUDP("udp", laddr)
		if err != nil {
			log.Printf("[客户端] %s UDP-DIRECT 建立失败 %s: %v", clientSourceAddr(a.tcpConn), target, err)
			return
		}
		a.mu.Lock()
		if a.directConn != nil && a.directConn != nc {
			_ = a.directConn.Close()
		}
		a.directConn = nc
		a.mu.Unlock()
		conn = nc
		log.Printf("[客户端] udp_assoc=%d UDP-DIRECT 绑定目标 %s 本地 %s", a.id, target, nc.LocalAddr())
		go a.directReadLoop(nc)
	}
	if conn == nil {
		return
	}
	raddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return
	}
	if _, err := conn.WriteToUDP(data, raddr); err != nil {
		log.Printf("[客户端] udp_assoc=%d UDP-DIRECT 写入失败 %s: %v", a.id, target, err)
	}
}

// directReadLoop 读 DIRECT socket 的响应，组 SOCKS5 UDP 帧回写客户端；
// DNS（端口 53）响应走嗅探写 IP→域名映射。
func (a *UDPAssociation) directReadLoop(conn *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		conn.SetReadDeadline(time.Now().Add(cfg.UDPReadTimeout))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// 空闲超时不关 socket（保持直发通道），继续等下一包。
				continue
			}
			return
		}
		if n == 0 {
			continue
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		if from != nil && from.Port == 53 {
			if qname, ips := sniffDNSAnswers(payload); qname != "" {
				for _, ip := range ips {
					rememberHostFromDNS(ip, qname)
				}
			}
		}
		host := ""
		if from != nil {
			host = from.IP.String()
		}
		port := 0
		if from != nil {
			port = from.Port
		}
		pkt, err := buildSOCKS5UDPPacket(host, port, payload)
		if err != nil {
			continue
		}
		a.mu.Lock()
		client := a.clientUDPAddr
		closed := a.closed
		a.mu.Unlock()
		if closed || client == nil {
			return
		}
		_, _ = writeUDPDatagram(a.udpListener, pkt, client)
	}
}

func (a *UDPAssociation) handleUDPResponse(addrStr string, data []byte) {
	host, portStr, err := net.SplitHostPort(addrStr)
	if err != nil {
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return
	}
	// §2.2 DNS 嗅探：响应侧从 DNS 报文提取 QNAME + A/AAAA 答案，写入 IP→域名
	// 映射（routeRT.remember），使后续 SOCKS5/HTTP 的 IP 字面量目标能反查域名
	// 命中 geosite/domain 规则。旁路观察，不改动数据流；引擎未启用时跳过。
	if routeRT.engineSnapshot() != nil && port == 53 {
		if qname, ips := sniffDNSAnswers(data); qname != "" {
			for _, ip := range ips {
				rememberHostFromDNS(ip, qname)
			}
		}
	}
	pkt, err := buildSOCKS5UDPPacket(host, port, data)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.clientUDPAddr != nil {
		_, _ = writeUDPDatagram(a.udpListener, pkt, a.clientUDPAddr)
	}
}

func (a *UDPAssociation) Close() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	stream := a.stream
	target := a.target
	chID := a.channelID
	directConn := a.directConn
	a.closed = true
	a.stream = nil
	a.directConn = nil
	active := a.active
	a.active = false
	a.mu.Unlock()
	if active {
		atomic.AddUint64(&udpAssociationActiveSeq, ^uint64(0))
	}
	if stream != nil {
		_ = stream.Close()
	}
	if directConn != nil {
		_ = directConn.Close() // 中断 directReadLoop
	}
	if chID > 0 && target != "" {
		log.Printf("[客户端] udp_assoc=%d SOCKS5-UDP 关联关闭 target=%s 通道 %d", a.id, target, chID)
		logClientConnEvent(a.tcpConn, "SOCKS5-UDP", target, chID, false)
	}
	_ = a.udpListener.Close()
	if a.tcpConn != nil {
		_ = a.tcpConn.Close()
	}
}

func parseSOCKS5UDPPacket(b []byte) (string, []byte, error) {
	target, offset, err := parseSOCKS5UDPFrameAddr(b)
	if err != nil {
		return "", nil, err
	}
	return target, b[offset:], nil
}

func buildSOCKS5UDPPacket(h string, p int, d []byte) ([]byte, error) {
	if p <= 0 || p > 65535 {
		return nil, fmt.Errorf("端口必须在 1-65535 之间")
	}
	buf := []byte{0, 0, 0}
	buf, err := appendSOCKS5UDPAddrChecked(buf, h, p)
	if err != nil {
		return nil, err
	}
	buf = append(buf, d...)
	return buf, nil
}

func parseSOCKS5UDPFrameAddr(packet []byte) (string, int, error) {
	if len(packet) < 4 {
		return "", 0, fmt.Errorf("数据包过短")
	}
	if packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return "", 0, fmt.Errorf("RSV/FRAG 字段必须为 0")
	}
	offset := 4
	host, offset, err := parseSOCKS5AddrBytes(packet, packet[3], offset)
	if err != nil {
		return "", 0, err
	}
	if offset+2 > len(packet) {
		return "", 0, fmt.Errorf("端口字段过短")
	}
	port := int(packet[offset])<<8 | int(packet[offset+1])
	if port == 0 {
		return "", 0, fmt.Errorf("端口必须在 1-65535 之间")
	}
	offset += 2
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if err := validateHostPort(addr); err != nil {
		return "", 0, err
	}
	return addr, offset, nil
}

func parseSOCKS5AddrBytes(packet []byte, atyp byte, offset int) (string, int, error) {
	switch atyp {
	case 0x01:
		if offset+4 > len(packet) {
			return "", 0, fmt.Errorf("IPv4地址长度过短")
		}
		return net.IP(packet[offset : offset+4]).String(), offset + 4, nil
	case 0x03:
		if offset+1 > len(packet) {
			return "", 0, fmt.Errorf("域名长度字段过短")
		}
		l := int(packet[offset])
		if l == 0 {
			return "", 0, fmt.Errorf("域名不能为空")
		}
		offset++
		if offset+l > len(packet) {
			return "", 0, fmt.Errorf("域名长度不足")
		}
		return string(packet[offset : offset+l]), offset + l, nil
	case 0x04:
		if offset+16 > len(packet) {
			return "", 0, fmt.Errorf("IPv6地址长度过短")
		}
		return net.IP(packet[offset : offset+16]).String(), offset + 16, nil
	default:
		return "", 0, fmt.Errorf("地址类型无效: %d", atyp)
	}
}

func appendSOCKS5UDPAddrChecked(buf []byte, h string, p int) ([]byte, error) {
	if h == "" {
		return nil, fmt.Errorf("域名不能为空")
	}
	if len(h) > 255 {
		return nil, fmt.Errorf("域名过长")
	}
	if err := validateHostnameOrIP(h); err != nil {
		return nil, err
	}
	return appendSOCKS5UDPAddr(buf, h, p), nil
}

func appendSOCKS5UDPAddr(buf []byte, h string, p int) []byte {
	ip := net.ParseIP(h)
	if ip4 := ip.To4(); ip4 != nil {
		buf = append(buf, 0x01)
		buf = append(buf, ip4...)
	} else if ip != nil {
		buf = append(buf, 0x04)
		buf = append(buf, ip.To16()...)
	} else {
		buf = append(buf, 0x03, byte(len(h)))
		buf = append(buf, h...)
	}
	buf = append(buf, byte(p>>8), byte(p))
	return buf
}
