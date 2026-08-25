package app

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// dnsCacheEntry 是单个主机的解析缓存项。
type dnsCacheEntry struct {
	ips     []net.IPAddr
	rrIndex int // 候选轮询下标：系统解析器的首选可能是协议层坏端点（如 CF 边缘未回源），轮询让重连逐个尝试
	expires time.Time
	// goodIP 记录该主机最近一次通过 v2 协商验证的 IP（真正可用的隧道端点），
	// 供重连直连，跳过重复慢速 DNS。由 dialAndServe 在协商成功后写入；
	// TCP 不可达、WS 握手失败或上层协商失败时被 ClearGood 清除以回退候选轮询。
	goodIP net.IP
	// pending 表示正在解析中；waiters 为并发等待结果的通道（防击穿）。
	pending bool
	waiters []chan []net.IPAddr
}

// dnsCache 是一个线程安全、带 TTL 与防击穿的 DNS 解析缓存。
// TTL 取自全局配置 cfg.DNSCacheTTL（<=0 表示禁用缓存，每次重新解析）。
// 缓存全部解析结果避免重复慢速 DNS；并记录最近一次通过 v2 协商验证的可用 IP 供重连直连，
// 端点失效（TCP 不可达、握手失败或协商失败）时由 ClearGood 清除并回退系统解析器（Happy Eyeballs）。
type dnsCache struct {
	mu      sync.Mutex
	entries map[string]*dnsCacheEntry
}

// globalDNSCache 进程级单例，所有拨号共用，避免重复慢速解析。
var globalDNSCache = &dnsCache{entries: make(map[string]*dnsCacheEntry)}

// Resolve 解析主机名并返回其 IP 地址列表，结果按 TTL 缓存。
// 缓存未命中时并发请求会合并为一次真实解析（防击穿），重连风暴时只付出一次 DNS 代价。
func (c *dnsCache) Resolve(ctx context.Context, host string) ([]net.IPAddr, error) {
	if net.ParseIP(host) != nil {
		// 已经是 IP 字面量，无需解析
		return []net.IPAddr{{IP: net.ParseIP(host)}}, nil
	}
	ttl := cfg.DNSCacheTTL
	if ttl <= 0 {
		return lookupHost(ctx, host)
	}

	c.mu.Lock()
	if e, ok := c.entries[host]; ok && time.Now().Before(e.expires) {
		ips := dupIPAddrs(e.ips)
		c.mu.Unlock()
		return ips, nil
	}
	if e, ok := c.entries[host]; ok && e.pending {
		ch := make(chan []net.IPAddr, 1)
		e.waiters = append(e.waiters, ch)
		c.mu.Unlock()
		return waitForResolve(ctx, c, host, ch)
	}
	// 成为本次解析的发起者
	e := &dnsCacheEntry{pending: true}
	c.entries[host] = e
	c.mu.Unlock()

	start := time.Now()
	ips, err := lookupHost(ctx, host)
	elapsed := time.Since(start)
	c.mu.Lock()
	e.pending = false
	waiters := e.waiters
	e.waiters = nil
	if err != nil {
		delete(c.entries, host)
		c.mu.Unlock()
		log.Printf("[DNS] 解析 %s 失败 (耗时 %s): %v", host, elapsed, err)
		for _, w := range waiters {
			w <- nil
		}
		return nil, err
	}
	e.ips = ips
	e.expires = time.Now().Add(ttl)
	c.mu.Unlock()
	log.Printf("[DNS] 解析 %s -> %s (耗时 %s, 缓存 %s)", host, ipAddrsString(ips), elapsed, ttl)
	for _, w := range waiters {
		w <- ips
	}
	return dupIPAddrs(ips), nil
}

// GoodIP 返回该主机最近一次成功建链的已知可用 IP；缓存缺失/过期或尚未记录时返回 nil。
// 调用方应优先直连该 IP 以规避重连风暴下的重复慢速 DNS；直连失败再回退系统解析器。
func (c *dnsCache) GoodIP(host string) net.IP {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[host]
	if !ok || time.Now().After(e.expires) || e.goodIP == nil {
		return nil
	}
	return e.goodIP
}

// MarkGood 记录主机 host 通过 v2 协商验证的可用 IP，供后续重连直连。
// 若缓存条目已过期/不存在则新建一条仅含该可用 IP 的轻量条目（不触发解析），
// 保证"已验证可用端点"在 TTL 内对后续重连可见。
func (c *dnsCache) MarkGood(host string, ip net.IP) {
	if ip == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[host]
	if !ok || time.Now().After(e.expires) {
		e = &dnsCacheEntry{
			ips:     []net.IPAddr{{IP: ip}},
			expires: time.Now().Add(cfg.DNSCacheTTL),
		}
		c.entries[host] = e
	}
	e.goodIP = ip
}

// ClearGood 清除该主机的已知可用 IP（端点失效时调用），迫使下次拨号回退系统解析器重选端点。
// 缓存条目本身保留（解析结果仍在 TTL 内可继续复用），仅清空 goodIP 标记。
func (c *dnsCache) ClearGood(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[host]; ok {
		e.goodIP = nil
	}
}

// NextCandidate 返回该主机候选列表中轮询到的下一个 IP，并推进下标。
// 若缓存中有有效列表则用缓存（调用方传入的 ips 仅用于首次填充/过期刷新）。
// 目的：系统解析器的首选端点可能 TCP 可达但隧道不可用（协商 EOF），
// 轮询让后续重连依次尝试其余候选，直到某个端点通过 v2 协商并被 MarkGood 锁定。
func (c *dnsCache) NextCandidate(host string, ips []net.IPAddr) net.IP {
	if len(ips) == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[host]
	if !ok || time.Now().After(e.expires) || len(e.ips) == 0 {
		e = &dnsCacheEntry{ips: dupIPAddrs(ips), expires: time.Now().Add(cfg.DNSCacheTTL)}
		c.entries[host] = e
	}
	if e.rrIndex >= len(e.ips) {
		e.rrIndex = 0
	}
	ip := e.ips[e.rrIndex].IP
	e.rrIndex = (e.rrIndex + 1) % len(e.ips)
	return ip
}

// waitForResolve 等待发起者完成解析并取结果；发起者失败时递归重试一次。
func waitForResolve(ctx context.Context, c *dnsCache, host string, ch chan []net.IPAddr) ([]net.IPAddr, error) {
	select {
	case ips := <-ch:
		if ips == nil {
			// 发起者解析失败，自行重试
			return c.Resolve(ctx, host)
		}
		return ips, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// lookupHost 通过系统解析器解析主机名，超时受 cfg.DNSQueryTimeout 约束。
func lookupHost(ctx context.Context, host string) ([]net.IPAddr, error) {
	rctx, cancel := context.WithTimeout(ctx, cfg.DNSQueryTimeout)
	defer cancel()
	return net.DefaultResolver.LookupIPAddr(rctx, host)
}

func dupIPAddrs(in []net.IPAddr) []net.IPAddr {
	out := make([]net.IPAddr, len(in))
	copy(out, in)
	return out
}

func ipAddrsString(ips []net.IPAddr) string {
	parts := make([]string, 0, len(ips))
	for _, ip := range ips {
		parts = append(parts, ip.IP.String())
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
