package app

import (
	"context"
	"net"
	"testing"
	"time"
)

// 备份/恢复受测代码依赖的全局配置，避免污染其他用例。
func withDNSConfig(t *testing.T, ttl, qTimeout time.Duration) {
	t.Helper()
	oldTTL := cfg.DNSCacheTTL
	oldQ := cfg.DNSQueryTimeout
	t.Cleanup(func() {
		cfg.DNSCacheTTL = oldTTL
		cfg.DNSQueryTimeout = oldQ
	})
	cfg.DNSCacheTTL = ttl
	cfg.DNSQueryTimeout = qTimeout
}

func TestResolveLiteralIP(t *testing.T) {
	withDNSConfig(t, 5*time.Minute, time.Second)
	ips, err := globalDNSCache.Resolve(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("Resolve 字面量 IP 失败: %v", err)
	}
	if len(ips) != 1 || !ips[0].IP.Equal(net.ParseIP("1.2.3.4")) {
		t.Fatalf("Resolve 字面量应原样返回，got %v", ips)
	}
}

func TestGoodIPLifecycle(t *testing.T) {
	withDNSConfig(t, 5*time.Minute, time.Second)
	const host = "example.test"
	c := &dnsCache{entries: make(map[string]*dnsCacheEntry)}

	if ip := c.GoodIP(host); ip != nil {
		t.Fatalf("未记录时应返回 nil，got %v", ip)
	}
	want := net.ParseIP("203.0.113.7")
	c.MarkGood(host, want)
	if got := c.GoodIP(host); got == nil || !got.Equal(want) {
		t.Fatalf("MarkGood 后应返回该 IP，got %v want %v", got, want)
	}
	// 不同主机互不干扰
	if got := c.GoodIP("other.test"); got != nil {
		t.Fatalf("其他主机不应受影响，got %v", got)
	}
	c.ClearGood(host)
	if got := c.GoodIP(host); got != nil {
		t.Fatalf("ClearGood 后应返回 nil，got %v", got)
	}
}

// DNSCacheTTL=0 时条目立即过期，GoodIP 即便刚 MarkGood 也应返回 nil。
func TestGoodIPExpiredImmediately(t *testing.T) {
	withDNSConfig(t, 0, time.Second)
	c := &dnsCache{entries: make(map[string]*dnsCacheEntry)}
	c.MarkGood("example.test", net.ParseIP("203.0.113.8"))
	if got := c.GoodIP("example.test"); got != nil {
		t.Fatalf("TTL=0 时 GoodIP 应过期返回 nil，got %v", got)
	}
}
