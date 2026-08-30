package route

import (
	"net/netip"
	"os"
	"testing"
)

// round41：内置 CN 兜底表验证——典型国内 IP 应命中、典型境外 IP 不应命中。
func TestBuiltinCNContains(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"122.114.192.226", true}, // 河南联通（r40 诊断包实测 IP）
		{"202.96.209.5", true},    // 上海电信 DNS
		{"223.5.5.5", true},       // 阿里公共 DNS
		{"119.29.29.29", true},    // 腾讯 DNSPod
		{"180.76.76.76", true},    // 百度 DNS
		{"36.152.44.96", true},    // 移动段
		{"1.2.3.4", false},        // 亚太非 CN
		{"8.8.8.8", false},        // Google
		{"1.1.1.1", false},        // Cloudflare
		{"104.16.132.229", false}, // Cloudflare
	}
	for _, c := range cases {
		ip := netip.MustParseAddr(c.ip)
		if got := builtinCNContains(ip); got != c.want {
			t.Errorf("builtinCNContains(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

// 降级路径端到端：geo 库缺失 + 规则 direct,geoip:cn → 国内 IP 命中 direct。
func TestMatchCNFallbackWhenGeoMissing(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/rules.txt"
	if err := os.WriteFile(path, []byte("direct,geoip:cn\ndefault:proxy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(path, dir) // geoDir 无 GEO 库 → 降级路径
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	action, _, matched := e.Match("122.114.192.226", netip.Addr{})
	if !matched || action != ActionDirect {
		t.Fatalf("CN IP with geo missing: got (%q,%v), want (direct,true)", action, matched)
	}
	// 境外 IP 仍兜底 proxy
	action, _, matched = e.Match("8.8.8.8", netip.Addr{})
	// 8.8.8.8 不在 geoip:cn → 命中 default:proxy 兜底
	if !matched || action != ActionProxy {
		t.Fatalf("foreign IP should fallback proxy via default, got (%q,%v)", action, matched)
	}
}
