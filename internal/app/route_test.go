package app

import (
	"os"

	"net/netip"
	"testing"
	"x-tunnel/internal/route"
)

// round40 兜底语义回归测试：decideForTarget 未命中必须兜底 proxy（防被墙），
// 不得把 matched=false 的 direct 零值当真——GEO 库缺失时规则全不命中，
// 旧逻辑会放大成「全部流量直连」（round39 真机实锤的根因 1）。

func TestDecideForTargetFallbackWhenEngineDisabled(t *testing.T) {
	// 引擎未启用（routeRT 无引擎）：恒 proxy。
	if got := decideForTarget("example.com", netip.Addr{}); got != routeProxy {
		t.Fatalf("engine disabled: got %v, want routeProxy", got)
	}
}

func TestDecideForTargetFallbackOnNoMatch(t *testing.T) {
	// 引擎启用但目标不在任何规则内：兜底 proxy（防被墙），绝不 direct。
	e, err := newTestRouteEngine(t, "direct,geoip:cn\n")
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	// 非中国 IP（8.8.8.8）不在 geoip:cn → 未命中 → 必须 proxy。
	if got := decideForTarget("8.8.8.8", netip.Addr{}); got != routeProxy {
		t.Fatalf("no match: got %v, want routeProxy (fallback)", got)
	}
}

func TestDecideForTargetExplicitDirect(t *testing.T) {
	// 规则显式命中 direct 才允许直连。
	e, err := newTestRouteEngine(t, "direct,domain:baidu.com\n")
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if got := decideForTarget("www.baidu.com", netip.Addr{}); got != routeDirect {
		t.Fatalf("explicit direct: got %v, want routeDirect", got)
	}
}

func TestDecideForTargetRejectRule(t *testing.T) {
	e, err := newTestRouteEngine(t, "reject,domain:ads.example.com\n")
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if got := decideForTarget("ads.example.com", netip.Addr{}); got != routeReject {
		t.Fatalf("explicit reject: got %v, want routeReject", got)
	}
}

func TestDecideForTargetDefaultFallbackDeclared(t *testing.T) {
	// 规则文件声明 default:proxy → 未命中按声明走 proxy（matched=true 路径）。
	e, err := newTestRouteEngine(t, "direct,geoip:cn\ndefault:proxy\n")
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if got := decideForTarget("1.2.3.4", netip.Addr{}); got != routeProxy {
		t.Fatalf("declared default: got %v, want routeProxy", got)
	}
}

// newTestRouteEngine 用临时规则文件装配引擎并挂到 routeRT（测试结束恢复）。
func newTestRouteEngine(t *testing.T, rulesText string) (*route.Engine, error) {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/rules.txt"
	if err := os.WriteFile(path, []byte(rulesText), 0o644); err != nil {
		return nil, err
	}
	engine, err := route.NewEngine(path, dir)
	if err != nil {
		return nil, err
	}
	prev := routeRT.engineSnapshot()
	routeRT.setEngine(engine)
	t.Cleanup(func() {
		routeRT.setEngine(prev)
	})
	return engine, nil
}

// round45：DNS 源分流语义回归——「未命中/库缺失」必须走国内直连解析（保底），
// 仅明确 proxy 的域名才走隧道解析。r43 反语义在 GEO 库缺失时把国内域名也
// 推到隧道 DNS，隧道不稳 = 全断（r44 真机实锤）。
func TestDNSSourceRoutingSemantic(t *testing.T) {
	// 场景1：GEO 库缺失（只有 domain 规则可命中的引擎）。
	e, err := newTestRouteEngine(t, "direct,domain:baidu.com\nproxy,domain:github.com\n")
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	// 国内域名（命中 direct）→ 不走隧道解析（直连解析）。
	if shouldTunnelDNS("www.baidu.com") {
		t.Fatalf("cn domain: shouldTunnelDNS=true, want false（直连解析）")
	}
	// 明确 proxy 的境外域名 → 走隧道解析。
	if !shouldTunnelDNS("github.com") {
		t.Fatalf("proxy domain: shouldTunnelDNS=false, want true（隧道解析）")
	}
	// 未命中任何规则的域名 → 保底直连解析（不得推隧道，r43 反语义回归）。
	if shouldTunnelDNS("example.org") {
		t.Fatalf("unmatched domain: shouldTunnelDNS=true, want false（保底直连）")
	}
	// TCP 判定兜底语义保持：未命中仍 proxy（防被墙）——与 DNS 语义刻意不同。
	if got := decideForTarget("example.org", netip.Addr{}); got != routeProxy {
		t.Fatalf("tcp unmatched: got %v, want routeProxy（防被墙兜底不变）", got)
	}
}
