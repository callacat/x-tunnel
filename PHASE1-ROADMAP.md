# Phase1 分流引擎实施路线图（recvtBpt，续传用）

> 本文件是 Phase1 实施状态载体（东哥定调：跨会话靠文件，不靠对话记忆）。
> 方案权威：`/home/agent/workspace/.tasks/x-tunnel-phase2-research/定稿方案-phase2-v2-warp-go对齐-2026-08-29.md`
> 仓库：x-tunnel core /tmp/x-tunnel（callacat fork，分支 feat/route-engine），自研豁免 H1 可改源码。

## 已完成（5df2e38 已 push）

- [x] §1.1 移植 route 包：warp-go route/ 6 源 4 测 → internal/route/（package=route 不变）
- [x] 依赖：v2fly/v2ray-core/v5 v5.53.0 + google.golang.org/protobuf v1.36.11（go 1.25.5）
- [x] go build/vet/test 全绿（route 测试 18+ 原样搬入，httptest 离线可跑）

## 关键 API 已摸清（续传无需再查）

- Match 签名：`func (e *route.Engine) Match(host string, ip netip.Addr) (string, Rule, bool)`
  - 返回 (action, matchedRule, matched)，action ∈ {"proxy","direct","reject"}（见 matcher.go:60）
- 接入点：`internal/app/local_socks5.go:313 handleSOCKS5Connect(c net.Conn, target string)`
  - 现在直接 `echPool.openTCPStream(target)`，需在此前插 RouteEngine.Match 三分支
- Engine 挂载位：`internal/app/engine.go:32 type Engine struct`，需新增 `routeEngine *route.Engine` 字段
  - 初始化点：`startRuntime()`（engine.go:138），依据 config.RouteEnabled
- route 引擎初始化 API：`route.NewEngine(rulesPath, geoDir string) (*Engine, error)`

## 待做（按序）

### §1.2 SOCKS5/HTTP 接入 Match
1. config.go：RuntimeConfig 增 `RulesPath/GeoDir/RouteEnabled`（+ RuntimeOptions 透传）
2. engine.go：Engine 增 routeEngine 字段；startRuntime 里若 RouteEnabled 则 NewEngine 初始化
   （rules 缺失写默认模板、geo 缺失 warning 降级 rules-only）
3. local_socks5.go handleSOCKS5Connect（:313）：
   - host 从 target 拆（ATYP 域名直接用 / IP 字面量先查 DNS 嗅探映射，miss 则 Match(ip,零值)）
   - action=proxy → 原 openTCPStream(target)
   - action=direct → 新 DIRECT 出口（见 §1.3）
   - action=reject → writeSOCKS5Reply(c, 0x02) + close
4. local_http.go 同位置（req.Host）接入

### §1.3 DIRECT 出口
- TCP：`net.DialTimeout("tcp", target, dialTimeout)` + proxyConnStream 第二参泛化为 io.ReadWriteCloser
  （client.go:317-340 proxyConnStream 当前签名）
- UDP：复用 DirectUDPRelayer（upstream_socks5.go:221-237）+ writeUDPDatagram（:243）
- 客户端 DIRECT 自行 DNS 解析（物理 DNS，sidecar 在 VPN 外，无需 SetSocketProtector）

### §1.4 config/control API
- control.go 增 `/v1/rules`（读）/ `/v1/rules/reload` / `/v1/route/stats`
- 路由注册模式同现有 /v1/xxx（control.go:73-81）

### §1.5 门禁
- gofmt / go vet / go test ./... / go test -race 全绿

## 依赖（runroute 已落地）
- go.mod 已含 v2fly/v2ray-core/v5 + protobuf（go mod tidy 已归置 direct）

## 完成判定
- CI 全绿出 debug APK（round N 三处版本号一致）
- 方案 §2.4 验收 12 项自测 + CT107 冒烟 + 东哥真机