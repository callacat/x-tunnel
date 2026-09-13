# 合并预演：8 文件冲突解法清单

> 仓库：`/root/workspace/merge-preview`（本地 worktree，`local-merge-preview` 分支）
> 合并方向：`main`(HEAD 384323b) ← `feat/route-engine`(MERGE_HEAD b3eedd6)，base 98e75a0
> 时间：2026-09-13。**已本地 commit，未 push。**

## 总则

- **分流接线（route 线能力）全保留**：`internal/route/*` 全套 + app 层 dnscache/dnssniff/snisniff/route/control/engine 挂载。
- **主 v3 线（main）协议栈全保留**：`internal/transport/*`、`internal/wire/*`（v3 双栈、KDF、record-layer、ForwardSecrecy 1<<12）。
- 冲突逐文件按「主 v3 线协议为准、并入 route 线接线」原则手工归一。

## 逐文件解法

### 1. `.github/workflows/ci.yml`
- **解法**：`go-version` 取 main 线 `"1.25.x"`（route 线锁 `1.25.5` 太死，workflow 语义应浮点 minor）。
- 其余（checkout@v6/setup-go@v6/fuzz 步骤/race）两侧一致，无冲突。

### 2. `.github/workflows/release.yml`
- **解法**：`GO_VERSION: "1.25.x"`（同上，浮点 minor）。
- **合并后的修复**：`env:` 下 `GO_VERSION` 缩进丢失（列 0，YAML 非法）→ 补缩进 2 空格，与 `jobs:` 平级对齐。

### 3. `go.mod`
- **解法**：`go 1.25.5`；require 归一为「主 v3 线直接依赖 + route 线直接依赖 + indirect」三块：
  - direct：uuid / gorilla/websocket / **v2fly/v2ray-core/v5 v5.53.0** / smux / **protobuf v1.36.11**
  - direct（主线）：quic-go v0.61.0、golang.org/x/crypto v0.54.0
  - indirect：adrg/xdg、golang/protobuf、golang.org/x/net、golang.org/x/sys
- **注意**：v2ray-core / protobuf 从 route 线 indirect 提升为 direct（route 包 import 它们）。

### 4. `go.sum`
- **解法**：手工归一后 `go mod tidy` 收口（v2fly v5.53.0 + protobuf v1.36.11 及其传递依赖）；最终 36 行。

### 5. `internal/app/client.go` — **主 v3 线胜**
- **解法**：整体取 main 版本（`git checkout HEAD -- internal/app/client.go`），**删除 route 线客户端加固**：
  - `hostName` 字段 + `markHost()`、`dialCached()`、`globalDNSCache` 引用、`preResolveDialTargets(startup)`
  - `resolveWebSocketDialTarget` 恢复 main 的 2 参签名 `(address, ip) string, error`（route 线改 3 参带 ctx）
- **保留（main 线本就有的 v3 接线）**：`endpointPool`、`V3SessionKeys` 池、`channelCiphers` 池、v3 协商日志、`Capabilities|ForwardSecrecy(1<<12)`。
- **理由**：dnscache.go（route 线新增文件）仍是独立未接入文件，靠 `cfg.DNSCacheTTL` 编译自洽；拨号加固与 v3 线不冲突但按方案 §3 不入本合并。

### 6. `internal/app/config.go` — **主 FileConfig 全字段 + route 接线字段**
- **解法**：
  - main `FileConfig` 全字段为基底（listen/forward/ip/block/… 不动）
  - **补回** `DNSCacheTTL`（flag `-dns-cache-ttl`、GlobalConfig、default 5m、applyDuration）
  - **并入 route 线 4 字段**：`rulesPath`/`geoDir`/`routeEnabled`/`sniSniff`（flag `-rules-path`/`-geo-dir`/`-route-enabled`/`-sni` 默认 true）
  - `defaultRuntimeValues()` 补 `SNISniff: true`；`applyConfigJSONToValues` 4 分支（rules/geo/route-enabled/sni）并入
  - `validateDialIPOverride` 允许域名（route 线增强，配合 `-ip` 可带域名）
  - gofmt 收口整个文件。
- **说明**：`enableECH bool` + `-ech-domain`（route 线 flag 定义走 v3 语义）按 v3 线 flag 保留。

### 7. `internal/app/engine.go` — **主 ECHPool+gracful shutdown 保留，route 挂载并入**
- **解法**：保留 main 的 `echPool` 字段 + `pool.WaitDone(ctx)` 优雅关闭；并入 route 线：
  - `routeEngine *route.Engine` 字段
  - `startRuntime()` 内 `initRouteEngine()`（routeEnabled 时装配，错误 `route.init_failed`）
  - `Close()` 内 `routeEngine.Close()` + `routeRT.setEngine(nil)`（先关池再关路由）
- `protocol=...` 日志按 main v3 线（`protocol=v3`）。

### 8. `internal/app/local_socks5.go` — **主 UDP v3 流 + route 线 DNS 分流/SNI 嗅探并入**
- **解法**：
  - `UDPAssociation.stream` 取 main 的 `*V3CipherStream`（v3 加密 UDP）
  - 并入 route 线：`directConn` UDP 直连出口、`sendDirect`、`directReadLoop`
  - **DNS 源分流 `shouldTunnelDNS`**：1.1.1.1（境外）走隧道、223.5.5.5（国内）保底直连解析
  - **round47 SNI 嗅探**：`handleSNIProxyConnect`/`sniffSNITarget`/`sniCandidate`/`routeRT` 三分支（SOCKS5+DNS source 判定）
  - `tunnelDNSHost`/`directDNSHost` 常量并入

## 测试修复：TestSNISniffRewriteSOCKS5Connect

**根因**（上个子代理已定位 90%）：route 线 v2 mock ECHPool 无 v3 keys；合并后 `openTCPStream` 走 v3 加密 → mock 解密失败、首包时序乱、failOpen 分支死逻辑。

**本代理完成**（`internal/app/snisniff_wiring_test.go`）：
1. **同会话协商**：keys/cipher 是 **smux 会话级**，业务流与协商握手流必须同一配对——改为在业务流同一 `serverSession/clientSession` 上跑真实 v3 协商（删掉"第二条配对"），注入 `endpointPool` 的 keys 才能解业务流。
2. **状态码变体对齐**：客户端 `readTCPOpenStatusCode`（caps 含 OpenStatusCode），服务端 mock 必须写 `writeTCPOpenStatusCode(OK,0,"")`——原写 `writeTCPOpenStatus`（无 code 字节）导致客户端解析错位、超时。
3. **删死块**：failOpen 用例原先在 Accept 后立即 `serverDone <- "不应 Accept 业务流"`（死逻辑，业务流必然到达）→ 删除，保留下方正确的失败应答 `writeTCPOpenStatusCode(error, policyDenied)`。
4. **慢发用例**：`cfg.DialTimeout = 5s`（原 1s，SNI 嗅探 1s deadline + 握手序列在 1s 内不够，误报超时）。
5. **wantClosed 用例**：读 0x00 后补发 ClientHello，真实走改写路径再触发远端错误关闭（原不发首包、改写路径没被执行）。

**验证**：`TestSNISniffRewriteSOCKS5Connect` 7 子用例全 PASS（服务端解密 open 头 kind=1 strat=0 target=www.example.com:443 正确、payload 首包 0x16 完整回读；上个子代理的临时单测 TestDebug6 已随调试文件一并删除）。

## 额外修复（route 线存量缺陷，合并后 go test 必绿暴露）

- **`internal/route/download.go`**：`downloadWithMirrors` 对 **回环地址 URL**（httptest：`127.0.0.1:port/...`）会先拼真实加速镜像（gh-proxy.org/com）→ 外部 URL 无法到达 → 挂 90s 超时 → 两个"offline"测试（`TestDownloadDefaultRulesOffline`/`TestUpdateGeoDataOffline`）全挂。
  - 修复：新增 `isLocalDownloadURL()`（localhost/127.0.0.1/::1 判定），本地 URL 直接 `fetch` 原始地址，跳过镜像。
  - 这是生产级合理的健壮性改进（本地自建 GEO/规则源 / 测试端点本就不该走加速镜像），两测试 9ms 内过。

## 环境备注
- Go 1.26.5（PATH=/usr/local/go/bin），`GOTOOLCHAIN=local`。
- `/tmp` 是 tmpfs 2G，go build 缓存写满 → `TMPDIR=/root/tmp-go GOCACHE=/root/.cache/go-build`。

## 验证（最终全绿）
```
go build ./...   → OK
go vet ./...     → OK
gofmt -l ./cmd ./internal → 空
go test -count=1 -timeout=4m ./... → 全 ok（app 7.0s / netaddr / route 0.16s / transport / wire）
```