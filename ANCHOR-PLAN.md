# 合并预演锚定方案（Anchor Plan）

> 用途：真实合并（push 到远端）前的**锚定基线**。合并预演已完成并本地 commit（未 push），
> 本文件把「已定案的事实」「合并时要复验的锚点」「剩余风险」「不得触碰的边界」固化为文档，
> 供后续会话/代理续接，不靠对话记忆。

## 0. 结论速览

- **预演合并成功**：8 个 UU 文件全部解冲突，`go build`/`go vet`/`go test ./...` 全绿，本地 commit（未 push）。
- **分流能力已并入**：route 引擎、DNS 源分流、SNI 嗅探改写、control API（/v1/rules…）、config 字段全部进合并结果。
- **主 v3 协议栈未被污染**：client.go 保持 main 原样（route 线客户端拨号加固按方案不入本合并）。
- **auth proof invalid 根因已定案（另一子代理白盒实锤，非代码 bug）**：客户端 `-f` 带 `/tunnel` 路径，服务端实际收 `/`——path 分歧导致 proof 不匹配；v2 proof 是纯函数，client/server 字节一致。此结论与本次合并无代码耦合，但影响验收方式。

## 1. 合并事实锚点（commit / 文件）

| 项 | 值 |
|---|---|
| 仓库 | `/root/workspace/merge-preview`（worktree，`local-merge-preview` 分支） |
| HEAD（main 侧） | `384323b` docs: add repository guidelines in AGENTS.md |
| MERGE_HEAD（route 侧） | `b3eedd6` feat(sni): r47——裸 IP:443 嗅探 TLS SNI 改写域名目标 |
| merge base | `98e75a0` |
| 本地合并 commit | 见 git log（本文件落盘后即 commit，哈希以 `git rev-parse local-merge-preview` 为准） |
| 冲突文件 | ci.yml / release.yml / go.mod / go.sum / client.go / config.go / engine.go / local_socks5.go（8 个，全解） |
| 新并入文件 | internal/route/* 全套、internal/app/{route,dnscache,dnssniff,snisniff}.go + 对应测试、snisniff_wiring_test.go |
| 交付文档 | MERGE-CONFLICT-RESOLUTION.md（本目录，未 commit，工作区落盘） |

## 2. 锚定方案：真实合并前必须复验的 8 个锚点

> 每次真实合并（或重新预演）按此清单逐项核对，任何一项不满足即停。

1. **ci.yml / release.yml**：`go-version`/`GO_VERSION` = `"1.25.x"`（浮点 minor，不锁 1.25.5）；release.yml `env:` 下 GO_VERSION 有 2 空格缩进（YAML 合法）。
2. **go.mod**：`go 1.25.5`；v2fly/v2ray-core/v5 v5.53.0 **direct**；protobuf v1.36.11 **direct**；quic-go v0.61.0 / x/crypto v0.54.0 direct；go.sum 经 `go mod tidy` 收口（当前 36 行）。
3. **client.go == main 原样**：`git diff HEAD -- internal/app/client.go` 为空。无 hostName/markHost/dialCached/globalDNSCache/preResolveDialTargets；`resolveWebSocketDialTarget(address, ip)` 2 参签名。
4. **front_proxy_test.go == main 原样**：同 3（该测试按 main 的 2 参签名，不得改回 ctx 版）。
5. **config.go**：main FileConfig 全字段 + `DNSCacheTTL` + `rulesPath/geoDir/routeEnabled/sniSniff`（flag 齐全，`-sni` 默认 true）；`applyConfigJSONToValues` 有 route 4 分支；gofmt 干净。
6. **engine.go**：`routeEngine *route.Engine` + `initRouteEngine()`（routeEnabled 时）+ `Close()` 先 `pool.WaitDone` 再 `routeEngine.Close()` + `routeRT.setEngine(nil)`。
7. **local_socks5.go**：`UDPAssociation.stream` 是 `*V3CipherStream`；`shouldTunnelDNS`（1.1.1.1 隧道 / 223.5.5.5 直连）；`handleSNIProxyConnect`+`sniffSNITarget`+`sniCandidate`；SOCKS5/HTTP/DNS 接入点三分支。
8. **wiring 测试锚点（regression 守护）**：`TestSNISniffRewriteSOCKS5Connect` 用**业务流同一 smux 配对**跑 v3 协商（keys 会话级）；服务端应答用 `writeTCPOpenStatusCode(OK,0)`（客户端走 OpenStatusCode 变体）；`cfg.DialTimeout=5s`；failOpen 不走死块。

## 3. 验证命令（锚定脚本）

```bash
cd /root/workspace/merge-preview
export PATH=$PATH:/usr/local/go/bin GOTOOLCHAIN=local TMPDIR=/root/tmp-go
gofmt -l ./cmd ./internal          # 空
go build ./...                     # OK
go vet ./...                       # OK
go test -count=1 -timeout=4m ./... # {app,netaddr,route,transport,wire} 全 ok
# 定点回归（SNI 嗅探改写端到端）：
go test -count=1 -run TestSNISniffRewriteSOCKS5Connect -v ./internal/app/   # 7 子用例 PASS
```

> 注意：`/tmp` 是 tmpfs 2G，go 构建缓存会写满——一律 `TMPDIR=/root/tmp-go`。

## 4. 剩余风险（真实合并/上线前要盯）

| 风险 | 说明 | 缓解 |
|---|---|---|
| **auth proof path 分歧** | 客户端 `-f` 带 `/tunnel` 路径，服务端实际收 `/` → v2 proof 不匹配（白盒实锤，非代码 bug）。真机/验收时若 auth 失败先查两侧 path 配置是否一致，**不要**去改 proof 代码。 | 验收脚本统一 `-f` 与服务端规则；诊断增强 commit 9a940ef 已在 /tmp/xt-route（feat/route-engine worktree，未 push）可复用。 |
| **route 线客户端拨号加固未并入** | dnscache.go 已入库但**未被任何拨号路径引用**（`globalDNSCache` 只被自身测试引用）；`-dns-cache-ttl` flag 存在但拨号不走缓存。行为 = main 原样（每次系统解析）。 | 真实合并若需要拨号缓存，另开 commit 接 `dialWebSocketWithECH`；本合并刻意不含。 |
| **镜像 download 依赖变更** | `isLocalDownloadURL` 本地 URL 跳过加速镜像——生产上自建 GEO 源走直连；镜像语义仅对公网 URL 生效。 | 已在 download.go 注释固化；回归由两 offline 测试守护。 |
| **sniSniff 默认开启** | `-sni` 默认 true：裸 IP:443 连接会先回 0x00 再嗅探（SNI 路径打开失败时已无法回错误码，只能关连接，与 sing-box 一致）。 | 文档已说明；若线上有非 TLS 协议裸连 443 场景，`-sni=false` 可关。 |
| **test -race 未跑** | 本预演跑的是 `go test`（非 -race）。CI 的 race 步骤（3m）需在真实合并 CI 上验证。 | CI 已含 race 步骤；本地如需可加 `-race -count=1 ./internal/app`。 |
| **go 1.26.5 本地 vs CI 1.25.x** | 本地用 1.26.5 验证（GOTOOLCHAIN=local）；route 线声称 go 1.25.5 兼容。 | CI（1.25.x）为准；若 1.25 编译报错，属 route 线依赖版本问题，回看 go.mod。 |

## 5. 明确不做（边界）

- 不 push、不动远端、不改 `feat/route-engine`/`main` 分支。
- 不并入 route 线客户端拨号加固（hostName/markHost/dialCached/globalDNSCache/preResolveDialTargets）——按方案 §3 属后续独立工作。
- 不修复 auth proof 服务端 `-f` path 分歧——定案为配置问题，非代码缺陷；诊断 commit 在 /tmp/xt-route 备查。
- 不删 `-dns-cache-ttl` flag 与 dnscache.go（已入库，后续拨号缓存工作复用）。
- 交付文档不入 commit（避免污染合并提交）；落盘在仓库根但保持 untracked。

## 6. 续传入口

下次接手（无论谁）：
1. `cd /root/workspace/merge-preview && git status` 应显示合并已 commit、工作区只有两份文档 untracked + PHASE1-ROADMAP.md 已 A。
2. 核对 §2 的 8 个锚点（重点 3/4：client.go、front_proxy_test.go 与 main 零差异）。
3. 需要验收 auth 链路 → 看 §4 风险行，用 /tmp/xt-route 9a940ef 的诊断增强。
4. 需要接拨号缓存 → 在合并结果上从 `dialWebSocketWithECH` 接入 globalDNSCache（dnscache.go 已就绪）。