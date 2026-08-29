# x-tunnel QUIC/TCP 双栈传输层设计规范 (P2 阶段)

状态: 架构设计稿 (Design Document)
交付阶段: P2 阶段传输层双栈核心设计 ("先出设计再动代码")
设计依据: 
- `docs/protocol-v3-optimization.md` §3 (传输层双栈与会话层统一)
- `docs/protocol-v3-research/mux-transport.md` (多路复用与传输层优化研究)
- `docs/protocol-v3-research/traffic-shape.md` §B.3, §C.3 (流量伪装与抗审查)
- `docs/protocol-v3-research/handshake-replay.md` (防重放与前向保密)
- `docs/protocol.md` §3 (v3 握手与通道安全基线)

---

## 1. 目标与非目标 (Goals and Non-goals)

### 1.1 背景与痛点
x-tunnel 现有 v2/v3 协议基于单个 TCP 连接（经由 WebSocket / TLS 1.3）运行 smux 多路复用。尽管该架构在穿透防火墙与伪装方面表现优秀，但在弱网与高丢包网络（如移动蜂窝网络、跨国拥塞链路）中存在难以逾越的结构性瓶颈：
1. **TCP 队头阻塞 (Head-of-Line Blocking)**: 所有内层代理流（TCP/UDP）共享单条底层 TCP 连接的发送与接收窗口。任意单包丢失均会触发 TCP 重传，导致整条长连接上的所有流同时停顿，流越多、丢包率越高，卡顿越明显。
2. **拥塞控制粒度粗糙**: 无法区分交互式小流（SSH/DNS/网页首屏）与吞吐型大流（大文件下载/视频），大流会挤占整条 TCP 拥塞窗口。
3. **网络切换连接断开**: 客户端在 Wi-Fi 与蜂窝移动网络之间切换时，由于 TCP 强绑定 IP+Port 四元组，导致底层连接必定被重置（RST），所有在传流全部中断。

引入 IETF QUIC (RFC 9000) + QUIC Datagram (RFC 9221) 可以彻底消除队头阻塞并获得连接迁移能力。但由于 GFW 具备对标准 QUIC Initial 报文的 SNI 解密与阻断能力（USENIX Security '25），且国内运营商存在常态化 UDP QoS 限速，**QUIC 绝不能作为唯一传输依赖**。必须构建 **QUIC + TCP 双栈架构**：QUIC 作为主力提供极致性能，TCP (wss) 作为保底提供高可达性。

### 1.2 设计目标 (Goals)
1. **传输层抽象与解耦**: 定义统一的 `Transport`、`TransportSession` 与 `TransportStream` 抽象接口，隔离底层传输载体（QUIC vs TCP/smux）差异，使上层 v3 认证、流控制、SOCKS5/HTTP 业务转发逻辑 100% 复用。
2. **根治弱网队头阻塞**: 在 UDP 可达且网络质量良好时，默认走 QUIC 协议栈，利用 QUIC 原生独立的 Stream 机制实现多流真正隔离。
3. **原生 UDP 数据报转发 (RFC 9221)**: 在 QUIC 栈下，利用不可靠 Datagram 传输 UDP 代理流量，保持消息边界，彻底摆脱流式封装对 UDP 造成的时延劣质化。
4. **客户端连接平滑迁移 (Connection Migration)**: 利用 QUIC Connection ID 机制，实现客户端网络路径（Wi-Fi <-> 5G）切换时底层连接不断开、上层业务流无感迁移。
5. **智能探测、记忆与快速回退**: 客户端内置双栈选择器，支持根据网络可达性、丢包率与历史记忆自动选择最优栈；在 UDP 被拦截或劣化时，秒级无缝回退至 TCP 保底通道。

### 1.3 非目标 (Non-goals) 【硬约束】
1. **不做 0-RTT 会话恢复票据 (No 0-RTT Session Resumption Tickets)**:
   - **明确放弃 0-RTT Early Data**: 严禁在 QUIC 握手阶段支持或发送 0-RTT 早期数据。
   - **根本原因**: 0-RTT 数据不具备前向安全性且极易受到网络重放攻击。在代理场景下，长连接建立后所有数据流均在已建会话内复用，握手仅在首次建连发生（发生频率极低），1-RTT 带来的握手时延开销完全可以忽略。彻底关闭 0-RTT 可以完全消除重放隐患，避免在服务端引入复杂的分布式防重放持久化缓存，符合纵深防御原则。
2. **不改动 v3 密码层与端到端安全模型 (No Modifications to v3 Crypto Layer)**:
   - **传输与加密职责分离**: QUIC 仅作为底层的“传输载体”（Transport Carrier），负责网络报文调度、拥塞控制与流复用。
   - **内层仍走 v3 记录层**: 无论底层是 QUIC 还是 TCP，流内部的载荷一律由 v3 的 `V3CipherStream` 进行端到端 AEAD 加密（ChaCha20-Poly1305 / AES-GCM），维持 64 位独立计数器与滑动窗口抗重放。不因 QUIC 带有外层 TLS 1.3 而削弱内层端到端安全。
3. **不自研私有不可靠传输协议**:
   - 严格基于标准 IETF QUIC 规范，绝不引入未经密码学与工程验证的自研 UDP 协议。

---

## 2. Transport 抽象接口定义 (Transport Abstraction)

### 2.1 架构分层全景图

```text
+-------------------------------------------------------------------------+
|                  应用层: SOCKS5 / HTTP Proxy / TCP Forward              |
+-------------------------------------------------------------------------+
|      v3 统一会话层 (V3CipherStream / AEAD 加密 / 64位计数器 + 滑动窗口)   |
+-------------------------------------------------------------------------+
|        v3 控制面: ChannelInit / ChannelAccept / AuthProof / KeyDerive    |
+-------------------------------------------------------------------------+
|                  Transport 统一抽象接口 (TransportSession)              |
+------------------------------------+------------------------------------+
|          QuicTransport             |            TcpTransport            |
|  - RFC 9000 QUIC Streams           |  - Gorilla WebSocket / net.Conn    |
|  - RFC 9221 Datagram               |  - smux v2 Multiplexer             |
|  - HTTP/3 伪装 (/auth)             |  - wss:// TLS 1.3 伪装             |
|  - Connection Migration            |  - 保底穿透通路                    |
+------------------------------------+------------------------------------+
|              UDP 网络层            |             TCP 网络层             |
+------------------------------------+------------------------------------+
```

### 2.2 Go 接口草案设计 (`internal/transport`)

```go
package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

var (
	// ErrDatagramNotSupported 当底层传输协议不支持 Datagram 时返回
	ErrDatagramNotSupported = errors.New("transport: datagram not supported")
	// ErrSessionClosed 会话已关闭
	ErrSessionClosed = errors.New("transport: session closed")
)

// TransportType 定义传输层类型
type TransportType string

const (
	TransportTypeQUIC TransportType = "quic"
	TransportTypeTCP  TransportType = "tcp"
	TransportTypeAuto TransportType = "auto"
)

// Transport 定义通用传输驱动接口
type Transport interface {
	Type() TransportType
	Close() error
}

// ClientTransport 客户端传输接口
type ClientTransport interface {
	Transport
	// DialSession 连接目标服务器并建立多路复用会话
	DialSession(ctx context.Context, addr string, opts DialOptions) (TransportSession, error)
}

// ServerTransport 服务端传输接口
type ServerTransport interface {
	Transport
	// AcceptSession 等待接入新的客户端传输会话
	AcceptSession(ctx context.Context) (TransportSession, error)
	// Addr 返回监听地址
	Addr() net.Addr
}

// DialOptions 客户端建连参数
type DialOptions struct {
	ServerName      string        // SNI / 主机名
	Path            string        // 伪装路径 (如 /auth)
	ConnectTimeout  time.Duration // 建连超时
	KeepAlivePeriod time.Duration // 心跳周期
	OverrideIP      string        // 覆盖目标 IP (如 DNS 探测指定)
	InsecureSkipTLS bool          // 是否跳过 TLS 校验 (仅测试)
}

// TransportSession 代表一条已建立底层握手的逻辑复用通道
type TransportSession interface {
	// OpenStream 打开一个新的双向可靠字节流
	OpenStream(ctx context.Context) (TransportStream, error)
	// AcceptStream 接收由对端发起的双向可靠字节流
	AcceptStream(ctx context.Context) (TransportStream, error)

	// SendDatagram 发送不可靠数据报 (RFC 9221)
	SendDatagram(payload []byte) error
	// ReceiveDatagram 接收不可靠数据报
	ReceiveDatagram(ctx context.Context) ([]byte, error)

	// LocalAddr 与 RemoteAddr
	LocalAddr() net.Addr
	RemoteAddr() net.Addr

	// RTT 返回当前链路估计的往返时延
	RTT() time.Duration
	// Type 返回当前会话实际使用的传输类型 (QUIC 或 TCP)
	Type() TransportType
	// IsClosed 检查会话是否已经关闭
	IsClosed() bool
	// Close 关闭整个传输会话及所有底层资源
	Close() error
}

// TransportStream 代表会话内部的一个逻辑双向字节流 (包装 quic.Stream 或 smux.Stream)
type TransportStream interface {
	io.Reader
	io.Writer
	io.Closer

	// ID 返回流的唯一标识符
	ID() uint32

	// Deadline 管理
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}
```

### 2.3 现有 `wsNetConn` + `smux` 路径的映射 (`TcpTransport`)

现有代码的 WSS + smux 体系完全封装为 `TcpTransport`:
1. **会话映射 (`TcpTransportSession`)**:
   - 客户端执行 `dialWebSocketWithECH` 得到 `wsConn`，包装为 `wsNetConn`。
   - 调用 `smux.Client(wsNet, smuxCfg)` 建立 `*smux.Session`。
   - `OpenStream(ctx)` 映射为 `smux.Session.OpenStream()` 并包装为 `TcpTransportStream`（适配 `TransportStream` 接口）。
   - `AcceptStream(ctx)` 映射为 `smux.Session.AcceptStream()` 并包装为 `TcpTransportStream`。
   - `SendDatagram` / `ReceiveDatagram` 返回 `ErrDatagramNotSupported`，告知上层退化为流式 UDP 封装。
   - `Close()` 顺序关闭 `smux.Session` 与底层 `wsConn`。
2. **流映射 (`TcpTransportStream`)**:
   - 直接委托 `*smux.Stream` 的 `Read`、`Write`、`Close`、`ID` 及 `SetDeadline` 方法。

### 2.4 对现有代码的插入点评估 (Insertion Points)

#### 2.4.1 客户端插入点 (`internal/app/client.go`)
- **当前实现现状**:
  - `ECHPool.dialAndServe` (位于 `client.go:88`) 内部硬编码调用 `dialWebSocketWithECH`，直接获取 `*websocket.Conn`，立即构造 `newWSNetConn` 并调用 `smux.Client`，随后在其首个 stream 上调用 `negotiateClientProtocol`。
  - `ECHPool` 内部数组 `smuxConns []*smux.Session` 紧密耦合 smux。
- **重构插入点与方案**:
  1. **数据结构抽象**: 将 `ECHPool` 内的 `smuxConns []*smux.Session` 重构为 `transportSessions []transport.TransportSession`。
  2. **建连上一层切入**: 在 `dialAndServe` 循环内部，将 `dialWebSocketWithECH` + `smux.Client` 整体替换为调用 `p.transportSelector.DialSession(ctx, p.wsServerAddr, dialOpts)`。
  3. **协议握手复用**: 获得 `TransportSession` 后，调用 `session.OpenStream(ctx)` 创建第 1 条流，直接执行原有的 `negotiateClientProtocol`（无需任何改动）。
  4. **数据流调度复用**: `openBestStream` 改为从活跃的 `TransportSession` 中通过 `session.OpenStream` 获取流，随后包裹 `newV3CipherStream`，彻底解耦底层传输。

#### 2.4.2 服务端插入点 (`internal/app/server.go`)
- **当前实现现状**:
  - `startWebSocketServer` (位于 `server.go:343`) 在 HTTP handler 中执行 WebSocket Upgrade，随后在独立 goroutine 中调用 `handlePreAuthWebSocketChannel(wsConn, clientIP, serverName, path)`。
  - `handlePreAuthWebSocketChannel` (位于 `server.go:420`) 内部完成 `newWSNetConn` -> `smux.Server` -> `sess.AcceptStream` -> 读取 `ChannelInit` -> 校验 `AuthProof` -> 密钥派生 -> 回写 `ChannelAccept` -> `handleAuthenticatedSmuxSession`。
- **重构插入点与方案**:
  1. **服务入口统一**: 构建聚合型 `ServerListener`，内部并发启动 `WSS ServerListener` 与 `QUIC ServerListener`，将两者接收到的底层连接分别包装为 `TcpTransportSession` 与 `QuicTransportSession`，统一送入 `sessionChan chan transport.TransportSession`。
  2. **认证处理下沉上一层**: 将 `handlePreAuthWebSocketChannel` 重构为通用的 `handlePreAuthChannel(session transport.TransportSession, clientIP, serverName, path)`。
  3. **认证流程保持一致**: `handlePreAuthChannel` 调用 `session.AcceptStream(ctx)` 接收握手流，读取并校验 `ChannelInit`，验证通过后调用 `handleAuthenticatedSession(ch, session)` 开始流接收循环。

---

## 3. QuicTransport 深度设计 (RFC 9000 + RFC 9221)

### 3.1 协议基础与 RFC 规范
- **RFC 9000 (QUIC)**: 提供基于 UDP 的安全、多路复用传输。单连接内支持高达 $2^{62}$ 条独立的双向/单向流，流之间相互独立，任意流丢包不影响其他流。
- **RFC 9002 (拥塞控制与丢包恢复)**: QUIC 默认采用单调递增的 Packet Number（无 TCP 重传歧义），支持 BBRv1 / Cubic / NewReno 拥塞控制。
- **RFC 9221 (QUIC Datagram 扩展)**: 引入 `DATAGRAM` 帧类型（Frame Type `0x30` / `0x31`），允许应用在 QUIC 连接上下文内直接发送不可靠、无连接、保边界的单包数据报，不受流控和重传队头阻塞约束。

### 3.2 Go 库选型评估

| 候选库 | 成熟度与社区地位 | 许可证 | 维护现状与版本支持 | RFC 9221 支持 | 推荐度 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`github.com/quic-go/quic-go`** | **Go 生态绝对垄断标准** (Caddy, Cloudflare, Traefik, Sing-box, Xray, Hysteria2) | **MIT** | 极度活跃，持续维护，已支持 Go 1.22+ 与最新 QUIC 规范 | **完美支持** (`quic.Connection.SendDatagram`) | **强烈推荐 (唯一选型)** |
| `golang.org/x/net/quic` | 官方实验项目，尚未完备 | BSD-3 | 处于早期阶段，缺少大量高级特性与 Datagram 支持 | 尚不完善 | 暂不推荐 |

**选型结论**: 采用 `github.com/quic-go/quic-go`（版本推荐锁定 `>= v0.42.0`）。其具备以下核心优势：
- 完整支持 RFC 9000、RFC 9001 (TLS 1.3 for QUIC) 与 RFC 9221 Datagram。
- 内置针对 Linux/macOS/Windows 的 UDP GSO (Generic Segmentation Offload) 与批处理优化，系统调用开销低。
- 允许精细控制 `quic.Config`（流控窗口、最大并发流、超时与 Connection ID 长度）。

### 3.3 HTTP/3 伪装与 ALPN / SNI / 证书策略

#### 3.3.1 伪装架构 (Hysteria2 风格)
为了抵御审查者对未知 UDP 协议的探针与流量分类，`QuicTransport` 必须深度伪装为标准的 HTTP/3 Web 服务：
1. **ALPN 协商**: 默认配置 TLS ALPN 为 `h3`（标准 HTTP/3）或提供配置项允许自定义 ALPN。
2. **鉴权路径伪装**: 客户端的 QUIC 建连与首流握手模拟 HTTP/3 伪装路径（如 `POST /auth` 或配置的掩护路径）。
3. **主动探测回退 (Fallback)**: 若未授权扫描者通过 UDP 向服务端发送畸形 QUIC 握手或未携带合法凭据的 HTTP/3 请求，服务端直接回落至真实的 HTTP/3 静态网页响应（200 OK HTML / 404 Not Found），在行为特征与响应时延上与真实 Web 服务器不可区分。

#### 3.3.2 SNI 与证书策略对比

| 证书策略 | 审查风险分析 | 主动探测防御能力 | 部署与运维成本 | 推荐结论 |
| :--- | :--- | :--- | :--- | :--- |
| **自签名证书 (Self-Signed)** | **高危**。QUIC TLS 1.3 握手中证书以密文传输，但自签证书在客户端必须启用 `InsecureSkipVerify`，攻击者可通过伪造中间人探针轻易诱捕客户端；且自签证书缺少合法 CA 证书链特征。 | 极差 | 极低（零配置） | **严禁在生产中使用** |
| **真实域名 + ACME 有效证书** | **极低**。外层 SNI 匹配真实公网域名，TLS 1.3 握手呈现完整的 Let's Encrypt / ZeroSSL 证书链，与正常 HTTP/3 流量 100% 一致。 | 极强 | 中等（需配置域名解析与 ACME 自动申请） | **强烈推荐 (默认标准)** |

### 3.4 0-RTT 的取舍与防重放分析

#### 3.4.1 0-RTT 的重大安全风险
QUIC 允许客户端使用前次连接缓存的会话票据（Session Ticket）在第一个数据包中发送 `0-RTT Early Data`。
在代理场景中，这会带来严重的重放威胁：
- **网络层重放**: 中间人审查者可截获包含 0-RTT 的 Initial UDP 报文并原样重新投递到服务端。如果应用层在 0-RTT 中传输了代理控制指令或初始数据，可能导致服务端被利用进行重放攻击、资源耗尽或状态去同步。

#### 3.4.2 结合 P1 防重放现状的评估
在 x-tunnel v3 架构中（参考 `handshake-replay.md` 与 `protocol-v3-optimization.md` §2）：
1. v3 控制面已在握手载荷中引入了 `TAI64N` 单调纳秒时间戳、`client_nonce` 以及服务端内存 `nonceReplayCache`。
2. 即使内层具备防重放机制，0-RTT 仍会使密文在外层被网络观察者反复观察，且要求服务端必须跨进程或分布式维护大容量 Anti-Replay Cache。
3. **收益对比**: x-tunnel 为多路复用长连接模型，一次握手建立后，数以万计的 TCP/UDP 代理流都在已建通道内复用，建连动作极为罕见。
4. **决策结论**: **彻底禁用 QUIC 0-RTT**。在 `quic.Config` 中显式设置 `Allow0RTT: false`，服务端不颁发 0-RTT 恢复票据，强制执行 1-RTT 完整握手。用极小且无关紧要的一次性握手时延（数十毫秒），换取绝对的抗重放安全性与极度简化的系统状态机。

---

## 4. TcpTransport: 现栈保底与平滑兼容

### 4.1 定位与存在必要性
尽管 QUIC 性能优异，但在以下恶劣审查网络环境中，QUIC 可能会完全不可用：
- 严格企业防火墙/学校网络：完全封禁 UDP 流量（仅放行 UDP 53，封禁 UDP 443 及其他高位端口）。
- 运营商强力 QoS：部分省份运营商在高峰时段对非已知白名单的 UDP 流量执行高达 50%~90% 的丢包率。
- GFW 动态阻断：触发 180 秒 IP:Port 封禁。

因此，**`TcpTransport` (wss + TLS 1.3 + smux v2) 必须长期保留为基石保底通道**。

### 4.2 实现复用原则
- 零破坏、零性能回退：`TcpTransport` 完整封装 `internal/app/transport_ws.go` 中的 `wsNetConn` 及已通过大量压测验证的 `smux` 管道。
- 向上层统一暴露为 `TransportSession` 实例。

---

## 5. 选择器 (Transport Selector) 与故障转移机制

### 5.1 整体工作流程

```text
                  客户端发起代理请求
                          │
                  ┌───────▼───────┐
                  │ 检查配置模式  │
                  └───────┬───────┘
          ┌───────────────┼───────────────┐
          │ (quic)        │ (auto)        │ (tcp)
          ▼               ▼               ▼
    [强制 QUIC]     [查询状态记忆缓存]    [强制 TCP]
                          │
               ┌──────────┴──────────┐
               │ 命中 TCP (冷却中)?   │
               ├──────────┬──────────┘
             (是)         │ (否)
               ▼          ▼
           [直连 TCP]  [优先尝试 QUIC]
                          │
                  ┌───────┴───────┐
                  │ QUIC 握手结果 │
                  └───────┬───────┘
            ┌─────────────┴─────────────┐
          (成功)                      (失败/超时)
            ▼                           ▼
      [记录成功记忆]               [记录失败/进入冷却]
      [进入 QUIC 数据传输]         [秒级回退至 TCP 栈]
                                        ▼
                                  [进入 TCP 数据传输]
```

### 5.2 状态记忆与缓存设计 (Transport Memory Cache)
客户端维护内存级（并可持久化至本地）的 Host 传输状态缓存：

```go
type TransportCacheEntry struct {
	Host             string        // 服务端地址 (host:port)
	Preferred        TransportType // 当前优选协议 (QUIC 或 TCP)
	LastSuccessTime  time.Time     // 上次成功时间
	LastFailTime     time.Time     // 上次失败时间
	ConsecutiveFails int           // 连续失败次数
	SmoothedRTT      time.Duration // 平滑往返时延
	LossRate         float64       // 估算的丢包率
	CoolDownUntil    time.Time     // 降级冷却截止时间
}
```

- **降级冷却策略**: 当 QUIC 发生阻断（连续失败 $\ge 2$ 次），自动将该 Host 标记为降级状态，并在冷却期（初始 10 分钟，按指数退避递增至 1 小时）内所有新连接直连 TCP，避免每次新建连接均承受 UDP 超时等待。
- **后台静默探活**: 在冷却期即将结束时，由后台轻量探活协程发起单包 QUIC 探测，若探测恢复则平滑切回 QUIC 优先。

### 5.3 回退触发条件 (Fallback Triggers)
在 `auto` 模式下，满足以下任意条件立即触发 TCP 回退：
1. **QUIC 握手超时**: QUIC Initial 报文发出后，在设定的快速超时阈值（默认 `1500ms`）内未收到服务端任何回包（ServerHello / Retry）。
2. **显式网络阻断**: 收到操作系统返回的 `ICMP Port Unreachable`、`Network Unreachable` 或 `WSAECONNRESET`。
3. **严重 QoS 丢包**: 运行期连续 5 个 RTT 测量周期内丢包率 $> 35\%$ 且时延剧烈抖动，判定为遭受运营商 QoS 压制，平滑新建 TCP 会话并迁移后续流量。

### 5.4 CLI 标志与配置项设计

- **命令行标志**:
  ```bash
  # 自动选择 (默认，优先 QUIC，失败切 TCP)
  ./x-tunnel-client -transport auto -s wss://node.example.com:443
  # 强制 QUIC (仅使用 QUIC/UDP，失败直接报错)
  ./x-tunnel-client -transport quic -s wss://node.example.com:443
  # 强制 TCP (仅使用 TCP/WSS，完全不发送 UDP)
  ./x-tunnel-client -transport tcp -s wss://node.example.com:443
  ```
- **JSON 配置文件**:
  ```json
  {
    "transport": "auto",
    "transport_options": {
      "quic_congestion_control": "bbr",
      "handshake_timeout_ms": 1500,
      "cooldown_period_sec": 600,
      "max_loss_rate_threshold": 0.35
    }
  }
  ```

---

## 6. UDP-over-QUIC Datagram 帧设计 (RFC 9221 + TUIC 风格)

### 6.1 Datagram 帧二进制结构

在 `QuicTransport` 栈中，UDP 代理包不再作为字节流在 Stream 中分帧排队，而是直接编码为 RFC 9221 `DATAGRAM` 负载发送：

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           ASSOC_ID            |            PKT_ID             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  FRAG_TOTAL   |    FRAG_ID    |          PAYLOAD_LEN          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   ADDR_TYPE   |       TARGET_ADDR (Variable Length...)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          TARGET_PORT          |       UDP_PAYLOAD...          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### 字段详细规范
- **`ASSOC_ID` (uint16)**: 本地 SOCKS5 UDP 客户端关联会话 ID。服务端利用该 ID 管理目标 UDP 套接字生命周期。
- **`PKT_ID` (uint16)**: 单调递增的数据包序号，用于监控丢包率及乱序分片重组。
- **`FRAG_TOTAL` (uint8)**: 该 UDP 数据报的总分片数（不分片时为 `1`）。
- **`FRAG_ID` (uint8)**: 当前分片索引（从 `0` 开始，不分片时为 `0`）。
- **`PAYLOAD_LEN` (uint16)**: 当前帧内携带的 `UDP_PAYLOAD` 字节长度。
- **`ADDR_TYPE` (uint8)**: 目标地址类型 (`0x01`=IPv4 4B, `0x03`=Domain 1B Len + Str, `0x04`=IPv6 16B)。
- **`TARGET_PORT` (uint16)**: 目标端口号。
- **`UDP_PAYLOAD` (bytes)**: 原始 UDP 数据包明文（或内层 v3 AEAD 加密片段）。

### 6.2 消息边界保持与 MTU 分片机制
1. **消息边界天然保持**: RFC 9221 Datagram 属于原子传输单位，单个 Datagram 严格对应单个 UDP 数据包，彻底消除 Stream 传输中的拆包/粘包及边界解析开销。
2. **Path MTU 动态适配与前置分片**:
   - QUIC 传输层的最大可用 Datagram 尺寸受限于网络 PMTU（通常为 1200 ~ 1350 字节）。
   - 若原始 UDP 报文（如游戏巨帧、DNS 响应）超过当前链路的 `MaxDatagramFrameSize`，客户端传输层在发送前进行应用层切片（设置 `FRAG_TOTAL > 1` 和对应 `FRAG_ID`）。
   - 服务端接收完全部分片后在内存重组，避免由于 IP 层分片（IP Fragmentation）被中间防火墙策略性丢弃。

### 6.3 与现有 TCP 栈 UDP Chunk 帧的关系
- **QUIC 栈**: 全量启用 RFC 9221 Datagram 承载，享受零队头阻塞、极低抖动与即时丢弃语义。
- **TCP 栈**: 保持现有模式，在 smux Stream 内部按照 Stream Open Header (`kind=streamKindUDP`) 开启流，并在流内发送 UDP Chunk 封装。

---

## 7. 会话恢复与连接迁移 (Connection Migration)

### 7.1 QUIC 连接迁移能力分析

```text
[客户端 Wi-Fi 4-Tuple] ──(QUIC Packet with CID=0x88AB)──► [服务端]
          │
  (网络切换至 5G 蜂窝)
          │
[客户端 5G 4-Tuple]   ──(QUIC Packet with CID=0x88AB)──► [服务端]
                                                               │
                                               [检测到新 IP:Port 但 CID 相同]
                                               [发起 PATH_CHALLENGE 验证]
                                               [完成路径迁移，所有 Stream 保持活跃]
```

- **Connection ID (CID) 机制**: QUIC 不依赖 IP+Port 四元组标识连接，而是由通信双方协商的一组 Connection ID 标识。
- **无缝切换收益**:
  - 当客户端由 Wi-Fi 切换至移动蜂窝网络（IP 发生改变）时，客户端仅需使用新的网络接口发送带有相同 CID 的 QUIC 报文。
  - 服务端通过 `PATH_CHALLENGE` 与 `PATH_RESPONSE` 帧完成路径可达性校验，即刻将下行数据路由切换至新地址。
  - **业务层零感知**: 上层正在运行的 SOCKS5 连接、HTTP 长连接无需中断重连，完全消除了移动办公场景下的频繁掉线卡死。

### 7.2 TCP 栈的局限性对比
- TCP 协议栈强绑定四元组。一旦客户端 IP 或 NAT 端口发生变动，原 TCP 连接在操作系统内核层面立即失效。
- TCP 侧只能通过应用控制面重连：重新拨打 TCP -> 重新握手 WebSocket -> 传递 `session_id` 尝试恢复应用层会话状态。

### 7.3 与 v3 密码层的关系 (核心安全推论)
1. **会话密钥不变**: QUIC 层的连接迁移仅属于 L4 传输层物理路径的切换。内层 v3 安全通道的会话密钥（`V3SessionKeys`）由初次建立通道时的 Transcript Hash 派生，**在连接迁移过程中保持绝对不变**。
2. **计数器与滑动窗口无缝延续**: 内层 `V3CipherStream` 的 64 位单调发送计数器与接收端 2048 位 `replayWindow` 保持连续递增与滑动，**不需要重置，也不需要重新触发 X25519 密钥交换**。
3. **状态连续性与安全性**: 传输层无论如何迁移，端到端 AEAD 保护与抗重放防线保持完全闭合。

---

## 8. 风险清单与威胁建模 (Risk Matrix)

### 8.1 核心风险评估表

| 风险项 | 威胁来源与机理 | 影响程度 | 针对性防御与缓解措施 |
| :--- | :--- | :--- | :--- |
| **1. GFW 对 QUIC Initial 的 SNI 解密与 180s 封禁** | **USENIX Security '25 论文实证**: GFW 部署了针对 QUIC Initial 的解密流水线。由于 Initial 报文的加密密钥由 RFC 9001 公开 Salt 与 DCID 派生，GFW 能实时解密出 ClientHello 中的 SNI。若命中敏感黑名单或指纹异常，**直接对该服务器 IP:Port 施加 180 秒丢包阻断**。 | **致命** | 1. 严格使用合法真实公网域名，严禁使用未注册或自签伪造 SNI；<br>2. 配合有效 ACME 证书；<br>3. `TransportSelector` 识别出 180s 丢包特征后，秒级无缝降级至 TCP (wss) 保底通道。 |
| **2. 国内运营商 UDP QoS 限速与高丢包** | 运营商在晚高峰或跨网链路上对非白名单 UDP 流量施加阶梯限速与丢包策略（丢包率常达 20%~80%），导致 QUIC 拥塞窗口收缩、吞吐严重衰减。 | 高 | 1. 客户端持续监测 QUIC 丢包率与 RTT 抖动；<br>2. 丢包率持续超过 35% 时主动将新流调度至 TCP 栈；<br>3. 配置 BBR 拥塞控制提升抗丢包能力。 |
| **3. quic-go 外部依赖开销与维护复杂度** | 引入 `quic-go` 依赖会增加约 3.5MB 的编译二进制体积，且 QUIC 内部维护复杂的流控缓冲区与 goroutine 调度。 | 中 | 1. 精细调优 `quic.Config`（限制最大并发流与缓冲上限）；<br>2. 严格遵循依赖审计，锁定稳定版本；<br>3. 编写隔离的 Benchmark 监控内存与协程泄漏。 |
| **4. 双栈状态机膨胀与测试覆盖** | 两种传输栈并存可能引入状态不一致、连接泄漏及选择器振荡 bug。 | 中 | 1. 接口边界严格收敛于 `TransportSession`，业务层零分支；<br>2. 构建全面的 Mock 弱网、丢包与回退测试矩阵。 |

---

## 9. 分阶段落地计划与验证标准 (Phased Rollout Plan)

为确保工程质量，坚决贯彻 **"先出设计再动代码、先做抽象重构再引新栈"** 的原则。

```text
Phase 1: Transport 接口抽象 + TcpTransport 重构 (零行为变更)
   │
   ▼
Phase 2: QuicTransport 独立实现与单栈验证
   │
   ▼
Phase 3: 双栈 TransportSelector (探测 + 记忆 + 自动回退)
   │
   ▼
Phase 4: RFC 9221 UDP Datagram 原生支持与弱网压测
```

### 9.1 Phase 1: Transport 接口抽象与现有 TCP 栈重构 (首要推荐)
- **目标**:
  - 创建 `internal/transport` 包，定义 `Transport`, `TransportSession`, `TransportStream` 接口。
  - 将现有的 `wsNetConn` + `smux` 封装为 `TcpTransport`。
  - 重构 `client.go` 与 `server.go` 的通道接线逻辑，使其面向 `TransportSession` 编程。
- **验收标准**:
  - 现有全部单元测试、集成测试、基准测试 100% 通过。
  - 外部网络协议行为与流量形态 0 变化，生产零回归。

### 9.2 Phase 2: QuicTransport 独立实现与单栈接入
- **目标**:
  - 引入 `github.com/quic-go/quic-go` 依赖。
  - 实现 `QuicTransport` 客户端 Dialer 与服务端 Listener。
  - 接入标准 TLS 1.3 握手与 HTTP/3 (`h3`) ALPN 伪装。
  - 支持 CLI `-transport quic` 强制指定 QUIC 栈。
- **验收标准**:
  - 客户端通过纯 QUIC 栈与服务端建连，顺利完成 v3 握手并代理 TCP 流量。
  - 验证 0-RTT 处于显式禁用状态。

### 9.3 Phase 3: 双栈选择器 (TransportSelector) 与状态记忆
- **目标**:
  - 实现 `TransportSelector`，支持 `-transport auto` 默认模式。
  - 实现 1.5s 握手超时快速回退至 TCP 机制。
  - 实现 Host 级状态记忆缓存、连续失败冷却与后台轻量探测。
- **验收标准**:
  - 在模拟环境（通过 `iptables` / `pfctl` DROP 所有 UDP 报文）下，客户端在 1.5 秒内自动平滑回退至 TCP 栈，代理请求不中断。
  - 触发回退后，后续新连接命中缓存秒级直连 TCP。

### 9.4 Phase 4: RFC 9221 UDP Datagram 优化与全量性能压测
- **目标**:
  - 实现基于 RFC 9221 的 TUIC 风格 UDP Datagram 编解码与 PMTU 动态分片。
  - 编写网络切换（Wi-Fi <-> 5G）模拟测试，验证 Connection ID 迁移期间流零中断。
  - 进行弱网丢包（5%, 10%, 20% 丢包率）对比压测。
- **验收标准**:
  - 10% 丢包网络下，QUIC 栈的多流并发下载吞吐与时延抖动显著优于 TCP/smux 栈。
  - IP 切换后，活跃长连接在 100ms 内恢复数据传输，无需应用层重新认证。

---

## 10. 明确结论 (Conclusion)

1. **纯设计交付**: 本设计规范为 P2 阶段的架构与评估交付物，**仅包含设计标准与技术方案评估，不附带任何工程代码变更**。
2. **实施路径建议**: 坚决遵循分阶段实施策略，优先推进 **Phase 1（Transport 抽象与 TcpTransport 封装）**，在保持现有生产基线完全稳定的前提下，再开展后续 QUIC 栈与双栈选择器的代码实现。
