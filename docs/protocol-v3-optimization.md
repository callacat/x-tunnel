# x-tunnel 代理协议优化设计(v3 方向)

状态:优化设计稿。基于对现有"TAI64N+设备ID 防重放 + Stream ID 多路复用 + 首包动态 padding + 算法协商(ChaCha20/AES-128-GCM/XOR)"协议的多路研究综合。
研究底稿见 `docs/protocol-v3-research/`:`handshake-replay.md`、`mux-transport.md`、`traffic-shape.md`、`crypto-selection.md`。
参考基线:本仓库现有 v2(docs/protocol.md,wss + TLS1.3 + smux + HMAC 通道认证)。

---

## 0. 结论速览

现有设计吸收了 SS2022/TUIC/Multiplex 的正确思想(防重放、多路复用、首包拟形、算法协商),但有四个**必须修正**的硬伤,以及若干**应当升级**的点:

| 问题 | 严重度 | 修正 |
| --- | --- | --- |
| XOR / 裸 ChaCha20 非 AEAD,可比特翻转、可已知明文恢复密钥流 | **致命** | 全 AEAD,删 XOR,默认 ChaCha20-Poly1305 |
| 算法协商不绑定 transcript,可降级到 XOR | **致命** | 协商字段进 auth_proof,未知算法显式拒绝 |
| 无临时密钥,长期密钥泄露即全量解密 | 高 | 每会话 ephemeral X25519 + HKDF(前向保密) |
| 单调时间戳用于所有包,乱序误杀、时钟回拨锁死、映射表洪泛 | 高 | 握手单调时间戳 + 数据面计数器滑动窗口分工 |
| 裸二进制 over TCP:高熵+无 TLS+双向饱满,最易被分类 | 高 | 主力改 TLS 应用伪装 + 真实站点 fallback |
| 仅首包 padding,后续包长/边界/时序仍是指纹 | 中 | per-record padding + 分段合并 + 时序抖动 |
| TCP 复用队头阻塞、拥塞被单连接绑架 | 中 | 双栈:默认 QUIC/UDP,回退 TCP |
| ECH 现已被 GFW 针对性阻断 | 中 | ECH 默认关/可配置 |

一句话方案:**全 AEAD + 前向保密 + 协商防降级;握手单调时间戳、数据计数器窗口;主力 TLS 伪装 + 真实站点兜底 + 全流拟形;传输双栈(QUIC 主力/TCP 保底)。**

---

## 1. 密码层(最高优先级)

### 1.1 算法表
| 值 | 算法 | 说明 |
| --- | --- | --- |
| 1 | ChaCha20-Poly1305 | 默认,跨平台、纯软件快、抗侧信道 |
| 2 | AES-256-GCM | 有 AES-NI 的 x86 高吞吐 |
| 3 | AES-128-GCM | 可选,有 AES-NI |

**删除 XOR 与原裸 ChaCha20。** 所有 payload 一律 AEAD,消除 malleability、已知明文异或、跨流重放、降级目标。

### 1.2 Nonce 与防重放
- 每流 64 位发送计数器作 nonce,每包 +1;双向独立子密钥/前缀。
- nonce 唯一性是 GCM 硬约束(SP 800-38D §8),计数器近上限前 rekey。
- 接收端用滑动窗口记录已见计数器:既防重放又容忍乱序(WireGuard RFC 6479 风格)。

### 1.3 密钥派生
```
PRK   = HKDF-Extract(salt="xtunnel-v3-kdf", IKM=pre_shared_token)
seed  = HKDF-Expand(PRK, info=transcript_hash, L)
        transcript_hash = SHA256(version|caps|cipher_pref|
                                 client_eph_pk|server_eph_pk|
                                 session_id|timestamp|server_name|path)
seed  混入 X25519 ephemeral 共享秘密(前向保密)
      -> c2s_key, s2c_key, 双向 nonce 前缀, (可选)每流 subkey
```

---

## 2. 握手与防重放

### 2.1 分工原则(WireGuard 式)
- **握手**:加密认证后的 TAI64N 时间戳,按"该认证身份上次最大值"单调比较;只对**认证通过**的连接写映射(防设备ID 洪泛),映射表 LRU 封顶。
- **数据**:不用时间戳,用 §1.2 的计数器 + 滑动窗口。
- 时间戳只需 per-身份单调,不要求真实时间;可截断低位纳秒减少信息泄漏。

### 2.2 修正的具体缺陷
- 时钟回拨/NTP 跳变:数据面不再依赖时间戳,握手时间戳单调比较只在重建会话时生效,避免长期锁死。
- 映射表洪泛:设备ID 必须与认证身份绑定,未通过认证不写状态;按 IP 限速 + LRU 上限。
- 多实例:按认证身份粘性路由,或共享状态;避免每实例独立最大值导致误拒。
- 静态设备ID 跟踪:session_id 每会话随机/从会话密钥派生,不用长期稳定标识。

### 2.3 前向保密
每会话 ephemeral X25519:客户端首包带 `client_eph_pk`,服务端响应带 `server_eph_pk`,共享秘密混入密钥派生。长期 token 泄露不再解密历史流量。成本每会话约 30µs。

### 2.4 静默丢弃的取舍
- 对外保持静默(不回协议错误),但**本地日志/指标可观测**丢弃原因,供运维排障。
- 认证失败与网络故障在外部观察(时延/字节数)不可区分;HMAC 常数时间比较,避免时序 oracle。
- 更强的主动探测防御交给 §4 的真实站点 fallback,而非单纯静默。

### 2.5 防降级
cipher_pref、version、caps 全部进 transcript_hash 参与 auth_proof;篡改即失败。服务端对未知版本/算法显式拒绝(fail closed),不降级。删 XOR 后降级目标消失。

---

## 3. 传输层(多路复用)

### 3.1 双栈架构
```
Transport 抽象:
  QuicTransport: RFC9000 + RFC9221 datagram,HTTP/3 伪装(Hysteria2 式 /auth)
  TcpTransport : smux v2 over wss(保留现有热路径)
选择器:探测 + 记忆,默认 QUIC,失败/被 QoS 回退 TCP
```
- **QUIC 主力**:根治队头阻塞(流独立)、0-RTT、连接迁移;但 GFW 已能解密 QUIC Initial 读 SNI(USENIX Sec '25),UDP 可被限速/阻断,故不能唯一依赖。
- **TCP 保底**:wss 穿透性最好、最不易被整体阻断;继承 smux 现有实现,弱网有队头阻塞但可达性优先。

### 3.2 统一会话层(两种传输之上)
```
数据帧: kind(u8) | stream_id(u32) | flags(u8) | len | payload
  kind: TCP数据 / UDP数据 / Ping / 控制(SYN/FIN/RST/窗口更新)
UDP帧: assoc_id | pkt_id | frag_total | frag_id | size | addr | payload  (TUIC 式,保消息边界)
流控: 每流滑动窗口 + 会话级缓冲封顶
优先级: 交互流优先,大流限速
会话恢复: session_id + 幂等 SYN + 服务端短期续传缓存
```
- Stream ID 32 位,客户端奇/服务端偶,回收防回绕歧义。
- UDP-over-mux 保留消息边界,每 datagram 独立成帧。
- 会话恢复幂等:重复 SYN 不重复建流;TCP 栈只恢复控制面,无缝迁移靠 QUIC 连接迁移。

---

## 4. 流量外形(抗检测)

### 4.1 主力外形
**TLS 1.3 + 真实域名 + 有效证书**,隧道承载为 TLS 应用数据(wss/HTTP2 形态),并配**真实站点 fallback**(Reality 思路):未授权探测者拿到合法站点证书/响应/时延,主动探测无从下手。裸二进制降级为可选高性能内核,且外包"模仿 TLS 记录尺寸/时序"整形层。

### 4.2 全流拟形(不只首包)
- **首包**:padding 采样自 cover 协议首包长度分布(如 ClientHello ~517B),而非固定区间随机;token/padding 用随机字节保熵。
- **后续记录**:per-record padding 到目标尺寸(≤1200~1400B 贴近 MTU);大消息分段、小消息批合并(5~30ms 上限),隐藏消息边界与复用帧结构。
- **时序**:发送端抖动/pacing,keepalive 随机化间隔,消除周期信号;双向对称整形。

### 4.3 其他
- **ECH 默认关/可配置**(当前已被 GFW 针对性阻断,是红旗)。
- 多 IP DNS 轮询 + 健康检查 + 自动故障切换 + 封禁监控轮换。
- 加密收敛到 AEAD(§1),消除 XOR 弱熵指纹。

---

## 5. 与现有 x-tunnel v2 的关系

现有 wss + TLS1.3 + smux + HMAC 通道认证**方向正确**,本优化应作为其增强而非另起裸协议:
- 吸收:首包融合 + 拟形 padding、静默丢弃对外/可观测对内、计数器防重放、ephemeral 前向保密、协商绑定 transcript。
- 修正:ECH 默认开→默认关/可配置;补真实站点 fallback;对 smux 帧做尺寸/时序整形;评估 QUIC 双栈。
- 数据面热路径保持紧凑(v2 已验证 TCP/UDP 开流/状态帧性能),改动集中在控制面与外形层。

---

## 6. 落地优先级

| 优先级 | 动作 | 成本 | 收益 |
| --- | --- | --- | --- |
| P0 | 删 XOR/裸 ChaCha20,全 AEAD(默认 ChaCha20-Poly1305) | 低 | 消除致命密码缺陷 |
| P0 | 协商绑定 transcript 防降级 | 低 | 消除降级攻击 |
| P0 | 主力 TLS 伪装 + 真实站点 fallback | 中 | 大幅降低整体异常度 |
| P1 | ephemeral X25519 前向保密 | 低 | 长期密钥泄露不解密历史 |
| P1 | 握手单调时间戳 + 数据计数器窗口分工 | 中 | 抗乱序误杀/时钟回拨/洪泛 |
| P1 | 首包拟形 padding(采样 cover 分布) | 低 | 消除首包长度指纹 |
| P1 | per-record padding + 分段合并(≤1200B) | 中 | 消除后续包长/边界指纹 |
| P2 | 时序抖动/pacing + keepalive 随机化 | 中 | 对抗时序/突发分析 |
| P2 | ECH 默认关/可配置 | 低 | 规避针对性阻断 |
| P2 | QUIC/TCP 双栈 | 高 | 弱网体验 + 可达性解耦 |
| P3 | 多 IP 轮换 + 封禁监控闭环 | 中 | 被封后生存能力 |

---

## 7. 验证清单(沿用 v2 验证风格)

- 密码:AEAD 比特翻转/注入被拒;XOR 不存在于协商表;nonce 回绕前 rekey。
- 防重放:重放包被拒;乱序包在窗口内被接受;时钟回拨客户端不被锁死。
- 防降级:篡改 cipher_pref/version/caps 导致 auth_proof 失败。
- 前向保密:泄露 token 无法解密已捕获会话。
- 外形:模拟审查代理(GFW 画像)下,首包/后续包长分布、时序与 cover 重合;未授权探测命中真实站点 fallback。
- 传输:QUIC 被阻断时自动回退 TCP;弱网下 QUIC 流独立不互相停顿。
- 基准:数据面热路径不低于 v2 现有基准(见 protocol-v2-improvement-plan.md §16)。
