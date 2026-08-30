# x-tunnel 握手与防重放优化研究报告

状态:研究稿。针对"TAI64N 纳秒时间戳 + 设备ID 映射防重放 + 校验失败静默丢弃"的握手设计。
资料来源:WireGuard 白皮书(wireguard.txt)、Shadowsocks 2022 SIP022(sip022.md)、TUIC 规范(tuic-spec.md)、x-tunnel 现有 v2(docs/protocol.md)。

---

## A. TAI64N + 设备ID 防重放的缺陷

### A.1 机制回顾
客户端发送 TAI64N(12 字节 = 46 位秒 + 46 位纳秒的大端时间戳)+ 设备ID;服务端维护 `设备ID -> 最近时间戳` 映射,要求新包时间戳严格大于该设备上次记录值,否则静默丢弃。

### A.2 具体缺陷

1. **客户端时钟回拨/漂移导致合法包被拒**
   TAI64N 依赖单调时钟。NTP 校时回拨、虚拟机暂停恢复、休眠唤醒、闰秒都会使客户端时间戳变小,服务端按"必须大于上次"规则拒绝,合法用户被锁死,直到本地时钟追上历史最大值。WireGuard 白皮书明确说明:TAI64N 只需"每 peer 单调递增的 96 位数",不要求真实时间——但本协议把"时间戳"同时当"新鲜度证明"用,时钟语义被绑死。

2. **NTP 跳变 / 时间戳前冲**
   若客户端时钟被大幅向前校,时间戳一下跳到很远未来;之后即使时钟恢复正常,也长期低于"历史最大值",持续被拒。单调递增校验对"向前跳"同样脆弱。

3. **服务端映射表内存增长 + 设备ID 洪泛 DoS**
   `设备ID -> 时间戳` 映射以设备ID为键。攻击者可伪造海量不同设备ID(若设备ID 不绑定认证密钥,或攻击者能构造合法设备ID),每个都写入一条映射,耗尽服务端内存。需要:设备ID 必须与认证身份绑定(只有合法证明通过才写映射)、映射表加 LRU/容量上限、按 IP 限速。

4. **多实例/分布式服务端状态不一致**
   映射是每服务端本地状态。负载均衡到多实例时,同一设备ID 落到不同实例会各自维护"最大值",导致误拒或防重放失效。需要粘性路由(按设备ID哈希)或共享状态(Redis 类),增加复杂度。

5. **静态设备ID 的关联跟踪与隐私问题**
   设备ID 若长期不变,是稳定的关联标识:审查者即使不解密,也可用设备ID 把同一用户的多次连接、多个服务器访问串起来做画像。建议设备ID 每会话轮换(从会话密钥派生),或改为"一次性随机 + 服务端按认证身份索引"。

6. **单调时间戳不能替代重放窗口**
   单调递增只防"重放旧包",但无法处理乱序:网络乱序到达时,后到的小时间戳合法包会被误判为重放而丢弃。WireGuard 的做法是**握手用 TAI64N 单调校验,数据用 64 位计数器 + 滑动窗口位图**(RFC 6479 风格),两者分工。本协议把单调时间戳用于所有包,会在高丢包/乱序链路上误杀。

### A.3 WireGuard 的可借鉴点
- 握手时间戳**加密且认证**后才比较(本协议若明文发时间戳,攻击者可观察/篡改)。
- 时间戳只需 per-peer 单调,不要求真实时间;允许截断 24 位纳秒减少信息泄漏。
- 数据面用独立的 64 位计数器 + 滑动重放窗口,容忍乱序。
- 重启丢状态不是问题:新握手时间戳更大,自然作废旧状态。

---

## B. 与 SS2022 / TUIC / WireGuard 的对比

| 维度 | SS2022 | TUIC | WireGuard | 本协议现状 |
| --- | --- | --- | --- | --- |
| 防重放 | 每流独立 nonce 计数器 + 独立 header chunk,天然抗重放 | 依赖 QUIC/TLS 层防重放 | 握手 TAI64N 单调 + 数据滑动窗口 | TAI64N+设备ID 单调映射 |
| 密钥 | PSK + 随机 salt 派生 session subkey(BLAKE3) | TLS 会话内用 RFC5705 导出 token | Noise_IK + 可选 PSK,临时 X25519 | 未定义(需补) |
| 前向保密 | **不提供**(明确声明) | 依赖 TLS 1.3(有) | 有(临时密钥) | 未定义 |
| 会话恢复 | 无 | QUIC 0-RTT | 无(靠重握手) | 未定义 |

可借鉴点:
- **SS2022**:把"防重放"下沉到每流 nonce 计数器,而不是全局时间戳;独立 header chunk 让每消息类型唯一、不可跨用途重放。
- **TUIC**:认证 token 从当前 TLS 会话用 RFC5705 Keying Material Exporter 导出(label=UUID, context=密码),token 与会话绑定、不可离线重放。
- **WireGuard**:握手单调时间戳 + 数据滑动窗口分工;时间戳加密认证后比较。

---

## C. 前向保密:X25519 临时密钥 + HKDF

当前设计若只用长期 PSK 派生会话密钥(类似 SS2022),则**长期密钥一旦泄露,所有历史流量可解密**。改进:

```
客户端首包携带:
  client_ephemeral_pk = X25519(client_sk, G)      // 32B,每次会话新生成
  timestamp_tai64n                                 // 12B,加密认证后比较
  device_id / session_id                           // 会话级,非长期
  auth_proof = HMAC-SHA256(auth_key, transcript)   // transcript 含双方 ephemeral pk

服务端响应携带:
  server_ephemeral_pk = X25519(server_sk, G)      // 32B,每次会话新生成

共享秘密:
  shared = X25519(client_sk, server_ephemeral_pk)  // 双方一致

密钥派生(HKDF-SHA256):
  psk_key   = HKDF-Extract(salt="xtunnel-v3", IKM=pre_shared_token)
  handshake = HKDF-Expand(psk_key, info=transcript_hash, L=32)
  session   = HKDF-Expand(handshake, info=shared, L=32)
  // 再从 session 派生 每流 subkey + 每方向 nonce 空间
```

收益:即使 PSK 事后泄露,没有本次 ephemeral 私钥也无法解密本次会话(前向保密)。成本:每会话一次 X25519(约 30µs),可忽略。

---

## D. 静默丢弃的利弊与改进

**利**:不回错误,主动探测者拿不到协议指纹,无法区分"协议不匹配/认证失败/不是本协议"。
**弊**:客户端也无法区分"被静默丢弃"与"网络故障/服务端宕机",排障困难;且"端口对任何输入都静默"本身可被差异探测识别(合法客户端能连通 vs 探测者永远静默)。

改进建议:
1. **对外行为保持静默**(不回任何协议错误),但**本地日志/指标可观测**:服务端记录丢弃原因(时间戳越界/证明失败/重放),供运维排障,不泄漏到线上。
2. **认证失败与网络故障在外部观察上不可区分**:时延、字节数一致;HMAC 用常数时间比较,避免时序 oracle。
3. **更强的主动探测防御是真实站点 fallback**(见 traffic-shape 报告):未授权者看到合法站点内容,而非静默。静默是"次优但便宜"的选择。

---

## E. 防降级

算法/版本协商(如 ChaCha20/AES-GCM/XOR、协议版本)若不在认证范围内,攻击者可篡改协商字段把双方降到弱算法(XOR)再攻击。防御:
- **协商内容全部绑定进 transcript**,transcript 参与 auth_proof / HMAC;任何篡改导致证明失败。
- 服务端对未知/不支持的版本**显式拒绝**而非降级(与 x-tunnel v2 现有"fail closed"原则一致)。
- 删除 XOR 等弱算法选项,从根上消除降级目标(见 crypto-selection 报告)。

---

## F. 推荐握手流程(分步)

```
C->S 首包(融合 header + 首数据,padding 拟形):
  version(u8) | flags(u16) | client_ephemeral_pk(32) |
  session_id(16,会话级随机) | timestamp_tai64n(12,加密) |
  capabilities(u64) | cipher_pref(list) |
  auth_proof(32) = HMAC-SHA256(auth_key, transcript) |
  padding(采样自 cover 首包分布) | [可选首数据]

S 校验顺序(fail closed):
  1. 解析 + 长度/版本校验(未知关键记录拒绝)
  2. 常数时间验证 auth_proof(transcript 含双方协商字段)
  3. 时间戳:解密后与"该认证身份上次最大值"比较,单调则接受
     (只写认证通过的映射,防设备ID洪泛;LRU 上限)
  4. 重放:session_id/nonce 去重
  5. 协商能力/算法(绑定 transcript,防降级)
  6. 资源限额(max-clients)

S->C 响应:
  server_ephemeral_pk(32) | negotiated_caps(u64) |
  negotiated_cipher(u8) | server_time(u64) |
  padding | [真实站点 fallback:未授权者走此分支]

之后数据面:
  每流独立 subkey + 64 位计数器 nonce + 滑动重放窗口(容忍乱序)
```

要点:握手用单调时间戳(加密认证后比较),数据用计数器+滑动窗口;ephemeral X25519 提供前向保密;协商绑定 transcript 防降级;静默对外、可观测对内。
