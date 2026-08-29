# x-tunnel 多路复用与传输层优化研究报告

状态:研究稿。针对"单条 TCP 长连接 + Stream ID 指令化多路复用(1=开流/2=数据/3=关流)"的传输层设计。
资料来源:RFC 9000(QUIC)、RFC 9114(HTTP/3)、RFC 9221(QUIC Datagram)、GFW QUIC 审查论文(gfw-quic.md)、Hysteria2 协议(hys-proto.md)、TUIC 规范(tuic-spec.md)、smux/yamux 规范。

---

## A. TCP 上多路复用的根本问题

### A.1 队头阻塞(Head-of-Line Blocking)
所有内部流共享一条 TCP。TCP 保证按序可靠交付,**任何一个流的一个丢包都会阻塞整条 TCP 的接收窗口**,所有其他流的数据即使已到达也必须排队等待重传。流越多、丢包率越高,停顿越明显。这是 TCP 复用的结构性缺陷,smux/yamux 都无法消除(它们依赖底层 TCP 的可靠性与顺序)。

### A.2 拥塞控制被单连接绑架
一条 TCP 只有一个拥塞窗口。所有流共享这一个 cwnd:一条大下载流会把窗口占满,交互式小流被饿死;反之一次丢包让 cwnd 收缩,所有流同时变慢。无法按流做拥塞隔离。

### A.3 丢包时全部流同时停顿
与 A.1 同因:丢包恢复期间(一个 RTT 级),所有流吞吐归零。弱网/移动网络下体验显著劣化。

### A.4 smux/yamux 实际表现
- **smux**(本项目现用):8 字节帧头、会话级共享接收缓冲、v2 起每流滑动窗口(cmdUPD 携带 CONSUMED/WINDOW)、token bucket 整形、slab 帧分配器。工程上很省,但仍是 TCP 上复用,继承全部 A.1–A.3 问题。
- **yamux**:12 字节帧头,Type(Data/WindowUpdate/Ping/GoAway)+ Flags(SYN/ACK/FIN/RST),会话级流控窗口。同样受 TCP 队头阻塞约束。
结论:两者都是"在可靠有序传输上复用"的优秀实现,但**底层换成 TCP 就躲不开队头阻塞**。要根治需换 QUIC。

---

## B. QUIC/UDP 路线

### B.1 RFC 9000 的关键能力
- **流独立**:每条 QUIC stream 独立有序可靠,一条流丢包只阻塞该流,其他流不受影响(根治队头阻塞)。
- **0-RTT**:会话恢复时首包即可携带应用数据。
- **连接迁移**:connection ID 而非四元组标识连接,网络切换(NAT 重绑/Wi-Fi 切蜂窝)不断连。
- **每连接拥塞控制 + 流级流控**。

### B.2 GFW 对 QUIC 的现状(gfw-quic.md,USENIX Security '25)
- 2024-04 起 GFW **解密 QUIC Initial 包**(Initial 密钥可由 DCID+版本盐推导,任何人可解),读取其中 TLS ClientHello 的 **SNI**,命中 QUIC 专用黑名单即触发封禁。
- 封禁方式:丢弃该 (源IP,目的IP,目的端口) 三元组后续客户端→服务端 UDP 包 **180 秒**(残余封禁,单包即可触发)。
- GFW 忽略源端口 < 目的端口的包(优化只查客户端流量);封禁延迟 60ms–7.5s,90% 在 1s 内。
- **可利用弱点**:解密开销大,中等流量洪泛即可让 QUIC 审查降级;但这也意味着 QUIC 已被重点盯防。
- QUIC 黑名单约为 DNS 黑名单的 60%,且与 TLS/HTTP/DNS 黑名单**不同**。
推论:**QUIC 不再是"免检区"**。用 QUIC 必须处理 SNI(真域名或伪装)、Initial 包指纹,并接受 UDP 可能被 QoS 限速/阻断的风险。

### B.3 Hysteria2(hys-proto.md)
- 标准 QUIC + RFC 9221 不可靠 datagram;**HTTP/3 伪装**:未认证者看到的是标准 HTTP/3 服务器,认证走 `POST /auth`(成功返回状态码 233),失败则像普通 web 服务器一样响应或反代到真实站点(抗主动探测)。
- **Brutal 拥塞控制**:客户端上报接收速率,服务端按设定速率猛发,牺牲公平换吞吐(适合弱网/高丢包,但会挤占带宽)。
- TCP=每连接一条 QUIC 双向流;UDP=datagram + 关联 ID。

### B.4 TUIC(tuic-spec.md)
- QUIC 上复用 5 类命令(Authenticate/Connect/Packet/Dissociate/Heartbeat)。
- 认证 token 从 TLS 会话用 RFC5705 导出,与 QUIC 会话绑定。
- UDP 用 ASSOC_ID + PKT_ID + 分片字段(FRAG_TOTAL/FRAG_ID/SIZE)承载,支持 UDP 分片重组。

### B.5 对比结论
QUIC 根治队头阻塞、给 0-RTT/连接迁移,但**审查风险与运维复杂度上升**(SNI 指纹、UDP 限速、Initial 可解密)。TCP 复用简单稳定、穿透性好,但弱网体验差。

---

## C. 若保留 TCP 复用的要点

1. **流控窗口**:沿用 smux v2 的每流滑动窗口(cmdUPD: CONSUMED/WINDOW),会话级共享接收缓冲封顶,防内存膨胀。
2. **Stream ID 位宽与回绕**:32 位 ID,客户端奇数/服务端偶数(smux 约定)避免冲突;ID 耗尽前回收已关闭流的 ID,用"ID + epoch"或足够大的空间防回绕歧义。
3. **优先级与背压**:交互式流(Ping/SSH/聊天)优先调度,大流限速;接收缓冲满时反压发送端,避免无界排队。
4. **UDP-over-mux 消息边界**:UDP 有消息边界,不能当字节流。参考 TUIC:`ASSOC_ID(2) | PKT_ID(2) | FRAG_TOTAL(1) | FRAG_ID(1) | SIZE(2) | ADDR | payload`;每 datagram 独立成帧,不跨帧合并语义。
5. **断线重连与会话恢复**:
   - 服务端为每会话缓存"已发送未确认"数据与流状态一段时间;
   - 客户端重连带 session_id + 续传游标,服务端幂等重发未消费数据;
   - 开流/关流指令幂等(重复 SYN 不重复建流,用 stream_id 去重)。
   注意:TCP 复用下"会话恢复"只能恢复控制面,底层 TCP 仍需重建;真正的无缝迁移要靠 QUIC 连接迁移。

---

## D. 推荐架构

**推荐:双栈——默认 QUIC/UDP,自动回退 TCP 复用。**

理由:
- QUIC 根治队头阻塞,是弱网/高丢包下的体验上限;0-RTT + 连接迁移是 TCP 复用给不了的。
- 但 GFW 已能解密 QUIC Initial 读 SNI、UDP 可被限速/阻断,**QUIC 不能作为唯一依赖**;审查环境 UDP 可达性不稳。
- TCP(wss)穿透性最好、最不易被整体阻断,作为保底回退。
取舍:
- 若只做一条栈,审查环境选 **TCP(wss)+ 流量整形**(穿透优先);无审查/弱网场景选 **QUIC**(体验优先)。
- 双栈增加实现量,但把"体验"与"可达性"解耦,是长期最优。
落地:客户端先试 QUIC(真域名 SNI + HTTP/3 伪装 + 非 443 备选端口),探测失败/被 QoS 即切 TCP;记住每条链路的可用传输,避免反复试探。

---

## E. 推荐传输层设计

```
传输层抽象 Transport:
  - QuicTransport: RFC9000 + RFC9221 datagram,HTTP/3 伪装(Hysteria2 式 /auth)
  - TcpTransport : 现有 smux v2(wss 承载),保留热路径
  选择器:探测 + 记忆,默认 Quic,失败回退 Tcp

统一会话层(两种传输之上同一套):
  ChannelInit/Accept(认证,见 handshake-replay)
  数据帧: kind(u8) | stream_id(u32) | flags(u8) | len | payload
    kind: TCP数据 / UDP数据 / Ping / 控制(SYN/FIN/RST/窗口更新)
  UDP 帧: assoc_id | pkt_id | frag_total | frag_id | size | addr | payload
  流控: 每流滑动窗口 + 会话级缓冲封顶
  优先级: 交互流优先,大流限速
  会话恢复: session_id + 幂等 SYN + 服务端短期续传缓存
```

要点:传输层可插拔(QUIC 主力/TCP 保底),会话层协议统一,UDP 保留消息边界,流控与优先级在会话层实现,会话恢复幂等。
