# x-tunnel 密码算法与密钥管理优化研究报告

状态:研究稿。针对"payload 算法可协商:1=ChaCha20, 2=AES-128-GCM, 3=XOR"的算法表与密钥管理。
资料来源:NIST SP 800-38D(GCM)、Shadowsocks 2022 SIP022(sip022.md)、WireGuard(ChaCha20-Poly1305)、x-tunnel 现有 HKDF-SHA256 用法。

---

## A. 当前算法表的致命问题

### A.1 裸 ChaCha20 与 XOR 都不是 AEAD
- **裸 ChaCha20**(RFC 8439 的纯流密码)只提供机密性,**无完整性/认证**。攻击者可在不解密的情况下对密文做**比特翻转**,解密后明文对应位被异或——即 malleability(可锻性)。
- **XOR**(密钥流异或)同样无认证,且更弱。

### A.2 具体攻击场景
1. **已知明文异或恢复密钥流(XOR)**:代理流量里大量可预测明文(HTTP 请求行 `GET / HTTP/1.1\r\n`、TLS ClientHello 固定开头、SOCKS5 头)。若同一 XOR 密钥流被复用(密钥/nonce 重复),`明文A XOR 密文A = keystream`,再用 keystream XOR 密文B 即得明文B。两段密文直接 XOR 还能消去密钥流得到"明文A XOR 明文B",配合已知明文可连锁恢复。这是致命的。
2. **比特翻转/流量注入(裸 ChaCha20 / XOR)**:无 MAC,攻击者翻转密文位即翻转明文位。可篡改目标地址、端口、HTTP 头,或注入伪造的流控/关流指令破坏多路复用。
3. **跨流/跨包重放**:无认证+无绑定,攻击者可把一段密文复制到另一位置;若 nonce 管理不严即可重放。
4. **Padding/长度 oracle**:无认证时解密失败的行为差异(静默丢弃 vs 断连)可被当作 oracle,逐字节探测。
5. **降级到 XOR**:协商不绑定 transcript 时,攻击者把算法字段改成 3(XOR),直接落到上述最弱情形。

结论:**XOR 必须删除;裸 ChaCha20 必须升级为 ChaCha20-Poly1305(AEAD)**。所有 payload 一律 AEAD。

---

## B. AEAD 选型

| 算法 | 优势 | 劣势 | 适用 |
| --- | --- | --- | --- |
| ChaCha20-Poly1305 | 纯软件极快、无硬件依赖、移动端/ARM 优势大、常数时间天然抗侧信道 | 无硬件加速时大吞吐略逊 AES-NI | 移动端、无 AES-NI 的 CPU、默认选项 |
| AES-256-GCM | 有 AES-NI 时吞吐极高、安全余量大 | 依赖 AES-NI;nonce 管理严格(见 D);GHASH 无硬件时慢 | x86 服务器(有 AES-NI) |
| AES-128-GCM | AES-NI 下最快、128 位安全足够 | 同上;密钥更短 | x86 高吞吐 |

- **AES-NI 影响**:现代 x86(Intel/AMD)与 ARMv8 多有 AES 硬件指令,AES-GCM 可达数 GB/s;无硬件时 GHASH 成为瓶颈,ChaCha20-Poly1305 反超。
- **移动端**:多数手机 SoC 有 ARMv8 Crypto Extensions(AES+PMULL),但低端/老设备无;ChaCha20-Poly1305 在纯软件下更稳。
- **SS2022 参照**:SIP022 必选 `2022-blake3-aes-128-gcm`/`aes-256-gcm`,可选 ChaCha20-Poly1305;密钥派生用 BLAKE3。

**推荐**:默认 **ChaCha20-Poly1305**(跨平台稳、无侧信道包袱);在确认有 AES-NI 的 x86 服务器可协商 **AES-256-GCM** 换吞吐。**删除 XOR 与裸 ChaCha20**。

---

## C. Nonce/IV 管理

- **每包递增计数器作 nonce**:每流维护 64 位发送计数器,每加密一包 +1。AEAD nonce 由"固定前缀 + 计数器"构成(如 ChaCha20-Poly1305 用 32 位 0 + 64 位小端计数器,WireGuard 做法;GCM 用 96 位 IV = 4 字节固定 + 8 字节计数器)。
- **双向独立 nonce 空间**:客户端→服务端与服务端→客户端用不同子密钥或不同 nonce 前缀,避免双向计数器碰撞。
- **nonce 唯一性是硬约束**(SP 800-38D §8):GCM 同一密钥下 IV 重复会同时破坏机密性与完整性。计数器方案天然保证唯一,但**绝不能回绕后复用**——见重密钥。
- **重密钥(rekey)**:计数器接近上限(如 2^63,或按 SP 800-38D 的调用次数上限)前触发重密钥:用当前会话密钥 + 计数派生新密钥并重置计数器;或直接用新 ephemeral 重新握手。
- **与防重放配合**:nonce 计数器同时充当重放检测序号——接收端用滑动窗口记录已见计数器(见 handshake-replay),既防重放又容忍乱序。

---

## D. 密钥派生与协商安全

```
pre_shared_token (用户配置,base64,长度=算法密钥长)
  -> HKDF-Extract(salt="xtunnel-v3-kdf", IKM=token) = PRK
  -> HKDF-Expand(PRK, info=transcript_hash, L) = session_seed
     transcript_hash = SHA256(version|caps|cipher_pref|
                              client_eph_pk|server_eph_pk|
                              session_id|timestamp|server_name|path)
  -> 从 session_seed 派生:
       c2s_key, s2c_key (各 AEAD 密钥)
       c2s_nonce_prefix, s2c_nonce_prefix
       每流 subkey(如需,含 stream_id)
```

- **防降级**:cipher_pref、version、caps 全进 transcript_hash,参与 auth_proof;篡改协商字段即证明失败。服务端对未知版本/算法**显式拒绝**,不降级。
- **是否保留 XOR**:不保留。删除后协商表只剩 AEAD,降级目标消失。诊断用途可用独立的、永不承载用户数据的 loopback 模式,不进协商表。

---

## E. 前向保密

引入每会话 ephemeral X25519(见 handshake-replay §C):session_seed 混入 X25519 共享秘密,长期 token 泄露不再导致历史流量可解密。成本每会话一次 X25519(约 30µs),可忽略。SS2022 明确不提供前向保密(其取舍是 PSK 免握手);本协议既然已有握手,应顺手获得前向保密。

---

## F. 推荐算法表与密钥派生流程

**算法表(协商值)**:
| 值 | 算法 | 说明 |
| --- | --- | --- |
| 1 | ChaCha20-Poly1305 | 默认,跨平台 |
| 2 | AES-256-GCM | 有 AES-NI 的 x86 高吞吐 |
| 3 | AES-128-GCM | 可选,有 AES-NI |
(删除原 XOR;原裸 ChaCha20 升级为 ChaCha20-Poly1305)

**流程**:
```
1. 协商:cipher_pref 列表进 transcript,绑定 auth_proof(防降级)
2. 派生:HKDF-SHA256(token, transcript_hash) -> session_seed
3. 前向保密:session_seed 混入 X25519 ephemeral 共享秘密
4. 子密钥:派生 c2s/s2c AEAD 密钥 + nonce 前缀
5. 数据面:每流 64 位计数器 nonce,每包 +1;双向独立空间
6. 防重放:计数器 + 滑动窗口(容忍乱序)
7. 重密钥:计数器近上限前 rekey
```

要点:全 AEAD、默认 ChaCha20-Poly1305、删 XOR、nonce=计数器、协商绑定 transcript 防降级、ephemeral X25519 提供前向保密。
