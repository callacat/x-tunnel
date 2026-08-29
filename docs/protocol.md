# x-tunnel Protocol Specification

Status: Protocol v3 (P0 + P1 + P2 implemented; all-AEAD, ephemeral X25519 forward secrecy, server proof, sliding replay window, TAI64N anti-replay, first-packet morphing, per-record padding, traffic shaping, smux keepalive randomization, send pacing, ECH default off/configurable, and configurable cipher preference).

This document describes the wire behavior implemented in `internal/wire` and
used by `cmd/x-tunnel`. Current builds negotiate and enforce protocol v3
`ChannelInit` and `ChannelAccept` with mutual authentication and ephemeral
X25519 forward secrecy. A peer that cannot complete v3 authentication or lacks
required capabilities fails closed before any client session is created.

Standards references used for local proxy behavior:

- SOCKS Protocol Version 5: RFC 1928, <https://www.rfc-editor.org/rfc/rfc1928>
- Username/Password Authentication for SOCKS V5: RFC 1929, <https://www.rfc-editor.org/rfc/rfc1929>
- HTTP Semantics, including CONNECT and hop-by-hop header handling: RFC 9110, <https://www.rfc-editor.org/rfc/rfc9110>
- Elliptic Curves for Security (X25519): RFC 7748, <https://www.rfc-editor.org/rfc/rfc7748>
- HMAC-based Extract-and-Expand Key Derivation Function (HKDF): RFC 5869, <https://www.rfc-editor.org/rfc/rfc5869>

## 1. Topology

x-tunnel has two runtime roles:

- Client mode: starts local SOCKS5, HTTP proxy, and TCP forward listeners, then
  dials a remote WebSocket server.
- Server mode: accepts WebSocket connections, authenticates v3 channels, opens
  smux streams, and dials target TCP/UDP endpoints directly or through an
  upstream SOCKS5 proxy.

The transport stack is:

```text
local app
  -> local SOCKS5 / HTTP / TCP listener
  -> smux stream (v3 AEAD encrypted)
  -> smux session
  -> WebSocket connection
  -> TLS 1.3 transport
```

Every smux stream carries an independent AEAD encrypted channel after
handshake negotiation.

## 2. WebSocket Transport

The outer transport is WebSocket over TCP or TLS:

- `ws://`
- `wss://`

For `wss://`, the client uses TLS 1.3. ECH is disabled by default because it is
currently targeted and blocked by the GFW (acting as a red flag); it can be
explicitly enabled via configuration (`-ech`). Fallback to standard TLS 1.3 is preserved.
`-insecure` disables certificate verification for standard TLS fallback behavior and
should not be used in production.

The WebSocket request does not carry protocol metadata:

- no `client_id` query parameter;
- no `channel_id` query parameter;
- no token in `Sec-WebSocket-Protocol`.

Authentication happens after the WebSocket upgrade, on the first smux stream,
using v3 `ChannelInit`.

The client also sets a generic WebSocket request `User-Agent` instead of
leaving Go's default `Go-http-client` value on the upgrade request. This is
request-shape hygiene only; it does not carry protocol state and does not change
the TCP/UDP data path.

## 3. Protocol v3 Channel Authentication and Cryptography

Each WebSocket channel carries one smux session. Immediately after smux setup,
the client opens the first stream and sends a v3 frame:

```text
frame_type (u8) | version (u8) | flags (BE16) | body_len (BE32) | body ...
```

Frame types:

| Type | Name | Meaning |
| --- | --- | --- |
| `1` | ChannelInit | Client initiation frame. |
| `2` | ChannelAccept | Server acceptance frame with server proof and ephemeral public key. |
| `3` | ChannelReject | Server rejection frame with structured reject code and message. |

The v3 frame version is `3`. `body_len` is capped by `MaxV2FrameSize` (`16 KiB`).

### 3.1 TLV Records

Frame bodies are TLV records:

```text
type (BE16) | len (BE16) | value ...
```

Type bit `0x8000` indicates a critical record: peers must reject unknown
critical types (fail closed).

Critical records in v3:

| Type | Name | Frame | Length | Meaning |
| --- | --- | --- | --- | --- |
| `0x8001` | SessionID | ChannelInit | 16 B | Client session identifier (UUID). |
| `0x8002` | ChannelID | ChannelInit | 4 B | Monotonic 1-based channel index within session. |
| `0x8003` | ClientNonce | ChannelInit | 32 B | Random client nonce. |
| `0x8004` | Timestamp | ChannelInit | 8 B | Unix epoch seconds (BE64). |
| `0x8005` | Capabilities | ChannelInit, ChannelAccept | 8 B | Negotiated capability bitmask (BE64). |
| `0x8006` | AuthProof | ChannelInit | 32 B | HMAC-SHA256 proof over `transcript_hash_init`. |
| `0x8010` | ServerNonce | ChannelAccept | 32 B | Random server nonce. |
| `0x8011` | ServerTime | ChannelAccept | 8 B | Unix epoch seconds (BE64). |
| `0x8020` | RejectCode | ChannelReject | 1 B | Structured reject code (1..9). |
| `0x8030` | CipherPref | ChannelInit | 1..8 B | Ordered cipher preference list (all-AEAD IDs). |
| `0x8031` | Cipher | ChannelAccept | 1 B | Chosen negotiated cipher algorithm ID. |
| `0x8032` | ClientEphPK | ChannelInit | 32 B | Client ephemeral X25519 public key. |
| `0x8033` | ServerEphPK | ChannelAccept | 32 B | Server ephemeral X25519 public key. |
| `0x8034` | ServerProof | ChannelAccept | 32 B | HMAC-SHA256 proof over `transcript_hash_full`. |
| `0x8035` | TAI64N | ChannelInit | 12 B | WireGuard-style TAI64N timestamp (8B BE64 2^62+unix_sec || 4B BE32 nanos). |

Optional records:

| Type | Name | Frame | Meaning |
| --- | --- | --- | --- |
| `0x0007` | ClientName | ChannelInit | Client implementation identifier. |
| `0x0008` | BuildInfo | ChannelInit | Build metadata string. |
| `0x0009` | DesiredChannels | ChannelInit | Client pool target channel count (BE16). |
| `0x000a` | TransportHints | ChannelInit | Transport optimization hints. |
| `0x000b` | Padding | Any | Ignored padding bytes. |
| `0x0012` | MaxFrameSize | ChannelAccept | Maximum accepted frame size (BE32). |
| `0x0013` | MaxStreams | ChannelAccept | Maximum concurrent streams per channel (BE32). |
| `0x0015` | Message | ChannelAccept | Informational server welcome string. |
| `0x0021` | RejectReason | ChannelReject | Rejection reason string. |

### 3.2 Cipher Negotiation

Protocol v3 requires authenticated encryption (AEAD). Non-AEAD modes (such as
bare ChaCha20 or XOR) do not exist in v3:

| ID | Name | Key Length | Nonce Length | Tag Length |
| --- | --- | --- | --- | --- |
| `1` | ChaCha20-Poly1305 | 32 B | 12 B | 16 B |
| `2` | AES-256-GCM | 32 B | 12 B | 16 B |
| `3` | AES-128-GCM | 16 B | 12 B | 16 B |

The client provides `CipherPref` (default: `[1, 2, 3]`). The server chooses the
first supported cipher ID. If no supported cipher exists or `CipherPref` is empty,
the server rejects with code `9` (`V3RejectUnsupportedCipher`), failing closed
without downgrade.

### 3.3 Dual Transcript Hashing and Proofs

Handshake authentication uses dual SHA-256 transcripts to prevent MITM tampering,
replay, algorithm downgrade, and ephemeral key replacement.

1. **Init Transcript (`transcript_init`)**:
   Layout:
   ```text
   0..0   : 0x01 (ChannelInit frame type)
   1..1   : 0x03 (version 3)
   2..3   : 0x0000 (flags)
   4..19  : SessionID (16 B)
   20..23 : ChannelID (4 B, BE32)
   24..55 : ClientNonce (32 B)
   56..63 : Timestamp (8 B, BE64)
   64..71 : Capabilities (8 B, BE64)
   72..103: ClientEphPK (32 B)
   104..135: ServerEphPK placeholder (32 zeros)
   136..136: CipherPrefLen (1 B)
   137..N : CipherPref (N bytes)
   N+1..N+2: ServerNameLen (BE16)
   ...    : ServerName
   ...    : PathLen (BE16)
   ...    : Path
   ...    : TAI64N (12 B)
   ```
   - `transcript_hash_init = SHA256(transcript_init)`
   - `auth_key = HKDF-SHA256(secret_token, salt="x-tunnel-v3-auth", info=server_name)` (32 B)
   - `auth_proof = HMAC-SHA256(auth_key, transcript_hash_init)`

2. **Full Transcript (`transcript_full`)**:
   Same layout as `transcript_init`, with `ServerEphPK` (32 B) at offset 104..135,
   and 1 byte `negotiated_cipher` appended after `TAI64N`:
   `... || path_len + path || tai64n (12 B) || negotiated_cipher (1 B)`
   - `transcript_hash_full = SHA256(transcript_full)`
   - `server_proof = HMAC-SHA256(auth_key, transcript_hash_full)`

The server verifies `auth_proof` in constant time before proceeding. The client
verifies `server_proof` in constant time using `ServerEphPK` and `accept.Cipher`
before deriving session keys. If verification fails, the connection closes
immediately (fail closed).

### 3.4 Ephemeral Key Exchange and Forward Secrecy (P1)

Each channel generates a fresh ephemeral X25519 keypair:

- Client generates `(client_sk, client_pk)`; writes `client_pk` in TLV `0x8032`.
- Server generates `(server_sk, server_pk)`; writes `server_pk` in TLV `0x8033`.
- Both compute `shared = X25519(sk, peer_pk)`.
- RFC 7748 low-order points (output is all zeros or invalid) are explicitly
  rejected with error (fail closed).
- Ephemeral private keys are wiped and discarded immediately after handshake.
  Even if the pre-shared token is compromised later, recorded historical traffic
  cannot be decrypted.

### 3.5 Key Derivation Schedule

Session keys and stream subkeys are derived using HKDF-SHA256:

```text
PRK          = HKDF-Extract(salt="xtunnel-v3-kdf", IKM=secret_token)
seed         = HKDF-Expand(PRK, info=transcript_hash_full, L=32)
session_seed = HKDF-Expand(seed, info="xtunnel-v3 fs mix" || shared, L=32)

c2s_nonce_prefix = HKDF-Expand(session_seed, info="xtunnel-v3 c2s nonce", L=4)
s2c_nonce_prefix = HKDF-Expand(session_seed, info="xtunnel-v3 s2c nonce", L=4)
```

Per-stream AEAD keys are derived deterministically on demand:

```text
info = label || cipher_id (1 B) || stream_id (BE32) || generation (BE64)
  label = "xtunnel-v3 c2s key" (client -> server)
  label = "xtunnel-v3 s2c key" (server -> client)

stream_key = HKDF-Expand(session_seed, info=info, L=key_len)
```

### 3.6 First-Packet Morphing (P1)

To eliminate first-packet length fingerprinting (a primary classification signal used by network censors), `ChannelInit` incorporates dynamic morphing padding using the non-critical TLV `Padding` (`0x000b`):

- **Target Length Sampling**: The target total packet size is sampled across three confidence bands derived from typical cover protocol distributions (such as TLS ClientHello):
  - Band A: `[480, 576]` B (50% probability)
  - Band B: `[1024, 1152]` B (25% probability)
  - Band C: `[1280, 1400]` B (25% probability)
- **Sampling Strategy**: A band is chosen according to its weight, and a target size is uniformly sampled within that band. If the sampled target is smaller than the unpadded frame length or the frame length is `>= 1400` bytes, no padding is appended (the frame is never truncated).
- **Payload Entropy**: Padding bytes are generated using cryptographically secure random numbers (`crypto/rand`) rather than zeros, maintaining high entropy across the packet.
- **Transcript Invariance**: Padding is carried in the optional non-critical `0x000b` TLV, which the server parses and ignores. Padding bytes are excluded from both `transcript_hash_init` and `transcript_hash_full`, ensuring that `auth_proof` and `server_proof` remain completely invariant to padding.

### 3.7 Per-Stream AEAD Framing, Per-Record Padding, and Traffic Shaping (P1)

Data streams within smux are wrapped with `V3CipherStream`:

```text
counter (BE64) | plain_len (BE16) | pad_len (BE16) | AEAD(plain || pad || tag)
```

- **Header (12 B)**: Unencrypted header consisting of:
  - `counter`: 64-bit monotonic sequence counter starting at 1 (BE64).
  - `plain_len`: 16-bit plaintext length in bytes (BE16).
  - `pad_len`: 16-bit padding length in bytes (BE16).
- **AEAD Input**: `plain || pad` with a 16-byte Poly1305 / GCM authentication tag.
- **Nonce (12 B)**: `4B direction prefix || 8B counter (BE64)`.
- **AD (8 B)**: `8B counter (BE64)`.
- **Validation & Bounds**: The receiver enforces `plain_len >= 1`, `pad_len >= 0`, and `plain_len + pad_len <= maxV3RecordPayload` (1400 B). Any violation immediately drops the connection (fail closed).
- **Anti-Replay**: RFC 6479-style 2048-bit sliding bitmap window checked prior to AEAD decryption. Replayed or out-of-window sequence numbers fail immediately.
- **Deterministic Rekeying**: When `counter` crosses multiples of `2^32` (`generation++`), both sides advance the generation counter and recompute `stream_key` without control frames.
- **Per-Record Padding**: Enabled by default (`PadRecords = true` in `NewV3CipherStream`). For each write chunk (`<= 1400` B), `pad_len` is uniformly sampled in `[0, 1400 - plain_len]`, uniformly covering `[plain_len, 1400]` to conceal exact application message lengths. The receiver decrypts `plain || pad`, returns the first `plain_len` bytes, and discards the padding.
- **Segment Coalescing (Traffic Shaping)**: Controlled by `CoalesceDelay` (time.Duration). Defaults to `0` (disabled) to preserve zero-added interactive latency. When `CoalesceDelay > 0`, small writes are buffered until either accumulated data reaches `coalesceFlushThreshold` (1024 B) or the `CoalesceDelay` timer fires, emitting a single coalesced record (`<= 1400` B). Stream `Close()` immediately flushes any remaining buffered data. Bulk writes (`io.Copy`) larger than 1024 B immediately emit full records without timer delay.

### 3.8 Server Validation Order and Silent Rejection

The server executes handshake validation in the following strict order (fail closed):

1. Parse `ChannelInit` frame and TLVs.
2. Decode and validate `TAI64N` timestamp format (12 B, seconds >= 2^62, nanoseconds < 10^9).
3. Check timestamp skew (`-auth-skew`, default `5m`) using `Timestamp` (0x8004).
4. Validate `ClientEphPK` (exactly 32 bytes).
5. Verify `auth_proof` via constant-time HMAC comparison over `transcript_hash_init`.
6. Reject replayed `(SessionID, ChannelID, ClientNonce)` values via `serverNonceCache`.
7. TAI64N monotonic anti-replay check and registration: verify `TAI64N` is strictly greater than the historical maximum recorded for `SessionID` in the bounded LRU cache (`serverTAI64NCache`, capacity 65536).
8. Check required capabilities (must include `ProtocolCapabilityForwardSecrecy`).
9. Negotiate cipher from `CipherPref`.
10. Enforce `-max-clients` session limits.
11. Generate `ServerEphPK` and compute `shared = X25519(server_sk, client_pk)`.
12. Compute `transcript_hash_full` and `server_proof`.
13. Derive `session_seed` and channel session keys.
14. Reply with `ChannelAccept` containing `ServerEphPK` and `ServerProof`, then start accepting data streams.

The pre-auth stage is bounded by `-preauth-timeout` (default `5s`).

### 3.9 Silent Drop Behavior and Observability

To prevent protocol fingerprinting and timing oracles, any failure during pre-auth validation does not send a `ChannelReject` frame. Instead, the server **silently drops** the connection by immediately closing the underlying WebSocket connection.
- **External View**: Handshake failures and network disconnects are indistinguishable to unauthenticated probes.
- **Local Observability**: Specific failure reasons are recorded in server logs and exposed via internal Prometheus metrics (`x_tunnel_server_auth_rejections_total`, `x_tunnel_server_tai64n_rejections_total`, `x_tunnel_server_tai64n_lru_evictions_total`, etc.) for operations and troubleshooting.

### 3.10 Roadmap Status

- **P0 (Implemented)**: All-AEAD cipher suite (ChaCha20-Poly1305, AES-256-GCM, AES-128-GCM), transcript-bound authentication & anti-downgrade proofs, per-stream AEAD framing with 2048-bit sliding replay window and automatic generation rekey.
- **P1 (Implemented)**: Ephemeral X25519 forward secrecy, dual transcript hashes, server proof validation, `ForwardSecrecy` capability enforcement, WireGuard-style TAI64N monotonic anti-replay with bounded LRU cache, external silent drop, ChannelInit first-packet morphing padding across 3 confidence bands, and per-record uniform padding with configurable segment coalescing. Coalescing defaults to 0 (disabled) to preserve low interactive latency, but can be enabled for strict packet-size shaping.
- **P2 (Implemented)**: Application layer traffic shaping & fingerprint mitigation:
  - Keepalive randomization with ±20% uniform jitter on smux sessions (default enabled, anti-periodic fingerprint).
  - Optional token bucket send pacing (`-pacing-rate-mbps`, default 0 / disabled for zero overhead).
  - ECH default off / configurable (`-ech` bool flag default false, `-ech-domain` string, rationale: GFW targeted blocking).
  - Configurable client cipher preference (`-cipher-pref`, default "1,2,3", validated against supported ciphers, fail closed on error).
  - Segmentation coalescing switch wiring (`-shaping-coalesce-ms`, default 0 / disabled to avoid adding interactive latency; ping probe streams keep 0 delay to avoid RTT measurement distortion).
- **Remaining Items**:
  - Dual-stack QUIC / HTTP/3 transport alongside WebSocket/TCP.

## 4. Capabilities

Capability bit allocation:

| Bit | Name | Meaning |
| --- | --- | --- |
| `1 << 0` | TCP | TCP streams are supported. |
| `1 << 1` | UDP | UDP streams are supported. |
| `1 << 2` | Ping | Ping streams are supported. |
| `1 << 3` | IPStrategy | IP strategy byte is understood. |
| `1 << 4` | TCPStatus | TCP streams begin with an open-status frame. |
| `1 << 5` | UDPStatus | UDP streams begin with an open-status frame. |
| `1 << 6` | OpenStatusCode | Status frames include a structured error code byte. |
| `1 << 9` | ChannelStats | Channel metrics expose negotiated capabilities. |
| `1 << 10` | DrainSignal | Channel supports server drain notification. |
| `1 << 11` | DatagramV2 | Datagram framing v2 supported. |
| `1 << 12` | ForwardSecrecy | Ephemeral X25519 forward secrecy + server proof supported. |

Runtime requirements:
- In protocol v3, `TCP`, `Ping`, `TCPStatus`, `OpenStatusCode`, and `ForwardSecrecy` are required bits.
- Peers that do not advertise required bits are rejected with `MissingRequiredCapability` (code 2), failing closed.

## 5. smux Stream Open Header

After channel authentication, every data stream starts with the compact
open header (carried inside the AEAD encrypted payload):

```text
kind (u8) | ip_strategy (u8) | target_len (BE16) | target bytes ...
```

Stream kinds:

| Value | Name | Meaning |
| --- | --- | --- |
| `1` | TCP | Open a TCP proxy stream to `target`. |
| `2` | UDP | Open a UDP relay stream to `target`. |
| `3` | Ping | Echo an 8-byte ping payload. |

Unknown stream kinds are logged, counted in
`x_tunnel_server_unsupported_streams_total`, and closed.

IP strategies:

| Value | CLI | Meaning |
| --- | --- | --- |
| `0` | `auto` | Resolve target hostname locally using system DNS order. |
| `1` | `ipv4` | Force IPv4 only. |
| `2` | `ipv6` | Force IPv6 only. |
| `3` | `4,6` | Prefer IPv4, fall back to IPv6. |
| `4` | `6,4` | Prefer IPv6, fall back to IPv4. |

Limits:

- `target_len <= 65535`.
- TCP and UDP streams reject `ip_strategy` values outside `0..4`.
- TCP/UDP targets must be valid `host:port` authorities.

## 6. TCP Streams

After a TCP open header, the server validates target syntax, target policy, and
then dials the target. Before proxied bytes begin, it writes:

```text
status (u8) | code (u8) | msg_len (BE16) | message bytes ...
```

Status values:

| Value | Name | Meaning |
| --- | --- | --- |
| `0` | OK | Target policy and remote TCP dial succeeded. |
| `1` | Error | Target validation, policy, dial, or resource-limit failure. |

Structured codes:

| Value | Name | Meaning |
| --- | --- | --- |
| `0` | None | No structured error. Used for OK. |
| `1` | BadTarget | Invalid IP strategy or malformed target. |
| `2` | PolicyDenied | Target policy rejected the target. |
| `3` | DialFailed | Remote TCP dial or upstream setup failed. |
| `4` | ResourceLimit | Server stream limit was reached. |

Local mapping:

- SOCKS5 CONNECT maps `PolicyDenied` to reply `0x02`; other remote open errors
  map to `0x05`.
- HTTP proxy and CONNECT map `PolicyDenied` to `403 Forbidden`; other remote
  open errors map to `502 Bad Gateway`.
- TCP forward listeners close the local connection on remote open error.

After OK, TCP bytes are copied bidirectionally until either side exits, then
the stream is half-closed or closed.

## 7. UDP Streams

After a UDP open header, the server validates the target, establishes remote
UDP connectivity or an upstream SOCKS5 UDP association, and writes:

```text
status (u8) | code (u8) | msg_len (BE16) | message bytes ...
```

After OK, UDP packets are framed in both directions.

### Client-to-Server Datagrams

```text
length (BE16) | payload ...
```

The server sends `payload` to the stream's open target.

### Server-to-Client Replies

```text
addr_len (BE16) | addr bytes ... | payload_len (BE16) | payload ...
```

`addr` is the literal `host:port` string of the remote UDP sender. Clients
match replies against the active UDP association.

## 8. Ping Streams

Ping streams measure application RTT through the smux channel:

- The client sends 8 random bytes.
- The server echoes the 8 bytes back.
- The client measures duration until the echo returns.

Ping frames do not use open-status headers; the payload is raw and echoes
immediately after the 4-byte stream open header.

## 9. Local SOCKS5 and HTTP Proxy Behavior

### SOCKS5

- Supports `NO AUTHENTICATION REQUIRED` (`0x00`).
- Supports `CONNECT` (`0x01`) and `UDP ASSOCIATE` (`0x03`).
- Rejects `BIND` with `Command not supported` (`0x07`).
- Binds a dedicated smux stream per TCP connection and per UDP associate.

### HTTP Proxy

- Standard `CONNECT host:port HTTP/1.1` switches to TCP stream tunneling.
- Plain HTTP methods (`GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`) parse
  the absolute URI or `Host` header, open a TCP stream to the origin server,
  forward the modified request, and stream the response. Hop-by-hop headers
  are stripped before forwarding, and forwarded non-CONNECT requests append
  `Via: 1.1 x-tunnel`.

Successful CONNECT returns `HTTP/1.1 200 Connection Established` without
`Content-Length` or `Transfer-Encoding`, then switches to opaque tunnel bytes.

## 10. Risk Map

### Compatibility

- The protocol is v3 with mandatory all-AEAD, ephemeral X25519 forward secrecy,
  and dual transcript authentication. Peers that cannot complete v3
  fail closed instead of silently downgrading.
- The TCP/UDP/Ping data open header is carried inside per-stream AEAD ciphertext
  after v3 `ChannelAccept`.

### Reliability

- TCP/UDP open failures have structured status codes. Mid-stream TCP failures
  are still byte-stream closures rather than structured protocol errors.
- Reconnect timing and major network timeouts are configurable through
  `GlobalConfig`.

### Security

- Tokens are pre-shared secrets used for transcript-bound HMAC proofs and HKDF seed derivation.
- Ephemeral X25519 key exchange guarantees forward secrecy per channel session.
- `ws://` is allowed for local tests and trusted private networks; exposed
  deployments should use `wss://`, source CIDR filtering, and optionally mTLS.
- Server-side egress policy is pre-dial: CIDR rules apply to literal IP targets,
  and host rules apply to literal domain targets before DNS resolution.

## 11. Dual-Stack Transport Architecture (QUIC + TCP/WSS) & RFC 9221 Datagram

### Dual-Stack Selection and Auto-Fallback
- **Modes**: `auto` (default), `quic`, `tcp`.
- **Auto Mode**: Probes QUIC first with a 1.5s fallback deadline (`quicFallbackTimeout`).
- **Host Memory Cache**: Caches connection success/failure per endpoint host. If QUIC fails repeatedly, automatic cooldown prevents redundant connection delays and connects via TCP/WSS directly while probing in the background.
- **Transport Abstraction**: Core v3 authentication and AEAD recording layers operate on top of `transport.TransportSession` and `transport.TransportStream`, cleanly decoupling transport protocols from encryption and application logic.

### RFC 9221 QUIC Datagram Framing
- Format: `AssocID (2B) + PktID (2B) + FragTotal (1B) + FragID (1B) + PayloadLen (2B) + AddrType (1B) + TargetAddr (var) + TargetPort (2B) + Payload (var)`.
- Reassembler: Multi-fragment datagrams are reassembled with bounded capacity and TTL eviction.

### Multi-IP Rotation & Block Detection (P3)
- `EndpointPool` maintains multiple server IPs, monitors connection health, auto-demotes failed IPs with circuit-breaking cooldown, and rotates across available healthy endpoints.

## 12. Evolution Rules

- Keep authentication and capability negotiation on v3 control frames.
- Keep the hot TCP/UDP payload path inside AEAD streams without redundant framing.
- Add tests for exact wire bytes and golden vectors before changing encoders/decoders.
- Prefer explicit rejection over fallback when peers do not support required v3
  behavior.
