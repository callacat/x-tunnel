package app

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

// ======================== round47：SOCKS5 裸 IP:443 SNI 嗅探改写 接线测试 ========================
//
// 端到端验证 handleSOCKS5Connect 对「裸 IP 字面量 + 443」目标的首包 TLS SNI
// 嗅探改写：mock echPool（真实 smux 对，对齐 x_tunnel_test.go 既有写法），
// 在服务端读到 open 头里改写后的 target。ClientHello 用本地最小构造
// （snisniff_test.go 的 helper 属并行子代理，这里独立复制一份，重复无妨）。
//
// 用例覆盖：应答后快发首包改写（真实 hev 行为主路径）/ pipeline 早发同样改写 /
// -sni=false 关闭 / 非 443 端口 / 非 TLS 首包（首包不丢）/ 慢发首包超时（不挂死，
// 回落原 IP）/ 隧道打开失败（SNI 路径已回 0x00，连接被关）。
//
// 关键回归（r47 自查修正）：hev-socks5-core 标准握手是 write_request →
// read_response 之后才 splice TUN 数据，Android tun2socks.yml 未开 pipeline——
// 真实客户端必须先收到 0x00 回复才发 ClientHello。本文件的默认时序即「先读
// 回复再发首包」（realTiming=true）；早年的 pipeline 时序只作为兼容用例保留。

// buildMinTLSClientHello 构造一个最小合法 TLS ClientHello 记录（SNI=host）：
// record type=0x16 + version + record len + handshake(ClientHello + server_name
// 扩展)。字节布局按 RFC 8446 §4.1.2 / §5.1 与 RFC 6066 §3，与 sniffSNI 对齐。
func buildMinTLSClientHello(host string) []byte {
	name := []byte(host)
	// server_name 扩展：type(2) + len(2) + server_name_list(2 + entry)，
	// entry = NameType(1) + len(2) + name。
	entry := append([]byte{0x00, byte(len(name) >> 8), byte(len(name))}, name...)
	snl := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
	ext := append([]byte{0x00, 0x00, byte(len(snl) >> 8), byte(len(snl))}, snl...)

	body := make([]byte, 0, 64)
	body = append(body, 0x03, 0x03)             // client_version: TLS 1.2
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // legacy_session_id: 空
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites: TLS_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00)             // compression_methods: null
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	hs := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := make([]byte, 5+len(hs))
	rec[0] = 0x16               // handshake record type
	rec[1], rec[2] = 0x03, 0x01 // TLS 1.0 record version
	rec[3], rec[4] = byte(len(hs)>>8), byte(len(hs))
	copy(rec[5:], hs)
	return rec
}

type snisniffSOCKS5Case struct {
	name          string
	sniEnabled    bool
	target        string
	payload       []byte
	pipeline      bool          // true=在等 SOCKS5 回复前就写首包（兼容优化型客户端）
	payloadDelay  time.Duration // 读回复后延迟写首包（慢发用例）
	wantTarget    string
	wantFirstByte byte
	wantClosed    bool // true=SNI 路径隧道打开失败：已回 0x00 后连接被关
}

func TestSNISniffRewriteSOCKS5Connect(t *testing.T) {
	hello := buildMinTLSClientHello("www.example.com")
	cases := []snisniffSOCKS5Case{
		{
			name:          "应答后发首包 SNI 命中改写（真实 hev 时序）",
			sniEnabled:    true,
			target:        "203.0.113.10:443", // TEST-NET-3 文档段，避免真连
			payload:       hello,
			wantTarget:    "www.example.com:443",
			wantFirstByte: 0x16,
		},
		{
			name:          "pipeline 早发首包同样命中改写",
			sniEnabled:    true,
			target:        "203.0.113.10:443",
			payload:       hello,
			pipeline:      true,
			wantTarget:    "www.example.com:443",
			wantFirstByte: 0x16,
		},
		{
			name:       "关闭 -sni 保留原 IP",
			sniEnabled: false,
			target:     "203.0.113.10:443",
			payload:    hello,
			wantTarget: "203.0.113.10:443",
		},
		{
			name:       "非 443 端口不嗅探",
			sniEnabled: true,
			target:     "203.0.113.10:8080",
			payload:    hello,
			wantTarget: "203.0.113.10:8080",
		},
		{
			name:          "非 TLS 首包保留原 IP 且首包不丢",
			sniEnabled:    true,
			target:        "203.0.113.10:443",
			payload:       []byte("GET / HTTP/1.1\r\n\r\n"),
			wantTarget:    "203.0.113.10:443",
			wantFirstByte: 'G',
		},
		{
			name:         "慢发首包超时按无 SNI 处理不挂死",
			sniEnabled:   true,
			target:       "203.0.113.10:443",
			payload:      hello,
			payloadDelay: 1200 * time.Millisecond, // 超过 1s 嗅探 deadline
			wantTarget:   "203.0.113.10:443",
		},
		{
			name:       "SNI 路径隧道打开失败连接被关（已回 0x00 无法回错误码）",
			sniEnabled: true,
			target:     "203.0.113.10:443",
			payload:    hello,
			wantTarget: "www.example.com:443",
			wantClosed: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runSNISniffSOCKS5Case(t, tc)
		})
	}
}

func runSNISniffSOCKS5Case(t *testing.T, tc snisniffSOCKS5Case) {
	t.Helper()
	setSNISniff(t, tc.sniEnabled)
	// 分流引擎保持 nil：decideForTarget 恒 proxy（对齐既有 handleSOCKS5Connect 测试）。
	oldEngine := routeRT.engineSnapshot()
	routeRT.setEngine(nil)
	t.Cleanup(func() { routeRT.setEngine(oldEngine) })

	oldPool := echPool
	oldCfg := cfg
	t.Cleanup(func() {
		echPool = oldPool
		cfg = oldCfg
	})
	cfg.DialTimeout = time.Second

	serverSession, clientSession := newProtocolNegotiationSmuxPair(t)
	var openTarget atomic.Value
	// failOpen=true（wantClosed 用例）：服务端模拟隧道打开失败。
	failOpen := tc.wantClosed
	echPool = &ECHPool{
		smuxConns:   []*smux.Session{clientSession},
		channelRTT:  []int64{int64(5 * time.Millisecond)},
		channelCaps: []uint64{protocolCapabilityTCPStatus},
	}

	serverDone := make(chan error, 1)
	go func() {
		stream, err := serverSession.AcceptStream()
		if err != nil {
			serverDone <- fmt.Errorf("AcceptStream: %w", err)
			return
		}
		defer stream.Close()
		_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
		kind, strategy, target, err := readSmuxOpenHeader(stream)
		if err != nil {
			serverDone <- fmt.Errorf("readSmuxOpenHeader: %w", err)
			return
		}
		openTarget.Store(target)
		if kind != streamKindTCP || strategy != IPStrategyDefault {
			serverDone <- fmt.Errorf("open header kind=%d strategy=%d, want TCP/%d", kind, strategy, IPStrategyDefault)
			return
		}
		if failOpen {
			// SNI 路径在 0x00 之后才打开隧道：失败时客户端只看到连接被关。
			_ = writeTCPOpenStatus(stream, tcpOpenStatusError, "mock fail")
			serverDone <- nil
			return
		}
		if target != tc.wantTarget {
			serverDone <- fmt.Errorf("open target = %q, want %q", target, tc.wantTarget)
			return
		}
		if err := writeTCPOpenStatus(stream, tcpOpenStatusOK, ""); err != nil {
			serverDone <- fmt.Errorf("writeTCPOpenStatus: %w", err)
			return
		}
		got := make([]byte, len(tc.payload))
		if _, err := io.ReadFull(stream, got); err != nil {
			serverDone <- fmt.Errorf("read payload: %w", err)
			return
		}
		if tc.wantFirstByte != 0 {
			if got[0] != tc.wantFirstByte {
				serverDone <- fmt.Errorf("payload first byte = 0x%02x, want 0x%02x", got[0], tc.wantFirstByte)
				return
			}
			if !bytes.Equal(got, tc.payload) {
				serverDone <- fmt.Errorf("payload = %q, want %q", got, tc.payload)
				return
			}
		}
		serverDone <- writeAll(stream, []byte("sni-sniff-ok"))
	}()

	// 本地 TCP socketpair（非 net.Pipe）：net.Pipe 零缓冲，pipeline 用例里
	// 「客户端先写首包 + 服务端先写应答」会互等死锁；真实 TCP 的发送缓冲能
	// 同时容纳 10B 应答与首包，TCP socketpair 才能复现真实时序。
	proxyServer, proxyClient, closePair := tcpSocketPair(t)
	defer closePair()
	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		handleSOCKS5Connect(proxyServer, tc.target)
	}()

	// 整个客户端流程包在 5s 超时内：慢发用例验证 peek deadline 语义——
	// 不 panic、不永久阻塞。
	clientErr := make(chan error, 1)
	go func() {
		clientErr <- runSNIClientFlow(proxyClient, tc)
	}()
	select {
	case err := <-clientErr:
		if err != nil {
			t.Fatalf("client flow: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("用例整体超时：5s 内未完成（peek 疑似无 deadline 卡死）")
	}

	if err := <-serverDone; err != nil {
		t.Fatalf("server stream handler: %v", err)
	}
	if !tc.wantClosed {
		if got, _ := openTarget.Load().(string); got != tc.wantTarget {
			t.Fatalf("open target = %q, want %q", got, tc.wantTarget)
		}
	}
	select {
	case <-handlerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for handleSOCKS5Connect shutdown")
	}
}

// runSNIClientFlow 执行 SOCKS5 客户端侧交互。默认时序 = 真实 hev 行为：先读
// 0x00 回复、再发首包（hev-socks5-core 标准握手 read_response 之后才 splice
// TUN 数据；Android tun2socks.yml 未开 pipeline）。pipeline=true 兼容优化型
// 客户端（回复前就发首包）。wantClosed 用例：读完 0x00 后等连接被关（EOF）。
func runSNIClientFlow(client net.Conn, tc snisniffSOCKS5Case) error {
	if tc.pipeline {
		if err := writeAll(client, tc.payload); err != nil {
			return fmt.Errorf("write payload: %w", err)
		}
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		return fmt.Errorf("read SOCKS5 reply: %w", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		return fmt.Errorf("SOCKS5 reply = %v, want success", reply)
	}
	if tc.wantClosed {
		one := make([]byte, 1)
		_, err := client.Read(one)
		if err == nil {
			return fmt.Errorf("wantClosed: 连接未关闭（读到 0x%02x）", one[0])
		}
		return nil
	}
	if tc.payloadDelay > 0 {
		time.Sleep(tc.payloadDelay)
	}
	if !tc.pipeline {
		if err := writeAll(client, tc.payload); err != nil {
			return fmt.Errorf("write payload: %w", err)
		}
	}
	resp := make([]byte, len("sni-sniff-ok"))
	if _, err := io.ReadFull(client, resp); err != nil {
		return fmt.Errorf("read server response: %w", err)
	}
	if string(resp) != "sni-sniff-ok" {
		return fmt.Errorf("server response = %q", resp)
	}
	return nil
}

// tcpSocketPair 建一对环回 TCP 连接（127.0.0.1，内核有发送缓冲）。
func tcpSocketPair(t *testing.T) (net.Conn, net.Conn, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dialDone := make(chan net.Conn, 1)
	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			dialDone <- nil
			return
		}
		dialDone <- c
	}()
	s, err := ln.Accept()
	if err != nil {
		ln.Close()
		t.Fatalf("accept: %v", err)
	}
	d := <-dialDone
	if d == nil {
		s.Close()
		ln.Close()
		t.Fatal("dial failed")
	}
	ln.Close()
	closer := func() {
		s.Close()
		d.Close()
	}
	return s, d, closer
}

func setSNISniff(t *testing.T, v bool) {
	t.Helper()
	old := sniSniff
	sniSniff = v
	t.Cleanup(func() { sniSniff = old })
}
