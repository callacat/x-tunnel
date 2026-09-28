package transport

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// dialTargetForms 是 -ip 的全部合法形态（与 config.validateDialIPOverride 一致），
// QUIC 与 TCP 必须解析出完全相同的实拨地址。
var dialTargetForms = []struct {
	name     string
	targetIP string
	want     string
}{
	{"IP:port", "1.2.3.4:8443", "1.2.3.4:8443"},
	{"裸 IP", "1.2.3.4", "1.2.3.4:443"},
	{"裸 IPv6", "2001:db8::1", "[2001:db8::1]:443"},
	{"IPv6:port", "[2001:db8::1]:8443", "[2001:db8::1]:8443"},
	{"域名:port", "example.com:8443", "example.com:8443"},
	{"裸域名", "example.com", "example.com:443"},
}

func TestResolveQUICDialTarget(t *testing.T) {
	cases := []struct {
		name     string
		rawAddr  string
		targetIP string
		quicPort int
		wantAddr string
		wantHost string
	}{
		{"无 -ip 走原地址", "wss://tunnel.example.com:8443/ws", "", 0, "tunnel.example.com:8443", "tunnel.example.com"},
		{"无端口补 443", "tunnel.example.com", "", 0, "tunnel.example.com:443", "tunnel.example.com"},
		{"QUICPort 覆盖原端口", "tunnel.example.com:443", "", 8443, "tunnel.example.com:8443", "tunnel.example.com"},
		{"-ip 形态全集", "tunnel.example.com:443", "1.2.3.4:8443", 0, "1.2.3.4:8443", "tunnel.example.com"},
		{"-ip 带端口压过 QUICPort", "tunnel.example.com:443", "1.2.3.4:9443", 8443, "1.2.3.4:9443", "tunnel.example.com"},
		{"-ip 不带端口沿用 QUICPort", "tunnel.example.com:443", "1.2.3.4", 8443, "1.2.3.4:8443", "tunnel.example.com"},
		{"裸 IPv6 原址不被二次加括号", "[2001:db8::1]", "", 0, "[2001:db8::1]:443", "2001:db8::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, host := resolveQUICDialTarget(tc.rawAddr, tc.targetIP, tc.quicPort)
			if addr != tc.wantAddr {
				t.Fatalf("addr = %q, want %q", addr, tc.wantAddr)
			}
			if host != tc.wantHost {
				t.Fatalf("SNI host = %q, want %q", host, tc.wantHost)
			}
			assertNoIllegalHostPort(t, addr)
		})
	}

	for _, f := range dialTargetForms {
		t.Run(f.name, func(t *testing.T) {
			addr, host := resolveQUICDialTarget("wss://tunnel.example.com:443/ws", f.targetIP, 0)
			if addr != f.want {
				t.Fatalf("resolveQUICDialTarget(%q) = %q, want %q", f.targetIP, addr, f.want)
			}
			if host != "tunnel.example.com" {
				t.Fatalf("-ip 污染了 SNI host: %q", host)
			}
			assertNoIllegalHostPort(t, addr)
		})
	}
}

// TestQuicAndTCPResolveTargetIPIdentically 锁定「同一 -ip 在 QUIC/TCP 两侧语义一致」。
func TestQuicAndTCPResolveTargetIPIdentically(t *testing.T) {
	const tcpAddr = "tunnel.example.com:443" // gorilla 按 scheme 补默认端口后交给 resolveDialTarget
	for _, f := range dialTargetForms {
		t.Run(f.name, func(t *testing.T) {
			quicAddr, _ := resolveQUICDialTarget(tcpAddr, f.targetIP, 0)
			if tcpAddrGot := resolveDialTarget(tcpAddr, f.targetIP); quicAddr != tcpAddrGot {
				t.Fatalf("-ip %q 两侧不一致: QUIC=%q TCP=%q", f.targetIP, quicAddr, tcpAddrGot)
			}
		})
	}
}

// assertNoIllegalHostPort 拦住 net.JoinHostPort 误把 IP:port 整体当 host 拼出的
// "[1.2.3.4:8443]:443" 形态：合法 host 要么无冒号，要么是已加方括号的 IPv6。
func assertNoIllegalHostPort(t *testing.T, addr string) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("非法地址 %q: %v", addr, err)
	}
	if port == "" {
		t.Fatalf("地址 %q 缺端口", addr)
	}
	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		return // 合法 IP 字面量（IPv6 带不带方括号都由 SplitHostPort 归一）
	}
	if strings.ContainsAny(host, "[]:") {
		t.Fatalf("地址 %q 把 host:port 整体当 host 拼出非法形态", addr)
	}
}

// TestQuicTransportTargetIPRedirectsDial 端到端：rawAddr 打死端口，-ip 指向真实 QUIC 监听。
func TestQuicTransportTargetIPRedirectsDial(t *testing.T) {
	serverTLS, clientTLS := generateTestCert(t)
	quicTr := NewQuicTransport()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listener, err := quicTr.Listen(ctx, "127.0.0.1:0", ListenOptions{TLSConfig: serverTLS})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		sess, err := listener.AcceptSession(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		st, err := sess.AcceptStream(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(st, buf); err != nil {
			serverDone <- err
			return
		}
		if string(buf) != "PING" {
			t.Errorf("expected PING, got %s", string(buf))
		}
		_, err = st.Write([]byte("PONG"))
		serverDone <- err
	}()

	// 端口 1 上的 rawAddr 不可达，握手成功即证明实拨地址取自 -ip 且带得动端口。
	sess, err := quicTr.DialSession(ctx, "127.0.0.1:1", DialOptions{
		TLSConfig: clientTLS,
		TargetIP:  listener.Addr().String(),
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("QUIC 拨号未使用 -ip: %v", err)
	}
	defer sess.Close()

	st, err := sess.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer st.Close()
	if _, err := st.Write([]byte("PING")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf) != "PONG" {
		t.Fatalf("expected PONG, got %s", string(buf))
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server error: %v", err)
	}
}
