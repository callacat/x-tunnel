package transport

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// generateSNITestCert 返回 (服务端, 客户端) TLS 配置。证书只对 tunnel.example.com 生效，
// 不含任何 IP SAN：客户端只有用 URL 派生的 ServerName 才能握手通过，
// 一旦 SNI 被改写成拨号 IP（127.0.0.1）测试就会红。
func generateSNITestCert(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tunnel.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"tunnel.example.com"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(&x509.Certificate{Raw: certDER})
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}}},
		&tls.Config{RootCAs: pool}
}

func TestResolveTCPDialTarget(t *testing.T) {
	cases := []struct {
		name     string
		addr     string
		targetIP string
		want     string
	}{
		{"空 TargetIP 原样返回", "host.example.com:443", "", "host.example.com:443"},
		{"IP 补端口", "host.example.com:443", "1.2.3.4", "1.2.3.4:443"},
		{"IP:port 原样", "host.example.com:443", "1.2.3.4:8443", "1.2.3.4:8443"},
		{"域名补端口", "host.example.com:443", "cdn.example.com", "cdn.example.com:443"},
		{"域名:port 原样", "host.example.com:443", "cdn.example.com:8443", "cdn.example.com:8443"},
		{"裸 IPv6 补方括号端口", "host.example.com:443", "2001:db8::1", "[2001:db8::1]:443"},
		{"IPv6:port 原样", "host.example.com:443", "[2001:db8::1]:8443", "[2001:db8::1]:8443"},
		{"addr 缺端口时退回 TargetIP", "1.2.3.4", "5.6.7.8", "5.6.7.8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveTCPDialTarget(tc.addr, tc.targetIP); got != tc.want {
				t.Fatalf("resolveTCPDialTarget(%q, %q) = %q, want %q", tc.addr, tc.targetIP, got, tc.want)
			}
		})
	}
}

func TestTcpTransportTargetIPRedirectsDial(t *testing.T) {
	tcpTr := NewTcpTransport(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listener, err := tcpTr.Listen(ctx, "127.0.0.1:0", ListenOptions{Path: "/test-ws"})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	go serveEcho(ctx, listener)

	// URL 指向死端口 1：若拨号未被重定向到 TargetIP，会被立即拒绝而非连上。
	sess, err := tcpTr.DialSession(ctx, "ws://127.0.0.1:1/test-ws", DialOptions{
		TargetIP: listener.Addr().String(),
	})
	if err != nil {
		t.Fatalf("DialSession 未使用 TargetIP: %v", err)
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
}

func TestTcpTransportTargetIPKeepsSNI(t *testing.T) {
	serverTLS, clientTLS := generateSNITestCert(t)
	tcpTr := NewTcpTransport(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listener, err := tcpTr.Listen(ctx, "127.0.0.1:0", ListenOptions{Path: "/test-ws", TLSConfig: serverTLS})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()
	go drainSessions(ctx, listener)

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	// tunnel.example.com 无 DNS 记录且证书无 IP SAN：
	// 握手通过 == 既完成了重定向拨号，SNI/Host 又仍取自 URL。
	rawURL := "wss://tunnel.example.com:" + port + "/test-ws"

	for _, tc := range []struct{ name, serverName string }{
		{"显式 ServerName（生产形态）", "tunnel.example.com"},
		{"ServerName 留空由 gorilla 从 URL 派生", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sess, err := tcpTr.DialSession(ctx, rawURL, DialOptions{
				TLSConfig:  clientTLS.Clone(),
				ServerName: tc.serverName,
				TargetIP:   listener.Addr().String(),
			})
			if err != nil {
				t.Fatalf("握手失败，SNI/Host 可能被改写成拨号目标: %v", err)
			}
			sess.Close()
		})
	}
}

func TestTcpTransportTargetIPEmptyPreservesDialTarget(t *testing.T) {
	var mu sync.Mutex
	var got string
	sentinel := errors.New("sentinel")

	_, err := NewTcpTransport(nil).DialSession(context.Background(), "ws://tunnel.example.com:8443/test-ws", DialOptions{
		UnderlyingDialer: func(_ context.Context, _, addr string) (net.Conn, error) {
			mu.Lock()
			got = addr
			mu.Unlock()
			return nil, sentinel
		},
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := "tunnel.example.com:8443"; got != want {
		t.Fatalf("TargetIP 为空时拨号目标被改动: got %q, want %q", got, want)
	}
}

func TestSelectorFallbackUsesTargetIP(t *testing.T) {
	serverTLS, clientTLS := generateTestCert(t)
	// generateTestCert 带 QUIC 的 ALPN token，plain WS 升级链路协商它会握手失败，与本用例无关。
	serverTLS.NextProtos, clientTLS.NextProtos = nil, nil
	tcpTr := NewTcpTransport(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listener, err := tcpTr.Listen(ctx, "127.0.0.1:0", ListenOptions{Path: "/ws", TLSConfig: serverTLS})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()
	go serveEcho(ctx, listener)

	// Auto 模式：QUIC 无监听必然失败，回退 TCP 时若忽略 TargetIP 就会打到死端口 1。
	selector := NewTransportSelector(TransportTypeAuto, tcpTr, nil)
	selector.SetFallbackTimeout(500 * time.Millisecond)

	sess, err := selector.DialSession(ctx, "wss://127.0.0.1:1/ws", DialOptions{
		TLSConfig: clientTLS,
		TargetIP:  listener.Addr().String(),
		Timeout:   3 * time.Second,
	})
	if err != nil {
		t.Fatalf("回退 TCP 后未使用 TargetIP: %v", err)
	}
	defer sess.Close()
	if sess.Type() != TransportTypeTCP {
		t.Fatalf("expected TCP fallback, got %s", sess.Type())
	}

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
}

// serveEcho 接受连接并对每条 stream 回一句 PONG，测试只需证明链路通。
func serveEcho(ctx context.Context, l TransportListener) {
	for {
		sess, err := l.AcceptSession(ctx)
		if err != nil {
			return
		}
		go func(s TransportSession) {
			defer s.Close()
			st, err := s.AcceptStream(ctx)
			if err != nil {
				return
			}
			defer st.Close()
			buf := make([]byte, 4)
			if _, err := io.ReadFull(st, buf); err == nil {
				_, _ = st.Write([]byte("PONG"))
			}
		}(sess)
	}
}

// drainSessions 只保持连接存活，用于 SNI 用例（握手成功即断言通过）。
func drainSessions(ctx context.Context, l TransportListener) {
	for {
		sess, err := l.AcceptSession(ctx)
		if err != nil {
			return
		}
		go func(s TransportSession) {
			_, _ = s.AcceptStream(ctx)
			_ = s.Close()
		}(sess)
	}
}
