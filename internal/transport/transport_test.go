package transport

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func generateTestCert(t *testing.T) (*tls.Config, *tls.Config) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "127.0.0.1",
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{DefaultALPN},
	}
	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{DefaultALPN},
	}
	return serverTLS, clientTLS
}

func TestTcpTransport(t *testing.T) {
	tcpTr := NewTcpTransport(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listener, err := tcpTr.Listen(ctx, "127.0.0.1:0", ListenOptions{
		Path: "/test-ws",
	})
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
		defer sess.Close()

		st, err := sess.AcceptStream(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		defer st.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadFull(st, buf); err != nil {
			serverDone <- err
			return
		}
		if string(buf) != "PING" {
			t.Errorf("expected PING, got %s", string(buf))
		}
		if _, err := st.Write([]byte("PONG")); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
	}()

	addr := "ws://" + listener.Addr().String() + "/test-ws"
	sess, err := tcpTr.DialSession(ctx, addr, DialOptions{})
	if err != nil {
		t.Fatalf("DialSession: %v", err)
	}
	defer sess.Close()

	if sess.Type() != TransportTypeTCP {
		t.Errorf("expected TCP type, got %s", sess.Type())
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

	if err := <-serverDone; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

func TestQuicTransport(t *testing.T) {
	serverTLS, clientTLS := generateTestCert(t)
	quicTr := NewQuicTransport()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listener, err := quicTr.Listen(ctx, "127.0.0.1:0", ListenOptions{
		TLSConfig: serverTLS,
	})
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
		if _, err := st.Write([]byte("PONG")); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
	}()

	addr := listener.Addr().String()
	sess, err := quicTr.DialSession(ctx, addr, DialOptions{
		TLSConfig: clientTLS,
	})
	if err != nil {
		t.Fatalf("DialSession: %v", err)
	}
	defer sess.Close()

	if sess.Type() != TransportTypeQUIC {
		t.Errorf("expected QUIC type, got %s", sess.Type())
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

	if err := <-serverDone; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

func TestTransportSelectorFallback(t *testing.T) {
	// Start a TCP listener only (no QUIC listener)
	tcpTr := NewTcpTransport(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tcpListener, err := tcpTr.Listen(ctx, "127.0.0.1:0", ListenOptions{
		Path: "/ws",
	})
	if err != nil {
		t.Fatalf("tcp Listen: %v", err)
	}
	defer tcpListener.Close()

	go func() {
		sess, err := tcpListener.AcceptSession(ctx)
		if err != nil {
			return
		}
		defer sess.Close()
		st, err := sess.AcceptStream(ctx)
		if err != nil {
			return
		}
		defer st.Close()
		buf := make([]byte, 4)
		_, _ = io.ReadFull(st, buf)
		_, _ = st.Write([]byte("PONG"))
	}()

	// Selector in Auto mode should try QUIC, fail quickly, and fallback to TCP
	selector := NewTransportSelector(TransportTypeAuto, tcpTr, nil)
	selector.SetFallbackTimeout(300 * time.Millisecond)

	wsAddr := "ws://" + tcpListener.Addr().String() + "/ws"
	sess, err := selector.DialSession(ctx, wsAddr, DialOptions{})
	if err != nil {
		t.Fatalf("DialSession fallback failed: %v", err)
	}
	defer sess.Close()

	if sess.Type() != TransportTypeTCP {
		t.Fatalf("expected fallback to TCP, got %s", sess.Type())
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

func TestEndpointPool(t *testing.T) {
	pool := NewEndpointPool([]string{"1.1.1.1", "2.2.2.2"}, 2, 500*time.Millisecond)

	ep1, err := pool.SelectNext()
	if err != nil {
		t.Fatalf("SelectNext: %v", err)
	}
	ep2, err := pool.SelectNext()
	if err != nil {
		t.Fatalf("SelectNext: %v", err)
	}
	if ep1 == ep2 {
		t.Fatalf("expected round robin between two endpoints")
	}

	// Mark ep1 as failed twice (reaching threshold)
	pool.RecordResult(ep1, false, 0)
	pool.RecordResult(ep1, false, 0)

	if pool.HealthyCount() != 1 {
		t.Fatalf("expected 1 healthy endpoint, got %d", pool.HealthyCount())
	}

	// Next selections should all give ep2
	for i := 0; i < 3; i++ {
		selected, err := pool.SelectNext()
		if err != nil {
			t.Fatalf("SelectNext: %v", err)
		}
		if selected != ep2 {
			t.Fatalf("expected ep2, got %s", selected)
		}
	}
}
