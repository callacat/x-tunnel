package app

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"x-tunnel/internal/transport"
)

func TestQuicEndToEndTCPForward(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	const expectedBody = "quic-e2e-payload-data-test\n"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(expectedBody))
	}))
	defer origin.Close()
	targetAddr := strings.TrimPrefix(origin.URL, "http://")

	binPath := buildIntegrationBinary(t, ctx)
	wssAddr := freeTCPAddr(t)
	tcpAddr := freeTCPAddr(t)

	serverLog := t.TempDir() + "/server.log"
	clientLog := t.TempDir() + "/client.log"

	server := startXTunnel(t, ctx, binPath, serverLog,
		"-l", "wss://"+wssAddr+"/tunnel",
		"-token", "quic-secret-token",
		"-cidr", "127.0.0.1/32",
		"-allow-target", "127.0.0.0/8",
	)
	defer stopProcess(server)
	waitTCP(t, ctx, wssAddr, server)
	waitLogContains(t, ctx, serverLog, "QUIC 启动", server)

	client := startXTunnel(t, ctx, binPath, clientLog,
		"-l", "tcp://"+tcpAddr+"/"+targetAddr,
		"-f", "wss://"+wssAddr+"/tunnel",
		"-token", "quic-secret-token",
		"-n", "1",
		"-insecure",
		"-transport", "quic",
	)
	defer stopProcess(client)
	waitTCP(t, ctx, tcpAddr, client)
	waitLogContains(t, ctx, clientLog, "transport=quic", client)

	resp := fetchHTTP(t, "http://"+tcpAddr+"/test")
	assertBody(t, "quic tcp forward", resp, expectedBody)
}

func TestQuicClientChannelUpMetric(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	binPath := buildIntegrationBinary(t, ctx)
	wssAddr := freeTCPAddr(t)
	clientMetricsAddr := freeTCPAddr(t)

	serverLog := t.TempDir() + "/server.log"
	clientLog := t.TempDir() + "/client.log"

	server := startXTunnel(t, ctx, binPath, serverLog,
		"-l", "wss://"+wssAddr+"/tunnel",
		"-token", "quic-metrics-token",
		"-cidr", "127.0.0.1/32",
		"-allow-target", "127.0.0.0/8",
	)
	defer stopProcess(server)
	waitTCP(t, ctx, wssAddr, server)
	waitLogContains(t, ctx, serverLog, "QUIC 启动", server)

	client := startXTunnel(t, ctx, binPath, clientLog,
		"-l", "socks5://"+freeTCPAddr(t),
		"-f", "wss://"+wssAddr+"/tunnel",
		"-token", "quic-metrics-token",
		"-n", "1",
		"-insecure",
		"-transport", "quic",
		"-metrics", clientMetricsAddr,
	)
	defer stopProcess(client)
	waitTCP(t, ctx, clientMetricsAddr, client)
	waitLogContains(t, ctx, clientLog, "就绪 (quic)", client)

	assertMetricValue(t, fetchHTTP(t, "http://"+clientMetricsAddr+"/metrics"), `x_tunnel_client_channel_up{channel="1"}`, "1")
}

func TestDualStackAutoFallback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	const expectedBody = "dual-stack-fallback-data\n"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(expectedBody))
	}))
	defer origin.Close()
	targetAddr := strings.TrimPrefix(origin.URL, "http://")

	binPath := buildIntegrationBinary(t, ctx)
	wsAddr := freeTCPAddr(t)
	tcpAddr := freeTCPAddr(t)

	serverLog := t.TempDir() + "/server-ws.log"
	clientLog := t.TempDir() + "/client-fallback.log"

	// Start plain WS server (no QUIC listener)
	server := startXTunnel(t, ctx, binPath, serverLog,
		"-l", "ws://"+wsAddr+"/tunnel",
		"-token", "fallback-token",
		"-cidr", "127.0.0.1/32",
		"-allow-target", "127.0.0.0/8",
	)
	defer stopProcess(server)
	waitTCP(t, ctx, wsAddr, server)

	// Client with -transport auto should connect to WS successfully
	client := startXTunnel(t, ctx, binPath, clientLog,
		"-l", "tcp://"+tcpAddr+"/"+targetAddr,
		"-f", "ws://"+wsAddr+"/tunnel",
		"-token", "fallback-token",
		"-n", "1",
		"-transport", "auto",
	)
	defer stopProcess(client)
	waitTCP(t, ctx, tcpAddr, client)
	waitLogContains(t, ctx, clientLog, "协议协商成功", client)

	resp := fetchHTTP(t, "http://"+tcpAddr+"/test")
	assertBody(t, "dual stack fallback", resp, expectedBody)
}

func TestQuicDatagramRelayDirect(t *testing.T) {
	// Create echo UDP server
	echoConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer echoConn.Close()

	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := echoConn.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = echoConn.WriteTo(buf[:n], addr)
		}
	}()

	targetPort := echoConn.LocalAddr().(*net.UDPAddr).Port

	// Setup direct server channel with QUIC session
	serverTLS, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverTLS},
		NextProtos:   []string{transport.DefaultALPN},
	}

	quicTr := transport.NewQuicTransport()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listener, err := quicTr.Listen(ctx, "127.0.0.1:0", transport.ListenOptions{
		TLSConfig:       tlsConfig,
		EnableDatagrams: true,
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	serverReady := make(chan struct{})
	var serverSess transport.TransportSession
	go func() {
		sess, err := listener.AcceptSession(ctx)
		if err != nil {
			return
		}
		serverSess = sess
		ch := &WSChannel{
			id:        1,
			transport: sess,
		}
		go handleQuicDatagrams(ch, sess)
		close(serverReady)
	}()
	defer func() {
		if serverSess != nil {
			_ = serverSess.Close()
		}
	}()

	clientSess, err := quicTr.DialSession(ctx, listener.Addr().String(), transport.DialOptions{
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{transport.DefaultALPN},
		},
		EnableDatagrams: true,
	})
	if err != nil {
		t.Fatalf("DialSession: %v", err)
	}
	defer clientSess.Close()

	<-serverReady

	// Send datagram from client
	testMsg := []byte("ping-datagram-test")
	frame := transport.DatagramFrame{
		AssocID:    42,
		PktID:      1,
		AddrType:   transport.AddrTypeIPv4,
		TargetAddr: "127.0.0.1",
		TargetPort: uint16(targetPort),
		Payload:    testMsg,
	}
	encoded, err := transport.EncodeDatagram(frame)
	if err != nil {
		t.Fatalf("EncodeDatagram: %v", err)
	}

	if err := clientSess.SendDatagram(encoded); err != nil {
		t.Fatalf("SendDatagram: %v", err)
	}

	recvCtx, recvCancel := context.WithTimeout(ctx, 3*time.Second)
	defer recvCancel()

	respRaw, err := clientSess.ReceiveDatagram(recvCtx)
	if err != nil {
		t.Fatalf("ReceiveDatagram: %v", err)
	}

	respFrame, err := transport.DecodeDatagram(respRaw)
	if err != nil {
		t.Fatalf("DecodeDatagram: %v", err)
	}

	if respFrame.AssocID != 42 {
		t.Fatalf("AssocID = %d, want 42", respFrame.AssocID)
	}
	if string(respFrame.Payload) != string(testMsg) {
		t.Fatalf("payload = %s, want %s", string(respFrame.Payload), string(testMsg))
	}
}
func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("find free udp port: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

// TestQuicSeparatePortEndToEnd 验证服务端 -quic-port 分端口部署时，
// 客户端通过同名参数将 QUIC 拨号指向独立端口（auto 直接 QUIC 就绪，quic-only 亦可连通）。
func TestQuicSeparatePortEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const expectedBody = "quic-separate-port-e2e\n"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(expectedBody))
	}))
	defer origin.Close()
	targetAddr := strings.TrimPrefix(origin.URL, "http://")

	binPath := buildIntegrationBinary(t, ctx)
	wssAddr := freeTCPAddr(t)
	quicPort := freeUDPPort(t)
	_, wssPort, err := net.SplitHostPort(wssAddr)
	if err != nil {
		t.Fatalf("split wss addr: %v", err)
	}
	quicListenAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(quicPort))
	if strconv.Itoa(quicPort) == wssPort {
		t.Fatalf("quic port conflicts with wss port %s", wssPort)
	}

	serverLog := t.TempDir() + "/server-sep.log"
	server := startXTunnel(t, ctx, binPath, serverLog,
		"-l", "wss://"+wssAddr+"/tunnel",
		"-quic-port", strconv.Itoa(quicPort),
		"-token", "sep-port-token",
		"-cidr", "127.0.0.1/32",
		"-allow-target", "127.0.0.0/8",
	)
	defer stopProcess(server)
	waitTCP(t, ctx, wssAddr, server)
	waitLogContains(t, ctx, serverLog, "QUIC 启动 "+quicListenAddr, server)

	for _, mode := range []string{"auto", "quic"} {
		t.Run(mode, func(t *testing.T) {
			tcpAddr := freeTCPAddr(t)
			clientLog := t.TempDir() + "/client-sep-" + mode + ".log"
			client := startXTunnel(t, ctx, binPath, clientLog,
				"-l", "tcp://"+tcpAddr+"/"+targetAddr,
				"-f", "wss://"+wssAddr+"/tunnel",
				"-quic-port", strconv.Itoa(quicPort),
				"-token", "sep-port-token",
				"-n", "1",
				"-insecure",
				"-transport", mode,
			)
			defer stopProcess(client)
			waitTCP(t, ctx, tcpAddr, client)
			waitLogContains(t, ctx, clientLog, "transport=quic", client)
			waitLogContains(t, ctx, clientLog, "就绪 (quic)", client)

			resp := fetchHTTP(t, "http://"+tcpAddr+"/test")
			assertBody(t, "quic separate port forward", resp, expectedBody)

			raw, err := os.ReadFile(clientLog)
			if err != nil {
				t.Fatalf("read client log: %v", err)
			}
			if strings.Contains(string(raw), "回退至 TCP") {
				t.Fatalf("client fell back to TCP/WSS despite working QUIC port:\n%s", raw)
			}
		})
	}
}
