package app

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

// recvvlI1JMNbc7 WS 升级头剥离修复回归测试。
//
// 缺陷：HTTP 代理转发普通请求时 stripHTTPProxyHeaders 连 Upgrade/Connection
// 一并剥离（httpHopByHopHeaders 含 Upgrade），经系统代理访问内网 WebSocket
// （webssh）时握手降级为普通 GET → 服务端 404/403。
//
// 修复语义：请求含 Upgrade 头（或 Connection 含 upgrade token）时整段透传
// hop-by-hop 头（仅去 Proxy-Authorization/Proxy-Connection），不加 Via；
// 普通请求的剥离语义（剥 Connection、加 Via）保持不变（既有 POST 全链路
// 测试与 TestSanitizeHTTPProxyRequestClearsCloseState 继续守门）。

const testUpgradeRequestHead = "GET http://ws.example:8081/sessions/ws/terminal/abc HTTP/1.1\r\n" +
	"Host: ws.example:8081\r\n" +
	"Upgrade: websocket\r\n" +
	"Connection: Upgrade\r\n" +
	"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
	"Sec-WebSocket-Version: 13\r\n\r\n"

// readForwardedHead 从上游连接读出完整的请求行+头部（到空行为止）。
func readForwardedHead(t *testing.T, r io.Reader) (string, string) {
	t.Helper()
	br := bufio.NewReader(r)
	requestLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read forwarded request line: %v", err)
	}
	var headers strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read forwarded request header: %v", err)
		}
		if line == "\r\n" {
			break
		}
		headers.WriteString(line)
	}
	return requestLine, headers.String()
}

// TestHandleHTTPUpgradeTunnelPreservesHeaders：隧道（proxy）路径——升级请求
// 到达上游时必须保留 Upgrade/Connection/Sec-WebSocket-* 头，且不加 Via。
func TestHandleHTTPUpgradeTunnelPreservesHeaders(t *testing.T) {
	oldPool := echPool
	oldCfg := cfg
	oldIPStrategy := ipStrategy
	t.Cleanup(func() {
		echPool = oldPool
		cfg = oldCfg
		ipStrategy = oldIPStrategy
	})
	cfg.DialTimeout = time.Second
	ipStrategy = IPStrategyDefault

	serverConn, clientConn := net.Pipe()
	serverSession, err := smux.Server(serverConn, nil)
	if err != nil {
		t.Fatalf("smux server: %v", err)
	}
	clientSession, err := smux.Client(clientConn, nil)
	if err != nil {
		t.Fatalf("smux client: %v", err)
	}
	t.Cleanup(func() {
		serverSession.Close()
		clientSession.Close()
		serverConn.Close()
		clientConn.Close()
	})
	echPool = &ECHPool{
		smuxConns:      []*smux.Session{clientSession},
		channelRTT:     []int64{1},
		channelCaps:    []uint64{currentProtocolCapabilitiesV2()},
		channelKeys:    []V3SessionKeys{testV3Keys},
		channelCiphers: []byte{testV3Cipher},
	}

	accepted := make(chan *smux.Stream, 1)
	acceptErr := make(chan error, 1)
	go func() {
		stream, err := serverSession.AcceptStream()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- stream
	}()

	proxyServer, proxyClient := net.Pipe()
	_ = proxyServer.SetDeadline(time.Now().Add(5 * time.Second))
	_ = proxyClient.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleHTTP(proxyServer, &ProxyConfig{})
	}()

	if err := writeAll(proxyClient, []byte(testUpgradeRequestHead)); err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}

	var serverStream *smux.Stream
	select {
	case serverStream = <-accepted:
	case err := <-acceptErr:
		t.Fatalf("accept smux stream: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for upgrade smux stream")
	}
	defer serverStream.Close()
	csServer, err := newV3CipherStream(serverStream, testV3Keys, testV3Cipher, serverStream.ID(), false)
	if err != nil {
		t.Fatalf("new server cipher stream: %v", err)
	}
	if err := csServer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set server stream deadline: %v", err)
	}
	kind, strategy, target, err := readSmuxOpenHeader(csServer)
	if err != nil {
		t.Fatalf("read upgrade smux header: %v", err)
	}
	if kind != streamKindTCP || strategy != IPStrategyDefault || target != "ws.example:8081" {
		t.Fatalf("upgrade smux header = kind %d strategy %d target %q", kind, strategy, target)
	}
	if err := writeTCPOpenSuccess(csServer, currentProtocolCapabilitiesV2()); err != nil {
		t.Fatalf("write upgrade TCP open status: %v", err)
	}

	_, headers := readForwardedHead(t, csServer)
	// 头名大小写不敏感（Go ReadRequest 会规范化 Sec-WebSocket-Key → Sec-Websocket-Key，
	// RFC 6455 语义等价），双方统一小写比对。
	lower := strings.ToLower(headers)
	for _, want := range []string{
		"Upgrade: websocket\r\n",
		"Connection: Upgrade\r\n",
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
		"Sec-WebSocket-Version: 13\r\n",
	} {
		if !strings.Contains(lower, strings.ToLower(want)) {
			t.Fatalf("forwarded upgrade headers missing %q:\n%s", want, headers)
		}
	}
	if strings.Contains(headers, "Via:") {
		t.Fatalf("upgrade request must not gain Via header:\n%s", headers)
	}

	_ = proxyClient.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for HTTP handler shutdown")
	}
}

// TestHandleHTTPUpgradeDirectPreservesHeaders：DIRECT 路径（现网 webssh 命中的
// 正是这条）——分流命中 direct 后升级请求头同样必须透传到本地直连上游。
func TestHandleHTTPUpgradeDirectPreservesHeaders(t *testing.T) {
	if _, err := newTestRouteEngine(t, "direct,geoip:lan\n"); err != nil {
		t.Fatal(err)
	}

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstream.Close()
	port := upstream.Addr().(*net.TCPAddr).Port

	connCh := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		c, err := upstream.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		connCh <- c
	}()

	proxyServer, proxyClient := net.Pipe()
	_ = proxyServer.SetDeadline(time.Now().Add(5 * time.Second))
	_ = proxyClient.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleHTTP(proxyServer, &ProxyConfig{})
	}()

	req := strings.ReplaceAll(testUpgradeRequestHead, "ws.example:8081", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err := writeAll(proxyClient, []byte(req)); err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}

	var uconn net.Conn
	select {
	case uconn = <-connCh:
	case err := <-acceptErr:
		t.Fatalf("accept upstream: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for direct upstream connection")
	}
	defer uconn.Close()
	if err := uconn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set upstream deadline: %v", err)
	}

	_, headers := readForwardedHead(t, uconn)
	lower := strings.ToLower(headers)
	for _, want := range []string{
		"Upgrade: websocket\r\n",
		"Connection: Upgrade\r\n",
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
	} {
		if !strings.Contains(lower, strings.ToLower(want)) {
			t.Fatalf("direct forwarded upgrade headers missing %q:\n%s", want, headers)
		}
	}

	// 上游模拟服务端回 101，客户端（代理对端）应原样收到。
	if _, err := io.WriteString(uconn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		t.Fatalf("write 101: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(proxyClient), nil)
	if err != nil {
		t.Fatalf("read 101 response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("response status = %d, want 101", resp.StatusCode)
	}

	_ = proxyClient.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for HTTP handler shutdown")
	}
}

// TestIsHTTPUpgradeRequest：判定函数单测（Upgrade 头 / Connection token / 普通请求）。
func TestIsHTTPUpgradeRequest(t *testing.T) {
	upgradeHeader := http.Header{"Upgrade": []string{"websocket"}, "Connection": []string{"Upgrade"}}
	connectionToken := http.Header{"Connection": []string{"keep-alive, Upgrade"}}
	normal := http.Header{"Connection": []string{"keep-alive"}}
	empty := http.Header{}

	if !isHTTPUpgradeRequest(upgradeHeader) {
		t.Fatal("Upgrade header not detected")
	}
	if !isHTTPUpgradeRequest(connectionToken) {
		t.Fatal("Connection upgrade token not detected")
	}
	if isHTTPUpgradeRequest(normal) {
		t.Fatal("normal keep-alive misdetected as upgrade")
	}
	if isHTTPUpgradeRequest(empty) {
		t.Fatal("empty header misdetected as upgrade")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
