package app

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestLoadConfigFileAppliesWebSocketFrontProxy(t *testing.T) {
	oldListen, oldForward := listenAddr, forwardAddr
	oldProxy := websocketFrontProxyConfig
	t.Cleanup(func() {
		listenAddr, forwardAddr = oldListen, oldForward
		websocketFrontProxyConfig = oldProxy
	})
	listenAddr, forwardAddr = "", ""
	websocketFrontProxyConfig = WebSocketFrontProxyConfig{}

	path := filepath.Join(t.TempDir(), "client.json")
	raw := `{
		"listen": "socks5://127.0.0.1:11080",
		"forward": "wss://x-tunnel.example.com/tunnel",
		"websocket_front_proxy": {
			"enabled": true,
			"type": "http_connect",
			"server": "cloudnproxy.baidu.com:443",
			"connect_host": "sptest.baidu.com",
			"headers": {
				"X-T5-Auth": "test-auth",
				"User-Agent": "okhttp-test"
			}
		}
	}`
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadConfigFile(path, nil); err != nil {
		t.Fatalf("loadConfigFile returned error: %v", err)
	}
	if !frontProxyEnabled() {
		t.Fatal("front proxy should be enabled")
	}
	if websocketFrontProxyConfig.Type != webSocketFrontProxyTypeHTTPConnect {
		t.Fatalf("front proxy type = %q", websocketFrontProxyConfig.Type)
	}
	if websocketFrontProxyConfig.Server != "cloudnproxy.baidu.com:443" {
		t.Fatalf("front proxy server = %q", websocketFrontProxyConfig.Server)
	}
	if websocketFrontProxyConfig.ConnectHost != "sptest.baidu.com" {
		t.Fatalf("front proxy connect_host = %q", websocketFrontProxyConfig.ConnectHost)
	}
	if got := websocketFrontProxyConfig.Headers["X-T5-Auth"]; got != "test-auth" {
		t.Fatalf("X-T5-Auth = %q", got)
	}
}

func TestValidateWebSocketFrontProxyConfigRejectsInvalidInputs(t *testing.T) {
	base := WebSocketFrontProxyConfig{
		Enabled: true,
		Type:    webSocketFrontProxyTypeHTTPConnect,
		Server:  "proxy.example.com:443",
		Headers: map[string]string{
			"X-T5-Auth": "token",
		},
	}
	tests := []struct {
		name   string
		mutate func(*WebSocketFrontProxyConfig)
	}{
		{name: "unknown type", mutate: func(c *WebSocketFrontProxyConfig) { c.Type = "socks5" }},
		{name: "missing server", mutate: func(c *WebSocketFrontProxyConfig) { c.Server = "" }},
		{name: "invalid server", mutate: func(c *WebSocketFrontProxyConfig) { c.Server = "proxy.example.com" }},
		{name: "host header", mutate: func(c *WebSocketFrontProxyConfig) { c.Headers["Host"] = "blocked.example.com" }},
		{name: "empty header name", mutate: func(c *WebSocketFrontProxyConfig) { c.Headers[""] = "value" }},
		{name: "invalid header name", mutate: func(c *WebSocketFrontProxyConfig) { c.Headers["Bad Header"] = "value" }},
		{name: "header value injection", mutate: func(c *WebSocketFrontProxyConfig) { c.Headers["X-Test"] = "a\r\nb" }},
		{name: "connect host injection", mutate: func(c *WebSocketFrontProxyConfig) { c.ConnectHost = "a\nb" }},
		{name: "connect host whitespace", mutate: func(c *WebSocketFrontProxyConfig) { c.ConnectHost = "bad host" }},
		{name: "connect host path", mutate: func(c *WebSocketFrontProxyConfig) { c.ConnectHost = "example.com/path" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := cloneWebSocketFrontProxyConfig(base)
			tt.mutate(&config)
			if err := validateWebSocketFrontProxyConfig(config); err == nil {
				t.Fatal("validateWebSocketFrontProxyConfig accepted invalid config")
			}
		})
	}
}

func TestDialWebSocketFrontProxyCONNECTRequest(t *testing.T) {
	restore := installTestFrontProxyConfig(t, WebSocketFrontProxyConfig{
		Enabled:     true,
		Type:        webSocketFrontProxyTypeHTTPConnect,
		ConnectHost: "sptest.baidu.com",
		Headers: map[string]string{
			"X-T5-Auth":  "test-auth",
			"User-Agent": "okhttp-test",
		},
	})
	defer restore()

	requests := make(chan string, 1)
	addr, done := serveSingleRawHTTPConnectProxy(t, func(conn net.Conn, raw string) error {
		defer conn.Close()
		requests <- raw
		_, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		return err
	})
	websocketFrontProxyConfig.Server = addr

	conn, err := dialWebSocketFrontProxy(t.Context(), "target.example.com:443")
	if err != nil {
		t.Fatalf("dialWebSocketFrontProxy returned error: %v", err)
	}
	_ = conn.Close()

	raw := <-requests
	if !strings.HasPrefix(raw, "CONNECT target.example.com:443 HTTP/1.1\r\n") {
		t.Fatalf("CONNECT request line = %q", firstLine(raw))
	}
	if !strings.Contains(raw, "\r\nHost: sptest.baidu.com\r\n") {
		t.Fatalf("CONNECT Host header missing from raw request:\n%s", raw)
	}
	if !strings.Contains(raw, "\r\nX-T5-Auth: test-auth\r\n") {
		t.Fatalf("CONNECT X-T5-Auth header missing from raw request:\n%s", raw)
	}
	if !strings.Contains(raw, "\r\nUser-Agent: okhttp-test\r\n") {
		t.Fatalf("CONNECT User-Agent header missing from raw request:\n%s", raw)
	}
	if err := <-done; err != nil {
		t.Fatalf("CONNECT proxy failed: %v", err)
	}
}

func TestDialWebSocketFrontProxyNon200ClosesSocket(t *testing.T) {
	restore := installTestFrontProxyConfig(t, WebSocketFrontProxyConfig{
		Enabled: true,
		Type:    webSocketFrontProxyTypeHTTPConnect,
	})
	defer restore()

	closed := make(chan error, 1)
	addr, done := serveSingleHTTPConnectProxy(t, func(conn net.Conn, _ *http.Request, _ *bufio.Reader) error {
		_, err := io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		if err != nil {
			_ = conn.Close()
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		_, readErr := conn.Read(make([]byte, 1))
		closed <- readErr
		_ = conn.Close()
		return nil
	})
	websocketFrontProxyConfig.Server = addr

	conn, err := dialWebSocketFrontProxy(t.Context(), "target.example.com:443")
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "502 Bad Gateway") {
		t.Fatalf("non-200 CONNECT error = %v", err)
	}
	if readErr := <-closed; readErr != io.EOF {
		t.Fatalf("proxy server read after non-200 = %v, want EOF", readErr)
	}
	if err := <-done; err != nil {
		t.Fatalf("CONNECT proxy failed: %v", err)
	}
}

func TestDialWebSocketFrontProxyPreservesBufferedBytes(t *testing.T) {
	restore := installTestFrontProxyConfig(t, WebSocketFrontProxyConfig{
		Enabled: true,
		Type:    webSocketFrontProxyTypeHTTPConnect,
	})
	defer restore()

	addr, done := serveSingleHTTPConnectProxy(t, func(conn net.Conn, _ *http.Request, _ *bufio.Reader) error {
		_, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\npreface")
		return err
	})
	websocketFrontProxyConfig.Server = addr

	conn, err := dialWebSocketFrontProxy(t.Context(), "target.example.com:443")
	if err != nil {
		t.Fatalf("dialWebSocketFrontProxy returned error: %v", err)
	}
	defer conn.Close()
	buf := make([]byte, len("preface"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read buffered preface: %v", err)
	}
	if string(buf) != "preface" {
		t.Fatalf("buffered bytes = %q", string(buf))
	}
	if err := <-done; err != nil {
		t.Fatalf("CONNECT proxy failed: %v", err)
	}
}

func TestDialWebSocketWithECHThroughFrontProxyWS(t *testing.T) {
	restore := installTestFrontProxyConfig(t, WebSocketFrontProxyConfig{
		Enabled: true,
		Type:    webSocketFrontProxyTypeHTTPConnect,
		Headers: map[string]string{
			"X-T5-Auth": "test-auth",
		},
	})
	defer restore()

	type dialRequest struct {
		host        string
		clientID    string
		channelID   string
		subprotocol string
	}
	requests := make(chan dialRequest, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade websocket: %v", err)
			return
		}
		requests <- dialRequest{
			host:        r.Host,
			clientID:    r.URL.Query().Get("client_id"),
			channelID:   r.URL.Query().Get("channel_id"),
			subprotocol: conn.Subprotocol(),
		}
		_ = conn.Close()
	}))
	defer server.Close()

	addr, done := serveSingleHTTPConnectProxy(t, bridgeCONNECTToTarget)
	websocketFrontProxyConfig.Server = addr

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, err := dialWebSocketWithECH(wsURL, 1, "")
	if err != nil {
		t.Fatalf("dialWebSocketWithECH through front proxy returned error: %v", err)
	}
	_ = conn.Close()

	req := <-requests
	if req.clientID != "" || req.channelID != "" || req.subprotocol != "" {
		t.Fatalf("front proxy dial metadata = %#v, want no v2 query metadata or subprotocol", req)
	}
	if err := <-done; err != nil {
		t.Fatalf("CONNECT proxy failed: %v", err)
	}
}

func TestDialWebSocketWithECHThroughFrontProxyWSSFallback(t *testing.T) {
	restore := installTestFrontProxyConfig(t, WebSocketFrontProxyConfig{
		Enabled: true,
		Type:    webSocketFrontProxyTypeHTTPConnect,
	})
	defer restore()
	oldFallback, oldInsecure := fallback, insecure
	t.Cleanup(func() {
		fallback, insecure = oldFallback, oldInsecure
	})
	fallback = true
	insecure = true

	upgraded := make(chan struct{}, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade websocket: %v", err)
			return
		}
		upgraded <- struct{}{}
		_ = conn.Close()
	}))
	defer server.Close()

	addr, done := serveSingleHTTPConnectProxy(t, bridgeCONNECTToTarget)
	websocketFrontProxyConfig.Server = addr

	wssURL := "wss" + strings.TrimPrefix(server.URL, "https")
	conn, err := dialWebSocketWithECH(wssURL, 1, "")
	if err != nil {
		t.Fatalf("dialWebSocketWithECH wss through front proxy returned error: %v", err)
	}
	_ = conn.Close()

	select {
	case <-upgraded:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for wss websocket upgrade")
	}
	if err := <-done; err != nil {
		t.Fatalf("CONNECT proxy failed: %v", err)
	}
}

func TestDialWebSocketWithECHFrontProxyComposesWithIPOverride(t *testing.T) {
	restore := installTestFrontProxyConfig(t, WebSocketFrontProxyConfig{
		Enabled: true,
		Type:    webSocketFrontProxyTypeHTTPConnect,
	})
	defer restore()

	type proxyRequest struct {
		target string
		host   string
	}
	proxyRequests := make(chan proxyRequest, 1)
	serverRequests := make(chan string, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade websocket: %v", err)
			return
		}
		serverRequests <- r.Host
		_ = conn.Close()
	}))
	defer server.Close()

	addr, done := serveSingleHTTPConnectProxy(t, func(conn net.Conn, req *http.Request, reader *bufio.Reader) error {
		proxyRequests <- proxyRequest{target: req.RequestURI, host: req.Host}
		return bridgeCONNECTToTarget(conn, req, reader)
	})
	websocketFrontProxyConfig.Server = addr

	wsURL := "ws://example.invalid:1/tunnel"
	conn, err := dialWebSocketWithECH(wsURL, 1, server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dialWebSocketWithECH front proxy IP override returned error: %v", err)
	}
	_ = conn.Close()

	proxyReq := <-proxyRequests
	if proxyReq.target != server.Listener.Addr().String() {
		t.Fatalf("CONNECT target = %q, want override %q", proxyReq.target, server.Listener.Addr().String())
	}
	if proxyReq.host != server.Listener.Addr().String() {
		t.Fatalf("CONNECT host = %q, want override %q", proxyReq.host, server.Listener.Addr().String())
	}
	serverHost := <-serverRequests
	if serverHost != "example.invalid:1" {
		t.Fatalf("WebSocket Host = %q, want original forward host", serverHost)
	}
	if err := <-done; err != nil {
		t.Fatalf("CONNECT proxy failed: %v", err)
	}
}

func installTestFrontProxyConfig(t *testing.T, config WebSocketFrontProxyConfig) func() {
	t.Helper()
	oldCfg := cfg
	oldProxy := websocketFrontProxyConfig
	cfg.WSHandshakeTimeout = time.Second
	cfg.DialTimeout = time.Second
	cfg.ReadBuf = 1024
	websocketFrontProxyConfig = cloneWebSocketFrontProxyConfig(config)
	return func() {
		cfg = oldCfg
		websocketFrontProxyConfig = oldProxy
	}
}

func serveSingleHTTPConnectProxy(t *testing.T, handle func(net.Conn, *http.Request, *bufio.Reader) error) (string, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		defer close(done)
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			_ = conn.Close()
			done <- err
			return
		}
		done <- handle(conn, req, reader)
	}()
	t.Cleanup(func() {
		_ = ln.Close()
	})
	return ln.Addr().String(), done
}

func serveSingleRawHTTPConnectProxy(t *testing.T, handle func(net.Conn, string) error) (string, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		defer close(done)
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		reader := bufio.NewReader(conn)
		var raw strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				_ = conn.Close()
				done <- err
				return
			}
			raw.WriteString(line)
			if line == "\r\n" {
				break
			}
		}
		done <- handle(conn, raw.String())
	}()
	t.Cleanup(func() {
		_ = ln.Close()
	})
	return ln.Addr().String(), done
}

func firstLine(raw string) string {
	line, _, _ := strings.Cut(raw, "\r\n")
	return line
}

func bridgeCONNECTToTarget(conn net.Conn, req *http.Request, reader *bufio.Reader) error {
	upstream, err := net.DialTimeout("tcp", req.RequestURI, time.Second)
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		_ = conn.Close()
		return err
	}
	defer upstream.Close()
	defer conn.Close()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return err
	}
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(upstream, reader)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(conn, upstream)
		errCh <- err
	}()
	<-errCh
	_ = conn.Close()
	_ = upstream.Close()
	return nil
}

func TestResolveWebSocketDialTarget(t *testing.T) {
	tests := []struct {
		name    string
		address string
		ip      string
		want    string
	}{
		{name: "direct", address: "example.com:443", want: "example.com:443"},
		{name: "ip only", address: "example.com:443", ip: "127.0.0.1", want: "127.0.0.1:443"},
		{name: "ip with port", address: "example.com:443", ip: "127.0.0.1:8443", want: "127.0.0.1:8443"},
		{name: "ipv6 only", address: "example.com:443", ip: "::1", want: "[::1]:443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHost, gotPort, err := resolveWebSocketDialTarget(context.Background(), tt.address, tt.ip)
			if err != nil {
				t.Fatalf("resolveWebSocketDialTarget returned error: %v", err)
			}
			if got := net.JoinHostPort(gotHost, gotPort); got != tt.want {
				t.Fatalf("resolveWebSocketDialTarget = %q, want %q", got, tt.want)
			}
		})
	}
	if _, _, err := resolveWebSocketDialTarget(context.Background(), "example.com", "127.0.0.1"); err == nil {
		t.Fatal("resolveWebSocketDialTarget accepted address without port")
	}
}

func ExampleWebSocketFrontProxyConfig() {
	config := WebSocketFrontProxyConfig{
		Enabled:     true,
		Type:        webSocketFrontProxyTypeHTTPConnect,
		Server:      "cloudnproxy.baidu.com:443",
		ConnectHost: "sptest.baidu.com",
		Headers: map[string]string{
			"X-T5-Auth": "482857715",
		},
	}
	fmt.Println(config.Enabled, config.Type)
	// Output: true http_connect
}
