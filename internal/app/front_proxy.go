package app

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const webSocketFrontProxyTypeHTTPConnect = "http_connect"

type WebSocketFrontProxyConfig struct {
	Enabled     bool              `json:"enabled"`
	Type        string            `json:"type"`
	Server      string            `json:"server"`
	ConnectHost string            `json:"connect_host"`
	Headers     map[string]string `json:"headers"`
}

var websocketFrontProxyConfig WebSocketFrontProxyConfig

func frontProxyEnabled() bool {
	return websocketFrontProxyConfig.Enabled
}

func cloneWebSocketFrontProxyConfig(config WebSocketFrontProxyConfig) WebSocketFrontProxyConfig {
	if len(config.Headers) == 0 {
		config.Headers = nil
		return config
	}
	headers := make(map[string]string, len(config.Headers))
	for k, v := range config.Headers {
		headers[k] = v
	}
	config.Headers = headers
	return config
}

func validateWebSocketFrontProxyConfig(config WebSocketFrontProxyConfig) error {
	if !config.Enabled {
		return nil
	}
	if config.Type != webSocketFrontProxyTypeHTTPConnect {
		return fmt.Errorf("websocket_front_proxy.type 仅支持 %q", webSocketFrontProxyTypeHTTPConnect)
	}
	if strings.TrimSpace(config.Server) == "" {
		return fmt.Errorf("websocket_front_proxy.server 不能为空")
	}
	if err := validateHostPort(config.Server); err != nil {
		return fmt.Errorf("websocket_front_proxy.server 无效: %w", err)
	}
	if config.ConnectHost != "" && !isHTTPHostHeaderValue(config.ConnectHost) {
		return fmt.Errorf("websocket_front_proxy.connect_host 无效")
	}
	for name, value := range config.Headers {
		if err := validateHTTPConnectHeader(name, value); err != nil {
			return err
		}
	}
	return nil
}

func validateHTTPConnectHeader(name, value string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("websocket_front_proxy.headers 包含空 header 名")
	}
	if !isHTTPToken(name) {
		return fmt.Errorf("websocket_front_proxy.headers[%q] header 名无效", name)
	}
	if strings.EqualFold(name, "Host") {
		return fmt.Errorf("websocket_front_proxy.headers 不能设置 Host，请使用 connect_host")
	}
	if containsHTTPHeaderLineBreak(value) {
		return fmt.Errorf("websocket_front_proxy.headers[%q] 不能包含 CR/LF", name)
	}
	return nil
}

func containsHTTPHeaderLineBreak(value string) bool {
	return strings.ContainsAny(value, "\r\n")
}

func isHTTPHostHeaderValue(value string) bool {
	if value == "" || containsHTTPHeaderLineBreak(value) {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c <= 32 || c == 127 {
			return false
		}
		switch c {
		case '/', '\\':
			return false
		}
	}
	return true
}

func isHTTPToken(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func dialWebSocketFrontProxy(ctx context.Context, target string) (net.Conn, error) {
	return dialHTTPConnectFrontProxy(ctx, websocketFrontProxyConfig, target, cfg.DialTimeout, cfg.WSHandshakeTimeout)
}

// dialHTTPConnectFrontProxy 经 HTTP CONNECT 前置代理连到 target。前置代理既可以是
// 隧道服务端自身的 websocket 前置，也可以是任意 HTTP CONNECT 代理（例如百度云代理
// cloudnproxy），只要它接受 CONNECT <target> 并在 200 后做字节透传。
func dialHTTPConnectFrontProxy(ctx context.Context, config WebSocketFrontProxyConfig, target string, dialTimeout, handshakeTimeout time.Duration) (net.Conn, error) {
	if !config.Enabled {
		return nil, fmt.Errorf("websocket front proxy is disabled")
	}
	if err := validateWebSocketFrontProxyConfig(config); err != nil {
		return nil, err
	}
	if strings.TrimSpace(target) == "" {
		return nil, fmt.Errorf("websocket front proxy target is empty")
	}

	dialer := net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", config.Server)
	if err != nil {
		return nil, fmt.Errorf("dial websocket front proxy %s: %w", config.Server, err)
	}
	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()

	deadline := time.Now().Add(handshakeTimeout)
	if handshakeTimeout <= 0 {
		deadline = time.Now().Add(dialTimeout)
	}
	if !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
	}

	host := config.ConnectHost
	if host == "" {
		host = target
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   host,
		Header: make(http.Header, len(config.Headers)),
	}
	for name, value := range config.Headers {
		req.Header.Set(name, value)
	}
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("write websocket front proxy CONNECT: %w", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return nil, fmt.Errorf("read websocket front proxy CONNECT response: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("websocket front proxy CONNECT %s returned status %s", target, resp.Status)
	}
	_ = conn.SetDeadline(time.Time{})
	success = true
	if reader.Buffered() == 0 {
		return conn, nil
	}
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	if c.reader != nil && c.reader.Buffered() > 0 {
		return c.reader.Read(p)
	}
	return c.Conn.Read(p)
}

// CloseWrite 透传给底层连接（隧道透传结束后要半关闭对端，bufferedConn 不能吞掉）。
func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
