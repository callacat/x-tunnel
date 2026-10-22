package app

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeCONNECTProxy 起一个最小 HTTP CONNECT 前置代理：读完请求头，回 200 后原样回显。
func fakeCONNECTProxy(t *testing.T, requests chan<- string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				head, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				var raw strings.Builder
				raw.WriteString(head)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					raw.WriteString(line)
					if strings.TrimSpace(line) == "" {
						break
					}
				}
				select {
				case requests <- raw.String():
				default:
				}
				if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
					return
				}
				_, _ = io.Copy(conn, reader)
			}()
		}
	}()
	return listener.Addr().String()
}

func newTestBaiduSocks5Config(proxyAddr string) BaiduSocks5Config {
	return BaiduSocks5Config{
		Listen: "127.0.0.1:0",
		FrontProxy: WebSocketFrontProxyConfig{
			Enabled:     true,
			Type:        webSocketFrontProxyTypeHTTPConnect,
			Server:      proxyAddr,
			ConnectHost: "sptest.baidu.com",
			Headers: map[string]string{
				"X-T5-Auth":  "test-token",
				"User-Agent": "okhttp/3.11.0 test",
			},
		},
	}
}

func TestBaiduSocks5ConnectTunnelsThroughFrontProxy(t *testing.T) {
	requests := make(chan string, 4)
	proxyAddr := fakeCONNECTProxy(t, requests)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	listener, err := startBaiduSocks5(ctx, newTestBaiduSocks5Config(proxyAddr))
	if err != nil {
		t.Fatalf("启动 SOCKS5 失败: %v", err)
	}
	defer listener.Close()

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("连接 SOCKS5 失败: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write([]byte{socks5Version, 0x01, socks5AuthNone}); err != nil {
		t.Fatalf("写方法协商失败: %v", err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		t.Fatalf("读方法协商应答失败: %v", err)
	}
	if method[0] != socks5Version || method[1] != socks5AuthNone {
		t.Fatalf("方法协商应答 = %v，期望 05 00", method)
	}

	host := "example.com"
	request := append([]byte{socks5Version, socks5CmdConnect, 0x00, socks5AddrDomain, byte(len(host))}, []byte(host)...)
	request = append(request, 0x01, 0xbb) // 端口 443
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("写 CONNECT 请求失败: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("读 CONNECT 应答失败: %v", err)
	}
	if reply[0] != socks5Version || reply[1] != socks5ReplySuccess {
		t.Fatalf("CONNECT 应答 = %v，期望 05 00", reply[:2])
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("写载荷失败: %v", err)
	}
	echo := make([]byte, 4)
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatalf("读回显失败: %v", err)
	}
	if string(echo) != "ping" {
		t.Fatalf("回显 = %q，期望 ping", echo)
	}

	select {
	case raw := <-requests:
		if !strings.Contains(raw, "CONNECT example.com:443 HTTP/1.1") {
			t.Fatalf("前置代理收到的请求行不对:\n%s", raw)
		}
		if !strings.Contains(raw, "Host: sptest.baidu.com") {
			t.Fatalf("前置代理收到的 Host 不对:\n%s", raw)
		}
		if !strings.Contains(raw, "X-T5-Auth: test-token") {
			t.Fatalf("前置代理收到的 X-T5-Auth 不对:\n%s", raw)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("前置代理没收到 CONNECT 请求")
	}
}

func TestBaiduSocks5RejectsUDPAssociate(t *testing.T) {
	requests := make(chan string, 1)
	proxyAddr := fakeCONNECTProxy(t, requests)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	listener, err := startBaiduSocks5(ctx, newTestBaiduSocks5Config(proxyAddr))
	if err != nil {
		t.Fatalf("启动 SOCKS5 失败: %v", err)
	}
	defer listener.Close()

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("连接 SOCKS5 失败: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write([]byte{socks5Version, 0x01, socks5AuthNone}); err != nil {
		t.Fatalf("写方法协商失败: %v", err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		t.Fatalf("读方法协商应答失败: %v", err)
	}
	// UDP ASSOCIATE，地址 0.0.0.0:0
	if _, err := conn.Write([]byte{socks5Version, socks5CmdUDPAssociate, 0x00, socks5AddrIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("写 UDP ASSOCIATE 失败: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("读 UDP ASSOCIATE 应答失败: %v", err)
	}
	if reply[1] != socks5ReplyCommandNotSupport {
		t.Fatalf("UDP ASSOCIATE 应答 = %v，期望 05 07", reply[:2])
	}
}

func TestBaiduSocks5RejectsDisabledFrontProxy(t *testing.T) {
	config := newTestBaiduSocks5Config("127.0.0.1:1")
	config.FrontProxy.Enabled = false
	if _, err := newBaiduSocks5Server(config); err == nil {
		t.Fatal("front_proxy.enabled=false 时应当报错")
	}
}

// TestBaiduSocks5ExampleConfigValid 让示例配置保持可解析：examples 顶层的 *.json 走
// x-tunnel 客户端配置 schema，与 baidu-socks5 的 schema 不同，故单独校验。
func TestBaiduSocks5ExampleConfigValid(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "baidu-socks5", "config.json"))
	if err != nil {
		t.Fatalf("读示例配置失败: %v", err)
	}
	var config BaiduSocks5Config
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("示例配置不是合法 JSON: %v", err)
	}
	if _, err := newBaiduSocks5Server(config); err != nil {
		t.Fatalf("示例配置校验失败: %v", err)
	}
}
