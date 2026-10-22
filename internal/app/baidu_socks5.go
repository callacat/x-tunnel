package app

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// baidu-socks5：本地 SOCKS5 服务端，每个 CONNECT 请求经「HTTP CONNECT 前置代理」
// （百度云代理 cloudnproxy）出网。替代独立件 baidu（CT103 /root/baidu/baidu）的
// :10811 角色：同样的前置代理、同样的 CONNECT 模板，出口由百度云决定。
//
// 只实现 CONNECT：前置代理是纯 TCP 隧道，UDP ASSOCIATE 无从承载（现网独立件对
// UDP ASSOCIATE 回 0x07 command not supported，行为一致）。

const (
	socks5Version = 0x05

	socks5AuthNone   = 0x00
	socks5AuthNoneOK = 0xff

	socks5CmdConnect      = 0x01
	socks5CmdUDPAssociate = 0x03

	socks5ReplySuccess           = 0x00
	socks5ReplyGeneralFailure    = 0x01
	socks5ReplyCommandNotSupport = 0x07

	socks5AddrIPv4   = 0x01
	socks5AddrDomain = 0x03
	socks5AddrIPv6   = 0x04
)

// BaiduSocks5Config 是 baidu-socks5 服务的配置。
type BaiduSocks5Config struct {
	Listen           string                    `json:"listen"`
	DialTimeout      string                    `json:"dial_timeout"`
	HandshakeTimeout string                    `json:"handshake_timeout"`
	FrontProxy       WebSocketFrontProxyConfig `json:"front_proxy"`
}

type baiduSocks5Server struct {
	listen           string
	dialTimeout      time.Duration
	handshakeTimeout time.Duration
	frontProxy       WebSocketFrontProxyConfig
}

// RunBaiduSocks5 启动 SOCKS5 服务并阻塞，直到 ctx 取消。
func RunBaiduSocks5(ctx context.Context, config BaiduSocks5Config) error {
	listener, err := startBaiduSocks5(ctx, config)
	if err != nil {
		return err
	}
	<-ctx.Done()
	return listener.Close()
}

// startBaiduSocks5 监听并返回 listener（测试用：拿到实际监听地址）。
func startBaiduSocks5(ctx context.Context, config BaiduSocks5Config) (net.Listener, error) {
	server, err := newBaiduSocks5Server(config)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", server.listen)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 监听失败 %s: %w", server.listen, err)
	}
	log.Printf("[baidu-socks5] SOCKS5 监听 %s，前置代理 %s", listener.Addr(), server.frontProxy.Server)

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				log.Printf("[baidu-socks5] accept 失败: %v", err)
				continue
			}
			go server.handle(conn)
		}
	}()
	return listener, nil
}

func newBaiduSocks5Server(config BaiduSocks5Config) (*baiduSocks5Server, error) {
	listen := strings.TrimSpace(config.Listen)
	if listen == "" {
		listen = "0.0.0.0:10811"
	}
	if !config.FrontProxy.Enabled {
		return nil, errors.New("front_proxy.enabled 必须为 true")
	}
	if err := validateWebSocketFrontProxyConfig(config.FrontProxy); err != nil {
		return nil, err
	}
	dialTimeout, err := parseBaiduSocks5Duration(config.DialTimeout, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial_timeout: %w", err)
	}
	handshakeTimeout, err := parseBaiduSocks5Duration(config.HandshakeTimeout, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("handshake_timeout: %w", err)
	}
	return &baiduSocks5Server{
		listen:           listen,
		dialTimeout:      dialTimeout,
		handshakeTimeout: handshakeTimeout,
		frontProxy:       config.FrontProxy,
	}, nil
}

func parseBaiduSocks5Duration(value string, fallback time.Duration) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}
	if duration <= 0 {
		return 0, errors.New("时长必须为正")
	}
	return duration, nil
}

func (s *baiduSocks5Server) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.handshakeTimeout))

	method, err := s.negotiateAuth(conn)
	if err != nil {
		log.Printf("[baidu-socks5] %s 认证协商失败: %v", conn.RemoteAddr(), err)
		return
	}
	if method == socks5AuthNoneOK {
		return
	}

	cmd, target, err := readSOCKS5Request(conn)
	if err != nil {
		log.Printf("[baidu-socks5] %s 请求解析失败: %v", conn.RemoteAddr(), err)
		return
	}
	if cmd != socks5CmdConnect {
		_ = writeSOCKS5Reply(conn, socks5ReplyCommandNotSupport)
		log.Printf("[baidu-socks5] %s 不支持的命令 0x%02x", conn.RemoteAddr(), cmd)
		return
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), s.dialTimeout+s.handshakeTimeout)
	defer cancel()
	upstream, err := dialHTTPConnectFrontProxy(dialCtx, s.frontProxy, target, s.dialTimeout, s.handshakeTimeout)
	if err != nil {
		_ = writeSOCKS5Reply(conn, socks5ReplyGeneralFailure)
		log.Printf("[baidu-socks5] %s 连接 %s 失败: %v", conn.RemoteAddr(), target, err)
		return
	}
	defer upstream.Close()

	if err := writeSOCKS5Reply(conn, socks5ReplySuccess); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	proxyStream(conn, upstream)
}

// negotiateAuth 走 RFC1928 方法协商：只接受「不需要认证」，其余一律回 0xff。
func (s *baiduSocks5Server) negotiateAuth(conn net.Conn) (byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, err
	}
	if header[0] != socks5Version {
		return 0, fmt.Errorf("SOCKS 版本非法 0x%02x", header[0])
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, err
	}
	for _, method := range methods {
		if method == socks5AuthNone {
			if err := writeSOCKS5MethodSelection(conn, socks5AuthNone); err != nil {
				return 0, err
			}
			return socks5AuthNone, nil
		}
	}
	_ = writeSOCKS5MethodSelection(conn, socks5AuthNoneOK)
	return socks5AuthNoneOK, fmt.Errorf("客户端不支持免认证（提供了 %v）", methods)
}

// readSOCKS5Request 读一条 SOCKS5 请求，返回命令与 target（host:port）。
func readSOCKS5Request(conn net.Conn) (byte, string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, "", err
	}
	if header[0] != socks5Version {
		return 0, "", fmt.Errorf("SOCKS 版本非法 0x%02x", header[0])
	}
	cmd := header[1]
	atyp := header[3]

	var host string
	switch atyp {
	case socks5AddrIPv4:
		buf := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return 0, "", err
		}
		host = net.IP(buf).String()
	case socks5AddrIPv6:
		buf := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return 0, "", err
		}
		host = net.IP(buf).String()
	case socks5AddrDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return 0, "", err
		}
		buf := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return 0, "", err
		}
		host = string(buf)
	default:
		return 0, "", fmt.Errorf("地址类型非法 0x%02x", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return 0, "", err
	}
	port := binary.BigEndian.Uint16(portBuf)
	return cmd, net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// proxyStream 双向透传，结束后半关闭对端。
func proxyStream(client net.Conn, upstream net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, client)
		closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
		closeWrite(client)
	}()
	wg.Wait()
}

func closeWrite(conn net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = conn.Close()
}
