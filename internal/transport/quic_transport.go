package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	DefaultALPN = "xtunnel-v3"
)

// QuicTransportStream wraps a *quic.Stream to implement TransportStream.
type QuicTransportStream struct {
	stream *quic.Stream
}

func NewQuicTransportStream(stream *quic.Stream) *QuicTransportStream {
	return &QuicTransportStream{stream: stream}
}

func (s *QuicTransportStream) Read(p []byte) (int, error)        { return s.stream.Read(p) }
func (s *QuicTransportStream) Write(p []byte) (int, error)       { return s.stream.Write(p) }
func (s *QuicTransportStream) Close() error                      { return s.stream.Close() }
func (s *QuicTransportStream) ID() uint32                        { return uint32(s.stream.StreamID()) }
func (s *QuicTransportStream) SetDeadline(t time.Time) error     { return s.stream.SetDeadline(t) }
func (s *QuicTransportStream) SetReadDeadline(t time.Time) error { return s.stream.SetReadDeadline(t) }
func (s *QuicTransportStream) SetWriteDeadline(t time.Time) error {
	return s.stream.SetWriteDeadline(t)
}

// RawStream returns the underlying *quic.Stream.
func (s *QuicTransportStream) RawStream() *quic.Stream { return s.stream }

// QuicTransportSession wraps a *quic.Conn to implement TransportSession.
type QuicTransportSession struct {
	conn      *quic.Conn
	closeOnce sync.Once
}

func NewQuicTransportSession(conn *quic.Conn) *QuicTransportSession {
	return &QuicTransportSession{conn: conn}
}

func (s *QuicTransportSession) Type() TransportType {
	return TransportTypeQUIC
}

func (s *QuicTransportSession) OpenStream(ctx context.Context) (TransportStream, error) {
	if s.IsClosed() {
		return nil, ErrSessionClosed
	}
	st, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return NewQuicTransportStream(st), nil
}

func (s *QuicTransportSession) AcceptStream(ctx context.Context) (TransportStream, error) {
	if s.IsClosed() {
		return nil, ErrSessionClosed
	}
	st, err := s.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return NewQuicTransportStream(st), nil
}

func (s *QuicTransportSession) SendDatagram(payload []byte) error {
	if s.IsClosed() {
		return ErrSessionClosed
	}
	return s.conn.SendDatagram(payload)
}

func (s *QuicTransportSession) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if s.IsClosed() {
		return nil, ErrSessionClosed
	}
	return s.conn.ReceiveDatagram(ctx)
}

func (s *QuicTransportSession) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *QuicTransportSession) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

func (s *QuicTransportSession) IsClosed() bool {
	return s.conn.Context().Err() != nil
}

func (s *QuicTransportSession) Close() error {
	var err error
	s.closeOnce.Do(func() {
		err = s.conn.CloseWithError(0, "normal close")
	})
	return err
}

// RawConnection returns the underlying *quic.Conn.
func (s *QuicTransportSession) RawConnection() *quic.Conn {
	return s.conn
}

// QuicTransport implements Transport for IETF QUIC (RFC 9000 + RFC 9221).
type QuicTransport struct{}

func NewQuicTransport() *QuicTransport {
	return &QuicTransport{}
}

func (t *QuicTransport) Type() TransportType {
	return TransportTypeQUIC
}

func (t *QuicTransport) DialSession(ctx context.Context, rawAddr string, opts DialOptions) (TransportSession, error) {
	tlsConf := opts.TLSConfig
	if tlsConf == nil {
		tlsConf = &tls.Config{
			InsecureSkipVerify: true,
		}
	} else {
		tlsConf = tlsConf.Clone()
	}

	if len(tlsConf.NextProtos) == 0 {
		tlsConf.NextProtos = []string{DefaultALPN}
	}

	targetAddr := rawAddr
	// Strip scheme if present (e.g., "https://host:port" or "wss://host:port" -> "host:port")
	if strings.Contains(targetAddr, "://") {
		parts := strings.SplitN(targetAddr, "://", 2)
		targetAddr = parts[1]
	}
	if slashIdx := strings.Index(targetAddr, "/"); slashIdx != -1 {
		targetAddr = targetAddr[:slashIdx]
	}

	host, port, err := net.SplitHostPort(targetAddr)
	if err != nil {
		host = targetAddr
		port = "443"
		targetAddr = net.JoinHostPort(host, port)
	}

	// QUIC 独立监听端口：服务端分端口部署时客户端拨号端口与主端口不同
	if opts.QUICPort > 0 {
		port = strconv.Itoa(opts.QUICPort)
		targetAddr = net.JoinHostPort(host, port)
	}

	if tlsConf.ServerName == "" {
		if opts.ServerName != "" {
			tlsConf.ServerName = opts.ServerName
		} else {
			tlsConf.ServerName = host
		}
	}

	if opts.TargetIP != "" {
		targetAddr = net.JoinHostPort(opts.TargetIP, port)
	}

	maxIdleTimeout := opts.MaxIdleTimeout
	if maxIdleTimeout <= 0 {
		maxIdleTimeout = 30 * time.Second
	}

	keepAlive := opts.KeepAliveInterval
	if keepAlive <= 0 {
		keepAlive = 10 * time.Second
	}

	quicConf := &quic.Config{
		EnableDatagrams:      true,
		MaxIdleTimeout:       maxIdleTimeout,
		KeepAlivePeriod:      keepAlive,
		HandshakeIdleTimeout: opts.Timeout,
	}
	if quicConf.HandshakeIdleTimeout <= 0 {
		quicConf.HandshakeIdleTimeout = 5 * time.Second
	}

	conn, err := quic.DialAddr(ctx, targetAddr, tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("quic.DialAddr failed to %s: %w", targetAddr, err)
	}

	select {
	case <-conn.HandshakeComplete():
		if conn.Context().Err() != nil {
			_ = conn.CloseWithError(0, "handshake failed")
			return nil, fmt.Errorf("quic handshake to %s failed: %w", targetAddr, context.Cause(conn.Context()))
		}
	case <-ctx.Done():
		_ = conn.CloseWithError(0, "timeout")
		return nil, fmt.Errorf("quic handshake to %s timed out: %w", targetAddr, ctx.Err())
	}

	return NewQuicTransportSession(conn), nil
}

func (t *QuicTransport) Listen(ctx context.Context, addr string, opts ListenOptions) (TransportListener, error) {
	if opts.TLSConfig == nil {
		return nil, fmt.Errorf("tls.Config is required for QUIC listener")
	}
	tlsConf := opts.TLSConfig.Clone()
	if len(tlsConf.NextProtos) == 0 {
		tlsConf.NextProtos = []string{DefaultALPN}
	}

	maxIdleTimeout := opts.MaxIdleTimeout
	if maxIdleTimeout <= 0 {
		maxIdleTimeout = 30 * time.Second
	}

	quicConf := &quic.Config{
		EnableDatagrams:    true,
		MaxIdleTimeout:     maxIdleTimeout,
		MaxIncomingStreams: opts.MaxIncomingStreams,
	}

	listener, err := quic.ListenAddr(addr, tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("quic.ListenAddr failed on %s: %w", addr, err)
	}

	return &QuicTransportListener{listener: listener}, nil
}

func (t *QuicTransport) Close() error {
	return nil
}

// QuicTransportListener wraps *quic.Listener.
type QuicTransportListener struct {
	listener  *quic.Listener
	closeOnce sync.Once
}

func (l *QuicTransportListener) AcceptSession(ctx context.Context) (TransportSession, error) {
	conn, err := l.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return NewQuicTransportSession(conn), nil
}

func (l *QuicTransportListener) Addr() net.Addr {
	return l.listener.Addr()
}

func (l *QuicTransportListener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		err = l.listener.Close()
	})
	return err
}
