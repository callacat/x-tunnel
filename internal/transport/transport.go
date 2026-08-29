package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

var (
	ErrDatagramNotSupported = errors.New("transport: datagram not supported")
	ErrSessionClosed        = errors.New("transport: session closed")
	ErrStreamClosed         = errors.New("transport: stream closed")
	ErrTransportClosed      = errors.New("transport: transport closed")
	ErrUnsupportedType      = errors.New("transport: unsupported transport type")
)

type TransportType string

const (
	TransportTypeTCP  TransportType = "tcp"
	TransportTypeQUIC TransportType = "quic"
	TransportTypeAuto TransportType = "auto"
)

// DialOptions contains options for dialing a transport session.
type DialOptions struct {
	TLSConfig         *tls.Config
	ServerName        string
	Path              string
	Header            http.Header
	TargetIP          string
	Timeout           time.Duration
	KeepAliveInterval time.Duration
	MaxIdleTimeout    time.Duration
	EnableDatagrams   bool
	UnderlyingDialer  func(ctx context.Context, network, addr string) (net.Conn, error)
}

// ListenOptions contains options for listening for transport sessions.
type ListenOptions struct {
	TLSConfig          *tls.Config
	Path               string
	MaxIdleTimeout     time.Duration
	MaxIncomingStreams int64
	EnableDatagrams    bool
}

// Transport provides dialing and listening capabilities for a specific transport protocol.
type Transport interface {
	Type() TransportType
	DialSession(ctx context.Context, addr string, opts DialOptions) (TransportSession, error)
	Listen(ctx context.Context, addr string, opts ListenOptions) (TransportListener, error)
	Close() error
}

// TransportListener accepts incoming transport sessions.
type TransportListener interface {
	AcceptSession(ctx context.Context) (TransportSession, error)
	Addr() net.Addr
	Close() error
}

// TransportSession represents a multiplexed session (TCP/smux or QUIC).
type TransportSession interface {
	Type() TransportType
	OpenStream(ctx context.Context) (TransportStream, error)
	AcceptStream(ctx context.Context) (TransportStream, error)
	SendDatagram(payload []byte) error
	ReceiveDatagram(ctx context.Context) ([]byte, error)
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	IsClosed() bool
	Close() error
}

// TransportStream represents an individual bidirectional multiplexed stream within a session.
type TransportStream interface {
	io.ReadWriteCloser
	ID() uint32
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}
