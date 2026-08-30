package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtaci/smux"
)

// DefaultSmuxConfig returns standard smux configuration.
func DefaultSmuxConfig() *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.KeepAliveInterval = 10 * time.Second
	cfg.KeepAliveTimeout = 30 * time.Second
	cfg.MaxFrameSize = 32768
	cfg.MaxReceiveBuffer = 4194304
	cfg.MaxStreamBuffer = 1048576
	return cfg
}

// WSNetConn wraps a gorilla websocket.Conn to implement net.Conn.
type WSNetConn struct {
	ws       *websocket.Conn
	readMu   sync.Mutex
	writeMu  sync.Mutex
	reader   io.Reader
	deadCh   chan struct{}
	deadMu   sync.Mutex
	deadErr  error
	deadOnce sync.Once
}

// NewWSNetConn wraps a websocket.Conn into a net.Conn compatible struct.
func NewWSNetConn(ws *websocket.Conn) *WSNetConn {
	return &WSNetConn{
		ws:     ws,
		deadCh: make(chan struct{}),
	}
}

func (c *WSNetConn) signalDead(err error) {
	c.deadOnce.Do(func() {
		c.deadMu.Lock()
		c.deadErr = err
		c.deadMu.Unlock()
		close(c.deadCh)
	})
}

func (c *WSNetConn) DeadErr() error {
	c.deadMu.Lock()
	defer c.deadMu.Unlock()
	return c.deadErr
}

func (c *WSNetConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for {
		if c.reader != nil {
			n, err := c.reader.Read(p)
			if err == nil {
				return n, nil
			}
			if errors.Is(err, io.EOF) {
				c.reader = nil
				if n > 0 {
					return n, nil
				}
				continue
			}
			c.signalDead(err)
			return n, err
		}

		msgType, r, err := c.ws.NextReader()
		if err != nil {
			c.signalDead(err)
			return 0, err
		}
		if msgType != websocket.BinaryMessage {
			continue
		}
		c.reader = r
	}
}

func (c *WSNetConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := c.ws.WriteMessage(websocket.BinaryMessage, p); err != nil {
		c.signalDead(err)
		return 0, err
	}
	return len(p), nil
}

func (c *WSNetConn) Close() error {
	c.signalDead(io.ErrClosedPipe)
	return c.ws.Close()
}

func (c *WSNetConn) LocalAddr() net.Addr {
	if nc := c.ws.UnderlyingConn(); nc != nil {
		return nc.LocalAddr()
	}
	return nil
}

func (c *WSNetConn) RemoteAddr() net.Addr {
	if nc := c.ws.UnderlyingConn(); nc != nil {
		return nc.RemoteAddr()
	}
	return nil
}

func (c *WSNetConn) SetDeadline(t time.Time) error {
	if err := c.ws.SetReadDeadline(t); err != nil {
		return err
	}
	return c.ws.SetWriteDeadline(t)
}

func (c *WSNetConn) SetReadDeadline(t time.Time) error { return c.ws.SetReadDeadline(t) }

func (c *WSNetConn) SetWriteDeadline(t time.Time) error { return c.ws.SetWriteDeadline(t) }

// TcpTransportStream wraps a smux.Stream.
type TcpTransportStream struct {
	stream *smux.Stream
}

func NewTcpTransportStream(stream *smux.Stream) *TcpTransportStream {
	return &TcpTransportStream{stream: stream}
}

func (s *TcpTransportStream) Read(p []byte) (int, error)         { return s.stream.Read(p) }
func (s *TcpTransportStream) Write(p []byte) (int, error)        { return s.stream.Write(p) }
func (s *TcpTransportStream) Close() error                       { return s.stream.Close() }
func (s *TcpTransportStream) ID() uint32                         { return s.stream.ID() }
func (s *TcpTransportStream) SetDeadline(t time.Time) error      { return s.stream.SetDeadline(t) }
func (s *TcpTransportStream) SetReadDeadline(t time.Time) error  { return s.stream.SetReadDeadline(t) }
func (s *TcpTransportStream) SetWriteDeadline(t time.Time) error { return s.stream.SetWriteDeadline(t) }

// RawStream returns underlying smux.Stream if needed.
func (s *TcpTransportStream) RawStream() *smux.Stream { return s.stream }

// TcpTransportSession wraps a smux.Session.
type TcpTransportSession struct {
	session    *smux.Session
	underlying io.Closer
	closeOnce  sync.Once
}

// NewTcpTransportSession wraps a smux.Session into a TransportSession.
func NewTcpTransportSession(sess *smux.Session, underlying io.Closer) *TcpTransportSession {
	return &TcpTransportSession{
		session:    sess,
		underlying: underlying,
	}
}

func (s *TcpTransportSession) Type() TransportType {
	return TransportTypeTCP
}

func (s *TcpTransportSession) OpenStream(ctx context.Context) (TransportStream, error) {
	if s.session.IsClosed() {
		return nil, ErrSessionClosed
	}

	type result struct {
		st  *smux.Stream
		err error
	}
	resCh := make(chan result, 1)

	go func() {
		st, err := s.session.OpenStream()
		resCh <- result{st: st, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-resCh:
		if r.err != nil {
			return nil, r.err
		}
		return NewTcpTransportStream(r.st), nil
	}
}

func (s *TcpTransportSession) AcceptStream(ctx context.Context) (TransportStream, error) {
	if s.session.IsClosed() {
		return nil, ErrSessionClosed
	}

	type result struct {
		st  *smux.Stream
		err error
	}
	resCh := make(chan result, 1)

	go func() {
		st, err := s.session.AcceptStream()
		resCh <- result{st: st, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-resCh:
		if r.err != nil {
			return nil, r.err
		}
		return NewTcpTransportStream(r.st), nil
	}
}

func (s *TcpTransportSession) SendDatagram(payload []byte) error {
	return ErrDatagramNotSupported
}

func (s *TcpTransportSession) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return nil, ErrDatagramNotSupported
}

func (s *TcpTransportSession) LocalAddr() net.Addr {
	return s.session.LocalAddr()
}

func (s *TcpTransportSession) RemoteAddr() net.Addr {
	return s.session.RemoteAddr()
}

func (s *TcpTransportSession) IsClosed() bool {
	return s.session.IsClosed()
}

func (s *TcpTransportSession) Close() error {
	var err error
	s.closeOnce.Do(func() {
		err = s.session.Close()
		if s.underlying != nil {
			_ = s.underlying.Close()
		}
	})
	return err
}

// RawSession returns the underlying smux.Session.
func (s *TcpTransportSession) RawSession() *smux.Session {
	return s.session
}

// TcpTransport implements Transport over WebSocket/TCP + smux.
type TcpTransport struct {
	smuxConfig *smux.Config
}

func NewTcpTransport(smuxCfg *smux.Config) *TcpTransport {
	if smuxCfg == nil {
		smuxCfg = DefaultSmuxConfig()
	}
	return &TcpTransport{smuxConfig: smuxCfg}
}

func (t *TcpTransport) Type() TransportType {
	return TransportTypeTCP
}

func (t *TcpTransport) DialSession(ctx context.Context, rawURL string, opts DialOptions) (TransportSession, error) {
	dialer := websocket.Dialer{
		TLSClientConfig:  opts.TLSConfig,
		HandshakeTimeout: opts.Timeout,
		NetDialContext:   opts.UnderlyingDialer,
	}
	if dialer.HandshakeTimeout == 0 {
		dialer.HandshakeTimeout = 10 * time.Second
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}

	if opts.ServerName != "" && dialer.TLSClientConfig != nil {
		dialer.TLSClientConfig.ServerName = opts.ServerName
	}

	wsConn, _, err := dialer.DialContext(ctx, u.String(), opts.Header)
	if err != nil {
		return nil, fmt.Errorf("websocket dial failed: %w", err)
	}

	wsNet := NewWSNetConn(wsConn)
	sess, err := smux.Client(wsNet, t.smuxConfig)
	if err != nil {
		_ = wsConn.Close()
		return nil, fmt.Errorf("smux.Client failed: %w", err)
	}

	return NewTcpTransportSession(sess, wsNet), nil
}

func (t *TcpTransport) Listen(ctx context.Context, addr string, opts ListenOptions) (TransportListener, error) {
	httpListener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	path := opts.Path
	if path == "" {
		path = "/"
	}

	sessionCh := make(chan TransportSession, 128)
	closeCh := make(chan struct{})

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		wsNet := NewWSNetConn(wsConn)
		sess, err := smux.Server(wsNet, t.smuxConfig)
		if err != nil {
			_ = wsConn.Close()
			return
		}
		transportSess := NewTcpTransportSession(sess, wsNet)
		select {
		case sessionCh <- transportSess:
		case <-closeCh:
			_ = transportSess.Close()
		}
	})

	server := &http.Server{
		Handler:   mux,
		TLSConfig: opts.TLSConfig,
	}

	go func() {
		if opts.TLSConfig != nil {
			_ = server.ServeTLS(httpListener, "", "")
		} else {
			_ = server.Serve(httpListener)
		}
	}()

	return &TcpTransportListener{
		listener:  httpListener,
		server:    server,
		sessionCh: sessionCh,
		closeCh:   closeCh,
	}, nil
}

func (t *TcpTransport) Close() error {
	return nil
}

// TcpTransportListener accepts incoming TcpTransportSessions.
type TcpTransportListener struct {
	listener  net.Listener
	server    *http.Server
	sessionCh chan TransportSession
	closeCh   chan struct{}
	closeOnce sync.Once
}

func (l *TcpTransportListener) AcceptSession(ctx context.Context) (TransportSession, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.closeCh:
		return nil, ErrTransportClosed
	case sess, ok := <-l.sessionCh:
		if !ok {
			return nil, ErrTransportClosed
		}
		return sess, nil
	}
}

func (l *TcpTransportListener) Addr() net.Addr {
	return l.listener.Addr()
}

func (l *TcpTransportListener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		close(l.closeCh)
		err = l.server.Close()
	})
	return err
}
