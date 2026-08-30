package transport

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	DefaultQUICFallbackTimeout = 1500 * time.Millisecond
	DefaultHostCooldown        = 5 * time.Minute
	MaxConsecutiveFails        = 2
)

// HostStatus tracks connection history for a specific remote host.
type HostStatus struct {
	LastFailTime     time.Time
	ConsecutiveFails int
	Preferred        TransportType
}

// HostMemoryCache stores host-level transport health and fallback state.
type HostMemoryCache struct {
	mu       sync.RWMutex
	hosts    map[string]*HostStatus
	cooldown time.Duration
}

func NewHostMemoryCache(cooldown time.Duration) *HostMemoryCache {
	if cooldown <= 0 {
		cooldown = DefaultHostCooldown
	}
	return &HostMemoryCache{
		hosts:    make(map[string]*HostStatus),
		cooldown: cooldown,
	}
}

func (c *HostMemoryCache) extractHost(rawAddr string) string {
	target := rawAddr
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			target = u.Host
		}
	}
	if host, _, err := net.SplitHostPort(target); err == nil {
		return host
	}
	return target
}

func (c *HostMemoryCache) ShouldTryQUIC(rawAddr string) bool {
	host := c.extractHost(rawAddr)
	c.mu.RLock()
	defer c.mu.RUnlock()

	status, exists := c.hosts[host]
	if !exists {
		return true
	}

	if status.ConsecutiveFails >= MaxConsecutiveFails {
		if time.Since(status.LastFailTime) < c.cooldown {
			return false
		}
	}
	return true
}

func (c *HostMemoryCache) RecordSuccess(rawAddr string, t TransportType) {
	host := c.extractHost(rawAddr)
	c.mu.Lock()
	defer c.mu.Unlock()

	status, exists := c.hosts[host]
	if !exists {
		status = &HostStatus{}
		c.hosts[host] = status
	}
	status.ConsecutiveFails = 0
	status.Preferred = t
}

func (c *HostMemoryCache) RecordFailure(rawAddr string, t TransportType) {
	host := c.extractHost(rawAddr)
	c.mu.Lock()
	defer c.mu.Unlock()

	status, exists := c.hosts[host]
	if !exists {
		status = &HostStatus{}
		c.hosts[host] = status
	}
	status.ConsecutiveFails++
	status.LastFailTime = time.Now()
	if status.ConsecutiveFails >= MaxConsecutiveFails {
		status.Preferred = TransportTypeTCP
	}
}

// TransportSelector provides intelligent multi-transport selection and automatic fallback.
type TransportSelector struct {
	mode            TransportType
	tcpTransport    *TcpTransport
	quicTransport   *QuicTransport
	cache           *HostMemoryCache
	fallbackTimeout time.Duration
}

func NewTransportSelector(mode TransportType, tcp *TcpTransport, quic *QuicTransport) *TransportSelector {
	if mode == "" {
		mode = TransportTypeAuto
	}
	if tcp == nil {
		tcp = NewTcpTransport(nil)
	}
	if quic == nil {
		quic = NewQuicTransport()
	}
	return &TransportSelector{
		mode:            mode,
		tcpTransport:    tcp,
		quicTransport:   quic,
		cache:           NewHostMemoryCache(DefaultHostCooldown),
		fallbackTimeout: DefaultQUICFallbackTimeout,
	}
}

func (s *TransportSelector) Mode() TransportType {
	return s.mode
}

func (s *TransportSelector) SetMode(mode TransportType) {
	s.mode = mode
}

func (s *TransportSelector) SetFallbackTimeout(d time.Duration) {
	if d > 0 {
		s.fallbackTimeout = d
	}
}

func (s *TransportSelector) Cache() *HostMemoryCache {
	return s.cache
}

// DialSession dials a session according to configured mode and fallback policy.
func (s *TransportSelector) DialSession(ctx context.Context, addr string, opts DialOptions) (TransportSession, error) {
	switch s.mode {
	case TransportTypeTCP:
		return s.tcpTransport.DialSession(ctx, addr, opts)
	case TransportTypeQUIC:
		return s.quicTransport.DialSession(ctx, addr, opts)
	case TransportTypeAuto:
		return s.dialAuto(ctx, addr, opts)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedType, s.mode)
	}
}

func (s *TransportSelector) dialAuto(ctx context.Context, addr string, opts DialOptions) (TransportSession, error) {
	if !s.cache.ShouldTryQUIC(addr) {
		log.Printf("[TransportSelector] Host %s QUIC处于冷却期，直连 TCP/WSS", s.cache.extractHost(addr))
		return s.tcpTransport.DialSession(ctx, addr, opts)
	}

	quicTimeout := s.fallbackTimeout
	if opts.Timeout > 0 && opts.Timeout < quicTimeout {
		quicTimeout = opts.Timeout
	}

	quicCtx, quicCancel := context.WithTimeout(ctx, quicTimeout)
	defer quicCancel()

	quicOpts := opts
	quicOpts.Timeout = quicTimeout

	sess, err := s.quicTransport.DialSession(quicCtx, addr, quicOpts)
	if err == nil {
		s.cache.RecordSuccess(addr, TransportTypeQUIC)
		return sess, nil
	}

	// QUIC failed or timed out, record failure and fallback to TCP
	log.Printf("[TransportSelector] QUIC 建连失败 (%v)，回退至 TCP/WSS 保底通道: %s", err, addr)
	s.cache.RecordFailure(addr, TransportTypeQUIC)

	return s.tcpTransport.DialSession(ctx, addr, opts)
}

func (s *TransportSelector) Close() error {
	_ = s.tcpTransport.Close()
	_ = s.quicTransport.Close()
	return nil
}
