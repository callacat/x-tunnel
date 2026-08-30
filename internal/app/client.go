package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/xtaci/smux"
	"x-tunnel/internal/transport"
)

// defaultCipherPreference defines the default client cipher suite preference list.
// Future versions may allow runtime or config override.
var defaultCipherPreference = []byte{
	protocolCipherChaCha20Poly1305,
	protocolCipherAES256GCM,
	protocolCipherAES128GCM,
}

// clientTAI64NState guards the process-wide monotonically increasing TAI64N
// timestamp source used by client handshakes. Parallel channels must never
// emit duplicate or out-of-order timestamps.
var clientTAI64NState struct {
	sync.Mutex
	lastNano int64
}

// nextClientTAI64N returns the next strictly monotonically increasing TAI64N
// timestamp for client handshakes: result = max(last+1ns, now). Safe for
// concurrent use.
func nextClientTAI64N() []byte {
	now := time.Now().UnixNano()
	clientTAI64NState.Lock()
	if now <= clientTAI64NState.lastNano {
		now = clientTAI64NState.lastNano + 1
	}
	clientTAI64NState.lastNano = now
	clientTAI64NState.Unlock()
	return encodeTAI64N(time.Unix(0, now))
}

// clientAuthHintThreshold is the number of consecutive handshake failures
// after which the client logs a hint that the token may be wrong or the
// protocol incompatible. Retries stay silent up to the threshold, and the
// server-side silent-drop behavior is unchanged.
const clientAuthHintThreshold = 5

// clientAuthFailureHint returns a user-visible hint message when the given
// consecutive handshake failure count hits the threshold (or a multiple of
// it), and an empty string otherwise.
func clientAuthFailureHint(consecutiveFailures int) string {
	if consecutiveFailures > 0 && consecutiveFailures%clientAuthHintThreshold == 0 {
		return fmt.Sprintf("已连续 %d 次握手失败，可能是 token 错误或协议不兼容（请检查 token 与服务端版本）", consecutiveFailures)
	}
	return ""
}

// clientHandshakeFailureTracker counts consecutive handshake failures for one
// channel. It is reset on success.
type clientHandshakeFailureTracker struct {
	consecutive int
}

// recordFailure increments the failure count and reports whether the hint
// threshold has been hit.
func (t *clientHandshakeFailureTracker) recordFailure() bool {
	t.consecutive++
	return t.consecutive%clientAuthHintThreshold == 0
}

// recordSuccess resets the consecutive failure count.
func (t *clientHandshakeFailureTracker) recordSuccess() {
	t.consecutive = 0
}

type ECHPool struct {
	wsServerAddr  string
	connectionNum int
	targetIPs     []string
	clientID      string

	wsConnsMu         sync.RWMutex
	transportSessions []transport.TransportSession
	smuxConns         []*smux.Session
	channelRTT        []int64
	channelCaps       []uint64
	channelKeys       []V3SessionKeys
	channelCiphers    []byte
	selectCounter     uint64
	selector          *transport.TransportSelector
	endpointPool      *transport.EndpointPool
	coverTraffic      bool

	// Snapshot of process-global client config, captured at construction so
	// reconnect goroutines never read package-level variables that another
	// Engine instance may overwrite (data race under parallel tests).
	tlsInsecure    bool
	clientCertFile string
	clientKeyFile  string
	quicPort       int
	enableDatagram bool
}

func (p *ECHPool) channelV3Security(idx int) (V3SessionKeys, byte, bool) {
	p.wsConnsMu.RLock()
	defer p.wsConnsMu.RUnlock()
	if idx < 0 || idx >= len(p.channelKeys) {
		return V3SessionKeys{}, 0, false
	}
	return p.channelKeys[idx], p.channelCiphers[idx], true
}

func NewECHPool(addr string, n int, ips []string, clientID string) *ECHPool {
	total := n
	if len(ips) > 0 {
		total = len(ips) * n
	}
	p := &ECHPool{
		wsServerAddr:      addr,
		connectionNum:     n,
		targetIPs:         ips,
		clientID:          clientID,
		transportSessions: make([]transport.TransportSession, total),
		smuxConns:         make([]*smux.Session, total),
		channelRTT:        make([]int64, total),
		channelCaps:       make([]uint64, total),
		channelKeys:       make([]V3SessionKeys, total),
		channelCiphers:    make([]byte, total),
		coverTraffic:      coverTraffic,
		tlsInsecure:       insecure,
		clientCertFile:    clientCertFile,
		clientKeyFile:     clientKeyFile,
		quicPort:          quicPort,
		enableDatagram:    enableDatagram,
	}
	mode := transport.TransportType(strings.ToLower(strings.TrimSpace(transportMode)))
	if mode == "" {
		mode = transport.TransportTypeAuto
	}
	p.selector = transport.NewTransportSelector(mode, nil, nil)
	if len(ips) > 0 {
		p.endpointPool = transport.NewEndpointPool(ips, 3, 60*time.Second)
	}
	return p
}

func (p *ECHPool) Start(ctx context.Context) {
	for i := 0; i < len(p.smuxConns); i++ {
		ip := ""
		if len(p.targetIPs) > 0 {
			if idx := i / p.connectionNum; idx < len(p.targetIPs) {
				ip = p.targetIPs[idx]
			}
		}
		go p.dialAndServe(ctx, i, ip)
	}
}

func (p *ECHPool) dialAndServe(ctx context.Context, idx int, ip string) {
	chID := idx + 1
	ipLabel := ip
	if strings.TrimSpace(ipLabel) == "" {
		ipLabel = "自动解析"
	}
	reconnectAttempt := 0
	var hsTracker clientHandshakeFailureTracker
	sleepBeforeReconnect := func(reason string) bool {
		delay := reconnectDelay(reconnectAttempt)
		atomic.AddUint64(&clientReconnectSeq, 1)
		log.Printf("[客户端] 通道 %d (IP:%s) %s，%s 后重试 (attempt=%d)", chID, ipLabel, reason, delay, reconnectAttempt+1)
		reconnectAttempt++
		return sleepWithContext(ctx, delay)
	}
	for {
		if ctx.Err() != nil {
			return
		}

		targetIP := ip
		if p.endpointPool != nil {
			if nextIP, err := p.endpointPool.SelectNext(); err == nil && nextIP != "" {
				targetIP = nextIP
			}
		}

		dialStart := time.Now()
		var sess transport.TransportSession
		var err error

		tlsConf := &tls.Config{
			InsecureSkipVerify: p.tlsInsecure,
		}
		if p.clientCertFile != "" && p.clientKeyFile != "" {
			cert, certErr := tls.LoadX509KeyPair(p.clientCertFile, p.clientKeyFile)
			if certErr == nil {
				tlsConf.Certificates = []tls.Certificate{cert}
			}
		}

		isWSS := strings.HasPrefix(strings.ToLower(p.wsServerAddr), "wss://")
		if isWSS && p.selector != nil && (p.selector.Mode() == transport.TransportTypeAuto || p.selector.Mode() == transport.TransportTypeQUIC) && !frontProxyEnabled() {
			serverName := ""
			if u, errParse := url.Parse(p.wsServerAddr); errParse == nil && u != nil {
				serverName = u.Hostname()
			}
			tlsConf, _ := buildUnifiedTLSConfig(serverName)
			opts := transport.DialOptions{
				TLSConfig:         tlsConf,
				TargetIP:          targetIP,
				ServerName:        serverName,
				QUICPort:          p.quicPort,
				Timeout:           cfg.WSHandshakeTimeout,
				KeepAliveInterval: 10 * time.Second,
				MaxIdleTimeout:    30 * time.Second,
				EnableDatagrams:   p.enableDatagram,
			}
			sess, err = p.selector.DialSession(ctx, p.wsServerAddr, opts)
		} else {
			wsConn, dialErr := dialWebSocketWithECH(p.wsServerAddr, 3, targetIP)
			if dialErr != nil {
				err = dialErr
			} else {
				wsNet := newWSNetConn(wsConn)
				smuxSess, smuxErr := smux.Client(wsNet, newSmuxConfig())
				if smuxErr != nil {
					_ = wsConn.Close()
					err = smuxErr
				} else {
					sess = transport.NewTcpTransportSession(smuxSess, wsNet)
				}
			}
		}

		if err != nil {
			if p.endpointPool != nil && targetIP != "" {
				p.endpointPool.RecordResult(targetIP, false, 0)
			}
			if !sleepBeforeReconnect(fmt.Sprintf("连接失败: %v", err)) {
				return
			}
			continue
		}

		caps, keys, cipher, err := negotiateClientProtocol(sess, cfg.RTTProbeTimeout, p.clientID, uint32(chID), p.wsServerAddr)
		if err != nil {
			atomic.AddUint64(&clientProtocolFailureSeq, 1)
			if hsTracker.recordFailure() {
				log.Printf("[客户端] 通道 %d (IP:%s) %s", chID, ipLabel, clientAuthFailureHint(hsTracker.consecutive))
			}
			_ = sess.Close()
			if p.endpointPool != nil && targetIP != "" {
				p.endpointPool.RecordResult(targetIP, false, 0)
			}
			failReason := fmt.Sprintf("协议协商失败: %v", err)
			if strings.Contains(err.Error(), "certificate required") || strings.Contains(err.Error(), "CRYPTO_ERROR") || strings.Contains(err.Error(), "tls:") {
				failReason = fmt.Sprintf("连接失败: %v", err)
			}
			if !sleepBeforeReconnect(failReason) {
				return
			}
			continue
		}
		hsTracker.recordSuccess()
		atomic.AddUint64(&clientProtocolOKSeq, 1)
		log.Printf("[客户端] 通道 %d (IP:%s) v3 协议协商成功: transport=%s version=3 caps=0x%x cipher=%s", chID, ipLabel, sess.Type(), caps, v3CipherName(cipher))

		p.wsConnsMu.Lock()
		if idx < len(p.transportSessions) {
			p.transportSessions[idx] = sess
		}
		if idx < len(p.smuxConns) {
			if tcpSess, ok := sess.(*transport.TcpTransportSession); ok {
				p.smuxConns[idx] = tcpSess.RawSession()
			} else {
				p.smuxConns[idx] = nil
			}
		}
		p.channelRTT[idx] = 0
		p.channelCaps[idx] = caps
		p.channelKeys[idx] = keys
		p.channelCiphers[idx] = cipher
		p.wsConnsMu.Unlock()
		log.Printf("[客户端] 通道 %d (IP:%s) 就绪 (%s)", chID, ipLabel, sess.Type())
		reconnectAttempt = 0

		if rtt, err := p.probeChannelRTTOnce(sess, idx, cfg.RTTProbeTimeout); err == nil {
			atomic.StoreInt64(&p.channelRTT[idx], rtt)
			if p.endpointPool != nil && targetIP != "" {
				p.endpointPool.RecordResult(targetIP, true, time.Duration(rtt))
			}
		} else {
			atomic.AddUint64(&clientRTTProbeFailureSeq, 1)
			if p.endpointPool != nil && targetIP != "" {
				p.endpointPool.RecordResult(targetIP, true, time.Since(dialStart))
			}
		}

		done := make(chan error, 1)
		go p.probeChannelRTT(sess, idx, done)
		if p.coverTraffic {
			go p.runCoverTraffic(ctx, sess, idx)
		}

		var probeErr error
		select {
		case probeErr = <-done:
		case <-ctx.Done():
			_ = sess.Close()
			<-done
			probeErr = ctx.Err()
		}

		_ = sess.Close()

		p.wsConnsMu.Lock()
		if idx < len(p.transportSessions) {
			p.transportSessions[idx] = nil
		}
		if idx < len(p.smuxConns) {
			p.smuxConns[idx] = nil
		}
		p.channelRTT[idx] = 0
		p.channelCaps[idx] = 0
		p.channelKeys[idx] = V3SessionKeys{}
		p.channelCiphers[idx] = 0
		p.wsConnsMu.Unlock()
		if probeErr != nil {
			log.Printf("[客户端] 通道 %d 断开原因: %v", chID, probeErr)
		}
		if ctx.Err() != nil {
			return
		}
		if !sleepBeforeReconnect("断开") {
			return
		}
	}
}

func (p *ECHPool) runCoverTraffic(ctx context.Context, sess transport.TransportSession, idx int) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if sess == nil || sess.IsClosed() {
				return
			}
			_, _ = p.probeChannelRTTOnce(sess, idx, 2*time.Second)
		}
	}
}

func (p *ECHPool) probeChannelRTT(sessAny any, idx int, done chan error) {
	var exitErr error
	defer func() {
		done <- exitErr
		close(done)
	}()
	ticker := time.NewTicker(cfg.RTTProbeTimeout)
	defer ticker.Stop()
	for {
		rtt, err := p.probeChannelRTTOnce(sessAny, idx, cfg.RTTProbeTimeout)
		if err != nil {
			atomic.AddUint64(&clientRTTProbeFailureSeq, 1)
			atomic.StoreInt64(&p.channelRTT[idx], int64(cfg.RTTProbeTimeout.Nanoseconds()))
			var isClosed bool
			if sess, ok := sessAny.(transport.TransportSession); ok {
				isClosed = sess.IsClosed()
			} else if smuxSess, ok := sessAny.(*smux.Session); ok {
				isClosed = smuxSess.IsClosed()
			}
			if isClosed {
				exitErr = err
				return
			}
			<-ticker.C
			continue
		}
		atomic.StoreInt64(&p.channelRTT[idx], rtt)
		select {
		case <-ticker.C:
		case <-done:
			return
		}
	}
}

func (p *ECHPool) probeChannelRTTOnce(sessAny any, idx int, timeout time.Duration) (int64, error) {
	keys, cipher, ok := p.channelV3Security(idx)
	if !ok {
		return 0, fmt.Errorf("通道安全配置不可用")
	}
	start := time.Now()
	var s transport.TransportStream
	if sess, ok := sessAny.(transport.TransportSession); ok {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		st, err := sess.OpenStream(ctx)
		if err != nil {
			return 0, err
		}
		s = st
	} else if smuxSess, ok := sessAny.(*smux.Session); ok {
		st, err := smuxSess.OpenStream()
		if err != nil {
			return 0, err
		}
		s = transport.NewTcpTransportStream(st)
	} else {
		return 0, fmt.Errorf("unsupported session type: %T", sessAny)
	}
	defer s.Close()
	cs, err := newV3CipherStream(s, keys, cipher, s.ID(), true)
	if err != nil {
		return 0, err
	}
	_ = cs.SetDeadline(time.Now().Add(timeout))
	if err := writeSmuxOpenHeader(cs, streamKindPing, 0, ""); err != nil {
		return 0, err
	}
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, uint64(start.UnixNano()))
	if err := writeAll(cs, payload); err != nil {
		return 0, err
	}
	ack := make([]byte, 8)
	if _, err := io.ReadFull(cs, ack); err != nil {
		return 0, err
	}
	if !bytes.Equal(ack, payload) {
		return 0, fmt.Errorf("ping ack mismatch")
	}
	rtt := time.Since(start).Nanoseconds()
	if rtt <= 0 {
		rtt = 1
	}
	return rtt, nil
}

func negotiateClientProtocol(sessAny any, timeout time.Duration, clientID string, channelID uint32, serverAddr string) (uint64, V3SessionKeys, byte, error) {
	var s transport.TransportStream
	if sess, ok := sessAny.(transport.TransportSession); ok {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		st, err := sess.OpenStream(ctx)
		if err != nil {
			return 0, V3SessionKeys{}, 0, err
		}
		s = st
	} else if smuxSess, ok := sessAny.(*smux.Session); ok {
		st, err := smuxSess.OpenStream()
		if err != nil {
			return 0, V3SessionKeys{}, 0, err
		}
		s = transport.NewTcpTransportStream(st)
	} else {
		return 0, V3SessionKeys{}, 0, fmt.Errorf("unsupported session type: %T", sessAny)
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(timeout))
	sessionID, err := clientSessionIDBytes(clientID)
	if err != nil {
		return 0, V3SessionKeys{}, 0, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return 0, V3SessionKeys{}, 0, err
	}
	serverName, serverPath, err := protocolAuthEndpoint(serverAddr)
	if err != nil {
		return 0, V3SessionKeys{}, 0, err
	}

	clientSk, clientPk, err := newV3ClientEphemeralKey()
	if err != nil {
		return 0, V3SessionKeys{}, 0, fmt.Errorf("生成客户端 ephemeral 密钥失败: %w", err)
	}
	defer func() {
		for i := range clientSk {
			clientSk[i] = 0
		}
	}()

	init := ChannelInit{
		SessionID:    sessionID,
		ChannelID:    channelID,
		ClientNonce:  nonce,
		Timestamp:    time.Now().Unix(),
		Capabilities: currentProtocolCapabilitiesV2() | protocolCapabilityForwardSecrecy,
		CipherPref:   clientCipherPreference(),
		ClientEphPK:  clientPk,
		TAI64N:       nextClientTAI64N(),
	}
	proof, err := computeV3AuthProof(token, serverName, serverPath, init)
	if err != nil {
		return 0, V3SessionKeys{}, 0, err
	}
	init.AuthProof = proof

	unpaddedBody, err := encodeChannelInitV3(init)
	if err != nil {
		return 0, V3SessionKeys{}, 0, fmt.Errorf("编码 ChannelInit 失败: %w", err)
	}
	frameLen := 8 + len(unpaddedBody)
	if target, ok := sampleFirstPacketTarget(frameLen); ok {
		padLen := target - frameLen - 4
		if padLen >= 0 {
			pad := make([]byte, padLen)
			if _, err := rand.Read(pad); err != nil {
				return 0, V3SessionKeys{}, 0, fmt.Errorf("生成首包 padding 失败: %w", err)
			}
			init.Padding = pad
		}
	}

	if err := writeChannelInitV3(s, init); err != nil {
		return 0, V3SessionKeys{}, 0, err
	}
	accept, reject, err := readChannelAcceptOrRejectV3(s, maxV2FrameSize)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || err == io.EOF || err == io.ErrUnexpectedEOF {
			return 0, V3SessionKeys{}, 0, errors.New("连接被服务端关闭")
		}
		return 0, V3SessionKeys{}, 0, err
	}
	if reject.Code != 0 {
		if reject.Code == v2RejectAuthenticationFailed {
			if reject.Message != "" {
				return 0, V3SessionKeys{}, 0, fmt.Errorf("认证失败: %s", reject.Message)
			}
			return 0, V3SessionKeys{}, 0, fmt.Errorf("认证失败")
		}
		if reject.Message != "" {
			return 0, V3SessionKeys{}, 0, fmt.Errorf("协议协商失败: reject=%d %s", reject.Code, reject.Message)
		}
		return 0, V3SessionKeys{}, 0, fmt.Errorf("协议协商失败: reject=%d", reject.Code)
	}
	required := requiredProtocolCapabilitiesV2() | protocolCapabilityForwardSecrecy
	if accept.Capabilities&required != required {
		return 0, V3SessionKeys{}, 0, fmt.Errorf("协议能力不足: caps=0x%x", accept.Capabilities)
	}
	if len(accept.ServerEphPK) != 32 || len(accept.ServerProof) != 32 {
		return 0, V3SessionKeys{}, 0, fmt.Errorf("服务端证明或公钥格式非法")
	}

	shared, err := computeV3SharedSecret(clientSk, accept.ServerEphPK)
	if err != nil {
		return 0, V3SessionKeys{}, 0, fmt.Errorf("计算共享秘密失败: %w", err)
	}

	if !verifyV3ServerProof(token, serverName, serverPath, init, accept) {
		return 0, V3SessionKeys{}, 0, fmt.Errorf("服务端证明校验失败")
	}

	thFull, err := computeV3TranscriptHashFull(serverName, serverPath, init, accept.ServerEphPK, accept.ServerNonce, accept.Cipher)
	if err != nil {
		return 0, V3SessionKeys{}, 0, fmt.Errorf("计算 transcript hash 失败: %w", err)
	}
	keys, err := deriveV3SessionSeed(token, thFull, shared)
	if err != nil {
		return 0, V3SessionKeys{}, 0, fmt.Errorf("派生会话密钥失败: %w", err)
	}
	return accept.Capabilities, keys, accept.Cipher, nil
}

func shortID(id string) string {
	if len(id) >= 8 {
		return id[:8]
	}
	return id
}

func clientSessionIDBytes(clientID string) ([]byte, error) {
	id, err := uuid.Parse(clientID)
	if err != nil {
		return nil, fmt.Errorf("client id invalid: %w", err)
	}
	return id[:], nil
}

// sampleFirstPacketTarget samples a target length for the ChannelInit first packet according to 3 confidence bands:
// Band A: [480, 576] (50% weight)
// Band B: [1024, 1152] (25% weight)
// Band C: [1280, 1400] (25% weight)
// If frameLen >= 1400 or the sampled target < frameLen, it returns ok=false.
func sampleFirstPacketTarget(frameLen int) (target int, ok bool) {
	if frameLen >= 1400 {
		return 0, false
	}

	w, err := rand.Int(rand.Reader, big.NewInt(100))
	if err != nil {
		return 0, false
	}
	weight := w.Int64()

	var min, max int
	if weight < 50 {
		min, max = 480, 576
	} else if weight < 75 {
		min, max = 1024, 1152
	} else {
		min, max = 1280, 1400
	}

	bandRange := int64(max - min + 1)
	offset, err := rand.Int(rand.Reader, big.NewInt(bandRange))
	if err != nil {
		return 0, false
	}
	target = min + int(offset.Int64())

	if target < frameLen {
		return target, false
	}
	return target, true
}

func protocolAuthEndpoint(raw string) (string, string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", err
	}
	serverName := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if serverName == "" {
		return "", "", fmt.Errorf("server name is empty")
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	return serverName, path, nil
}

const defaultWebSocketUserAgent = "Mozilla/5.0"

func webSocketRequestHeader() http.Header {
	header := make(http.Header)
	header.Set("User-Agent", defaultWebSocketUserAgent)
	header.Set("Accept-Language", "en-US,en;q=0.9")
	header.Set("Cache-Control", "no-cache")
	header.Set("Pragma", "no-cache")
	return header
}

func proxyConnStream(c net.Conn, stream io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() {
		var dst io.Writer = stream
		if pacingRateMbps > 0 {
			dst = newPacerWriterMbps(stream, pacingRateMbps)
		}
		n, _ := io.Copy(dst, c)
		if n > 0 {
			atomic.AddUint64(&runtimeBytesSentSeq, uint64(n))
		}
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(c, stream)
		if n > 0 {
			atomic.AddUint64(&runtimeBytesReceivedSeq, uint64(n))
		}
		done <- struct{}{}
	}()
	<-done

	// 立即关闭双方，强制中断另一方向的 io.Copy
	_ = stream.Close()
	_ = c.Close()

	<-done // 等待另一方向退出
}

func clientSourceAddr(c net.Conn) string {
	if ra := c.RemoteAddr(); ra != nil {
		return ra.String()
	}
	return "-"
}

func logClientConnEvent(c net.Conn, reqType, target string, chID int, opened bool) {
	arrow := "关闭"
	if opened {
		arrow = "打开"
	}
	log.Printf("[客户端] %s %s %s %s 通道 %d", clientSourceAddr(c), reqType, arrow, target, chID)
}

func (p *ECHPool) openBestStream() (transport.TransportStream, int, int, uint64, V3SessionKeys, byte, error) {
	p.wsConnsMu.RLock()
	type candidate struct {
		idx int
		rtt int64
	}
	totalSlots := len(p.transportSessions)
	if len(p.smuxConns) > totalSlots {
		totalSlots = len(p.smuxConns)
	}
	cands := make([]candidate, 0, totalSlots)
	for i := 0; i < totalSlots; i++ {
		var isClosed bool = true
		if i < len(p.transportSessions) && p.transportSessions[i] != nil {
			isClosed = p.transportSessions[i].IsClosed()
		} else if i < len(p.smuxConns) && p.smuxConns[i] != nil {
			isClosed = p.smuxConns[i].IsClosed()
		}
		if isClosed {
			continue
		}
		rtt := int64(0)
		if i < len(p.channelRTT) {
			rtt = atomic.LoadInt64(&p.channelRTT[i])
		}
		if rtt <= 0 {
			rtt = int64(cfg.RTTProbeTimeout.Nanoseconds())
		}
		cands = append(cands, candidate{idx: i, rtt: rtt})
	}
	if len(cands) == 0 {
		p.wsConnsMu.RUnlock()
		return nil, 0, 0, 0, V3SessionKeys{}, 0, fmt.Errorf("无可用 smux 通道")
	}
	minRTT := cands[0].rtt
	for _, c := range cands[1:] {
		if c.rtt < minRTT {
			minRTT = c.rtt
		}
	}
	tieWindow := int64((10 * time.Millisecond).Nanoseconds())
	near := make([]candidate, 0, len(cands))
	for _, c := range cands {
		if c.rtt-minRTT <= tieWindow {
			near = append(near, c)
		}
	}
	pick := int(atomic.AddUint64(&p.selectCounter, 1)-1) % len(near)
	best := near[pick]

	var sess transport.TransportSession
	if best.idx < len(p.transportSessions) && p.transportSessions[best.idx] != nil {
		sess = p.transportSessions[best.idx]
	} else if best.idx < len(p.smuxConns) && p.smuxConns[best.idx] != nil {
		sess = transport.NewTcpTransportSession(p.smuxConns[best.idx], nil)
	}

	var caps uint64
	if best.idx < len(p.channelCaps) {
		caps = p.channelCaps[best.idx]
	}
	var keys V3SessionKeys
	if best.idx < len(p.channelKeys) {
		keys = p.channelKeys[best.idx]
	}
	var cipher byte
	if best.idx < len(p.channelCiphers) {
		cipher = p.channelCiphers[best.idx]
	}
	p.wsConnsMu.RUnlock()

	if sess == nil || sess.IsClosed() {
		return nil, 0, 0, 0, V3SessionKeys{}, 0, fmt.Errorf("通道不可用")
	}
	decision := best.idx + 1
	ctx, cancel := context.WithTimeout(context.Background(), cfg.DialTimeout)
	defer cancel()
	s, err := sess.OpenStream(ctx)
	if err != nil {
		return nil, 0, 0, 0, V3SessionKeys{}, 0, err
	}
	return s, best.idx + 1, decision, caps, keys, cipher, nil
}

func (p *ECHPool) openTCPStream(target string) (*V3CipherStream, int, int, error) {
	s, chID, decision, caps, keys, cipher, err := p.openBestStream()
	if err != nil {
		return nil, 0, 0, err
	}
	cs, err := newV3CipherStream(s, keys, cipher, s.ID(), true)
	if err != nil {
		_ = s.Close()
		return nil, 0, 0, err
	}
	if shapingCoalesceMs > 0 {
		cs.CoalesceDelay = time.Duration(shapingCoalesceMs) * time.Millisecond
	}
	if err := writeSmuxOpenHeader(cs, streamKindTCP, ipStrategy, target); err != nil {
		_ = cs.Close()
		return nil, 0, 0, err
	}
	_ = cs.SetDeadline(time.Now().Add(cfg.DialTimeout))
	var status byte
	var code byte
	var message string
	if caps&protocolCapabilityOpenStatusCode != 0 {
		status, code, message, err = readTCPOpenStatusCode(cs)
	} else {
		status, message, err = readTCPOpenStatus(cs)
	}
	_ = cs.SetDeadline(time.Time{})
	if err != nil {
		_ = cs.Close()
		return nil, 0, 0, err
	}
	if status != tcpOpenStatusOK {
		_ = cs.Close()
		return nil, 0, 0, &remoteOpenError{network: "TCP", status: status, code: code, message: message}
	}
	return cs, chID, decision, nil
}

func (p *ECHPool) openUDPStream(target string) (*V3CipherStream, int, int, error) {
	s, chID, decision, caps, keys, cipher, err := p.openBestStream()
	if err != nil {
		return nil, 0, 0, err
	}
	cs, err := newV3CipherStream(s, keys, cipher, s.ID(), true)
	if err != nil {
		_ = s.Close()
		return nil, 0, 0, err
	}
	if shapingCoalesceMs > 0 {
		cs.CoalesceDelay = time.Duration(shapingCoalesceMs) * time.Millisecond
	}
	if err := writeSmuxOpenHeader(cs, streamKindUDP, ipStrategy, target); err != nil {
		_ = cs.Close()
		return nil, 0, 0, err
	}
	_ = cs.SetDeadline(time.Now().Add(cfg.DialTimeout))
	var status byte
	var code byte
	var message string
	if caps&protocolCapabilityOpenStatusCode != 0 {
		status, code, message, err = readUDPOpenStatusCode(cs)
	} else {
		status, message, err = readUDPOpenStatus(cs)
	}
	_ = cs.SetDeadline(time.Time{})
	if err != nil {
		_ = cs.Close()
		return nil, 0, 0, err
	}
	if status != udpOpenStatusOK {
		_ = cs.Close()
		return nil, 0, 0, &remoteOpenError{network: "UDP", status: status, code: code, message: message}
	}
	return cs, chID, decision, nil
}

// ======================== TCP Forwarder ========================

func startTCPListener(ctx context.Context, rule string) (*runtimeListener, error) {
	lAddr, tAddr, err := parseTCPForwardRule(rule)
	if err != nil {
		return nil, fmt.Errorf("[客户端] TCP转发地址解析失败: %w", err)
	}
	l, err := net.Listen("tcp", lAddr)
	if err != nil {
		return nil, fmt.Errorf("[客户端] TCP监听失败: %w", err)
	}
	listener := newRuntimeListener("tcp", rule, "tcp://"+l.Addr().String()+"/"+tAddr, l.Close)
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	log.Printf("[客户端] TCP转发: %s -> %s", lAddr, tAddr)
	go func() {
		defer listener.finish(nil)
		for {
			c, err := l.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			go handleLocalTCP(c, tAddr)
		}
	}()
	return listener, nil
}

func handleLocalTCP(c net.Conn, target string) {
	stream, _, decision, err := echPool.openTCPStream(target)
	if err != nil {
		log.Printf("[客户端] %s TCP转发 打开失败 %s: %v", clientSourceAddr(c), target, err)
		_ = c.Close()
		return
	}
	logClientConnEvent(c, "TCP转发", target, decision, true)
	defer logClientConnEvent(c, "TCP转发", target, decision, false)
	proxyConnStream(c, stream)
}

// dialWebSocketWithECH：支持 ws:// 与 wss://；仅 wss 使用 TLS/ECH 逻辑。
// v2 通道身份、认证 proof 与 channel id 都在 WebSocket 升级后的
// ChannelInit 中发送；这里必须保持 URL query 与 Sec-WebSocket-Protocol 为空。
func dialWebSocketWithECH(addr string, retries int, ip string) (*websocket.Conn, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "wss" && scheme != "ws" {
		return nil, fmt.Errorf("仅支持 ws:// 或 wss:// (当前: %s)", u.Scheme)
	}

	dialURL := *u
	dialURL.RawQuery = ""
	dialAddr := dialURL.String()

	newDialer := func() websocket.Dialer {
		dialer := websocket.Dialer{
			HandshakeTimeout: cfg.WSHandshakeTimeout,
			ReadBufferSize:   cfg.ReadBuf,
			WriteBufferSize:  cfg.ReadBuf,
		}
		if ip != "" || frontProxyEnabled() {
			dialer.NetDialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				target, err := resolveWebSocketDialTarget(address, ip)
				if err != nil {
					return nil, err
				}
				if frontProxyEnabled() {
					return dialWebSocketFrontProxy(ctx, target)
				}
				d := net.Dialer{Timeout: cfg.DialTimeout}
				return d.DialContext(ctx, network, target)
			}
		}
		return dialer
	}

	if scheme == "ws" {
		dialer := newDialer()
		conn, resp, err := dialer.Dial(dialAddr, webSocketRequestHeader())
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusUnauthorized {
				return nil, fmt.Errorf("认证失败")
			}
			return nil, err
		}
		return conn, nil
	}

	serverName := u.Hostname()
	for i := 1; i <= retries; i++ {
		tlsCfg, e := buildUnifiedTLSConfig(serverName)
		if e != nil {
			if i < retries {
				_ = refreshECH()
				time.Sleep(cfg.ECHRetryDelay)
				continue
			}
			return nil, e
		}

		dialer := newDialer()
		dialer.TLSClientConfig = tlsCfg

		conn, resp, err := dialer.Dial(dialAddr, webSocketRequestHeader())
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusUnauthorized {
				return nil, fmt.Errorf("认证失败")
			}
			if !fallback && (strings.Contains(err.Error(), "ECH") || strings.Contains(err.Error(), "ech")) && i < retries {
				_ = refreshECH()
				time.Sleep(cfg.ECHRetryDelay)
				continue
			}
			return nil, err
		}
		return conn, nil
	}
	return nil, fmt.Errorf("连接失败")
}

func resolveWebSocketDialTarget(address, ip string) (string, error) {
	if ip == "" {
		return address, nil
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("解析 WebSocket 目标地址失败 %q: %w", address, err)
	}
	if host, overridePort, err := net.SplitHostPort(ip); err == nil {
		return net.JoinHostPort(host, overridePort), nil
	}
	return net.JoinHostPort(ip, port), nil
}

// ======================== SOCKS5 / HTTP Proxy ========================
