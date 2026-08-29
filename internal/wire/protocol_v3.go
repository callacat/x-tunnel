package wire

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	protocolV3Version byte = 3

	v3FrameTypeChannelInit   byte = 1
	v3FrameTypeChannelAccept byte = 2
	v3FrameTypeChannelReject byte = 3
)

const (
	v3RecordCipherPref uint16 = 0x8030
	v3RecordCipher     uint16 = 0x8031
)

const (
	v3RejectUnsupportedCipher byte = 9
)

const (
	ProtocolCipherChaCha20Poly1305 byte = 1
	ProtocolCipherAES256GCM        byte = 2
	ProtocolCipherAES128GCM        byte = 3
)

const (
	ProtocolV3Version         = protocolV3Version
	V3RejectUnsupportedCipher = v3RejectUnsupportedCipher
)

func isSupportedCipherV3(id byte) bool {
	switch id {
	case ProtocolCipherChaCha20Poly1305, ProtocolCipherAES256GCM, ProtocolCipherAES128GCM:
		return true
	default:
		return false
	}
}

// V3SupportedCiphers returns the slice of supported cipher IDs in protocol v3.
func V3SupportedCiphers() []byte {
	return []byte{
		ProtocolCipherChaCha20Poly1305,
		ProtocolCipherAES256GCM,
		ProtocolCipherAES128GCM,
	}
}

// V3CipherKeyLen returns the key length in bytes for the given cipher ID.
func V3CipherKeyLen(id byte) int {
	switch id {
	case ProtocolCipherChaCha20Poly1305:
		return 32
	case ProtocolCipherAES256GCM:
		return 32
	case ProtocolCipherAES128GCM:
		return 16
	default:
		return 0
	}
}

// V3CipherName returns the human-readable name of the given cipher algorithm.
func V3CipherName(id byte) string {
	switch id {
	case ProtocolCipherChaCha20Poly1305:
		return "ChaCha20-Poly1305"
	case ProtocolCipherAES256GCM:
		return "AES-256-GCM"
	case ProtocolCipherAES128GCM:
		return "AES-128-GCM"
	default:
		return "Unknown"
	}
}

// NegotiateCipherV3 selects the first supported cipher ID from the client preference list.
// If the preference list is empty or contains no supported ciphers, it returns code 9 (V3RejectUnsupportedCipher).
func NegotiateCipherV3(pref []byte) (chosen byte, rejectCode byte, msg string) {
	if len(pref) == 0 {
		return 0, v3RejectUnsupportedCipher, "empty cipher preference"
	}
	for _, c := range pref {
		if isSupportedCipherV3(c) {
			return c, 0, ""
		}
	}
	return 0, v3RejectUnsupportedCipher, "no supported cipher in preference"
}

// V3Frame represents a protocol v3 framing envelope.
type V3Frame struct {
	Type    byte
	Version byte
	Flags   uint16
	Body    []byte
}

func writeV3Frame(w io.Writer, frame V3Frame) error {
	if frame.Version == 0 {
		frame.Version = protocolV3Version
	}
	if frame.Version != protocolV3Version {
		return fmt.Errorf("v3 frame version invalid: %d", frame.Version)
	}
	if len(frame.Body) > maxV2FrameSize {
		return fmt.Errorf("v3 frame body too large: %d", len(frame.Body))
	}
	var head [8]byte
	head[0] = frame.Type
	head[1] = frame.Version
	binary.BigEndian.PutUint16(head[2:4], frame.Flags)
	binary.BigEndian.PutUint32(head[4:8], uint32(len(frame.Body)))
	if err := writeAll(w, head[:]); err != nil {
		return err
	}
	return writeOptionalPayload(w, frame.Body)
}

func readV3Frame(r io.Reader, maxSize int) (V3Frame, error) {
	if maxSize <= 0 {
		maxSize = maxV2FrameSize
	}
	head := make([]byte, 8)
	if _, err := io.ReadFull(r, head); err != nil {
		return V3Frame{}, err
	}
	frame := V3Frame{
		Type:    head[0],
		Version: head[1],
		Flags:   binary.BigEndian.Uint16(head[2:4]),
	}
	if frame.Version != protocolV3Version {
		return V3Frame{}, fmt.Errorf("v3 frame version invalid: %d", frame.Version)
	}
	bodyLen := int(binary.BigEndian.Uint32(head[4:8]))
	if bodyLen > maxSize {
		return V3Frame{}, fmt.Errorf("v3 frame body too large: %d", bodyLen)
	}
	body, err := readExactPayload(r, bodyLen)
	if err != nil {
		return V3Frame{}, err
	}
	frame.Body = body
	return frame, nil
}

func writeChannelInitV3(w io.Writer, init ChannelInit) error {
	body, err := encodeChannelInitV3(init)
	if err != nil {
		return err
	}
	return writeV3Frame(w, V3Frame{Type: v3FrameTypeChannelInit, Version: protocolV3Version, Body: body})
}

func readChannelInitV3(r io.Reader, maxSize int) (ChannelInit, error) {
	frame, err := readV3Frame(r, maxSize)
	if err != nil {
		return ChannelInit{}, err
	}
	if frame.Type != v3FrameTypeChannelInit {
		return ChannelInit{}, fmt.Errorf("unexpected v3 frame type: %d", frame.Type)
	}
	return decodeChannelInitV3(frame.Body)
}

func encodeChannelInitV3(init ChannelInit) ([]byte, error) {
	if len(init.SessionID) != 16 {
		return nil, fmt.Errorf("session id must be 16 bytes")
	}
	if init.ChannelID == 0 {
		return nil, fmt.Errorf("channel id must be positive")
	}
	if len(init.ClientNonce) != 32 {
		return nil, fmt.Errorf("client nonce must be 32 bytes")
	}
	if len(init.AuthProof) != 32 {
		return nil, fmt.Errorf("auth proof must be 32 bytes")
	}
	if len(init.CipherPref) < 1 || len(init.CipherPref) > 8 {
		return nil, fmt.Errorf("cipher preference count must be between 1 and 8: got %d", len(init.CipherPref))
	}
	for _, c := range init.CipherPref {
		if !isSupportedCipherV3(c) {
			return nil, fmt.Errorf("unsupported cipher in preference: %d", c)
		}
	}

	var channelIDBytes [4]byte
	binary.BigEndian.PutUint32(channelIDBytes[:], init.ChannelID)
	var timeBytes [8]byte
	binary.BigEndian.PutUint64(timeBytes[:], uint64(init.Timestamp))
	var capsBytes [8]byte
	binary.BigEndian.PutUint64(capsBytes[:], init.Capabilities)

	records := []V2TLV{
		{Type: v2RecordSessionID, Value: init.SessionID},
		{Type: v2RecordChannelID, Value: channelIDBytes[:]},
		{Type: v2RecordClientNonce, Value: init.ClientNonce},
		{Type: v2RecordTimestamp, Value: timeBytes[:]},
		{Type: v2RecordCapabilities, Value: capsBytes[:]},
		{Type: v2RecordAuthProof, Value: init.AuthProof},
		{Type: v3RecordCipherPref, Value: init.CipherPref},
	}
	return encodeV2TLVs(records)
}

func decodeChannelInitV3(body []byte) (ChannelInit, error) {
	known := map[uint16]bool{
		v2RecordSessionID:           true,
		v2RecordChannelID:           true,
		v2RecordClientNonce:         true,
		v2RecordTimestamp:           true,
		v2RecordCapabilities:        true,
		v2RecordAuthProof:           true,
		v2RecordClientName:          true,
		v2RecordBuildInfo:           true,
		v2RecordDesiredChannelCount: true,
		v2RecordTransportHints:      true,
		v2RecordPadding:             true,
		v3RecordCipherPref:          true,
	}
	records, err := parseV2TLVs(body, known)
	if err != nil {
		return ChannelInit{}, err
	}

	get := func(typ uint16, size int) ([]byte, error) {
		record, ok := records[typ]
		if !ok {
			return nil, fmt.Errorf("missing required v3 record: 0x%04x", typ)
		}
		if size > 0 && len(record.Value) != size {
			return nil, fmt.Errorf("invalid v3 record length: 0x%04x (want %d, got %d)", typ, size, len(record.Value))
		}
		return record.Value, nil
	}

	sessionID, err := get(v2RecordSessionID, 16)
	if err != nil {
		return ChannelInit{}, err
	}
	channelIDRaw, err := get(v2RecordChannelID, 4)
	if err != nil {
		return ChannelInit{}, err
	}
	clientNonce, err := get(v2RecordClientNonce, 32)
	if err != nil {
		return ChannelInit{}, err
	}
	clientTimeRaw, err := get(v2RecordTimestamp, 8)
	if err != nil {
		return ChannelInit{}, err
	}
	capsRaw, err := get(v2RecordCapabilities, 8)
	if err != nil {
		return ChannelInit{}, err
	}
	authProof, err := get(v2RecordAuthProof, 32)
	if err != nil {
		return ChannelInit{}, err
	}
	cipherPrefRaw, err := get(v3RecordCipherPref, 0)
	if err != nil {
		return ChannelInit{}, err
	}
	if len(cipherPrefRaw) < 1 || len(cipherPrefRaw) > 8 {
		return ChannelInit{}, fmt.Errorf("invalid cipher preference length: %d", len(cipherPrefRaw))
	}
	for _, c := range cipherPrefRaw {
		if !isSupportedCipherV3(c) {
			return ChannelInit{}, fmt.Errorf("unsupported cipher in preference: %d", c)
		}
	}

	channelID := binary.BigEndian.Uint32(channelIDRaw)
	if channelID == 0 {
		return ChannelInit{}, fmt.Errorf("channel id must be positive")
	}

	return ChannelInit{
		SessionID:    append([]byte(nil), sessionID...),
		ChannelID:    channelID,
		ClientNonce:  append([]byte(nil), clientNonce...),
		Timestamp:    int64(binary.BigEndian.Uint64(clientTimeRaw)),
		Capabilities: binary.BigEndian.Uint64(capsRaw),
		AuthProof:    append([]byte(nil), authProof...),
		CipherPref:   append([]byte(nil), cipherPrefRaw...),
	}, nil
}

func writeChannelAcceptV3(w io.Writer, accept ChannelAccept) error {
	body, err := encodeChannelAcceptV3(accept)
	if err != nil {
		return err
	}
	return writeV3Frame(w, V3Frame{Type: v3FrameTypeChannelAccept, Version: protocolV3Version, Body: body})
}

func encodeChannelAcceptV3(accept ChannelAccept) ([]byte, error) {
	if len(accept.ServerNonce) != 32 {
		return nil, fmt.Errorf("server nonce must be 32 bytes")
	}
	if !isSupportedCipherV3(accept.Cipher) {
		return nil, fmt.Errorf("unsupported cipher in accept: %d", accept.Cipher)
	}

	var capsBytes [8]byte
	binary.BigEndian.PutUint64(capsBytes[:], accept.Capabilities)
	var timeBytes [8]byte
	binary.BigEndian.PutUint64(timeBytes[:], uint64(accept.ServerTime))

	records := []V2TLV{
		{Type: v2RecordCapabilities, Value: capsBytes[:]},
		{Type: v2RecordServerNonce, Value: accept.ServerNonce},
		{Type: v2RecordServerTime, Value: timeBytes[:]},
	}

	if accept.MaxFrameSize > 0 {
		var frameBytes [4]byte
		binary.BigEndian.PutUint32(frameBytes[:], accept.MaxFrameSize)
		records = append(records, V2TLV{Type: v2RecordMaxFrameSize, Value: frameBytes[:]})
	}
	if accept.MaxStreams > 0 {
		var streamBytes [4]byte
		binary.BigEndian.PutUint32(streamBytes[:], accept.MaxStreams)
		records = append(records, V2TLV{Type: v2RecordMaxStreams, Value: streamBytes[:]})
	}
	if len(accept.Message) > 0 {
		records = append(records, V2TLV{Type: v2RecordMessage, Value: []byte(accept.Message)})
	}
	records = append(records, V2TLV{Type: v3RecordCipher, Value: []byte{accept.Cipher}})
	return encodeV2TLVs(records)
}

func decodeChannelAcceptV3(body []byte) (ChannelAccept, error) {
	known := map[uint16]bool{
		v2RecordCapabilities: true,
		v2RecordServerNonce:  true,
		v2RecordServerTime:   true,
		v2RecordMaxFrameSize: true,
		v2RecordMaxStreams:   true,
		v2RecordMessage:      true,
		v2RecordPadding:      true,
		v3RecordCipher:       true,
	}
	records, err := parseV2TLVs(body, known)
	if err != nil {
		return ChannelAccept{}, err
	}

	capsRecord, ok := records[v2RecordCapabilities]
	if !ok || len(capsRecord.Value) != 8 {
		return ChannelAccept{}, fmt.Errorf("invalid channel accept capabilities")
	}
	serverNonceRecord, ok := records[v2RecordServerNonce]
	if !ok || len(serverNonceRecord.Value) != 32 {
		return ChannelAccept{}, fmt.Errorf("invalid channel accept server nonce")
	}
	serverTimeRecord, ok := records[v2RecordServerTime]
	if !ok || len(serverTimeRecord.Value) != 8 {
		return ChannelAccept{}, fmt.Errorf("invalid channel accept server time")
	}
	cipherRecord, ok := records[v3RecordCipher]
	if !ok || len(cipherRecord.Value) != 1 {
		return ChannelAccept{}, fmt.Errorf("invalid channel accept cipher")
	}
	if !isSupportedCipherV3(cipherRecord.Value[0]) {
		return ChannelAccept{}, fmt.Errorf("unsupported cipher in accept: %d", cipherRecord.Value[0])
	}

	accept := ChannelAccept{
		Capabilities: binary.BigEndian.Uint64(capsRecord.Value),
		ServerNonce:  append([]byte(nil), serverNonceRecord.Value...),
		ServerTime:   int64(binary.BigEndian.Uint64(serverTimeRecord.Value)),
		Cipher:       cipherRecord.Value[0],
	}

	if maxFrameRecord, ok := records[v2RecordMaxFrameSize]; ok {
		if len(maxFrameRecord.Value) != 4 {
			return ChannelAccept{}, fmt.Errorf("invalid max frame size length")
		}
		accept.MaxFrameSize = binary.BigEndian.Uint32(maxFrameRecord.Value)
	}
	if maxStreamsRecord, ok := records[v2RecordMaxStreams]; ok {
		if len(maxStreamsRecord.Value) != 4 {
			return ChannelAccept{}, fmt.Errorf("invalid max streams length")
		}
		accept.MaxStreams = binary.BigEndian.Uint32(maxStreamsRecord.Value)
	}
	if msgRecord, ok := records[v2RecordMessage]; ok {
		accept.Message = string(msgRecord.Value)
	}
	return accept, nil
}

func readChannelAcceptOrRejectV3(r io.Reader, maxSize int) (ChannelAccept, ChannelReject, error) {
	frame, err := readV3Frame(r, maxSize)
	if err != nil {
		return ChannelAccept{}, ChannelReject{}, err
	}
	switch frame.Type {
	case v3FrameTypeChannelAccept:
		accept, err := decodeChannelAcceptV3(frame.Body)
		return accept, ChannelReject{}, err
	case v3FrameTypeChannelReject:
		reject, err := decodeChannelReject(frame.Body)
		return ChannelAccept{}, reject, err
	default:
		return ChannelAccept{}, ChannelReject{}, fmt.Errorf("unexpected v3 frame type: %d", frame.Type)
	}
}

func writeChannelRejectV3(w io.Writer, reject ChannelReject) error {
	body, err := encodeChannelReject(reject)
	if err != nil {
		return err
	}
	return writeV3Frame(w, V3Frame{Type: v3FrameTypeChannelReject, Version: protocolV3Version, Body: body})
}

// WriteV3Frame writes a v3 frame envelope to w.
func WriteV3Frame(w io.Writer, frame V3Frame) error {
	return writeV3Frame(w, frame)
}

// ReadV3Frame reads a v3 frame envelope from r.
func ReadV3Frame(r io.Reader, maxSize int) (V3Frame, error) {
	return readV3Frame(r, maxSize)
}

// WriteChannelInitV3 writes a v3 ChannelInit frame to w.
func WriteChannelInitV3(w io.Writer, init ChannelInit) error {
	return writeChannelInitV3(w, init)
}

// ReadChannelInitV3 reads a v3 ChannelInit frame from r.
func ReadChannelInitV3(r io.Reader, maxSize int) (ChannelInit, error) {
	return readChannelInitV3(r, maxSize)
}

// WriteChannelAcceptV3 writes a v3 ChannelAccept frame to w.
func WriteChannelAcceptV3(w io.Writer, accept ChannelAccept) error {
	return writeChannelAcceptV3(w, accept)
}

// ReadChannelAcceptOrRejectV3 reads either a ChannelAccept or ChannelReject frame in v3 format.
func ReadChannelAcceptOrRejectV3(r io.Reader, maxSize int) (ChannelAccept, ChannelReject, error) {
	return readChannelAcceptOrRejectV3(r, maxSize)
}

// WriteChannelRejectV3 writes a v3 ChannelReject frame to w.
func WriteChannelRejectV3(w io.Writer, reject ChannelReject) error {
	return writeChannelRejectV3(w, reject)
}

func channelInitTranscriptV3(serverName, path string, init ChannelInit) ([]byte, error) {
	if len(init.SessionID) != 16 {
		return nil, fmt.Errorf("session id must be 16 bytes")
	}
	if init.ChannelID == 0 {
		return nil, fmt.Errorf("channel id must be positive")
	}
	if len(init.ClientNonce) != 32 {
		return nil, fmt.Errorf("client nonce must be 32 bytes")
	}
	if len(init.CipherPref) < 1 || len(init.CipherPref) > 8 {
		return nil, fmt.Errorf("cipher preference count must be between 1 and 8")
	}
	if len(serverName) > 65535 {
		return nil, fmt.Errorf("server name too long")
	}
	if len(path) > 65535 {
		return nil, fmt.Errorf("path too long")
	}

	total := 137 + len(init.CipherPref) + 2 + len(serverName) + 2 + len(path)
	buf := make([]byte, total)
	buf[0] = 0x01 // ChannelInit frame type
	buf[1] = 0x03 // version 3
	buf[2] = 0x00 // flags BE16
	buf[3] = 0x00
	copy(buf[4:20], init.SessionID)
	binary.BigEndian.PutUint32(buf[20:24], init.ChannelID)
	copy(buf[24:56], init.ClientNonce)
	binary.BigEndian.PutUint64(buf[56:64], uint64(init.Timestamp))
	binary.BigEndian.PutUint64(buf[64:72], init.Capabilities)
	// buf[72:104] is 32 zeros (client_eph_pk placeholder for P0)
	// buf[104:136] is 32 zeros (server_eph_pk placeholder for P0)
	buf[136] = byte(len(init.CipherPref))
	copy(buf[137:137+len(init.CipherPref)], init.CipherPref)
	off := 137 + len(init.CipherPref)
	binary.BigEndian.PutUint16(buf[off:off+2], uint16(len(serverName)))
	off += 2
	copy(buf[off:off+len(serverName)], serverName)
	off += len(serverName)
	binary.BigEndian.PutUint16(buf[off:off+2], uint16(len(path)))
	off += 2
	copy(buf[off:off+len(path)], path)
	return buf, nil
}

// ComputeV3TranscriptHash computes the SHA256 hash of the v3 handshake transcript.
func ComputeV3TranscriptHash(serverName, path string, init ChannelInit) ([]byte, error) {
	transcript, err := channelInitTranscriptV3(serverName, path, init)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(transcript)
	return hash[:], nil
}

// ComputeV3AuthProof computes the HMAC-SHA256 authentication proof for v3 ChannelInit.
func ComputeV3AuthProof(token, serverName, path string, init ChannelInit) ([]byte, error) {
	transcriptHash, err := ComputeV3TranscriptHash(serverName, path, init)
	if err != nil {
		return nil, err
	}
	authKeyReader := hkdf.New(sha256.New, []byte(token), []byte("x-tunnel-v3-auth"), []byte(serverName))
	authKey := make([]byte, 32)
	if _, err := io.ReadFull(authKeyReader, authKey); err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, authKey)
	mac.Write(transcriptHash)
	return mac.Sum(nil), nil
}

// VerifyV3AuthProof verifies the HMAC-SHA256 authentication proof in constant time.
func VerifyV3AuthProof(token, serverName, path string, init ChannelInit) bool {
	expected, err := ComputeV3AuthProof(token, serverName, path, init)
	if err != nil {
		return false
	}
	if len(init.AuthProof) != 32 {
		return false
	}
	return hmac.Equal(init.AuthProof, expected)
}

// V3SessionKeys holds session seed and directional nonce prefixes.
type V3SessionKeys struct {
	Seed           []byte
	C2SNoncePrefix []byte
	S2CNoncePrefix []byte
}

// DeriveV3SessionKeys derives v3 session keys from token and transcript hash using HKDF-SHA256.
func DeriveV3SessionKeys(token string, transcriptHash []byte) (V3SessionKeys, error) {
	if len(token) == 0 {
		return V3SessionKeys{}, fmt.Errorf("empty token")
	}
	if len(transcriptHash) != 32 {
		return V3SessionKeys{}, fmt.Errorf("transcript hash must be 32 bytes")
	}

	prk := hkdf.Extract(sha256.New, []byte(token), []byte("xtunnel-v3-kdf"))

	seedReader := hkdf.Expand(sha256.New, prk, transcriptHash)
	seed := make([]byte, 32)
	if _, err := io.ReadFull(seedReader, seed); err != nil {
		return V3SessionKeys{}, err
	}

	c2sReader := hkdf.Expand(sha256.New, seed, []byte("xtunnel-v3 c2s nonce"))
	c2sNoncePrefix := make([]byte, 4)
	if _, err := io.ReadFull(c2sReader, c2sNoncePrefix); err != nil {
		return V3SessionKeys{}, err
	}

	s2cReader := hkdf.Expand(sha256.New, seed, []byte("xtunnel-v3 s2c nonce"))
	s2cNoncePrefix := make([]byte, 4)
	if _, err := io.ReadFull(s2cReader, s2cNoncePrefix); err != nil {
		return V3SessionKeys{}, err
	}

	return V3SessionKeys{
		Seed:           seed,
		C2SNoncePrefix: c2sNoncePrefix,
		S2CNoncePrefix: s2cNoncePrefix,
	}, nil
}

// StreamKey derives a directional stream AEAD key for a specific cipher, stream ID, and generation.
func (k V3SessionKeys) StreamKey(cipherID byte, clientToServer bool, streamID uint32, gen uint64) ([]byte, error) {
	keyLen := V3CipherKeyLen(cipherID)
	if keyLen <= 0 {
		return nil, fmt.Errorf("unsupported cipher ID: %d", cipherID)
	}
	if len(k.Seed) != 32 {
		return nil, fmt.Errorf("invalid session seed length")
	}

	var label string
	if clientToServer {
		label = "xtunnel-v3 c2s key"
	} else {
		label = "xtunnel-v3 s2c key"
	}

	info := make([]byte, len(label)+1+4+8)
	copy(info, label)
	off := len(label)
	info[off] = cipherID
	binary.BigEndian.PutUint32(info[off+1:off+5], streamID)
	binary.BigEndian.PutUint64(info[off+5:off+13], gen)

	keyReader := hkdf.Expand(sha256.New, k.Seed, info)
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(keyReader, key); err != nil {
		return nil, err
	}
	return key, nil
}
