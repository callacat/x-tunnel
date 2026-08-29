package wire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// ErrUnsupported is returned when an optional operation (such as setting deadlines) is not supported by the underlying stream.
var ErrUnsupported = errors.ErrUnsupported

const defaultRekeyInterval uint64 = 1 << 32

const (
	maxV3RecordPayload     = 1400
	coalesceFlushThreshold = 1024
	v3RecordHeaderSize     = 12
)

const (
	replayWindowSize  = 2048
	replayWindowWords = replayWindowSize / 64 // 32 uint64 words
)

// replayWindow tracks received sequence numbers using a 2048-bit sliding bitmap (RFC 6479 style).
type replayWindow struct {
	maxSeq uint64
	bitmap [replayWindowWords]uint64
}

func (w *replayWindow) checkAndAdd(seq uint64) bool {
	if seq == 0 {
		return false
	}

	if seq > w.maxSeq {
		diff := seq - w.maxSeq
		if diff >= replayWindowSize {
			// Advanced beyond entire window; reset bitmap
			for i := range w.bitmap {
				w.bitmap[i] = 0
			}
		} else {
			// Clear bits between old maxSeq and new seq
			for s := w.maxSeq + 1; s <= seq; s++ {
				idx := (s - 1) % replayWindowSize
				wordIdx := idx / 64
				bitIdx := idx % 64
				w.bitmap[wordIdx] &^= (1 << bitIdx)
			}
		}
		w.maxSeq = seq
		idx := (seq - 1) % replayWindowSize
		w.bitmap[idx/64] |= (1 << (idx % 64))
		return true
	}

	// seq <= w.maxSeq
	if w.maxSeq-seq >= replayWindowSize {
		// Too old, outside the 2048-packet window
		return false
	}

	idx := (seq - 1) % replayWindowSize
	wordIdx := idx / 64
	bitIdx := idx % 64
	if (w.bitmap[wordIdx] & (1 << bitIdx)) != 0 {
		return false
	}
	w.bitmap[wordIdx] |= (1 << bitIdx)
	return true
}

func newAEAD(cipherID byte, key []byte) (cipher.AEAD, error) {
	switch cipherID {
	case ProtocolCipherChaCha20Poly1305:
		return chacha20poly1305.New(key)
	case ProtocolCipherAES256GCM, ProtocolCipherAES128GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	default:
		return nil, fmt.Errorf("unsupported cipher: %d", cipherID)
	}
}

// V3CipherStream wraps an underlying io.ReadWriteCloser with authenticated encryption (AEAD).
type V3CipherStream struct {
	inner    io.ReadWriteCloser
	keys     V3SessionKeys
	cipherID byte
	streamID uint32

	RekeyInterval uint64        // Rekey interval in records; default 1<<32 if 0
	PadRecords    bool          // Enable uniform random padding up to maxV3RecordPayload; defaults to true in NewV3CipherStream
	CoalesceDelay time.Duration // If > 0, buffer small writes up to CoalesceDelay or coalesceFlushThreshold before flushing; default 0 (disabled)

	writeMu          sync.Mutex
	writeCounter     uint64
	writeC2S         bool
	writeNoncePrefix []byte
	writeAEAD        cipher.AEAD
	writeGen         uint64
	writeBuf         []byte
	writePayloadBuf  [maxV3RecordPayload]byte
	coalesceBuf      []byte
	coalesceTimer    *time.Timer
	closed           bool

	readMu          sync.Mutex
	readC2S         bool
	readNoncePrefix []byte
	readAEAD        cipher.AEAD
	readGen         uint64
	readWindow      replayWindow
	readPlainBuf    []byte
	readCipherBuf   []byte
	readPlainAlloc  []byte
}

func sampleRecordPadLen(maxPad int) int {
	if maxPad <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(maxPad+1)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}

// NewV3CipherStream creates a new AEAD-wrapped cipher stream.
func NewV3CipherStream(inner io.ReadWriteCloser, keys V3SessionKeys, cipherID byte, streamID uint32, clientSide bool) (*V3CipherStream, error) {
	if !isSupportedCipherV3(cipherID) {
		return nil, fmt.Errorf("unsupported cipher: %d", cipherID)
	}
	if len(keys.C2SNoncePrefix) != 4 || len(keys.S2CNoncePrefix) != 4 {
		return nil, fmt.Errorf("invalid nonce prefix in session keys")
	}

	s := &V3CipherStream{
		inner:         inner,
		keys:          keys,
		cipherID:      cipherID,
		streamID:      streamID,
		RekeyInterval: defaultRekeyInterval,
		PadRecords:    true,
		CoalesceDelay: 0,
	}

	if clientSide {
		s.writeC2S = true
		s.writeNoncePrefix = keys.C2SNoncePrefix
		s.readC2S = false
		s.readNoncePrefix = keys.S2CNoncePrefix
	} else {
		s.writeC2S = false
		s.writeNoncePrefix = keys.S2CNoncePrefix
		s.readC2S = true
		s.readNoncePrefix = keys.C2SNoncePrefix
	}

	return s, nil
}

func (s *V3CipherStream) writeRecordLocked(plain []byte) error {
	plainLen := len(plain)
	if plainLen == 0 {
		return nil
	}
	if plainLen > maxV3RecordPayload {
		return fmt.Errorf("plaintext length %d exceeds maximum record payload %d", plainLen, maxV3RecordPayload)
	}

	if s.writeCounter == math.MaxUint64 {
		return fmt.Errorf("write counter overflow")
	}
	s.writeCounter++
	counter := s.writeCounter

	interval := s.RekeyInterval
	if interval == 0 {
		interval = defaultRekeyInterval
	}
	gen := (counter - 1) / interval
	if s.writeAEAD == nil || gen != s.writeGen {
		key, err := s.keys.StreamKey(s.cipherID, s.writeC2S, s.streamID, gen)
		if err != nil {
			return err
		}
		aead, err := newAEAD(s.cipherID, key)
		if err != nil {
			return err
		}
		s.writeAEAD = aead
		s.writeGen = gen
	}

	padLen := 0
	if s.PadRecords {
		padLen = sampleRecordPadLen(maxV3RecordPayload - plainLen)
	}

	payloadLen := plainLen + padLen
	cipherLen := payloadLen + 16
	totalLen := v3RecordHeaderSize + cipherLen

	if cap(s.writeBuf) < totalLen {
		s.writeBuf = make([]byte, totalLen)
	} else {
		s.writeBuf = s.writeBuf[:totalLen]
	}

	// 12-byte header: counter (8B BE) | plain_len (2B BE) | pad_len (2B BE)
	binary.BigEndian.PutUint64(s.writeBuf[0:8], counter)
	binary.BigEndian.PutUint16(s.writeBuf[8:10], uint16(plainLen))
	binary.BigEndian.PutUint16(s.writeBuf[10:12], uint16(padLen))

	var nonce [12]byte
	copy(nonce[0:4], s.writeNoncePrefix)
	binary.BigEndian.PutUint64(nonce[4:12], counter)

	var ad [8]byte
	binary.BigEndian.PutUint64(ad[0:8], counter)

	copy(s.writePayloadBuf[:plainLen], plain)
	if padLen > 0 {
		if _, err := rand.Read(s.writePayloadBuf[plainLen:payloadLen]); err != nil {
			for i := plainLen; i < payloadLen; i++ {
				s.writePayloadBuf[i] = 0
			}
		}
	}

	sealed := s.writeAEAD.Seal(s.writeBuf[v3RecordHeaderSize:v3RecordHeaderSize], nonce[:], s.writePayloadBuf[:payloadLen], ad[:])
	recordBytes := s.writeBuf[:v3RecordHeaderSize+len(sealed)]

	_, err := s.inner.Write(recordBytes)
	return err
}

func (s *V3CipherStream) flushCoalesceBufLocked() error {
	for len(s.coalesceBuf) > 0 {
		chunkSize := len(s.coalesceBuf)
		if chunkSize > maxV3RecordPayload {
			chunkSize = maxV3RecordPayload
		}
		if err := s.writeRecordLocked(s.coalesceBuf[:chunkSize]); err != nil {
			return err
		}
		s.coalesceBuf = s.coalesceBuf[chunkSize:]
	}
	s.coalesceBuf = s.coalesceBuf[:0]
	return nil
}

func (s *V3CipherStream) onCoalesceTimer() {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.closed || len(s.coalesceBuf) == 0 {
		s.coalesceTimer = nil
		return
	}
	_ = s.flushCoalesceBufLocked()
	s.coalesceTimer = nil
}

// Write encrypts and sends plaintext in AEAD record frames.
func (s *V3CipherStream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if s.closed {
		return 0, io.ErrClosedPipe
	}

	if s.CoalesceDelay <= 0 {
		if len(s.coalesceBuf) > 0 {
			if err := s.flushCoalesceBufLocked(); err != nil {
				return 0, err
			}
		}
		totalWritten := 0
		for len(p) > 0 {
			chunkSize := len(p)
			if chunkSize > maxV3RecordPayload {
				chunkSize = maxV3RecordPayload
			}
			chunk := p[:chunkSize]
			if err := s.writeRecordLocked(chunk); err != nil {
				return totalWritten, err
			}
			totalWritten += chunkSize
			p = p[chunkSize:]
		}
		return totalWritten, nil
	}

	// Coalescing enabled (CoalesceDelay > 0)
	s.coalesceBuf = append(s.coalesceBuf, p...)
	totalWritten := len(p)

	for len(s.coalesceBuf) >= coalesceFlushThreshold {
		chunkSize := len(s.coalesceBuf)
		if chunkSize > maxV3RecordPayload {
			chunkSize = maxV3RecordPayload
		}
		if err := s.writeRecordLocked(s.coalesceBuf[:chunkSize]); err != nil {
			return 0, err
		}
		remaining := len(s.coalesceBuf) - chunkSize
		copy(s.coalesceBuf, s.coalesceBuf[chunkSize:])
		s.coalesceBuf = s.coalesceBuf[:remaining]
	}

	if len(s.coalesceBuf) == 0 {
		if s.coalesceTimer != nil {
			s.coalesceTimer.Stop()
			s.coalesceTimer = nil
		}
	} else {
		if s.coalesceTimer == nil {
			s.coalesceTimer = time.AfterFunc(s.CoalesceDelay, s.onCoalesceTimer)
		}
	}

	return totalWritten, nil
}

// Read decrypts and reads plaintext from AEAD record frames.
func (s *V3CipherStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.readMu.Lock()
	defer s.readMu.Unlock()

	if len(s.readPlainBuf) > 0 {
		n := copy(p, s.readPlainBuf)
		s.readPlainBuf = s.readPlainBuf[n:]
		return n, nil
	}

	var head [v3RecordHeaderSize]byte
	if _, err := io.ReadFull(s.inner, head[:]); err != nil {
		return 0, err
	}
	counter := binary.BigEndian.Uint64(head[0:8])
	plainLen := int(binary.BigEndian.Uint16(head[8:10]))
	padLen := int(binary.BigEndian.Uint16(head[10:12]))

	if counter < 1 {
		return 0, fmt.Errorf("invalid record counter: %d", counter)
	}
	if plainLen < 1 {
		return 0, fmt.Errorf("invalid record plaintext length: %d", plainLen)
	}
	if padLen < 0 || plainLen+padLen > maxV3RecordPayload {
		return 0, fmt.Errorf("invalid record payload length: plain=%d pad=%d", plainLen, padLen)
	}

	if !s.readWindow.checkAndAdd(counter) {
		return 0, fmt.Errorf("record counter rejected (replay or out of window): %d", counter)
	}

	interval := s.RekeyInterval
	if interval == 0 {
		interval = defaultRekeyInterval
	}
	gen := (counter - 1) / interval
	if s.readAEAD == nil || gen != s.readGen {
		key, err := s.keys.StreamKey(s.cipherID, s.readC2S, s.streamID, gen)
		if err != nil {
			return 0, err
		}
		aead, err := newAEAD(s.cipherID, key)
		if err != nil {
			return 0, err
		}
		s.readAEAD = aead
		s.readGen = gen
	}

	payloadLen := plainLen + padLen
	cipherLen := payloadLen + 16
	if cap(s.readCipherBuf) < cipherLen {
		s.readCipherBuf = make([]byte, cipherLen)
	} else {
		s.readCipherBuf = s.readCipherBuf[:cipherLen]
	}
	if _, err := io.ReadFull(s.inner, s.readCipherBuf); err != nil {
		return 0, err
	}

	var nonce [12]byte
	copy(nonce[0:4], s.readNoncePrefix)
	binary.BigEndian.PutUint64(nonce[4:12], counter)

	var ad [8]byte
	binary.BigEndian.PutUint64(ad[0:8], counter)

	if cap(s.readPlainAlloc) < payloadLen {
		s.readPlainAlloc = make([]byte, 0, payloadLen)
	}
	decrypted, err := s.readAEAD.Open(s.readPlainAlloc[:0], nonce[:], s.readCipherBuf, ad[:])
	if err != nil {
		return 0, fmt.Errorf("record decryption failed: %w", err)
	}
	if len(decrypted) != payloadLen {
		return 0, fmt.Errorf("decrypted length mismatch: got %d, want %d", len(decrypted), payloadLen)
	}
	s.readPlainAlloc = decrypted

	plain := decrypted[:plainLen]
	n := copy(p, plain)
	s.readPlainBuf = plain[n:]
	return n, nil
}

// Close closes the underlying stream and flushes any buffered coalesce data.
func (s *V3CipherStream) Close() error {
	s.writeMu.Lock()
	if s.coalesceTimer != nil {
		s.coalesceTimer.Stop()
		s.coalesceTimer = nil
	}
	if len(s.coalesceBuf) > 0 {
		_ = s.flushCoalesceBufLocked()
	}
	s.closed = true
	s.writeMu.Unlock()
	return s.inner.Close()
}

// SetDeadline sets read and write deadlines if supported by the underlying stream.
func (s *V3CipherStream) SetDeadline(t time.Time) error {
	if d, ok := s.inner.(interface{ SetDeadline(time.Time) error }); ok {
		return d.SetDeadline(t)
	}
	return ErrUnsupported
}

// SetReadDeadline sets the read deadline if supported by the underlying stream.
func (s *V3CipherStream) SetReadDeadline(t time.Time) error {
	if d, ok := s.inner.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return ErrUnsupported
}

// SetWriteDeadline sets the write deadline if supported by the underlying stream.
func (s *V3CipherStream) SetWriteDeadline(t time.Time) error {
	if d, ok := s.inner.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return d.SetWriteDeadline(t)
	}
	return ErrUnsupported
}
