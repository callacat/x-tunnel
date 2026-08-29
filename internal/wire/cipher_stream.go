package wire

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// ErrUnsupported is returned when an optional operation (such as setting deadlines) is not supported by the underlying stream.
var ErrUnsupported = errors.ErrUnsupported

const defaultRekeyInterval uint64 = 1 << 32

const (
	replayWindowSize  = 2048
	replayWindowWords = replayWindowSize / 64 // 32 uint64 words
)

// replayWindow implements an RFC 6479 style 2048-bit sliding bitmap window for anti-replay.
type replayWindow struct {
	maxSeq uint64
	bitmap [replayWindowWords]uint64
}

// checkAndAdd returns true if seq (must be >= 1) is accepted and not replayed, false otherwise.
func (w *replayWindow) checkAndAdd(seq uint64) bool {
	if seq == 0 {
		return false
	}
	if seq > w.maxSeq {
		diff := seq - w.maxSeq
		if diff >= replayWindowSize {
			for i := range w.bitmap {
				w.bitmap[i] = 0
			}
		} else {
			for s := w.maxSeq + 1; s <= seq; s++ {
				idx := (s - 1) % replayWindowSize
				w.bitmap[idx/64] &^= (1 << (idx % 64))
			}
		}
		w.maxSeq = seq
		idx := (seq - 1) % replayWindowSize
		w.bitmap[idx/64] |= (1 << (idx % 64))
		return true
	}

	if w.maxSeq-seq >= replayWindowSize {
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

	RekeyInterval uint64 // Rekey interval in records; default 1<<32 if 0

	writeMu          sync.Mutex
	writeCounter     uint64
	writeC2S         bool
	writeNoncePrefix []byte
	writeAEAD        cipher.AEAD
	writeGen         uint64
	writeBuf         []byte

	readMu          sync.Mutex
	readC2S         bool
	readNoncePrefix []byte
	readWindow      replayWindow
	readAEAD        cipher.AEAD
	readGen         uint64
	readCipherBuf   []byte
	readPlainAlloc  []byte
	readPlainBuf    []byte
}

// NewV3CipherStream creates a new authenticated encrypted stream wrapper.
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

// Write encrypts and sends plaintext in AEAD record frames.
func (s *V3CipherStream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	totalWritten := 0
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > 65535 {
			chunkSize = 65535
		}
		chunk := p[:chunkSize]

		if s.writeCounter == math.MaxUint64 {
			return totalWritten, fmt.Errorf("write counter overflow")
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
				return totalWritten, err
			}
			aead, err := newAEAD(s.cipherID, key)
			if err != nil {
				return totalWritten, err
			}
			s.writeAEAD = aead
			s.writeGen = gen
		}

		var nonce [12]byte
		copy(nonce[0:4], s.writeNoncePrefix)
		binary.BigEndian.PutUint64(nonce[4:12], counter)

		var ad [8]byte
		binary.BigEndian.PutUint64(ad[0:8], counter)

		needed := 10 + chunkSize + 16
		if cap(s.writeBuf) < needed {
			s.writeBuf = make([]byte, 10, needed)
		} else {
			s.writeBuf = s.writeBuf[:10]
		}
		binary.BigEndian.PutUint64(s.writeBuf[0:8], counter)
		binary.BigEndian.PutUint16(s.writeBuf[8:10], uint16(chunkSize))

		s.writeBuf = s.writeAEAD.Seal(s.writeBuf, nonce[:], chunk, ad[:])

		if err := writeAll(s.inner, s.writeBuf); err != nil {
			return totalWritten, err
		}

		totalWritten += chunkSize
		p = p[chunkSize:]
	}

	return totalWritten, nil
}

// Read reads and decrypts the next record into p.
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

	var head [10]byte
	if _, err := io.ReadFull(s.inner, head[:]); err != nil {
		return 0, err
	}
	counter := binary.BigEndian.Uint64(head[0:8])
	plainLen := int(binary.BigEndian.Uint16(head[8:10]))

	if counter < 1 {
		return 0, fmt.Errorf("invalid record counter: %d", counter)
	}
	if plainLen < 1 {
		return 0, fmt.Errorf("invalid record plaintext length: %d", plainLen)
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

	cipherLen := plainLen + 16
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

	if cap(s.readPlainAlloc) < plainLen {
		s.readPlainAlloc = make([]byte, 0, plainLen)
	}
	decrypted, err := s.readAEAD.Open(s.readPlainAlloc[:0], nonce[:], s.readCipherBuf, ad[:])
	if err != nil {
		return 0, fmt.Errorf("record decryption failed: %w", err)
	}
	s.readPlainAlloc = decrypted

	n := copy(p, decrypted)
	s.readPlainBuf = decrypted[n:]
	return n, nil
}

// Close closes the underlying stream.
func (s *V3CipherStream) Close() error {
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
