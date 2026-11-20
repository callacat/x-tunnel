package wire

import (
	"bytes"
	"crypto/sha256"
	"io"
	"sync"
	"testing"
)

// readWriter wraps an io.Reader into an io.ReadWriteCloser (Write/Close are
// unused by the read direction of the cipher stream).
type readWriter struct {
	io.Reader
}

func (w readWriter) Write(p []byte) (int, error) { return 0, io.ErrClosedPipe }
func (w readWriter) Close() error                { return nil }

// countWriter counts Write calls and accumulates payload bytes.
type countWriter struct {
	mu    sync.Mutex
	calls int
	bytes int64
	buf   bytes.Buffer
}

func (c *countWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.calls++
	c.bytes += int64(len(p))
	c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *countWriter) Read(p []byte) (int, error) { return 0, io.EOF }

func (c *countWriter) Close() error { return nil }

func (c *countWriter) stats() (calls int, bytes int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls, c.bytes
}

func coalesceTestKeys(t *testing.T) V3SessionKeys {
	t.Helper()
	transcriptHash := sha256.Sum256([]byte("coalesce-test"))
	shared := bytes.Repeat([]byte{0x42}, 32)
	keys, err := DeriveV3SessionSeed("bench-token", transcriptHash[:], shared)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// TestV3CipherStreamCoalescesWrites asserts that a single large Write results
// in a small number of underlying writes (one smux frame worth), instead of one
// write per ~1380B AEAD record. Fewer underlying writes mean fewer WebSocket
// and TLS records per byte on the smux carrier.
func TestV3CipherStreamCoalescesWrites(t *testing.T) {
	keys := coalesceTestKeys(t)
	payload := bytes.Repeat([]byte("a"), 32*1024) // 32 KiB, like io.Copy's buffer

	w := &countWriter{}
	stream, err := NewV3CipherStream(w, keys, ProtocolCipherChaCha20Poly1305, 7, true)
	if err != nil {
		t.Fatal(err)
	}

	if n, err := stream.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write returned n=%d err=%v, want %d nil", n, err, len(payload))
	}

	calls, _ := w.stats()
	// 32 KiB plaintext -> ~34 KiB ciphertext -> smux frames at 32 KiB => at most 2 frames.
	if calls > 2 {
		t.Fatalf("expected <= 2 underlying writes for 32 KiB payload, got %d", calls)
	}
}

// TestV3CipherStreamCoalesceSmallWrite ensures small/interactive writes are not
// delayed or merged beyond a single underlying write (no latency regression).
func TestV3CipherStreamCoalesceSmallWrite(t *testing.T) {
	keys := coalesceTestKeys(t)
	payload := bytes.Repeat([]byte("a"), 100)

	w := &countWriter{}
	stream, err := NewV3CipherStream(w, keys, ProtocolCipherChaCha20Poly1305, 7, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	calls, _ := w.stats()
	if calls != 1 {
		t.Fatalf("expected exactly 1 underlying write for 100B payload, got %d", calls)
	}
}

// TestV3CipherStreamCoalesceRoundTrip seals a payload through the coalescing
// write path and opens it back through a matching read stream, confirming the
// refactor did not break record framing/encryption.
func TestV3CipherStreamCoalesceRoundTrip(t *testing.T) {
	keys := coalesceTestKeys(t)
	payload := bytes.Repeat([]byte("a"), 1000)

	var sealed bytes.Buffer
	writeStream, err := NewV3CipherStream(&nopCloserBuffer{Buffer: &sealed}, keys, ProtocolCipherChaCha20Poly1305, 7, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writeStream.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writeStream.Close(); err != nil {
		t.Fatal(err)
	}

	readStream, err := NewV3CipherStream(&nopCloserBuffer{Buffer: bytes.NewBuffer(sealed.Bytes())}, keys, ProtocolCipherChaCha20Poly1305, 7, false)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(payload))
	n, err := io.ReadFull(readStream, out)
	if err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if n != len(payload) || !bytes.Equal(out, payload) {
		t.Fatalf("round-trip mismatch: got %d bytes", n)
	}
}
