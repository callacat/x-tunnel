package wire

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

// testV3StreamKeys returns deterministic session keys for cipher stream tests.
func testV3StreamKeys(t *testing.T) V3SessionKeys {
	t.Helper()
	thFull, err := ComputeV3TranscriptHashFull("edge.example.com", "/tunnel", fixedChannelInitV3(), fixedTestServerPk(), fixedTestServerNonce(), ProtocolCipherChaCha20Poly1305)
	if err != nil {
		t.Fatalf("ComputeV3TranscriptHashFull error: %v", err)
	}
	keys, err := DeriveV3SessionSeed("secret-token", thFull, fixedTestSharedSecret())
	if err != nil {
		t.Fatalf("DeriveV3SessionSeed error: %v", err)
	}
	return keys
}

// Bug A: a tampered plaintext header counter must not poison the replay window.
// The window may only be advanced after AEAD verification succeeds.
func TestV3CipherStreamTamperedCounterDoesNotPoisonWindow(t *testing.T) {
	keys := testV3StreamKeys(t)

	var wire bytes.Buffer
	client, err := NewV3CipherStream(&nopCloser{Buffer: &wire}, keys, ProtocolCipherChaCha20Poly1305, 1, true)
	if err != nil {
		t.Fatalf("NewV3CipherStream error: %v", err)
	}
	client.PadRecords = false

	msg1 := []byte("first-record-payload")
	if _, err := client.Write(msg1); err != nil {
		t.Fatalf("Write record 1 error: %v", err)
	}
	raw := wire.Bytes()
	// Attacker forges the plaintext header counter to a far-future value.
	binary.BigEndian.PutUint64(raw[0:8], 1<<40)

	msg2 := []byte("second-record-payload")
	if _, err := client.Write(msg2); err != nil {
		t.Fatalf("Write record 2 error: %v", err)
	}

	server, err := NewV3CipherStream(&nopCloser{Buffer: &wire}, keys, ProtocolCipherChaCha20Poly1305, 1, false)
	if err != nil {
		t.Fatalf("NewV3CipherStream error: %v", err)
	}

	// Forged record must fail authentication.
	buf := make([]byte, 64)
	if _, err := server.Read(buf); err == nil {
		t.Fatal("expected authentication error for forged counter, got nil")
	}

	// The replay window must not have been poisoned: the next legitimate
	// record (counter 2) must still decrypt.
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("legitimate record rejected after forged record (replay window poisoned): %v", err)
	}
	if !bytes.Equal(buf[:n], msg2) {
		t.Fatalf("decrypted payload mismatch: got %q, want %q", string(buf[:n]), string(msg2))
	}
}

// Bug B: with padding enabled, the wire must not expose the true plaintext
// length as a readable header field. The 12-byte header may only carry the
// counter plus values that already include randomized padding.
func TestV3CipherStreamPaddingHidesPlainLength(t *testing.T) {
	keys := testV3StreamKeys(t)

	for i := 0; i < 50; i++ {
		var wire bytes.Buffer
		client, err := NewV3CipherStream(&nopCloser{Buffer: &wire}, keys, ProtocolCipherChaCha20Poly1305, 1, true)
		if err != nil {
			t.Fatalf("NewV3CipherStream error: %v", err)
		}
		client.PadRecords = true

		plain := bytes.Repeat([]byte{0x42}, 100)
		if _, err := client.Write(plain); err != nil {
			t.Fatalf("Write error: %v", err)
		}
		raw := wire.Bytes()
		if len(raw) < v3RecordHeaderSize+16 {
			t.Fatalf("iteration %d: record too short: %d", i, len(raw))
		}
		head := raw[:v3RecordHeaderSize]
		if got := binary.BigEndian.Uint16(head[8:10]); got == uint16(len(plain)) {
			t.Fatalf("iteration %d: plaintext length %d readable in header bytes 8:10", i, got)
		}
		if got := binary.BigEndian.Uint16(head[10:12]); got == uint16(len(plain)) && len(plain) > 2 {
			t.Fatalf("iteration %d: plaintext length %d readable in header bytes 10:12", i, got)
		}

		// Padding is actually exercised: total record length must vary / exceed plain+overhead sometimes.
		// Roundtrip must still work.
		server, err := NewV3CipherStream(&nopCloser{Buffer: bytes.NewBuffer(append([]byte(nil), raw...))}, keys, ProtocolCipherChaCha20Poly1305, 1, false)
		if err != nil {
			t.Fatalf("NewV3CipherStream error: %v", err)
		}
		out := make([]byte, len(plain))
		if _, err := io.ReadFull(server, out); err != nil {
			t.Fatalf("iteration %d: ReadFull error: %v", i, err)
		}
		if !bytes.Equal(out, plain) {
			t.Fatalf("iteration %d: decrypted payload mismatch", i)
		}
	}
}
