package wire

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// discardRWC implements io.ReadWriteCloser by discarding all writes.
type discardRWC struct{}

func (discardRWC) Read(p []byte) (int, error)  { return 0, io.EOF }
func (discardRWC) Write(p []byte) (int, error) { return len(p), nil }
func (discardRWC) Close() error                { return nil }

// repeatingRecordReader provides continuous read streaming of a pre-sealed record.
type repeatingRecordReader struct {
	record []byte
	offset int
}

func (r *repeatingRecordReader) Read(p []byte) (int, error) {
	total := 0
	for total < len(p) {
		remain := len(r.record) - r.offset
		toCopy := len(p) - total
		if toCopy > remain {
			toCopy = remain
		}
		copy(p[total:total+toCopy], r.record[r.offset:r.offset+toCopy])
		total += toCopy
		r.offset += toCopy
		if r.offset >= len(r.record) {
			r.offset = 0 // loop
		}
	}
	return total, nil
}

func (r *repeatingRecordReader) Write(p []byte) (int, error) { return len(p), nil }
func (r *repeatingRecordReader) Close() error                { return nil }

type nopCloserBuffer struct {
	*bytes.Buffer
}

func (n *nopCloserBuffer) Close() error { return nil }

// BenchmarkV3DeriveSessionKeys benchmarks derivation of master seed and directional nonce prefixes with shared secret.
func BenchmarkV3DeriveSessionKeys(b *testing.B) {
	transcriptHash := sha256.Sum256([]byte("bench-transcript-sample"))
	shared := bytes.Repeat([]byte{0x42}, 32)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		keys, err := DeriveV3SessionSeed("bench-token", transcriptHash[:], shared)
		if err != nil {
			b.Fatal(err)
		}
		_ = keys
	}
}

// BenchmarkV3X25519 benchmarks X25519 ephemeral key generation and shared secret computation.
func BenchmarkV3X25519(b *testing.B) {
	sk1 := bytes.Repeat([]byte{0x01}, 32)
	sk2 := bytes.Repeat([]byte{0x02}, 32)
	pk2, _ := curve25519.X25519(sk2, curve25519.Basepoint)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk1, err := curve25519.X25519(sk1, curve25519.Basepoint)
		if err != nil {
			b.Fatal(err)
		}
		shared, err := ComputeV3SharedSecret(sk1, pk2)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = pk1, shared
	}
}

// BenchmarkV3StreamKeyDerive benchmarks deriving a per-stream AEAD key.
func BenchmarkV3StreamKeyDerive(b *testing.B) {
	transcriptHash := sha256.Sum256([]byte("bench-transcript-sample"))
	shared := bytes.Repeat([]byte{0x42}, 32)
	keys, err := DeriveV3SessionSeed("bench-token", transcriptHash[:], shared)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k, err := keys.StreamKey(ProtocolCipherChaCha20Poly1305, true, 1, 0)
		if err != nil {
			b.Fatal(err)
		}
		_ = k
	}
}

// BenchmarkV3RecordSeal benchmarks framing, encryption, and authentication of 1400B records.
func BenchmarkV3RecordSeal(b *testing.B) {
	transcriptHash := sha256.Sum256([]byte("bench-transcript-sample"))
	shared := bytes.Repeat([]byte{0x42}, 32)
	keys, err := DeriveV3SessionSeed("bench-token", transcriptHash[:], shared)
	if err != nil {
		b.Fatal(err)
	}

	payload := bytes.Repeat([]byte("a"), 1400)

	cases := []struct {
		name     string
		cipherID byte
	}{
		{"ChaCha20Poly1305", ProtocolCipherChaCha20Poly1305},
		{"AES256GCM", ProtocolCipherAES256GCM},
		{"AES128GCM", ProtocolCipherAES128GCM},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			stream, err := NewV3CipherStream(discardRWC{}, keys, tc.cipherID, 1, true)
			if err != nil {
				b.Fatal(err)
			}
			// Warm up 1 write so cipher is initialized and buffer preallocated
			if _, err := stream.Write(payload); err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := stream.Write(payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkV3RecordSealPadded benchmarks framing, uniform padding sampling, encryption, and authentication of smaller payloads padded to target sizes up to 1400B.
func BenchmarkV3RecordSealPadded(b *testing.B) {
	transcriptHash := sha256.Sum256([]byte("bench-transcript-sample"))
	shared := bytes.Repeat([]byte{0x42}, 32)
	keys, err := DeriveV3SessionSeed("bench-token", transcriptHash[:], shared)
	if err != nil {
		b.Fatal(err)
	}

	payload := bytes.Repeat([]byte("a"), 500)

	cases := []struct {
		name     string
		cipherID byte
	}{
		{"ChaCha20Poly1305", ProtocolCipherChaCha20Poly1305},
		{"AES256GCM", ProtocolCipherAES256GCM},
		{"AES128GCM", ProtocolCipherAES128GCM},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			stream, err := NewV3CipherStream(discardRWC{}, keys, tc.cipherID, 1, true)
			if err != nil {
				b.Fatal(err)
			}
			stream.PadRecords = true
			if _, err := stream.Write(payload); err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := stream.Write(payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkV3RecordOpen benchmarks reading, parsing, and decrypting 1400B records.
func BenchmarkV3RecordOpen(b *testing.B) {
	transcriptHash := sha256.Sum256([]byte("bench-transcript-sample"))
	shared := bytes.Repeat([]byte{0x42}, 32)
	keys, err := DeriveV3SessionSeed("bench-token", transcriptHash[:], shared)
	if err != nil {
		b.Fatal(err)
	}

	payload := bytes.Repeat([]byte("a"), 1400)

	cases := []struct {
		name     string
		cipherID byte
	}{
		{"ChaCha20Poly1305", ProtocolCipherChaCha20Poly1305},
		{"AES256GCM", ProtocolCipherAES256GCM},
		{"AES128GCM", ProtocolCipherAES128GCM},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			// Seal one sample record using client stream
			var recordBuf bytes.Buffer
			writeStream, err := NewV3CipherStream(&nopCloserBuffer{Buffer: &recordBuf}, keys, tc.cipherID, 1, true)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := writeStream.Write(payload); err != nil {
				b.Fatal(err)
			}
			sealedRecord := recordBuf.Bytes()

			reader := &repeatingRecordReader{record: sealedRecord}
			readStream, err := NewV3CipherStream(reader, keys, tc.cipherID, 1, false)
			if err != nil {
				b.Fatal(err)
			}

			out := make([]byte, len(payload))
			// Warm up 1 read to initialize cipher and buffers
			if _, err := readStream.Read(out); err != nil {
				b.Fatal(err)
			}

			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				readStream.readWindow = replayWindow{}
				n, err := readStream.Read(out)
				if err != nil {
					b.Fatal(err)
				}
				if n != len(payload) {
					b.Fatalf("read %d bytes, want %d", n, len(payload))
				}
			}
		})
	}
}

// BenchmarkV3ReplayWindowCheck benchmarks the 2048-bit sliding bitmap anti-replay check for sequential sequence numbers.
func BenchmarkV3ReplayWindowCheck(b *testing.B) {
	var rw replayWindow
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seq := uint64(i + 1)
		if !rw.checkAndAdd(seq) {
			b.Fatalf("seq %d rejected", seq)
		}
	}
}
