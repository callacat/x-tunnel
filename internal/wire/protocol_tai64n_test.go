package wire

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"
)

func TestTAI64NGoldenVectors(t *testing.T) {
	tests := []struct {
		name    string
		time    time.Time
		wantHex string
	}{
		{
			name:    "Unix 1700000000 + 500000000ns",
			time:    time.Unix(1700000000, 500000000).UTC(),
			wantHex: "400000006553f1001dcd6500",
		},
		{
			name:    "Unix Epoch 1970-01-01 00:00:00 UTC",
			time:    time.Unix(0, 0).UTC(),
			wantHex: "400000000000000000000000",
		},
		{
			name:    "WireGuard epoch (2^62 base) + 1234567890s + 999999999ns",
			time:    time.Unix(1234567890, 999999999).UTC(),
			wantHex: "40000000499602d23b9ac9ff",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeTAI64N(tt.time)
			gotHex := hex.EncodeToString(got)
			if gotHex != tt.wantHex {
				t.Fatalf("EncodeTAI64N(%v) = %s, want %s", tt.time, gotHex, tt.wantHex)
			}
			decoded, err := DecodeTAI64N(got)
			if err != nil {
				t.Fatalf("DecodeTAI64N(%s) error: %v", gotHex, err)
			}
			if !decoded.Equal(tt.time) {
				t.Fatalf("DecodeTAI64N(%s) = %v, want %v", gotHex, decoded, tt.time)
			}
		})
	}
}

func TestTAI64NRoundTrip(t *testing.T) {
	times := []time.Time{
		time.Unix(0, 0).UTC(),
		time.Unix(1, 1).UTC(),
		time.Unix(1700000000, 999999999).UTC(),
		time.Unix(2000000000, 123456789).UTC(),
		time.Now().UTC().Truncate(time.Nanosecond),
	}

	for _, tm := range times {
		encoded := EncodeTAI64N(tm)
		decoded, err := DecodeTAI64N(encoded)
		if err != nil {
			t.Fatalf("DecodeTAI64N error for %v: %v", tm, err)
		}
		if !decoded.Equal(tm) {
			t.Fatalf("Roundtrip mismatch: got %v, want %v", decoded, tm)
		}
	}
}

func TestTAI64NInvalidInputs(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "empty",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "too short (11 bytes)",
			input:   make([]byte, 11),
			wantErr: true,
		},
		{
			name:    "too long (13 bytes)",
			input:   make([]byte, 13),
			wantErr: true,
		},
		{
			name:    "sec < 2^62 (zeros)",
			input:   make([]byte, 12),
			wantErr: true,
		},
		{
			name:    "sec < 2^62 (0x3fffffffffffffff)",
			input:   []byte{0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0},
			wantErr: true,
		},
		{
			name:    "nanos >= 1e9 (1,000,000,000)",
			input:   []byte{0x40, 0, 0, 0, 0, 0, 0, 0, 0x3b, 0x9a, 0xca, 0x00},
			wantErr: true,
		},
		{
			name:    "valid boundary: sec == 2^62, nanos == 0",
			input:   []byte{0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			wantErr: false,
		},
		{
			name:    "valid boundary: sec == 2^62, nanos == 999999999",
			input:   []byte{0x40, 0, 0, 0, 0, 0, 0, 0, 0x3b, 0x9a, 0xc9, 0xff},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeTAI64N(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DecodeTAI64N() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestTAI64NComparison(t *testing.T) {
	t1 := EncodeTAI64N(time.Unix(100, 200).UTC())
	t2 := EncodeTAI64N(time.Unix(100, 300).UTC())
	t3 := EncodeTAI64N(time.Unix(101, 100).UTC())
	t1Copy := EncodeTAI64N(time.Unix(100, 200).UTC())

	// t1 < t2 (same sec, smaller nano)
	if CompareTAI64N(t1, t2) >= 0 || bytes.Compare(t1, t2) >= 0 {
		t.Errorf("expected t1 < t2")
	}
	// t2 < t3 (smaller sec)
	if CompareTAI64N(t2, t3) >= 0 || bytes.Compare(t2, t3) >= 0 {
		t.Errorf("expected t2 < t3")
	}
	// t1 == t1Copy
	if CompareTAI64N(t1, t1Copy) != 0 || bytes.Compare(t1, t1Copy) != 0 {
		t.Errorf("expected t1 == t1Copy")
	}
	// t3 > t1
	if CompareTAI64N(t3, t1) <= 0 || bytes.Compare(t3, t1) <= 0 {
		t.Errorf("expected t3 > t1")
	}
}
