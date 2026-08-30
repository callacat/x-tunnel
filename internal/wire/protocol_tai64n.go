package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const tai64Base uint64 = 1 << 62 // 0x4000000000000000

// EncodeTAI64N encodes a time.Time into a 12-byte TAI64N timestamp.
// 12 bytes = 8-byte big-endian (2^62 + unix seconds) || 4-byte big-endian nanoseconds (0..999999999).
// Following WireGuard, leap second adjustments are omitted.
func EncodeTAI64N(t time.Time) []byte {
	b := make([]byte, 12)
	sec := uint64(t.Unix()) + tai64Base
	nanos := uint32(t.Nanosecond())
	binary.BigEndian.PutUint64(b[:8], sec)
	binary.BigEndian.PutUint32(b[8:12], nanos)
	return b
}

// DecodeTAI64N decodes a 12-byte TAI64N timestamp into a UTC time.Time.
// The input must be exactly 12 bytes, the seconds part must be >= 2^62,
// and nanoseconds must be in the range [0, 999999999].
// Following WireGuard, leap second adjustments are omitted.
func DecodeTAI64N(b []byte) (time.Time, error) {
	if len(b) != 12 {
		return time.Time{}, fmt.Errorf("tai64n timestamp must be 12 bytes: got %d", len(b))
	}
	sec := binary.BigEndian.Uint64(b[:8])
	if sec < tai64Base {
		return time.Time{}, errors.New("invalid tai64n seconds: must be >= 2^62")
	}
	nanos := binary.BigEndian.Uint32(b[8:12])
	if nanos >= 1_000_000_000 {
		return time.Time{}, fmt.Errorf("invalid tai64n nanoseconds: %d >= 1000000000", nanos)
	}
	unixSec := int64(sec - tai64Base)
	return time.Unix(unixSec, int64(nanos)).UTC(), nil
}

// CompareTAI64N compares two 12-byte TAI64N timestamps in big-endian lexicographical order.
// Returns -1 if a < b, 0 if a == b, and +1 if a > b.
func CompareTAI64N(a, b []byte) int {
	return bytes.Compare(a, b)
}
