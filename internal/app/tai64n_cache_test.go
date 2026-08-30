package app

import (
	"sync"
	"testing"
	"time"
)

// TestTAI64NCacheFreshnessWindow verifies the freshness-window semantics:
// timestamps within the allowed skew are accepted regardless of order,
// including identical nanosecond timestamps from parallel handshakes;
// timestamps outside the skew are rejected.
func TestTAI64NCacheFreshnessWindow(t *testing.T) {
	cache := newTAI64NCache(16)
	session := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	now := time.Now()
	skew := 5 * time.Minute

	// Out-of-order arrivals within the skew must all be accepted.
	offsets := []time.Duration{-time.Second, -500 * time.Millisecond, 0, time.Second, 500 * time.Millisecond}
	for _, off := range offsets {
		ts := encodeTAI64N(now.Add(off))
		if !cache.CheckAndStore(session, ts, now, skew) {
			t.Fatalf("freshness window: timestamp offset %v wrongly rejected", off)
		}
	}

	// Identical nanosecond timestamp arriving again (parallel handshake with
	// a different client nonce) must not be rejected by the TAI64N cache.
	dup := encodeTAI64N(now)
	if !cache.CheckAndStore(session, dup, now, skew) {
		t.Fatal("duplicate timestamp for same session wrongly rejected")
	}

	// Timestamps beyond the skew must be rejected.
	if cache.CheckAndStore(session, encodeTAI64N(now.Add(-skew-2*time.Second)), now, skew) {
		t.Fatal("timestamp older than skew must be rejected")
	}
	if cache.CheckAndStore(session, encodeTAI64N(now.Add(skew+2*time.Second)), now, skew) {
		t.Fatal("timestamp newer than skew must be rejected")
	}

	// Invalid timestamps must be rejected.
	if cache.CheckAndStore(session, []byte{1, 2, 3}, now, skew) {
		t.Fatal("malformed TAI64N must be rejected")
	}
	if cache.CheckAndStore(session[:8], encodeTAI64N(now), now, skew) {
		t.Fatal("invalid sessionID length must be rejected")
	}

	// skew <= 0 disables the freshness check (consistent with validateChannelInitTime).
	if !cache.CheckAndStore(session, encodeTAI64N(now.Add(-time.Hour)), now, 0) {
		t.Fatal("skew<=0 must disable freshness rejection")
	}
}

// TestTAI64NCacheParallelHandshakeSameSession simulates parallel multi-channel
// handshakes sharing one client UUID (sessionID): identical or out-of-order
// nanosecond timestamps must all be accepted.
func TestTAI64NCacheParallelHandshakeSameSession(t *testing.T) {
	cache := newTAI64NCache(100)
	session := []byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}
	now := time.Now()
	skew := 5 * time.Minute

	const goroutines = 32
	errs := make(chan string, goroutines*2)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			// All goroutines share the exact same nanosecond timestamp.
			if !cache.CheckAndStore(session, encodeTAI64N(now), now, skew) {
				errs <- "identical timestamp rejected"
			}
			// Slightly jittered, out-of-order timestamps.
			off := time.Duration(goroutines/2-id) * time.Millisecond
			if !cache.CheckAndStore(session, encodeTAI64N(now.Add(off)), now, skew) {
				errs <- "out-of-order timestamp rejected"
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}
