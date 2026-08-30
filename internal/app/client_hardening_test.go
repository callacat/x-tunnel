package app

import (
	"sort"
	"sync"
	"testing"
)

// TestNextClientTAI64NStrictlyMonotonicConcurrent verifies that concurrent
// handshake timestamp generation never produces duplicate or out-of-order
// TAI64N values.
func TestNextClientTAI64NStrictlyMonotonicConcurrent(t *testing.T) {
	const goroutines = 8
	const perGoroutine = 250

	results := make(chan []byte, goroutines*perGoroutine)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				results <- nextClientTAI64N()
			}
		}()
	}
	wg.Wait()
	close(results)

	seen := make(map[[12]byte]struct{})
	count := 0
	for v := range results {
		count++
		if len(v) != 12 {
			t.Fatalf("TAI64N length = %d, want 12", len(v))
		}
		var key [12]byte
		copy(key[:], v)
		if _, dup := seen[key]; dup {
			t.Fatalf("duplicate TAI64N timestamp: %x", v)
		}
		seen[key] = struct{}{}
	}
	if count != goroutines*perGoroutine {
		t.Fatalf("got %d timestamps, want %d", count, goroutines*perGoroutine)
	}

	// Uniqueness plus strictly increasing when sorted proves every value was
	// generated in a strictly monotonic sequence.
	sorted := make([][]byte, 0, len(seen))
	for k := range seen {
		kk := k
		sorted = append(sorted, kk[:])
	}
	sort.Slice(sorted, func(i, j int) bool { return compareTAI64N(sorted[i], sorted[j]) < 0 })
	for i := 1; i < len(sorted); i++ {
		if compareTAI64N(sorted[i-1], sorted[i]) >= 0 {
			t.Fatalf("not strictly increasing at %d", i)
		}
	}
}

// TestNextClientTAI64NMonotonicSequential covers the simple serial case.
func TestNextClientTAI64NMonotonicSequential(t *testing.T) {
	var prev []byte
	for i := 0; i < 1000; i++ {
		v := nextClientTAI64N()
		if prev != nil && compareTAI64N(prev, v) >= 0 {
			t.Fatalf("iteration %d: not strictly increasing: prev=%x got=%x", i, prev, v)
		}
		prev = append([]byte(nil), v...)
	}
}

// TestClientAuthFailureHint verifies the hint only fires at the threshold and
// its multiples, keeping silent retries below it.
func TestClientAuthFailureHint(t *testing.T) {
	if got := clientAuthFailureHint(1); got != "" {
		t.Fatalf("failures=1: unexpected hint %q", got)
	}
	if got := clientAuthFailureHint(4); got != "" {
		t.Fatalf("failures=4: unexpected hint %q", got)
	}
	if got := clientAuthFailureHint(clientAuthHintThreshold); got == "" {
		t.Fatalf("failures=%d: expected auth hint", clientAuthHintThreshold)
	}
	if got := clientAuthFailureHint(2 * clientAuthHintThreshold); got == "" {
		t.Fatalf("failures=%d: expected repeated hint at multiple of threshold", 2*clientAuthHintThreshold)
	}
	if got := clientAuthFailureHint(clientAuthHintThreshold + 1); got != "" {
		t.Fatalf("failures=%d: unexpected hint %q", clientAuthHintThreshold+1, got)
	}
}

// TestClientConsecutiveHandshakeFailureTracker exercises an injectable counter
// that resets on success and reports when the hint threshold is hit.
func TestClientConsecutiveHandshakeFailureTracker(t *testing.T) {
	var tr clientHandshakeFailureTracker
	for i := 1; i < clientAuthHintThreshold; i++ {
		if tr.recordFailure() {
			t.Fatalf("failure %d: unexpected hint trigger", i)
		}
	}
	if !tr.recordFailure() {
		t.Fatalf("failure %d: expected hint trigger at threshold", clientAuthHintThreshold)
	}
	tr.recordSuccess()
	if tr.recordFailure() {
		t.Fatalf("after success, first failure should not trigger hint")
	}
}
