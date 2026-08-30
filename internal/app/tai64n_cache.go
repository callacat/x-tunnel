package app

import (
	"container/list"
	"sync"
	"sync/atomic"
	"time"
)

const defaultTAI64NCacheCapacity = 65536

type tai64nEntry struct {
	sessionID  [16]byte
	lastTAI64N [12]byte
}

type tai64nCache struct {
	mu       sync.Mutex
	capacity int
	items    map[[16]byte]*list.Element
	evict    *list.List
}

func newTAI64NCache(capacity int) *tai64nCache {
	if capacity <= 0 {
		capacity = defaultTAI64NCacheCapacity
	}
	return &tai64nCache{
		capacity: capacity,
		items:    make(map[[16]byte]*list.Element),
		evict:    list.New(),
	}
}

// CheckAndStore validates the TAI64N timestamp as a freshness window:
// the decoded timestamp must lie within [now-skew, now+skew]. A skew <= 0
// disables the check. Out-of-order or identical timestamps are accepted;
// parallel handshakes from one client share the sessionID (client UUID) and
// must not be rejected for non-monotonic timestamps. Replay protection is
// provided by serverNonceCache (keyed with clientNonce).
//
// The LRU still tracks the last accepted timestamp per session, but never
// rejects based on ordering. Returns false only for malformed input or a
// timestamp outside the freshness window.
func (c *tai64nCache) CheckAndStore(sessionID []byte, tai64n []byte, now time.Time, skew time.Duration) bool {
	if len(sessionID) != 16 {
		return false
	}
	decoded, err := decodeTAI64N(tai64n)
	if err != nil {
		return false
	}
	if skew > 0 && (decoded.Before(now.Add(-skew)) || decoded.After(now.Add(skew))) {
		return false
	}

	var sKey [16]byte
	copy(sKey[:], sessionID)
	var tVal [12]byte
	copy(tVal[:], tai64n)

	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[sKey]; ok {
		entry := elem.Value.(*tai64nEntry)
		entry.lastTAI64N = tVal
		c.evict.MoveToFront(elem)
		return true
	}

	if c.evict.Len() >= c.capacity {
		oldest := c.evict.Back()
		if oldest != nil {
			c.evict.Remove(oldest)
			oldEntry := oldest.Value.(*tai64nEntry)
			delete(c.items, oldEntry.sessionID)
			atomic.AddUint64(&serverTAI64NEvictSeq, 1)
		}
	}

	entry := &tai64nEntry{
		sessionID:  sKey,
		lastTAI64N: tVal,
	}
	elem := c.evict.PushFront(entry)
	c.items[sKey] = elem
	return true
}

func (c *tai64nCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}
