package app

import (
	"bytes"
	"container/list"
	"sync"
	"sync/atomic"
)

const defaultTAI64NCacheCapacity = 65536

type tai64nEntry struct {
	sessionID [16]byte
	maxTAI64N [12]byte
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

// CheckAndStore checks whether tai64n is strictly greater than the recorded
// timestamp for the sessionID. If the sessionID does not exist, it inserts it.
// If the capacity is reached, it evicts the least-recently used entry.
// Returns true if valid and stored/updated, false if rejected (replay or not strictly greater or invalid lengths).
func (c *tai64nCache) CheckAndStore(sessionID []byte, tai64n []byte) bool {
	if len(sessionID) != 16 || len(tai64n) != 12 {
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
		if bytes.Compare(tVal[:], entry.maxTAI64N[:]) <= 0 {
			return false
		}
		entry.maxTAI64N = tVal
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
		sessionID: sKey,
		maxTAI64N: tVal,
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
