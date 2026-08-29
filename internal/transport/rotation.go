package transport

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrNoAvailableEndpoints = errors.New("rotation: no available endpoints")
)

// Endpoint tracks connection metrics and health for an individual endpoint/IP.
type Endpoint struct {
	Address          string
	ConsecutiveFails int
	TotalSuccesses   int64
	TotalFails       int64
	LastFailTime     time.Time
	LastRTT          time.Duration
	Healthy          bool
}

// EndpointPool manages multi-IP endpoints with failure tracking and block detection.
type EndpointPool struct {
	mu             sync.RWMutex
	endpoints      []*Endpoint
	currentIndex   int
	failThreshold  int
	cooldownPeriod time.Duration
}

// NewEndpointPool creates a new EndpointPool with a list of initial addresses.
func NewEndpointPool(addrs []string, failThreshold int, cooldown time.Duration) *EndpointPool {
	if failThreshold <= 0 {
		failThreshold = 3
	}
	if cooldown <= 0 {
		cooldown = 60 * time.Second
	}

	pool := &EndpointPool{
		endpoints:      make([]*Endpoint, 0, len(addrs)),
		failThreshold:  failThreshold,
		cooldownPeriod: cooldown,
	}

	for _, addr := range addrs {
		if addr != "" {
			pool.endpoints = append(pool.endpoints, &Endpoint{
				Address: addr,
				Healthy: true,
			})
		}
	}

	return pool
}

// AddEndpoint adds a new endpoint address if not already present.
func (p *EndpointPool) AddEndpoint(addr string) {
	if addr == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, ep := range p.endpoints {
		if ep.Address == addr {
			return
		}
	}
	p.endpoints = append(p.endpoints, &Endpoint{
		Address: addr,
		Healthy: true,
	})
}

// SelectNext returns the next available healthy endpoint using round-robin selection.
func (p *EndpointPool) SelectNext() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.endpoints) == 0 {
		return "", ErrNoAvailableEndpoints
	}

	now := time.Now()
	// First pass: try round robin on healthy endpoints or cooled-down endpoints
	n := len(p.endpoints)
	for i := 0; i < n; i++ {
		idx := (p.currentIndex + i) % n
		ep := p.endpoints[idx]

		// Check if cooled down
		if !ep.Healthy && now.Sub(ep.LastFailTime) > p.cooldownPeriod {
			ep.Healthy = true // half-open probation
			p.currentIndex = (idx + 1) % n
			return ep.Address, nil
		}

		if ep.Healthy {
			p.currentIndex = (idx + 1) % n
			return ep.Address, nil
		}
	}

	// If all are unhealthy and none cooled down, fallback to the one with the earliest failure
	var oldest *Endpoint
	for _, ep := range p.endpoints {
		if oldest == nil || ep.LastFailTime.Before(oldest.LastFailTime) {
			oldest = ep
		}
	}
	if oldest != nil {
		return oldest.Address, nil
	}

	return "", ErrNoAvailableEndpoints
}

// RecordResult updates the metrics and health of an endpoint.
func (p *EndpointPool) RecordResult(addr string, success bool, rtt time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, ep := range p.endpoints {
		if ep.Address == addr {
			if success {
				ep.TotalSuccesses++
				ep.ConsecutiveFails = 0
				ep.Healthy = true
				if rtt > 0 {
					ep.LastRTT = rtt
				}
			} else {
				ep.TotalFails++
				ep.ConsecutiveFails++
				ep.LastFailTime = time.Now()
				if ep.ConsecutiveFails >= p.failThreshold {
					ep.Healthy = false
				}
			}
			return
		}
	}
}

// HealthyCount returns the number of currently healthy endpoints.
func (p *EndpointPool) HealthyCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	count := 0
	now := time.Now()
	for _, ep := range p.endpoints {
		if ep.Healthy || now.Sub(ep.LastFailTime) > p.cooldownPeriod {
			count++
		}
	}
	return count
}

// Endpoints returns a snapshot of all endpoints.
func (p *EndpointPool) Endpoints() []Endpoint {
	p.mu.RLock()
	defer p.mu.RUnlock()

	res := make([]Endpoint, len(p.endpoints))
	for i, ep := range p.endpoints {
		res[i] = *ep
	}
	return res
}
