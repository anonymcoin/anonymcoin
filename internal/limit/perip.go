// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package limit

import (
	"net"
	"sync"
	"time"
)

// PerIP manages one Bucket per source IP address, evicting idle entries so
// the map itself cannot become a memory-exhaustion vector (a spoofed-IP
// flood cannot grow it past the ceiling; eviction runs inline on the
// contested path).
type PerIP struct {
	mu      sync.Mutex
	buckets map[string]*Bucket
	rate    float64
	burst   float64
	maxIPs  int
	idleTTL time.Duration
	lastUse map[string]time.Time
}

// NewPerIP builds a per-IP limiter. maxIPs bounds concurrent tracked
// addresses; idleTTL evicts entries not used for that long.
func NewPerIP(ratePerSec, burst float64, maxIPs int) *PerIP {
	if maxIPs < 16 {
		maxIPs = 16
	}
	return &PerIP{
		buckets: make(map[string]*Bucket),
		rate:    ratePerSec,
		burst:   burst,
		maxIPs:  maxIPs,
		idleTTL: 5 * time.Minute,
		lastUse: make(map[string]time.Time),
	}
}

// Allow reports whether one action from ip is permitted.
func (p *PerIP) Allow(ip string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()

	if b, ok := p.buckets[ip]; ok {
		p.lastUse[ip] = now
		return b.Allow()
	}

	// Evict idle entries first so a long-lived server does not leak.
	if len(p.buckets) >= p.maxIPs {
		p.evictLocked(now)
	}
	// Still full? Refuse new entries (fail closed) but keep serving
	// already-tracked IPs.
	if len(p.buckets) >= p.maxIPs {
		return false
	}
	b := NewBucket(p.rate, p.burst)
	p.buckets[ip] = b
	p.lastUse[ip] = now
	return b.Allow()
}

// evictLocked removes idle entries, oldest first.
func (p *PerIP) evictLocked(now time.Time) {
	cutoff := now.Add(-p.idleTTL)
	for ip, t := range p.lastUse {
		if t.Before(cutoff) {
			delete(p.buckets, ip)
			delete(p.lastUse, ip)
		}
	}
	// If nothing was idle, drop the oldest entries until under budget.
	for len(p.buckets) >= p.maxIPs {
		var oldestIP string
		var oldest time.Time
		first := true
		for ip, t := range p.lastUse {
			if first || t.Before(oldest) {
				oldestIP, oldest, first = ip, t, false
			}
		}
		if first {
			break
		}
		delete(p.buckets, oldestIP)
		delete(p.lastUse, oldestIP)
	}
}

// SplitHostPort extracts the host part of a remote address for keying. Any
// unusual address format maps to the literal string (still bounded).
func RemoteKey(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	if h, _, err := net.SplitHostPort(addr.String()); err == nil && h != "" {
		return h
	}
	return addr.String()
}
