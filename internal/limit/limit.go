// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

// Package limit provides the shared token-bucket rate limiter used by the
// RPC and P2P layers as a DoS defense. It is deliberately tiny: no timers,
// no goroutines — refill is computed lazily from the wall clock, so a
// thousand limiters cost nothing when idle.
package limit

import (
	"sync"
	"time"
)

// Bucket is a token bucket with a fixed refill rate and burst capacity.
// It is safe for concurrent use.
type Bucket struct {
	mu sync.Mutex
	// rate: tokens per second; burst: maximum token count.
	rate  float64
	burst float64
	// State.
	tokens float64
	last   time.Time
}

// NewBucket creates a bucket that refills rate tokens per second and holds
// at most burst tokens.
func NewBucket(ratePerSec, burst float64) *Bucket {
	if ratePerSec <= 0 || burst < 1 {
		// Defensive: an unbounded or empty bucket is a config error; fail
		// closed with a minimal but working limiter.
		ratePerSec, burst = 1, 1
	}
	return &Bucket{
		rate:   ratePerSec,
		burst:  burst,
		tokens: burst,
		last:   time.Now(),
	}
}

// Allow consumes one token if available and reports whether the action is
// permitted. Denied calls do not consume tokens.
func (b *Bucket) Allow() bool {
	return b.AllowN(1)
}

// AllowN consumes n tokens if available.
func (b *Bucket) AllowN(n float64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.tokens += elapsed * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	if b.tokens < n {
		return false
	}
	b.tokens -= n
	return true
}
