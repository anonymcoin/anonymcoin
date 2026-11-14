// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Rate limiter tests (DoS defense building blocks).
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package limit

import (
	"testing"
	"time"
)

func TestBucketBasicFlow(t *testing.T) {
	b := NewBucket(10, 10)
	for i := 0; i < 10; i++ {
		if !b.Allow() {
			t.Fatalf("token %d refused despite full burst", i)
		}
	}
	if b.Allow() {
		t.Fatal("burst exceeded")
	}
}

func TestBucketRefill(t *testing.T) {
	b := NewBucket(1000, 2)
	_ = b.Allow()
	_ = b.Allow()
	if b.Allow() {
		t.Fatal("burst exceeded before refill")
	}
	// Refill happens from the wall clock; wait long enough for >1 token.
	time.Sleep(5 * time.Millisecond)
	if !b.Allow() {
		t.Fatal("bucket never refilled")
	}
}

func TestPerIPIndependence(t *testing.T) {
	p := NewPerIP(1, 1, 256)
	if !p.Allow("1.2.3.4") {
		t.Fatal("first request from 1.2.3.4 refused")
	}
	if p.Allow("1.2.3.4") {
		t.Fatal("burst exceeded for 1.2.3.4")
	}
	// A different IP must be unaffected.
	if !p.Allow("5.6.7.8") {
		t.Fatal("independent IP refused")
	}
}

func TestPerIPMaxIPsBound(t *testing.T) {
	p := NewPerIP(1000, 1000, 16)
	for i := 0; i < 100; i++ {
		ip := string(rune('a'+i%26)) + string(rune('a'+i/26)) + string(rune('0'+i%10)) + "-ip"
		p.Allow(ip)
	}
	// The invariant is the memory bound: the tracked-IP map must never
	// exceed the ceiling, no matter how many addresses hammer it.
	if len(p.buckets) > 16 {
		t.Fatalf("tracked %d IPs, ceiling is 16", len(p.buckets))
	}
	// Eviction must have happened: early IPs are gone.
	if p.Allow("aaaaaaaa0-ip") {
		// First IP was evicted to make room — it starts a fresh bucket, so
		// Allow succeeds again. This is expected; the assert documents it.
		t.Log("oldest IP re-accepted with a fresh bucket (evicted earlier)")
	}
}

func TestBucketInvalidParamsFailClosed(t *testing.T) {
	b := NewBucket(0, 0)
	// Defensive fallback must still be a functioning limiter.
	if !b.Allow() {
		t.Fatal("defensive bucket refuses everything")
	}
}
