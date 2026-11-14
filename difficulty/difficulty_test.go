// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package difficulty

import (
	"testing"

	"github.com/anonymcoin/anonymcoin/consensus"
)

func mk(n int, vtStep uint64, diff uint64) ([]ChainPoint, ChainPoint) {
	tip := ChainPoint{VT: 1000 + uint64(n)*vtStep, Difficulty: diff}
	window := make([]ChainPoint, 0, n)
	// window[0] is the closest ancestor, window[n-1] the farthest — exactly
	// the layout difficulty.Next expects.
	for i := 0; i < n; i++ {
		window = append(window, ChainPoint{VT: tip.VT - uint64(i+1)*vtStep, Difficulty: diff})
	}
	return window, tip
}

func TestNoRetargetBeforeFullWindow(t *testing.T) {
	p := consensus.Defaults()
	p.DifficultyWindow = 8
	w, tip := mk(5, 1, 64)
	if got := Next(&p, tip, w); got != 64 {
		t.Fatalf("difficulty changed before full window: %d", got)
	}
}

func TestStableAtTargetInterval(t *testing.T) {
	p := consensus.Defaults()
	p.DifficultyWindow = 8
	// 8 blocks spanning exactly 8 seconds -> difficulty unchanged.
	w, tip := mk(8, 1, 64)
	if got := Next(&p, tip, w); got != 64 {
		t.Fatalf("difficulty drifted at target interval: %d", got)
	}
}

func TestSpeedupAndSlowdownWithClamp(t *testing.T) {
	p := consensus.Defaults()
	p.DifficultyWindow = 8
	// Blocks came 4x too fast (span 2s over 8 blocks) -> diff would drop 4x,
	// clamp caps the drop at 4x.
	w, tip := mk(8, 1, 64)
	tip.VT = windowFirstVT(w) + 2
	if got := Next(&p, tip, w); got != 16 {
		t.Fatalf("fast chain: difficulty = %d, want 16 (4x clamp)", got)
	}
	// Blocks came 8x too slow (span 64s) -> diff rises 8x, clamp caps at 4x.
	w2, tip2 := mk(8, 8, 16)
	if got := Next(&p, tip2, w2); got != 64 {
		t.Fatalf("slow chain: difficulty = %d, want 64 (4x clamp)", got)
	}
}

func windowFirstVT(window []ChainPoint) uint64 {
	// window[0] is the closest ancestor; the farthest is the last one.
	return window[len(window)-1].VT
}

func TestBounds(t *testing.T) {
	p := consensus.Defaults()
	p.DifficultyWindow = 8
	p.DifficultyMin = 4
	// Collapsed span with minimal difficulty must respect DifficultyMin.
	w, tip := mk(8, 1, 4)
	tip.VT = windowFirstVT(w) + 1
	if got := Next(&p, tip, w); got != 4 {
		t.Fatalf("difficulty = %d, want floor 4", got)
	}
}
