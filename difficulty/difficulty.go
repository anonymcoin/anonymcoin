// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

// Package difficulty implements the deterministic ANONYMCOIN retarget rule.
//
// Difficulty retargets once per block along the selected-parent chain — the
// heaviest ancestral path of the BlockDAG. This is the DAG analogue of a
// chain-based window retarget: virtual time (VT) is monotone along the
// selected-parent chain, so the span of the last DifficultyWindow blocks is a
// manipulation-resistant measure of real elapsed time (VT is monotone and
// clamped per block by consensus.VTDriftCap).
//
//	newDiff = tipDiff * ActualSpan / TargetSpan
//	ActualSpan = VT(tip) - VT(tip - DifficultyWindow along SP chain)
//	TargetSpan = DifficultyWindow * BlockIntervalSec
//
// The change is clamped to [1/MaxChangeN, MaxChangeN/MaxChangeD] of the
// previous difficulty per retarget and to the global [Min, Max] bounds. The
// rule is a pure function of the DAG structure: every node computes the same
// expected difficulty for the same parent set, independent of arrival order.
package difficulty

import "github.com/anonymcoin/anonymcoin/consensus"

// ChainPoint is the minimal per-block state needed by the retarget rule.
type ChainPoint struct {
	VT         uint64 // virtual time of the block
	Difficulty uint64 // validated difficulty of the block
}

// Next returns the expected difficulty for a child of tip.
//
// window contains the last up-to-N selected-parent ancestors of tip,
// window[0] being the closest ancestor (tip's selected parent) and window[k]
// the (k+1)-th ancestor along the SP chain. If the full window is not yet
// available the parent difficulty is returned unchanged (bootstrap ramp).
func Next(p *consensus.Params, tip ChainPoint, window []ChainPoint) uint64 {
	n := int(p.DifficultyWindow)
	if len(window) < n {
		return clamp(p, tip.Difficulty)
	}
	first := window[n-1].VT
	last := tip.VT
	var span uint64
	if last > first {
		span = last - first
	}
	if span == 0 {
		span = 1
	}
	targetSpan := p.DifficultyWindow * p.BlockIntervalSec
	if targetSpan == 0 {
		targetSpan = 1
	}

	// newDiff = tipDiff * span / targetSpan  (integer, floor)
	newDiff := mulDivClamp64(tip.Difficulty, span, targetSpan)

	// Clamp relative change to [1/Nc, Nc/Dc].
	upLimit := tip.Difficulty * p.DifficultyMaxChangeN / p.DifficultyMaxChangeD
	if newDiff > upLimit {
		newDiff = upLimit
	}
	downLimit := tip.Difficulty * p.DifficultyMaxChangeD / p.DifficultyMaxChangeN
	if downLimit < 1 {
		downLimit = 1
	}
	if newDiff < downLimit {
		newDiff = downLimit
	}
	return clamp(p, newDiff)
}

func clamp(p *consensus.Params, d uint64) uint64 {
	if d < p.DifficultyMin {
		return p.DifficultyMin
	}
	if d > p.DifficultyMax {
		return p.DifficultyMax
	}
	return d
}

// mulDivClamp64 computes (a*b)/c saturating at ^uint64(0)/c without overflow.
func mulDivClamp64(a, b, c uint64) uint64 {
	if a == 0 || b == 0 || c == 0 {
		return 0
	}
	hi, lo := bitsMul64(a, b)
	if hi != 0 {
		// Saturate: return the largest value that keeps subsequent clamps sane.
		return ^uint64(0) / c
	}
	return lo / c
}

// bitsMul64 returns the 128-bit product of two 64-bit values.
func bitsMul64(x, y uint64) (hi, lo uint64) {
	const mask32 = 1<<32 - 1
	x0, x1 := x&mask32, x>>32
	y0, y1 := y&mask32, y>>32
	w00 := x0 * y0
	w01 := x0 * y1
	w10 := x1 * y0
	w11 := x1 * y1
	mid := w00>>32 + w01&mask32 + w10&mask32
	lo = w00&mask32 | mid<<32
	hi = w11 + mid>>32 + w01>>32 + w10>>32
	return hi, lo
}
