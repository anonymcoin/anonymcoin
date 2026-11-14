// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package consensus

import (
	"fmt"
	"math/big"
)

// ---------------------------------------------------------------------------
// TIE — Time Integral Emission
//
// ANONYMCOIN has an infinite (uncapped) maximum supply with a strictly
// controlled emission schedule. The design invariant is:
//
//     circulating supply  ==  integral of emission-per-second over canonical
//                             median time (MTP), piecewise integrated.
//
// Because block production in a BlockDAG is not a fixed-rate stream (parallel
// blocks widen the DAG), rewards are NOT paid per block as a constant.
// Instead each canonical block receives
//
//     reward(B) = emissionPerSecond(B) * dt(B)
//     dt(B)     = clamp(MTP(B) - MTP(prev), 0, MaxGapSeconds)
//
// so the total issuance telescopes exactly to the time integral regardless of
// how many parallel blocks the DAG produced in the same wall-clock second.
// This is the explicit reconciliation of the 50-Coin initial reward parameter
// with the inflation controller: during the bootstrap phase the emission rate
// is 50 Coin per canonical second, i.e. exactly the 50 Coin initial reward
// parameter per block at the one-second target interval.
//
// After the bootstrap phase the per-second rate is derived from the actual
// circulating supply and a deterministic annual rate schedule:
//
//     rate(year) = RateBase + RateExcess * 2^(-year / HalfLife)     (integer microBP)
//     emissionPerSecond = supply * rateMicroBP / 1e8 / SecondsPerYear
//
// The rate starts at 0.86% per year, decays asymptotically toward the 0.80%
// floor, and after RateTailStartYears the whole rate decays toward zero —
// approaching zero without necessarily reaching it. It never rises and never
// exceeds the 0.86% initial value, permanently below the 1% ceiling.
//
// All arithmetic is integer arithmetic; math/big is used only to avoid
// overflow in the product supply*rate. No floating point in consensus.
// ---------------------------------------------------------------------------

// RateMicroBP returns the deterministic annual inflation rate, expressed in
// micro basis points (1 microBP = 0.000001 %; 860000 microBP = 0.86 %), for
// the given canonical year. year 0 is the calendar year starting at
// GenesisTime. The function is monotonically non-increasing and bounded by
// RateBaseMicroBP + RateExcessMicroBP (0.86%).
func RateMicroBP(p *Params, year uint64) uint64 {
	if year < p.RateTailStartYears {
		shift := year / p.RateExcessHalfLifeYears
		if shift > 63 {
			shift = 63
		}
		excess := p.RateExcessMicroBP >> shift
		return p.RateBaseMicroBP + excess
	}
	// Long tail: the whole rate decays toward zero, halving every
	// RateTailHalfLifeYears. Integer truncation makes it eventually reach 0
	// in the limit; the decay is asymptotic in the mathematical schedule.
	y := year - p.RateTailStartYears
	shift := y / p.RateTailHalfLifeYears
	if shift > 63 {
		return 0
	}
	return p.RateBaseMicroBP >> shift
}

// EmissionPerSecondBase is the rate-era emission: baseSupply is the
// circulating supply snapshot taken when the canonical year started, so the
// realized annual inflation is exactly the schedule rate (no compounding
// overshoot). The division floors; the sub-atom dust this introduces is
// documented in MONETARY_POLICY.md (deflationary rounding, at most one atom
// per canonical block).
func EmissionPerSecondBase(p *Params, baseSupply uint64, year uint64) uint64 {
	rate := RateMicroBP(p, year)
	if rate == 0 || baseSupply == 0 {
		return 0
	}
	num := new(big.Int).Mul(new(big.Int).SetUint64(baseSupply), new(big.Int).SetUint64(rate))
	den := new(big.Int).Mul(
		big.NewInt(100_000_000), // 1e8: microBP -> fraction (microBP*1e-6 percent -> fraction*1e-8)
		new(big.Int).SetUint64(p.SecondsPerYear),
	)
	perSec := new(big.Int).Div(num, den)
	if !perSec.IsUint64() {
		// Cannot happen for validated params; defensive clamp keeps consensus
		// deterministic even under adversarial Params overrides.
		return ^uint64(0)
	}
	return perSec.Uint64()
}

// EmissionPerSecond is the combined entry point used by the DAG engine:
// during the bootstrap phase (mtp < GenesisTime + BootstrapSeconds) the rate
// is the fixed BootstrapPerSecond (50 Coin/s — the initial reward parameter
// reconciled with the controller); afterwards it is the year-snapshot based
// rate.
func EmissionPerSecond(p *Params, mtp uint64, yearBase uint64, year uint64) uint64 {
	if mtp < p.GenesisTime+p.BootstrapSeconds {
		return p.BootstrapPerSecond
	}
	return EmissionPerSecondBase(p, yearBase, year)
}

// RewardForSpan converts a per-second emission rate and a canonical time span
// into a block reward. Callers must clamp dt to MaxGapSeconds before calling.
func RewardForSpan(perSec, dt uint64) uint64 {
	return perSec * dt
}

// ClampGap clamps a canonical time delta to the emission gap cap.
func ClampGap(p *Params, dt uint64) uint64 {
	if dt > p.MaxGapSeconds {
		return p.MaxGapSeconds
	}
	return dt
}

// ScheduleYear returns the canonical year for a given median time past value.
func ScheduleYear(p *Params, mtp uint64) uint64 {
	if mtp < p.GenesisTime {
		return 0
	}
	return (mtp - p.GenesisTime) / p.SecondsPerYear
}

// ScheduleString renders the rate schedule at a given year for documentation
// and RPC purposes. The rate is in micro basis points (1 microBP = 0.000001
// percent), so the percent value is rate/1_000_000.
func ScheduleString(p *Params, year uint64) string {
	rate := RateMicroBP(p, year)
	percent := new(big.Rat).SetFrac64(int64(rate), 1_000_000)
	return fmt.Sprintf("year %d: %s %% per year", year, percent.FloatString(6))
}
