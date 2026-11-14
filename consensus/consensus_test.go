// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package consensus

import (
	"math/big"
	"testing"
)

func TestRateScheduleBounds(t *testing.T) {
	p := Defaults()
	prev := RateMicroBP(&p, 0)
	if prev != 860_000 {
		t.Fatalf("year 0 rate = %d microBP, want 860000 (0.86%%)", prev)
	}
	if RateMicroBP(&p, 0) > 1_000_000 {
		t.Fatal("initial rate exceeds the permanent 1% ceiling")
	}
	for y := uint64(1); y < 2000; y++ {
		r := RateMicroBP(&p, y)
		if r > prev {
			t.Fatalf("rate increased at year %d: %d > %d", y, r, prev)
		}
		prev = r
	}
	if prev > 800_000 {
		t.Fatalf("year 1999 rate %d should be at/below the 0.80%% floor", prev)
	}
	// Asymptotic approach to zero: strictly decreasing staircase until 0.
	if RateMicroBP(&p, 20) != 830_000 {
		t.Fatalf("year 20 rate = %d, want 830000", RateMicroBP(&p, 20))
	}
	if RateMicroBP(&p, 40) != 815_000 {
		t.Fatalf("year 40 rate = %d, want 815000", RateMicroBP(&p, 40))
	}
	if RateMicroBP(&p, 2400) != 0 {
		t.Fatalf("far-tail rate should truncate to 0, got %d", RateMicroBP(&p, 2400))
	}
}

func TestBootstrapEmissionIs50CoinPerSecond(t *testing.T) {
	p := Defaults()
	per := EmissionPerSecond(&p, p.GenesisTime+10, 0, 0)
	if per != p.BootstrapPerSecond {
		t.Fatalf("bootstrap rate = %d, want %d", per, p.BootstrapPerSecond)
	}
	if per != 50*p.AtomsPerCoin {
		t.Fatalf("bootstrap rate = %d atoms/s, want 50 Coin/s (initial reward parameter)", per)
	}
}

func TestRateEraEmissionMatchesFormula(t *testing.T) {
	p := Defaults()
	// Supply right after a 2-year bootstrap.
	supply := p.BootstrapPerSecond * p.BootstrapSeconds // 3,153,600,000 Coin
	mtp := p.GenesisTime + p.BootstrapSeconds + 5
	year := ScheduleYear(&p, mtp)
	per := EmissionPerSecondBase(&p, supply, year)

	// expected = supply * 0.0086 / secondsPerYear (integer)
	want := new(big.Int).Div(
		new(big.Int).Mul(new(big.Int).SetUint64(supply), big.NewInt(860_000)),
		new(big.Int).Mul(big.NewInt(100_000_000), new(big.Int).SetUint64(p.SecondsPerYear)),
	)
	if per != want.Uint64() {
		t.Fatalf("rate-era per-second = %d, want %d", per, want.Uint64())
	}
	if per != 86_000_000_000/1000 { // 3.1536e17 * 8.6e-4 / 3.1536e7 = 8.6e7 atoms/s = 0.86 Coin/s
		t.Logf("per-second emission: %d atoms (%0.8f Coin/s)", per, float64(per)/1e8)
	}
}

// TestInflationYearOneInBand simulates a full post-bootstrap year at one
// canonical second per step, with the year-start supply snapshot the DAG
// engine performs, and checks the realized inflation is exactly the 0.86%
// schedule rate (within integer truncation) and inside the target band.
func TestInflationYearOneInBand(t *testing.T) {
	p := Defaults()
	supply := p.BootstrapPerSecond * p.BootstrapSeconds
	start := supply
	mtp := p.GenesisTime + p.BootstrapSeconds
	yearIndex := uint64(0)
	yearBase := supply
	for s := uint64(0); s < p.SecondsPerYear; s++ {
		year := ScheduleYear(&p, mtp)
		if year != yearIndex {
			yearBase = supply
			yearIndex = year
		}
		per := EmissionPerSecond(&p, mtp, yearBase, year)
		supply += per
		mtp++
	}
	gained := supply - start
	// rate = gained / start; check 0.0080 <= rate <= 0.0086 with integer math.
	lo := new(big.Int).Div(new(big.Int).Mul(new(big.Int).SetUint64(start), big.NewInt(800_000)), big.NewInt(100_000_000))
	hi := new(big.Int).Div(new(big.Int).Mul(new(big.Int).SetUint64(start), big.NewInt(860_000)), big.NewInt(100_000_000))
	if gained < lo.Uint64() || gained > hi.Uint64() {
		t.Fatalf("year inflation %d outside band [%d, %d] (rate %.6f%%)", gained, lo.Uint64(), hi.Uint64(), float64(gained)/float64(start)*100)
	}
}

func TestMedian(t *testing.T) {
	cases := []struct {
		in   []uint64
		want uint64
	}{
		{[]uint64{5}, 5},
		{[]uint64{5, 9}, 5}, // lower median
		{[]uint64{9, 5}, 5}, // sorted internally
		{[]uint64{1, 2, 3}, 2},
		{[]uint64{9, 1, 5, 3}, 3}, // sorted {1,3,5,9} -> idx 1 -> 3
	}
	for i, c := range cases {
		if got := Median(c.in); got != c.want {
			t.Fatalf("case %d: median(%v) = %d, want %d", i, c.in, got, c.want)
		}
	}
}

func TestVirtualTimeClamp(t *testing.T) {
	p := Defaults()
	// Normal advance.
	if got := VirtualTime(100, []uint64{90}, &p); got != 100 {
		t.Fatalf("VT = %d, want 100", got)
	}
	// Backward timestamp clamps to parent VT.
	if got := VirtualTime(50, []uint64{90}, &p); got != 90 {
		t.Fatalf("VT = %d, want 90", got)
	}
	// Forward jump clamps to parent + drift cap.
	if got := VirtualTime(100000, []uint64{90}, &p); got != 90+p.VTDriftCap {
		t.Fatalf("VT = %d, want %d", got, 90+p.VTDriftCap)
	}
	// Multiple parents take the max.
	if got := VirtualTime(80, []uint64{10, 70, 30}, &p); got != 80 {
		t.Fatalf("VT = %d, want 80", got)
	}
}
