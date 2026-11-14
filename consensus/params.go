// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

// Package consensus holds the consensus constants of ANONYMCOIN and the
// deterministic, integer-only monetary emission controller (TIE — Time
// Integral Emission) and virtual-time rules.
//
// ANONYMCOIN is a BlockDAG cryptocurrency. Every consensus-critical value
// defined here is derived deterministically from the DAG structure by every
// independently operated node. All consensus arithmetic is integer arithmetic;
// floating point is never used in consensus code.
package consensus

import "fmt"

// Params is the complete, serializable set of consensus constants. Every
// field participates in consensus validation, so nodes that disagree on any
// field disagree on the canonical chain and will refuse each other's blocks.
type Params struct {
	// Identity.
	Name            string `json:"name"`
	Ticker          string `json:"ticker"`
	ProtocolVersion uint16 `json:"protocol_version"`

	// Block structure.
	BlockIntervalSec uint64 `json:"block_interval_sec"` // target interval (1 second)
	MaxParents       int    `json:"max_parents"`        // maximum parent references per block
	MaxBlockSize     int    `json:"max_block_size"`     // serialized block size limit
	MaxTxSize        int    `json:"max_tx_size"`
	MaxTxInputs      int    `json:"max_tx_inputs"`
	MaxTxOutputs     int    `json:"max_tx_outputs"`
	MaxAuxBytes      int    `json:"max_aux_bytes"` // coinbase auxiliary payload bound

	// Transaction economics.
	DustLimit    uint64 `json:"dust_limit"`    // minimum output value (atoms)
	MinRelayFee  uint64 `json:"min_relay_fee"` // minimum fee to relay a transaction (atoms)
	MaxMoney     uint64 `json:"max_money"`     // maximum value of a single output (atoms)
	AtomsPerCoin uint64 `json:"atoms_per_coin"`

	// Time rules.
	MaxFutureTimeSec uint64 `json:"max_future_time_sec"` // local acceptance policy: block time <= now + this
	VTDriftCap       uint64 `json:"vt_drift_cap"`        // max seconds virtual time may advance per block
	MTPWindow        int    `json:"mtp_window"`          // median-time-past window over canonical VTs

	// Difficulty.
	DifficultyWindow     uint64 `json:"difficulty_window"`       // selected-parent chain window
	DifficultyMaxChangeN uint64 `json:"difficulty_max_change_n"` // retarget clamp numerator (x4)
	DifficultyMaxChangeD uint64 `json:"difficulty_max_change_d"` // retarget clamp denominator
	DifficultyMin        uint64 `json:"difficulty_min"`
	DifficultyMax        uint64 `json:"difficulty_max"`

	// DAG engine.
	FinalizedDepth   int    `json:"finalized_depth"` // canonical prefix that never reorders
	OrphanPoolSize   int    `json:"orphan_pool_size"`
	OrphanTTLSec     uint64 `json:"orphan_ttl_sec"`
	CoinbaseMaturity uint64 `json:"coinbase_maturity"` // canonical blocks before a coinbase may be spent

	// Monetary policy (TIE — Time Integral Emission).
	GenesisTime             uint64 `json:"genesis_time"`         // unix seconds (2026-01-01T00:00:00Z)
	GenesisDifficulty       uint64 `json:"genesis_difficulty"`   // difficulty of first blocks
	BootstrapPerSecond      uint64 `json:"bootstrap_per_second"` // atoms per canonical second during bootstrap (50 Coin)
	BootstrapSeconds        uint64 `json:"bootstrap_seconds"`    // bootstrap phase length
	SecondsPerYear          uint64 `json:"seconds_per_year"`
	RateBaseMicroBP         uint64 `json:"rate_base_microbp"`   // long-run floor rate (0.80% = 800000)
	RateExcessMicroBP       uint64 `json:"rate_excess_microbp"` // initial excess over the floor (0.06% = 60000)
	RateExcessHalfLifeYears uint64 `json:"rate_excess_half_life_years"`
	RateTailStartYears      uint64 `json:"rate_tail_start_years"`
	RateTailHalfLifeYears   uint64 `json:"rate_tail_half_life_years"`
	MaxGapSeconds           uint64 `json:"max_gap_seconds"` // emission gap clamp per canonical block
}

// Defaults returns the ANONYMCOIN mainnet-parameter set.
func Defaults() Params {
	return Params{
		Name:            "ANONYMCOIN",
		Ticker:          "Coin",
		ProtocolVersion: 1,

		BlockIntervalSec: 1,
		MaxParents:       8,
		MaxBlockSize:     1_000_000,
		MaxTxSize:        128_000,
		MaxTxInputs:      512,
		MaxTxOutputs:     512,
		MaxAuxBytes:      64,

		DustLimit:    1_000,              // 0.00001 Coin
		MinRelayFee:  1_000,              // 0.00001 Coin per transaction
		MaxMoney:     10_000_000_000_000, // 100,000 Coin per output; must exceed the largest gap-clamped coinbase claim (MaxGapSeconds x per-second emission)
		AtomsPerCoin: 100_000_000,        // 1 Coin = 1e8 "anon"

		MaxFutureTimeSec: 7200, // 2 hours (local policy)
		VTDriftCap:       60,
		MTPWindow:        11,

		DifficultyWindow:     128,
		DifficultyMaxChangeN: 4,
		DifficultyMaxChangeD: 1,
		DifficultyMin:        1,
		DifficultyMax:        1 << 32,

		FinalizedDepth:   2000,
		OrphanPoolSize:   2048,
		OrphanTTLSec:     7200,
		CoinbaseMaturity: 10,

		GenesisTime:             1_767_225_600, // 2026-01-01T00:00:00Z
		GenesisDifficulty:       64,
		BootstrapPerSecond:      5_000_000_000,  // 50 Coin per canonical second (1e8 atoms per Coin)
		BootstrapSeconds:        2 * 31_536_000, // two years
		SecondsPerYear:          31_536_000,
		RateBaseMicroBP:         800_000, // 0.80 %
		RateExcessMicroBP:       60_000,  // +0.06 % decaying asymptotically
		RateExcessHalfLifeYears: 20,
		RateTailStartYears:      320,
		RateTailHalfLifeYears:   100,
		MaxGapSeconds:           60,
	}
}

// Validate checks internal consistency of the parameter set. It bounds every
// value that feeds consensus arithmetic so the engine's checked adds and
// saturation paths stay unreachable on honest configurations.
func (p *Params) Validate() error {
	if p.BlockIntervalSec == 0 {
		return fmt.Errorf("block interval must be positive")
	}
	if p.MaxParents < 1 || p.MaxParents > 64 {
		return fmt.Errorf("max_parents out of range")
	}
	if p.MaxBlockSize < 1000 {
		return fmt.Errorf("max_block_size too small")
	}
	if p.MaxTxSize < 100 || p.MaxTxSize > p.MaxBlockSize {
		return fmt.Errorf("max_tx_size out of range")
	}
	if p.MaxTxInputs < 1 || p.MaxTxInputs > 100_000 {
		return fmt.Errorf("max_tx_inputs out of range")
	}
	if p.MaxTxOutputs < 1 || p.MaxTxOutputs > 100_000 {
		return fmt.Errorf("max_tx_outputs out of range")
	}
	if p.MaxAuxBytes < 0 || p.MaxAuxBytes > 1024 {
		return fmt.Errorf("max_aux_bytes out of range")
	}
	if p.AtomsPerCoin == 0 || p.SecondsPerYear == 0 {
		return fmt.Errorf("atoms_per_coin and seconds_per_year must be positive")
	}
	if p.DustLimit > p.MaxMoney {
		return fmt.Errorf("dust_limit exceeds max_money")
	}
	if p.MinRelayFee > p.MaxMoney {
		return fmt.Errorf("min_relay_fee exceeds max_money")
	}
	// Emission arithmetic stays total: per-second rate times the gap clamp
	// must never overflow, and the rate-era supply snapshot product is
	// computed with math/big, so only the bootstrap product needs bounding.
	if p.BootstrapPerSecond != 0 && p.MaxGapSeconds > (^uint64(0))/p.BootstrapPerSecond {
		return fmt.Errorf("bootstrap_per_second * max_gap_seconds overflows")
	}
	if p.VTDriftCap == 0 || p.MaxGapSeconds == 0 {
		return fmt.Errorf("vt_drift_cap and max_gap_seconds must be positive")
	}
	if p.DifficultyWindow < 2 {
		return fmt.Errorf("difficulty_window must be at least 2")
	}
	if p.DifficultyMin < 1 || p.DifficultyMax < p.DifficultyMin {
		return fmt.Errorf("difficulty bounds invalid")
	}
	if p.DifficultyMax > 1<<62 {
		return fmt.Errorf("difficulty_max too large for checked retarget arithmetic")
	}
	// MTPWindow feeds only medians (no sums), but an absurd window would make
	// applyNode allocate unbounded slices.
	if p.MTPWindow < 1 || p.MTPWindow > 1024 {
		return fmt.Errorf("mtp_window out of range")
	}
	if p.FinalizedDepth < 1 {
		return fmt.Errorf("finalized_depth must be positive")
	}
	if p.OrphanPoolSize < 0 {
		return fmt.Errorf("orphan_pool_size negative")
	}
	// Rate schedule: never above the permanent 1% ceiling.
	if p.RateBaseMicroBP > 1_000_000 {
		return fmt.Errorf("rate base exceeds 1%% permanent ceiling")
	}
	if p.RateBaseMicroBP+p.RateExcessMicroBP > 1_000_000 {
		return fmt.Errorf("initial rate exceeds 1%% permanent ceiling")
	}
	return nil
}

// MaxBlockSizeLimit and MaxTxSizeLimit adapt Params to the wire decoder's
// blockdag.ParamsView interface.
func (p *Params) MaxBlockSizeLimit() int { return p.MaxBlockSize }
func (p *Params) MaxTxSizeLimit() int    { return p.MaxTxSize }

// CoinString renders an atom amount as a human readable Coin decimal string.
func (p *Params) CoinString(atoms uint64) string {
	whole := atoms / p.AtomsPerCoin
	frac := atoms % p.AtomsPerCoin
	return fmt.Sprintf("%d.%08d %s", whole, frac, p.Ticker)
}
