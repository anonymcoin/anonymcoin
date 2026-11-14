// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Integration test suite: full stack across packages.
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package tests

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/anonymcoin/anonymcoin/blockdag"
	"github.com/anonymcoin/anonymcoin/consensus"
	"github.com/anonymcoin/anonymcoin/cryptography"
	"github.com/anonymcoin/anonymcoin/mining"
	"github.com/anonymcoin/anonymcoin/storage"
	"github.com/anonymcoin/anonymcoin/transactions"
	"github.com/anonymcoin/anonymcoin/wallet"
)

// TestEndToEndMineStoreRestartSpend walks the full lifecycle:
//  1. mine 30 blocks into a wallet-funded chain
//  2. persist every accepted block to the block store
//  3. restart: rebuild the DAG purely from storage replay
//  4. the rebuilt node has identical canonical order and supply
//  5. build, sign and apply a real payment between two wallet keys
func TestEndToEndMineStoreRestartSpend(t *testing.T) {
	p := consensus.Defaults()
	p.GenesisDifficulty = 1
	p.DifficultyMax = 4
	p.CoinbaseMaturity = 1

	dag, err := blockdag.New(&p, blockdag.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(t.TempDir()+"/blocks.dat", &p, false)
	if err != nil {
		t.Fatal(err)
	}
	dag2, _ := blockdag.New(&p, blockdag.Hooks{})

	w, err := openWallet(t)
	if err != nil {
		t.Fatal(err)
	}
	addr0 := w.Addresses()[0]
	pkh, err := cryptography.AddressToPubKeyHash(addr0)
	if err != nil {
		t.Fatal(err)
	}
	sharedPool := mining.NewMemPool(&p)
	miner := mining.NewMiner(dag, sharedPool, pkh, 1)

	// 1+2: mine and persist.
	var accepted []*blockdag.Block
	for i := 0; i < 30; i++ {
		blk, err := miner.MineOne()
		if err != nil {
			t.Fatal(err)
		}
		if err := dag.AcceptBlock(blk); err != nil {
			t.Fatalf("accept %d: %v", i, err)
		}
		if err := store.Append(blk); err != nil {
			t.Fatal(err)
		}
		accepted = append(accepted, blk)
	}
	if len(accepted) != 30 {
		t.Fatal("mining produced wrong count")
	}
	supplyBefore := dag.CirculatingSupply()
	if supplyBefore == 0 {
		t.Fatal("no supply after 30 blocks")
	}

	// 3+4: restart from storage.
	if err := store.ForEach(&p, func(b *blockdag.Block) error {
		return dag2.AcceptBlock(b)
	}); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if dag2.CanonicalCount() != dag.CanonicalCount() {
		t.Fatalf("replay canonical %d != %d", dag2.CanonicalCount(), dag.CanonicalCount())
	}
	if dag2.CirculatingSupply() != supplyBefore {
		t.Fatalf("replay supply %d != %d", dag2.CirculatingSupply(), supplyBefore)
	}
	for i := 0; i < dag.CanonicalCount(); i++ {
		a, _ := dag.CanonicalHashAt(i)
		b, _ := dag2.CanonicalHashAt(i)
		if a != b {
			t.Fatalf("canonical order diverged at index %d", i)
		}
	}

	// 5: payment between wallet keys.
	recipient, _ := cryptography.NewKeyPair()
	addr := cryptography.AddressFromPubKey(recipient.Public)
	total, _, _ := dag.Balance(pkh)
	send := total / 3
	tx, err := w.BuildTx(dag, addr, send, 1000)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := sharedPool.Add(tx, dag.MempoolView()); err != nil {
		t.Fatalf("mempool: %v", err)
	}
	if err := miner.MineN(1); err != nil {
		t.Fatal(err)
	}
	rTotal, _, _ := dag.Balance(cryptography.Hash160Of(recipient.Public))
	if rTotal != send {
		t.Fatalf("recipient got %d, want %d", rTotal, send)
	}
}

func openWallet(t *testing.T) (*wallet.Wallet, error) {
	t.Helper()
	path := t.TempDir() + "/wallet.json"
	w, err := wallet.Create(path, "integration-passphrase")
	if err != nil {
		return nil, err
	}
	w.Close()
	return wallet.Open(path, "integration-passphrase")
}

// walletFirstKeyHash derives the first key's public key hash via the
// exported address API.
func walletFirstKeyHash(t *testing.T) [20]byte {
	t.Helper()
	w, err := openWallet(t)
	if err != nil {
		t.Fatal(err)
	}
	addr := w.Addresses()[0]
	pkh, err := cryptography.AddressToPubKeyHash(addr)
	if err != nil {
		t.Fatal(err)
	}
	return pkh
}

// TestParallelBranchesConverge: two miners building on different tips produce
// a widening DAG; every node that processes the same blocks in any order
// reaches the same canonical state.
func TestParallelBranchesConverge(t *testing.T) {
	p := consensus.Defaults()
	p.GenesisDifficulty = 1
	p.DifficultyMax = 4
	p.CoinbaseMaturity = 1

	dag, _ := blockdag.New(&p, blockdag.Hooks{})
	m1 := mining.NewMiner(dag, mining.NewMemPool(&p), cryptography.Hash160Of([]byte("m1")), 1)
	m2 := mining.NewMiner(dag, mining.NewMemPool(&p), cryptography.Hash160Of([]byte("m2")), 1)

	var branchA, branchB []*blockdag.Block
	for i := 0; i < 4; i++ {
		b, err := m1.MineOne()
		if err != nil {
			t.Fatal(err)
		}
		if err := dag.AcceptBlock(b); err != nil {
			t.Fatal(err)
		}
		branchA = append(branchA, b)
	}
	// Miner 2 builds on the DAG's tips too (parallel siblings with equal
	// scores exercise the hash tiebreak).
	for i := 0; i < 4; i++ {
		b, err := m2.MineOne()
		if err != nil {
			t.Fatal(err)
		}
		if err := dag.AcceptBlock(b); err != nil {
			t.Fatal(err)
		}
		branchB = append(branchB, b)
	}
	// All 8 blocks must be in the canonical order exactly once.
	seen := map[string]bool{}
	for i := 0; i < dag.CanonicalCount(); i++ {
		h, _ := dag.CanonicalHashAt(i)
		key := fmt.Sprintf("%x", h[:])
		if seen[key] {
			t.Fatalf("duplicate canonical entry at %d", i)
		}
		seen[key] = true
	}
	if dag.CanonicalCount() != 9 { // genesis + 8
		t.Fatalf("canonical = %d, want 9", dag.CanonicalCount())
	}
	// Rebuild in shuffled order and compare.
	dag3, _ := blockdag.New(&p, blockdag.Hooks{})
	all := append(append([]blockdag.Block{}, deref(branchA)...), deref(branchB)...)
	// deterministic shuffle
	for i := len(all) - 1; i > 0; i-- {
		j := int((uint64(i)*2654435761 + 1) % uint64(i+1))
		all[i], all[j] = all[j], all[i]
	}
	for i := range all {
		if err := dag3.AcceptBlock(&all[i]); err != nil && !errors.Is(err, blockdag.ErrOrphan) {
			t.Fatalf("replay: %v", err)
		}
	}
	if dag3.CanonicalCount() != dag.CanonicalCount() {
		t.Fatalf("shuffled replay count %d != %d", dag3.CanonicalCount(), dag.CanonicalCount())
	}
	for i := 0; i < dag3.CanonicalCount(); i++ {
		a, _ := dag.CanonicalHashAt(i)
		b, _ := dag3.CanonicalHashAt(i)
		if a != b {
			t.Fatalf("shuffled replay diverged at %d", i)
		}
	}
}

func deref(blocks []*blockdag.Block) []blockdag.Block {
	out := make([]blockdag.Block, 0, len(blocks))
	for _, b := range blocks {
		out = append(out, *b)
	}
	return out
}

// TestReplayAttackRejected: a transaction signed for one network (chain tag)
// must be rejected on a network with different genesis parameters.
func TestReplayAttackRejected(t *testing.T) {
	p1 := consensus.Defaults()
	p1.GenesisDifficulty = 1
	p2 := consensus.Defaults()
	p2.GenesisDifficulty = 1
	p2.GenesisTime = p1.GenesisTime + 999 // different genesis -> different tag

	if blockdag.ChainTag(&p1) == blockdag.ChainTag(&p2) {
		t.Fatal("chain tags identical across different genesis params")
	}

	// Sign a tx under p1's tag; validation under p2's tag must fail.
	kp, _ := cryptography.NewKeyPair()
	tx := &transactions.Tx{
		Version: 1,
		Inputs: []transactions.TxIn{{
			PrevTx:    cryptography.Hash256Single([]byte("funding")),
			PrevIndex: 0,
		}},
		Outputs: []transactions.TxOut{{Value: 1000, PubKeyHash: cryptography.Hash160Of(kp.Public)}},
	}
	copy(tx.Inputs[0].PubKey[:], kp.Public)
	d1 := tx.Digest(blockdag.ChainTag(&p1))
	copy(tx.Inputs[0].Sig[:], kp.Sign(d1[:]))
	// Structural check under p2 (which recomputes the digest with p2's tag).
	if err := transactions.CheckStructure(tx, &p2, blockdag.ChainTag(&p2)); err == nil {
		t.Fatal("cross-network replay accepted (replay protection broken)")
	}
	// And under p1 it is fine.
	if err := transactions.CheckStructure(tx, &p1, blockdag.ChainTag(&p1)); err != nil {
		t.Fatalf("own-network tx rejected: %v", err)
	}
}

// TestEmissionLongHorizon walks 10 simulated years and asserts the realized
// annual inflation never exceeds the schedule and the tail decays.
func TestEmissionLongHorizon(t *testing.T) {
	p := consensus.Defaults()
	// Compressed schedule for a fast test: 30-second "years", bootstrap of
	// exactly two years (60 seconds) so year 2 is the first rate year.
	p.SecondsPerYear = 30
	p.BootstrapSeconds = 2 * 30
	p.GenesisTime = uint64(time.Now().Unix())

	mtp := p.GenesisTime
	supply := uint64(0)
	yearIndex := uint64(0)
	yearBase := uint64(0)
	prevRate := uint64(860000) // theoretical cap
	perYear := make(map[uint64]uint64)
	var yearNow uint64
	for step := 0; step < 12*30; step++ { // 12 "years"
		year := consensus.ScheduleYear(&p, mtp)
		if year != yearIndex {
			yearBase = supply
			yearIndex = year
		}
		per := consensus.EmissionPerSecond(&p, mtp, yearBase, year)
		rate := consensus.RateMicroBP(&p, year)
		if rate > prevRate {
			t.Fatalf("rate rose in year %d: %d > %d", year, rate, prevRate)
		}
		prevRate = rate
		if rate > 860000 {
			t.Fatalf("year %d rate exceeds ceiling", year)
		}
		supply += per
		perYear[year] += per
		mtp++
		yearNow = year
	}
	// Bootstrap years must emit exactly bootstrap_per_second * seconds.
	want0 := p.BootstrapPerSecond * p.SecondsPerYear
	if perYear[0] != want0 || perYear[1] != want0 {
		t.Fatalf("bootstrap emission years 0/1 = %d/%d, want %d each", perYear[0], perYear[1], want0)
	}
	// Year 2 is the first rate year. The realized rate is emission relative
	// to the year-start supply (the snapshot); it must sit inside the band
	// and never rise across the horizon.
	rateOf := func(year uint64) uint64 {
		// The snapshot base for year y is the cumulative supply at its start.
		var base uint64
		for y := uint64(0); y < year; y++ {
			base += perYear[y]
		}
		if base == 0 {
			return 0
		}
		return perYear[year] * 100000000 / base
	}
	for _, y := range []uint64{2, 3, 4} {
		r := rateOf(y)
		if r < 800000 || r > 860000 {
			t.Fatalf("year %d realized rate %d microBP outside [800000, 860000]", y, r)
		}
	}
	if rateOf(4) > rateOf(2) {
		t.Fatalf("rate schedule rose: year4 %d > year2 %d", rateOf(4), rateOf(2))
	}
	_ = yearNow
}
