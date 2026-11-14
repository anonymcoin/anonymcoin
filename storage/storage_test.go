// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package storage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/anonymcoin/anonymcoin/blockdag"
	"github.com/anonymcoin/anonymcoin/consensus"
	"github.com/anonymcoin/anonymcoin/cryptography"
	"github.com/anonymcoin/anonymcoin/transactions"
)

// mineInto mines a linear chain of trivial-PoW blocks into a DAG and returns
// them in acceptance order.
func mineChain(t *testing.T, n int) (*blockdag.DAG, []*blockdag.Block, consensus.Params) {
	t.Helper()
	p := consensus.Defaults()
	p.GenesisDifficulty = 1
	p.CoinbaseMaturity = 1
	d, err := blockdag.New(&p, blockdag.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	var out []*blockdag.Block
	tm := p.GenesisTime
	for i := 0; i < n; i++ {
		tm++
		diff, _ := d.ExpectedDifficulty(d.TipsSorted(1))
		reward, _ := d.ForecastReward(d.TipsSorted(1), tm)
		cb := &transactions.Tx{
			Version: 1,
			Outputs: []transactions.TxOut{{Value: reward, PubKeyHash: cryptography.Hash160Of([]byte("m"))}},
			Aux:     []byte{byte(i), byte(i >> 8)},
		}
		blk := &blockdag.Block{
			Header: &blockdag.Header{
				Version:    p.ProtocolVersion,
				Parents:    d.TipsSorted(1),
				Time:       tm,
				Difficulty: diff,
			},
			Txs: []transactions.Tx{*cb},
		}
		blk.Header.TxMerkle = blockdag.ComputeMerkle(blk.TxIDs())
		mine(t, blk.Header)
		if err := d.AcceptBlock(blk); err != nil {
			t.Fatalf("accept block %d: %v", i, err)
		}
		out = append(out, blk)
	}
	return d, out, p
}

func mine(t *testing.T, h *blockdag.Header) {
	t.Helper()
	for nonce := uint64(0); nonce < 1<<30; nonce++ {
		h.Nonce = nonce
		if blockdag.HeaderMeetsTarget(h) {
			return
		}
	}
	t.Fatal("nonce exhausted")
}

func TestBlockStoreRoundtripAndReplay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocks.dat")
	_, blocks, p := mineChain(t, 25)

	bs, err := Open(path, &p, false)
	if err != nil {
		t.Fatal(err)
	}
	if bs.Count() != 0 {
		t.Fatal("fresh store not empty")
	}
	for _, b := range blocks {
		if err := bs.Append(b); err != nil {
			t.Fatal(err)
		}
	}
	if bs.Count() != len(blocks) {
		t.Fatalf("count = %d, want %d", bs.Count(), len(blocks))
	}
	// Duplicate append is a no-op.
	if err := bs.Append(blocks[0]); err != nil {
		t.Fatal(err)
	}
	if bs.Count() != len(blocks) {
		t.Fatal("duplicate append changed count")
	}
	// Get every block and compare.
	for _, want := range blocks {
		got, err := bs.Get(want.BlockHash(), &p)
		if err != nil {
			t.Fatal(err)
		}
		encW, _ := blockdag.EncodeBlock(want)
		encG, _ := blockdag.EncodeBlock(got)
		if string(encW) != string(encG) {
			t.Fatal("stored block differs")
		}
	}
	// Unknown hash.
	if _, err := bs.Get(cryptography.Hash256Single([]byte("nope")), &p); !errors.Is(err, ErrUnknownBlock) {
		t.Fatal("wrong error class for unknown block")
	}
	bs.Close()

	// Reopen: index rebuild must find everything.
	bs2, err := Open(path, &p, false)
	if err != nil {
		t.Fatal(err)
	}
	defer bs2.Close()
	if bs2.Count() != len(blocks) {
		t.Fatalf("reopen count = %d, want %d", bs2.Count(), len(blocks))
	}
	// Deterministic replay rebuilds the same canonical state.
	d2, err := blockdag.New(&p, blockdag.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	if err := bs2.ForEach(&p, func(b *blockdag.Block) error {
		return d2.AcceptBlock(b)
	}); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if d2.CanonicalCount() != len(blocks)+1 {
		t.Fatalf("replay canonical = %d, want %d", d2.CanonicalCount(), len(blocks)+1)
	}
	if d2.CirculatingSupply() != sumCoinbase(blocks) {
		t.Fatal("replay supply mismatch")
	}
}

func sumCoinbase(blocks []*blockdag.Block) uint64 {
	var sum uint64
	for _, b := range blocks {
		for i := range b.Txs[0].Outputs {
			sum += b.Txs[0].Outputs[i].Value
		}
	}
	return sum
}

func TestTornTailTruncated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocks.dat")
	_, blocks, p := mineChain(t, 5)
	bs, _ := Open(path, &p, false)
	for _, b := range blocks {
		bs.Append(b)
	}
	bs.Close()

	// Simulate a torn tail: append garbage.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.Write([]byte{'A', 'N', 'M', '1', 0xff, 0x00, 0x00, 0x00, 0xde, 0xad})
	f.Close()

	bs2, err := Open(path, &p, false)
	if err != nil {
		t.Fatalf("reopen after torn tail: %v", err)
	}
	defer bs2.Close()
	if bs2.Count() != len(blocks) {
		t.Fatalf("count after torn tail = %d, want %d", bs2.Count(), len(blocks))
	}
}
