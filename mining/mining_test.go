// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package mining

import (
	"crypto/ed25519"
	"testing"

	"github.com/anonymcoin/anonymcoin/blockdag"
	"github.com/anonymcoin/anonymcoin/consensus"
	"github.com/anonymcoin/anonymcoin/cryptography"
	"github.com/anonymcoin/anonymcoin/transactions"
)

func TestMempoolAddRemoveTop(t *testing.T) {
	p := consensus.Defaults()
	p.GenesisDifficulty = 1
	p.CoinbaseMaturity = 1
	d, _ := blockdag.New(&p, blockdag.Hooks{})

	kp, _ := cryptography.NewKeyPair()
	mineBlocksTo(t, d, &p, 5, cryptography.Hash160Of(kp.Public))
	view := d.MempoolView()

	// Unknown input rejected.
	unknown := &transactions.Tx{
		Version: 1,
		Inputs: []transactions.TxIn{{
			PrevTx:    cryptography.Hash256Single([]byte("never-was")),
			PrevIndex: 0,
		}},
		Outputs: []transactions.TxOut{{Value: p.MinRelayFee + 1, PubKeyHash: cryptography.Hash160Of([]byte("r"))}},
	}
	copy(unknown.Inputs[0].PubKey[:], kp.Public)
	unknownDigest := unknown.Digest(blockdag.ChainTag(&p))
	sig := ed25519.Sign(ed25519.PrivateKey(kp.Private), unknownDigest[:])
	copy(unknown.Inputs[0].Sig[:], sig)
	if err := NewMemPool(&p).Add(unknown, view); err == nil {
		t.Fatal("unknown-input tx accepted by mempool")
	}

	// Spending a mature, funded coinbase is accepted (block 4's coinbase has
	// one canonical second of emission and is mature at tip index 5).
	mp := NewMemPool(&p)
	tx := spendTx(t, d, &p, kp, 4, p.MinRelayFee+1)
	if err := mp.Add(tx, d.MempoolView()); err != nil {
		t.Fatalf("valid spend rejected by mempool: %v", err)
	}
	if !mp.Has(tx.ID()) || mp.Len() != 1 {
		t.Fatal("mempool state inconsistent")
	}
	top := mp.Top(10)
	if len(top) != 1 {
		t.Fatalf("pool top = %d entries", len(top))
	}
	// The recorded fee must equal input minus output for the spent coinbase
	// (its value depends on the node clock via the emission clamp, so derive
	// it from the stored block).
	inValue := coinbaseValueAt(t, d, 4)
	if top[0].Fee != inValue-(p.MinRelayFee+1) {
		t.Fatalf("fee mismatch: got %d want %d", top[0].Fee, inValue-(p.MinRelayFee+1))
	}
	mp.Remove(tx.ID())
	if mp.Len() != 0 {
		t.Fatal("remove failed")
	}

	// Coinbase transactions are never pooled.
	if err := mp.Add(&transactions.Tx{Version: 1}, d.MempoolView()); err == nil {
		t.Fatal("coinbase accepted into mempool")
	}
}

func TestMinerMinesBlocks(t *testing.T) {
	p := consensus.Defaults()
	p.GenesisDifficulty = 1
	p.DifficultyMax = 2
	p.CoinbaseMaturity = 1
	d, _ := blockdag.New(&p, blockdag.Hooks{})
	pool := NewMemPool(&p)
	payout := cryptography.Hash160Of([]byte("payout"))
	m := NewMiner(d, pool, payout, 2)
	if err := m.MineN(6); err != nil {
		t.Fatalf("mine 6: %v", err)
	}
	if d.CanonicalCount() != 7 {
		t.Fatalf("canonical = %d, want 7", d.CanonicalCount())
	}
	_, score, _ := d.TipInfo()
	if score == 0 {
		t.Fatal("tip score did not advance")
	}
	total, _, _ := d.Balance(payout)
	if total == 0 {
		t.Fatal("payout balance empty after mining")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func mineBlocks(t *testing.T, d *blockdag.DAG, p *consensus.Params, n int) {
	t.Helper()
	m := NewMiner(d, NewMemPool(p), cryptography.Hash160Of([]byte("miner")), 1)
	if err := m.MineN(n); err != nil {
		t.Fatalf("mine %d blocks: %v", n, err)
	}
}

func mineBlocksTo(t *testing.T, d *blockdag.DAG, p *consensus.Params, n int, payout [20]byte) {
	t.Helper()
	m := NewMiner(d, NewMemPool(p), payout, 1)
	if err := m.MineN(n); err != nil {
		t.Fatalf("mine %d blocks: %v", n, err)
	}
}

func coinbaseValueAt(t *testing.T, d *blockdag.DAG, blockIdx int) uint64 {
	t.Helper()
	h, err := d.CanonicalHashAt(blockIdx)
	if err != nil {
		t.Fatal(err)
	}
	blk, ok := d.BlockBody(h)
	if !ok {
		t.Fatal("block body unavailable")
	}
	return blk.Txs[0].Outputs[0].Value
}

func spendTx(t *testing.T, d *blockdag.DAG, p *consensus.Params, kp cryptography.KeyPair, blockIdx int, out uint64) *transactions.Tx {
	t.Helper()
	h, err := d.CanonicalHashAt(blockIdx)
	if err != nil {
		t.Fatal(err)
	}
	blk, ok := d.BlockBody(h)
	if !ok {
		t.Fatal("block body unavailable")
	}
	tx := &transactions.Tx{
		Version: 1,
		Inputs: []transactions.TxIn{{
			PrevTx:    blk.Txs[0].ID(),
			PrevIndex: 0,
		}},
		Outputs: []transactions.TxOut{{Value: out, PubKeyHash: cryptography.Hash160Of([]byte("r"))}},
	}
	copy(tx.Inputs[0].PubKey[:], kp.Public)
	digest := tx.Digest(blockdag.ChainTag(p))
	sig := ed25519.Sign(ed25519.PrivateKey(kp.Private), digest[:])
	copy(tx.Inputs[0].Sig[:], sig)
	return tx
}
