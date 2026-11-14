// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package blockdag

import (
	"testing"

	"github.com/anonymcoin/anonymcoin/cryptography"
	"github.com/anonymcoin/anonymcoin/transactions"
)

// ---------------------------------------------------------------------------
// Security regressions: these tests encode the two consensus-critical rules
// that were historically missing from the application path. They must keep
// failing loudly if anyone ever removes them again.
// ---------------------------------------------------------------------------

// TestRegressTheftViaForeignPubKeyRejected: a mined block that spends a UTXO
// it does not own (input signed under the attacker's key, output paid to the
// attacker) must be rejected as INVALID — not accepted, not skipped as a
// conflict, and the victim's UTXO must remain intact.
func TestRegressTheftViaForeignPubKeyRejected(t *testing.T) {
	p := testParams()
	p.MTPWindow = 2 // funding coinbases carry a real reward
	d, _ := New(&p, Hooks{})

	victim, _ := cryptography.NewKeyPair()
	attacker, _ := cryptography.NewKeyPair()
	victimPKH := cryptography.Hash160Of(victim.Public)
	attackerPKH := cryptography.Hash160Of(attacker.Public)

	tm := p.GenesisTime
	var fundingHashes []cryptography.Hash
	for i := 0; i < 8; i++ {
		tm++
		b := buildBlockPaying(t, d, d.TipsSorted(1), tm, nil, victimPKH)
		mustAccept(t, d, b)
		fundingHashes = append(fundingHashes, b.BlockHash())
	}
	// Spend the coinbase of the 5th funding block: canonical index 5, tip 8,
	// maturity 3 -> mature, and (with MTPWindow=2) worth a real reward.
	fundingHash := fundingHashes[4]

	// The theft: spend the victim's coinbase under the ATTACKER's key.
	cbID := coinbaseIDOf(t, d, fundingHash)
	theft := &transactions.Tx{
		Version: 1,
		Inputs: []transactions.TxIn{{
			PrevTx:    cbID,
			PrevIndex: 0,
		}},
		Outputs: []transactions.TxOut{{Value: p.MinRelayFee + 1, PubKeyHash: attackerPKH}},
	}
	copy(theft.Inputs[0].PubKey[:], attacker.Public) // NOT the owner
	sig := theft.Digest(d.ChainTag())
	copy(theft.Inputs[0].Sig[:], attacker.Sign(sig[:])) // validly signed — but by the wrong key

	theftBlock := buildBlock(t, d, []cryptography.Hash{fundingHash}, tm+1, []transactions.Tx{*theft})
	errTheft := d.AcceptBlock(theftBlock)
	if errTheft == nil {
		t.Fatal("theft block accepted: pay-to-pubkey-hash binding is not enforced in the application path")
	}
	if got := invalidReasonOf(errTheft); got != invalidPubKeyHashBinding {
		t.Fatalf("theft rejected for the wrong reason: %v", errTheft)
	}

	// The victim's coinbase must still be spendable by the rightful owner.
	claim := &transactions.Tx{
		Version: 1,
		Inputs: []transactions.TxIn{{
			PrevTx:    cbID,
			PrevIndex: 0,
		}},
		Outputs: []transactions.TxOut{{Value: p.MinRelayFee + 1, PubKeyHash: victimPKH}},
	}
	copy(claim.Inputs[0].PubKey[:], victim.Public)
	sig = claim.Digest(d.ChainTag())
	copy(claim.Inputs[0].Sig[:], victim.Sign(sig[:]))
	claimBlock := buildBlock(t, d, d.TipsSorted(1), tm+2, []transactions.Tx{*claim})
	if err := d.AcceptBlock(claimBlock); err != nil {
		t.Fatalf("victim claim rejected after failed theft: %v", err)
	}
}

// invalidReasonOf extracts the applyInvalidReason text from an
// ErrInvalidBlock error (best-effort; test helper).
func invalidReasonOf(err error) applyInvalidReason {
	const prefix = "blockdag: block invalid: "
	msg := err.Error()
	if len(msg) <= len(prefix) {
		return ""
	}
	reason := msg[len(prefix):]
	for _, r := range []applyInvalidReason{invalidUnknownInput, invalidPubKeyHashBinding,
		invalidInputOverflow, invalidOutputOverflow, invalidUnbalanced} {
		if string(r) == reason {
			return r
		}
	}
	return ""
}

// TestRegressUnbalancedTxCannotMint: a block containing a transaction whose
// outputs exceed its inputs (fee arithmetic would underflow) must be
// rejected; circulating supply must never grow beyond the emission integral.
func TestRegressUnbalancedTxCannotMint(t *testing.T) {
	p := testParams()
	p.MTPWindow = 2
	p.MaxMoney = 10_000_000_000_000 // keep the output inside MaxMoney
	d, _ := New(&p, Hooks{})

	owner, _ := cryptography.NewKeyPair()
	attacker, _ := cryptography.NewKeyPair()
	ownerPKH := cryptography.Hash160Of(owner.Public)

	tm := p.GenesisTime
	var fundingHashes []cryptography.Hash
	for i := 0; i < 12; i++ {
		tm++
		b := buildBlockPaying(t, d, d.TipsSorted(1), tm, nil, ownerPKH)
		mustAccept(t, d, b)
		fundingHashes = append(fundingHashes, b.BlockHash())
	}
	supplyBefore := d.CirculatingSupply()

	// One input of value V, two outputs totalling V + huge — the historical
	// underflow made feesApplied wrap and inflated the coinbase budget.
	cbID := coinbaseIDOf(t, d, fundingHashes[6])
	var inputVal uint64
	_, _, entries := d.Balance(ownerPKH)
	for _, e := range entries {
		inputVal += e.Value
	}
	if inputVal == 0 {
		t.Fatal("funding produced no value; test setup broken")
	}
	unbalanced := &transactions.Tx{
		Version: 1,
		Inputs: []transactions.TxIn{{
			PrevTx:    cbID,
			PrevIndex: 0,
		}},
		Outputs: []transactions.TxOut{
			{Value: p.MaxMoney, PubKeyHash: cryptography.Hash160Of(attacker.Public)},
			{Value: p.MaxMoney, PubKeyHash: cryptography.Hash160Of(attacker.Public)},
		},
	}
	copy(unbalanced.Inputs[0].PubKey[:], owner.Public)
	sig := unbalanced.Digest(d.ChainTag())
	copy(unbalanced.Inputs[0].Sig[:], owner.Sign(sig[:]))

	bad := buildBlock(t, d, d.TipsSorted(1), tm+1, []transactions.Tx{*unbalanced})
	if err := d.AcceptBlock(bad); err == nil {
		t.Fatal("unbalanced transaction accepted: fee underflow mints value")
	}
	if got := d.CirculatingSupply(); got != supplyBefore {
		t.Fatalf("supply changed after rejected block: %d -> %d", supplyBefore, got)
	}
}

// TestRegressLateBlockLeavesNoGhostNode: a late block (would reorder
// finalized history) must not stay registered in the node index; resubmitting
// it must return the same late-block error, not ErrDuplicate, and HasBlock
// must stay false.
func TestRegressLateBlockLeavesNoGhostNode(t *testing.T) {
	p := testParams()
	p.FinalizedDepth = 10
	d, _ := New(&p, Hooks{})
	tm := p.GenesisTime
	var hashes []cryptography.Hash
	for i := 0; i < 40; i++ {
		tm++
		b := buildBlock(t, d, d.TipsSorted(1), tm, nil)
		mustAccept(t, d, b)
		hashes = append(hashes, b.BlockHash())
	}
	late := buildBlock(t, d, []cryptography.Hash{hashes[8]}, tm+1, nil)
	h := late.BlockHash()

	err := d.AcceptBlock(late)
	if !errorsIsLate(err) {
		t.Fatalf("expected late-block rejection, got %v", err)
	}
	if d.HasBlock(h) {
		t.Fatal("late block stayed registered in the node index (ghost node)")
	}
	// Resubmission must produce the same classification.
	err2 := d.AcceptBlock(late)
	if !errorsIsLate(err2) {
		t.Fatalf("resubmission of late block changed error class: %v", err2)
	}
}
