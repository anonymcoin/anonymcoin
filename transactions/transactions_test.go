// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package transactions

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/anonymcoin/anonymcoin/consensus"
	"github.com/anonymcoin/anonymcoin/cryptography"
)

var chainTag = [4]byte{0x01, 0x02, 0x03, 0x04}

func newFundedTx(t *testing.T, key cryptography.KeyPair, outs []TxOut) (*Tx, cryptography.Hash) {
	t.Helper()
	tx := &Tx{
		Version: 1,
		Inputs: []TxIn{{
			PrevTx:    cryptography.Hash256Single([]byte("funding")),
			PrevIndex: 0,
		}},
		Outputs: outs,
	}
	// The pubkey is committed by the digest; fill it before signing.
	copy(tx.Inputs[0].PubKey[:], key.Public)
	d := tx.Digest(chainTag)
	copy(tx.Inputs[0].Sig[:], key.Sign(d[:]))
	return tx, tx.ID()
}

func TestEncodeDecodeRoundtrip(t *testing.T) {
	kp, _ := cryptography.NewKeyPair()
	tx, _ := newFundedTx(t, kp, []TxOut{{Value: 12345, PubKeyHash: cryptography.Hash160Of([]byte("abc"))}})
	enc := tx.Encode()
	back, err := Decode(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(back.Encode(), enc) {
		t.Fatal("roundtrip mismatch")
	}
	if back.ID() != tx.ID() {
		t.Fatal("id mismatch after roundtrip")
	}
}

func TestTrailingBytesRejected(t *testing.T) {
	kp, _ := cryptography.NewKeyPair()
	tx, _ := newFundedTx(t, kp, []TxOut{{Value: 1, PubKeyHash: cryptography.Hash160Of([]byte("x"))}})
	enc := tx.Encode()
	if _, err := Decode(append(enc, 0x00)); err == nil {
		t.Fatal("trailing byte accepted")
	}
	if _, err := Decode(enc[:len(enc)-1]); err == nil {
		t.Fatal("truncated encoding accepted")
	}
}

func TestSignatureVerificationAndTamper(t *testing.T) {
	p := consensus.Defaults()
	kp, _ := cryptography.NewKeyPair()
	tx, _ := newFundedTx(t, kp, []TxOut{{Value: 5_000, PubKeyHash: cryptography.Hash160Of(kp.Public)}})
	if err := CheckStructure(tx, &p, chainTag); err != nil {
		t.Fatalf("valid tx rejected: %v", err)
	}
	// Tamper with an output value -> digest no longer matches signature.
	tampered := *tx
	tampered.Outputs = append([]TxOut(nil), tx.Outputs...)
	tampered.Outputs[0].Value = 9_999
	if err := CheckStructure(&tampered, &p, chainTag); err == nil {
		t.Fatal("tampered tx accepted")
	}
	// Wrong chain tag -> invalid (replay protection across networks).
	wrongTag := [4]byte{0xaa, 0xbb, 0xcc, 0xdd}
	if err := CheckStructure(tx, &p, wrongTag); err == nil {
		t.Fatal("tx accepted under foreign chain tag (replay protection broken)")
	}
}

func TestDuplicateInputsRejected(t *testing.T) {
	p := consensus.Defaults()
	kp, _ := cryptography.NewKeyPair()
	tx := &Tx{
		Version: 1,
		Inputs: []TxIn{{
			PrevTx:    cryptography.Hash256Single([]byte("same")),
			PrevIndex: 0,
		}, {
			PrevTx:    cryptography.Hash256Single([]byte("same")),
			PrevIndex: 0,
		}},
		Outputs: []TxOut{{Value: 2 * p.DustLimit, PubKeyHash: cryptography.Hash160Of(kp.Public)}},
	}
	d := tx.Digest(chainTag)
	copy(tx.Inputs[0].PubKey[:], kp.Public)
	copy(tx.Inputs[0].Sig[:], kp.Sign(d[:]))
	copy(tx.Inputs[1].PubKey[:], kp.Public)
	copy(tx.Inputs[1].Sig[:], kp.Sign(d[:]))
	if err := CheckStructure(tx, &p, chainTag); err == nil {
		t.Fatal("duplicate input accepted")
	}
}

func TestDustAndFeeRules(t *testing.T) {
	p := consensus.Defaults()
	kp, _ := cryptography.NewKeyPair()
	// Dust output.
	tx, _ := newFundedTx(t, kp, []TxOut{{Value: p.DustLimit - 1, PubKeyHash: cryptography.Hash160Of(kp.Public)}})
	if err := CheckStructure(tx, &p, chainTag); err == nil {
		t.Fatal("dust output accepted")
	}
	// Fee below relay minimum.
	low := &Tx{
		Version: 1,
		Inputs:  []TxIn{{PrevTx: cryptography.Hash256Single([]byte("f")), PrevIndex: 0}},
		Outputs: []TxOut{{Value: 10_000 * p.AtomsPerCoin, PubKeyHash: cryptography.Hash160Of(kp.Public)}},
	}
	d := low.Digest(chainTag)
	copy(low.Inputs[0].PubKey[:], kp.Public)
	copy(low.Inputs[0].Sig[:], kp.Sign(d[:]))
	view := mapSpendView{
		key(tx.Inputs[0].PrevTx, 0): OutputView{Value: 10_000*p.AtomsPerCoin + p.MinRelayFee - 1, PubKeyHash: cryptography.Hash160Of(kp.Public)},
	}
	if err := ValidateSpendable(low, &p, chainTag, view); err == nil {
		t.Fatal("low-fee tx accepted")
	}
	// Unknown input rejected.
	if err := ValidateSpendable(low, &p, chainTag, mapSpendView{}); err == nil {
		t.Fatal("unknown input accepted")
	}
}

func TestFeeComputation(t *testing.T) {
	tx := &Tx{
		Inputs:  make([]TxIn, 2),
		Outputs: []TxOut{{Value: 30}, {Value: 20}},
	}
	fee, err := tx.Fee([]uint64{100, 10})
	if err != nil || fee != 60 {
		t.Fatalf("fee = %d err %v, want 60 nil", fee, err)
	}
	if _, err := tx.Fee([]uint64{1}); err == nil {
		t.Fatal("mismatched input values accepted")
	}
	if _, err := tx.Fee([]uint64{10, 10}); err == nil {
		t.Fatal("outputs exceeding inputs accepted")
	}
}

// mapSpendView is a test SpendView.
type mapSpendView map[[36]byte]OutputView

func key(h [32]byte, i uint32) [36]byte {
	var k [36]byte
	copy(k[:32], h[:])
	k[32] = byte(i)
	k[33] = byte(i >> 8)
	k[34] = byte(i >> 16)
	k[35] = byte(i >> 24)
	return k
}

func (m mapSpendView) Lookup(prev [32]byte, index uint32) (OutputView, bool) {
	v, ok := m[key(prev, index)]
	return v, ok
}

func TestPubkeyHashBinding(t *testing.T) {
	p := consensus.Defaults()
	kp, _ := cryptography.NewKeyPair()
	other, _ := cryptography.NewKeyPair()
	tx := &Tx{
		Version: 1,
		Inputs:  []TxIn{{PrevTx: cryptography.Hash256Single([]byte("f2")), PrevIndex: 0}},
		Outputs: []TxOut{{Value: 1_000_000, PubKeyHash: cryptography.Hash160Of(other.Public)}},
	}
	d := tx.Digest(chainTag)
	copy(tx.Inputs[0].PubKey[:], kp.Public)
	copy(tx.Inputs[0].Sig[:], kp.Sign(d[:]))
	// The spender's pubkey does not match the locked hash -> rejected.
	view := mapSpendView{
		key(tx.Inputs[0].PrevTx, 0): OutputView{Value: 2_000_000, PubKeyHash: cryptography.Hash160Of(other.Public)},
	}
	if err := ValidateSpendable(tx, &p, chainTag, view); err == nil {
		t.Fatal("pubkey/hash mismatch accepted")
	}
	_ = ed25519.PublicKeySize
	_ = rand.Reader
}
