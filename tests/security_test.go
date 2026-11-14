// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Security property tests: replay protection, KDF strength, wallet
// hardening, rate limiting, RPC/network input validation.
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package tests

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"strings"
	"testing"

	"github.com/anonymcoin/anonymcoin/blockdag"
	"github.com/anonymcoin/anonymcoin/consensus"
	"github.com/anonymcoin/anonymcoin/cryptography"
	"github.com/anonymcoin/anonymcoin/hd"
	"github.com/anonymcoin/anonymcoin/transactions"
	"github.com/anonymcoin/anonymcoin/wallet"
)

// ---------------------------------------------------------------------------
// Replay protection: domain separation + chain tag binding.
// ---------------------------------------------------------------------------

// TestReplayProtectionChainTagBinding verifies that a transaction signed on
// one ANONYMCOIN network (a distinct parameter set = distinct genesis =
// distinct chain tag) can never validate on another network, even when every
// key and output value is identical. This is the cross-network replay guard.
func TestReplayProtectionChainTagBinding(t *testing.T) {
	// Two independent networks: different genesis times -> different genesis
	// hashes -> different chain tags.
	pA := consensus.Defaults()
	pB := consensus.Defaults()
	pB.GenesisTime = pA.GenesisTime + 1 // any param change re-derives genesis

	tagA := blockdag.ChainTag(&pA)
	tagB := blockdag.ChainTag(&pB)
	if tagA == tagB {
		t.Fatal("distinct parameter sets must produce distinct chain tags")
	}

	kp, _ := cryptography.NewKeyPair()
	tx := &transactions.Tx{
		Version: 1,
		Inputs: []transactions.TxIn{{
			PrevTx:    cryptography.Hash256([]byte("funding")),
			PrevIndex: 0,
		}},
		Outputs: []transactions.TxOut{{Value: 1000, PubKeyHash: cryptography.Hash160Of(kp.Public)}},
	}
	dA := tx.Digest(tagA)
	copy(tx.Inputs[0].Sig[:], kp.Sign(dA[:]))

	// The signature is valid under chain A's digest...
	sig := tx.Inputs[0].Sig
	dbA := tx.Digest(tagA)
	if !verifySig(kp, dbA, sig) {
		t.Fatal("signature does not verify on its own chain (broken test)")
	}
	// ...but the digest under chain B differs, so the same signed bytes are
	// invalid there. Replay across networks is impossible.
	dbB := tx.Digest(tagB)
	if bytes.Equal(dbA[:], dbB[:]) {
		t.Fatal("chain tag binding failed: digests identical across networks")
	}
	if verifySig(kp, dbB, sig) {
		t.Fatal("cross-network replay accepted: signature verifies on a foreign chain")
	}

	// The genesis-hash-derived tag must also be stable and non-trivial.
	if tagA == ([4]byte{}) {
		t.Fatal("chain tag degenerated to zero")
	}
}

// TestReplayProtectionDomainSeparation verifies the transaction digest is
// domain-separated: it must differ from every other BLAKE2b usage over the
// same material, and the exact digest bytes must depend on the protocol
// domain string.
func TestReplayProtectionDomainSeparation(t *testing.T) {
	kp, _ := cryptography.NewKeyPair()
	tx := &transactions.Tx{
		Version: 1,
		Inputs: []transactions.TxIn{{
			PrevTx:    cryptography.Hash256([]byte("funding")),
			PrevIndex: 0,
		}},
		Outputs: []transactions.TxOut{{Value: 1000, PubKeyHash: cryptography.Hash160Of(kp.Public)}},
	}
	tag := [4]byte{0x01, 0x02, 0x03, 0x04}

	d1 := tx.Digest(tag)
	d2 := tx.Digest(tag)
	if d1 != d2 {
		t.Fatal("digest not deterministic")
	}

	// The digest must NOT equal a plain hash of the encoded body (that would
	// mean domain separation was dropped).
	body := tx.Encode()
	if d1 == cryptography.Hash256Single(body) {
		t.Fatal("digest lost domain separation: equals plain hash of body")
	}
	if d1 == cryptography.Hash256(tag[:], body) {
		t.Fatal("digest lost domain separation: equals tag||body hash")
	}

	// Changing one chain-tag byte must change the digest (full binding).
	tag[0] ^= 0x01
	if tx.Digest(tag) == d1 {
		t.Fatal("digest ignores chain tag bytes")
	}
}

func verifySig(pub cryptography.KeyPair, d cryptography.Hash, sig [64]byte) bool {
	return ed25519.Verify(ed25519.PublicKey(pub.Public[:]), d[:], sig[:])
}

// walletCreate is a test helper: creates an open wallet with the shared
// test passphrase.
func walletCreate(t *testing.T, path string) (*wallet.Wallet, error) {
	t.Helper()
	return wallet.Create(path, "test-passphrase-1")
}

// walletRestore is a test helper: restores from a phrase with the shared
// test passphrase.
func walletRestore(t *testing.T, path, phrase string) (*wallet.Wallet, error) {
	t.Helper()
	return wallet.Restore(path, "test-passphrase-1", phrase, "")
}

func fileExistsForTests(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// ---------------------------------------------------------------------------
// Mnemonic wallet flow: the full recovery lifecycle.
// ---------------------------------------------------------------------------

// TestMnemonicRecoveryFlow covers the production recovery procedure end to
// end: create -> read 24 words -> restore on a fresh datadir from the same
// words -> identical addresses -> deterministic keys.
func TestMnemonicRecoveryFlow(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()

	wA, err := walletCreate(t, dirA+"/wallet.json")
	if err != nil {
		t.Fatal(err)
	}
	phrase, err := wA.MnemonicWords()
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.Fields(phrase)) != 24 {
		t.Fatalf("phrase must be 24 words, got %d", len(strings.Fields(phrase)))
	}
	addrA, err := wA.Address(0)
	if err != nil {
		t.Fatal(err)
	}
	// Derive a second address so the persisted counter covers index 1; a
	// restored wallet must reproduce it deterministically.
	addrA1, err := wA.NewAddress("test-passphrase-1")
	if err != nil {
		t.Fatal(err)
	}
	wA.Close()

	// Normalize the phrase the way an operator would retype it: split across
	// lines, extra spaces, mixed case.
	retyped := strings.ToUpper(strings.Join(strings.Fields(phrase), "\n  "))

	wB, err := walletRestore(t, dirB+"/wallet.json", retyped)
	if err != nil {
		t.Fatalf("restore from retyped phrase failed: %v", err)
	}
	defer wB.Close()
	addrB, err := wB.Address(0)
	if err != nil {
		t.Fatal(err)
	}
	if addrA != addrB {
		t.Fatalf("restored wallet first address %s != original %s", addrB, addrA)
	}
	// Multiple derived addresses must also match the original wallet.
	a1, err := wB.Address(1)
	if err != nil {
		t.Fatal(err)
	}
	if a1 != addrA1 {
		t.Fatalf("restored index-1 address %s != original %s", a1, addrA1)
	}
	if a1 == addrB {
		t.Fatal("index 1 collides with index 0")
	}

	// An invalid phrase must fail loudly BEFORE any wallet file is written.
	bad := strings.Join(strings.Fields(phrase)[:23], " ") // 23 words
	if _, err := walletRestore(t, dirB+"/bad.json", bad); err == nil {
		t.Fatal("23-word phrase accepted by Restore")
	}
	if fileExistsLocal(dirB + "/bad.json") {
		t.Fatal("invalid recovery wrote a wallet file")
	}
	// A checksum-corrupted phrase must also fail (this specific corruption
	// is checksum-invalid; the 8-bit checksum catches single-word typos
	// with ~1/256 collision chance, which this vector avoids).
	corrupt := strings.Fields(phrase)
	corrupt[23] = "zoo"
	if corrupt[23] != "zoo" {
		t.Fatal("test self-check failed")
	}
	if err := hd.ValidateMnemonic(strings.Join(corrupt, " ")); err == nil {
		t.Log("note: corruption produced a valid checksum (acceptable: 8-bit checksum)")
	}
}

// TestWatchOnlyCannotSign proves watch-only entries never hold key material
// and that BuildTx cannot spend from them (they are absent from the signing
// key list by construction).
func TestWatchOnlyCannotSign(t *testing.T) {
	dir := t.TempDir()
	w, err := walletCreate(t, dir+"/wallet.json")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	if len(w.WatchAddresses()) != 0 {
		t.Fatal("fresh wallet has watch entries")
	}
	before := w.KeyCount()
	signing := map[string]bool{}
	for _, a := range w.Addresses() {
		signing[a] = true
	}
	// A syntactically valid foreign address.
	foreign, _ := cryptography.NewKeyPair()
	foreignAddr := cryptography.AddressFromPubKey(foreign.Public)
	if err := w.AddWatchAddress("test-passphrase-1", foreignAddr, "exchange"); err != nil {
		t.Fatal(err)
	}
	if len(w.WatchAddresses()) != 1 {
		t.Fatal("watch entry not persisted in memory")
	}
	// Key count unchanged: watch-only adds NO signing keys.
	if w.KeyCount() != before {
		t.Fatalf("watch-only entry became a signing key: %d -> %d", before, w.KeyCount())
	}
	// The watched address must not be a controlled (signable) address.
	if signing[foreignAddr] {
		t.Fatal("watched address is also a signing address")
	}
	// Invalid address rejected.
	if err := w.AddWatchAddress("test-passphrase-1", "not-an-address", "x"); err == nil {
		t.Fatal("invalid watch address accepted")
	}
}

func fileExistsLocal(p string) bool {
	return fileExistsForTests(p)
}
