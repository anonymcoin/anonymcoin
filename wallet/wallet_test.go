// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package wallet

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/anonymcoin/anonymcoin/blockdag"
	"github.com/anonymcoin/anonymcoin/consensus"
	"github.com/anonymcoin/anonymcoin/cryptography"
	"github.com/anonymcoin/anonymcoin/hd"
	"github.com/anonymcoin/anonymcoin/mining"
)

func TestCreateOpenRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/wallet.json"
	w0, err := Create(path, "hunter2hunter2")
	if err != nil {
		t.Fatal(err)
	}
	phrase, err := w0.MnemonicWords()
	if err != nil {
		t.Fatal(err)
	}
	if len(bytes.Fields([]byte(phrase))) != 24 {
		t.Fatalf("recovery phrase must be 24 words, got %d", len(bytes.Fields([]byte(phrase))))
	}
	w0.Close()

	w, err := Open(path, "hunter2hunter2")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	// BIP-44 gap semantics: the fresh wallet holds its used address plus the
	// lookahead window.
	if w.KeyCount() != 1+AddressLookahead {
		t.Fatalf("fresh wallet keys = %d, want %d (used + lookahead)", w.KeyCount(), 1+AddressLookahead)
	}
	addr, err := w.Address(0)
	if err != nil {
		t.Fatal(err)
	}
	if !cryptography.IsValidAddress(addr) {
		t.Fatal("wallet address invalid")
	}
	// New address persists: it must be exactly the next lookahead slot.
	addr2, err := w.NewAddress("hunter2hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if addr2 == addr {
		t.Fatal("new address identical")
	}
	nextSlot, _ := w.Address(1)
	if addr2 != nextSlot {
		t.Fatalf("NewAddress returned %s, want the index-1 slot %s", addr2, nextSlot)
	}
	// Reopen must keep at least the same key set (the gap window refreshes
	// relative to the used counter, so the count can grow to 2+lookahead).
	w2, err := Open(path, "hunter2hunter2")
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	if w2.KeyCount() < w.KeyCount() {
		t.Fatalf("keys after reopen = %d, want >= %d", w2.KeyCount(), w.KeyCount())
	}
	a0, _ := w2.Address(0)
	if a0 != addr {
		t.Fatal("index 0 changed across reopen")
	}
	a1, _ := w2.Address(1)
	if a1 != nextSlot {
		t.Fatal("index 1 changed across reopen")
	}
	// Wrong passphrase fails.
	if _, err := Open(path, "wrongwrong"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	// Short passphrase rejected at creation.
	if _, err := Create(dir+"/short.json", "short"); err == nil {
		t.Fatal("short passphrase accepted")
	}
}

func TestEncryptedAtRest(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/wallet.json"
	w0, err := Create(path, "correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	w0.Close()
	w, err := Open(path, "correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	privSeed := w.keys[0].pair.Private.Seed()
	raw, err := readWalletFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, privSeed) {
		t.Fatal("private key material found in plaintext on disk")
	}
	if bytes.Contains(raw, []byte(hexEncode(w.keys[0].pair.Public))) {
		t.Fatal("public key found in plaintext on disk")
	}
	// The mnemonic itself must never appear in plaintext either: the phrase
	// IS the master key. Single-word matching false-positives on JSON field
	// names (e.g. the word "type" and the KDF key "type"), so the check is
	// the full phrase, all 4-word sliding windows, and the derived seed.
	phrase, _ := w.MnemonicWords()
	words := bytes.Fields([]byte(phrase))
	if bytes.Contains(raw, []byte(phrase)) {
		t.Fatal("recovery phrase found in plaintext on disk")
	}
	for i := 0; i+4 <= len(words); i++ {
		window := string(bytes.Join(words[i:i+4], []byte(" ")))
		if bytes.Contains(raw, []byte(window)) {
			t.Fatalf("recovery phrase window %d found in plaintext on disk", i)
		}
	}
	seed, err := hd.MnemonicToSeed(phrase, "")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(hex.EncodeToString(seed))) {
		t.Fatal("derived BIP-39 seed found in plaintext on disk")
	}
}

func readWalletFile(path string) ([]byte, error) {
	return osReadFile(path)
}

func hexEncode(b []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexd[c>>4], hexd[c&0x0f])
	}
	return string(out)
}

func TestBuildTxAndSubmit(t *testing.T) {
	p := consensus.Defaults()
	p.GenesisDifficulty = 1
	p.DifficultyMax = 4
	p.CoinbaseMaturity = 1
	d, _ := blockdag.New(&p, blockdag.Hooks{})

	// Miner pays to the wallet's first key; the same mempool feeds both the
	// miner templates and the manual tx submission below.
	w, err := openTempWallet(t)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	pkh := cryptography.Hash160Of(w.keys[0].pair.Public)
	mp := mining.NewMemPool(&p)
	miner := mining.NewMiner(d, mp, pkh, 1)
	if err := miner.MineN(5); err != nil {
		t.Fatal(err)
	}

	recipient, _ := cryptography.NewKeyPair()
	recipientAddr := cryptography.AddressFromPubKey(recipient.Public)

	total, _, _ := d.Balance(pkh)
	if total == 0 {
		t.Fatal("wallet balance empty after mining")
	}
	send := total / 4
	tx, err := w.BuildTx(d, recipientAddr, send, 1000)
	if err != nil {
		t.Fatalf("build tx: %v", err)
	}
	// Valid against the live view.
	if err := transactionsValidate(tx, &p, d); err != nil {
		t.Fatalf("built tx invalid: %v", err)
	}
	// Submit through a block: mine it into the DAG via the shared mempool.
	if err := mp.Add(tx, d.MempoolView()); err != nil {
		t.Fatalf("mempool rejected built tx: %v", err)
	}
	if err := miner.MineN(1); err != nil {
		t.Fatal(err)
	}
	rTotal, _, _ := d.Balance(cryptography.Hash160Of(recipient.Public))
	if rTotal != send {
		t.Fatalf("recipient balance = %d, want %d", rTotal, send)
	}
	// Spend balance decreased by send+fee (the fee went to the miner).
	newTotal, _, _ := d.Balance(pkh)
	if newTotal+send+1000 != total {
		t.Fatalf("balance accounting mismatch: %d + %d + 1000 != %d", newTotal, send, total)
	}
}
