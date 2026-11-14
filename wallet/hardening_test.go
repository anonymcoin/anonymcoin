// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Wallet hardening tests: KDF strength, encrypted backup/export, legacy v1
// compatibility, secure-close behavior.
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/anonymcoin/anonymcoin/cryptography"
	"github.com/anonymcoin/anonymcoin/hd"
)

// TestExportBackupRoundtrip: an exported backup must open under the EXPORT
// passphrase (not the wallet passphrase) and contain the identical
// addresses, accounts and watch entries.
func TestExportBackupRoundtrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "wallet.json")
	bak := filepath.Join(dir, "backup.json")

	w, err := Create(src, "wallet-passphrase-123")
	if err != nil {
		t.Fatal(err)
	}
	phrase, err := w.MnemonicWords()
	if err != nil {
		t.Fatal(err)
	}
	addr0, err := w.Address(0)
	if err != nil {
		t.Fatal(err)
	}
	acct, err := w.NewAccount("wallet-passphrase-123")
	if err != nil {
		t.Fatal(err)
	}
	if acct != 1 {
		t.Fatalf("second account index = %d", acct)
	}
	foreign, _ := cryptography.NewKeyPair()
	if err := w.AddWatchAddress("wallet-passphrase-123", cryptography.AddressFromPubKey(foreign.Public), "cold"); err != nil {
		t.Fatal(err)
	}
	w.Close()

	// Export under a DIFFERENT passphrase.
	if err := Export(bak, src, "wallet-passphrase-123", "backup-passphrase-456"); err != nil {
		t.Fatal(err)
	}

	// The backup must NOT open under the wallet passphrase.
	if _, err := Open(bak, "wallet-passphrase-123"); err == nil {
		t.Fatal("backup opened with the wallet passphrase (export did not re-encrypt)")
	}
	// It must open under the export passphrase.
	wb, err := Open(bak, "backup-passphrase-456")
	if err != nil {
		t.Fatal(err)
	}
	defer wb.Close()
	if wb.Accounts() != 2 {
		t.Fatalf("backup accounts = %d, want 2", wb.Accounts())
	}
	b0, _ := wb.Address(0)
	if b0 != addr0 {
		t.Fatalf("backup address mismatch: %s != %s", b0, addr0)
	}
	if len(wb.WatchAddresses()) != 1 || wb.WatchAddresses()[0].Address != cryptography.AddressFromPubKey(foreign.Public) {
		t.Fatal("watch entries lost in export")
	}
	// The exported file is a v2 container with a strong KDF.
	raw, _ := os.ReadFile(bak)
	var wf walletFile
	if err := json.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	if wf.Version != walletVersion {
		t.Fatalf("backup version = %d", wf.Version)
	}
	if KDFType(wf.KDF.Type) != KDFScrypt || wf.KDF.N < scryptN {
		t.Fatalf("backup KDF too weak: %+v", wf.KDF)
	}
	// The mnemonic survives inside the backup (validated on open).
	phrase2, err := wb.MnemonicWords()
	if err != nil {
		t.Fatal(err)
	}
	if phrase2 != phrase {
		t.Fatal("recovery phrase changed in export")
	}
}

// TestArgon2idOption: a wallet created with the Argon2id KDF must open, must
// persist its KDF parameters, and a wrong passphrase must fail.
func TestArgon2idOption(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wallet.json")
	w, err := CreateWithKDF(path, "argon2-passphrase-1", KDFArgon2id)
	if err != nil {
		t.Fatal(err)
	}
	w.Close()

	raw, _ := os.ReadFile(path)
	var wf walletFile
	if err := json.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	if KDFType(wf.KDF.Type) != KDFArgon2id {
		t.Fatalf("KDF on disk = %s, want argon2id", wf.KDF.Type)
	}
	if wf.KDF.Memory < argon2MemoryKiB || wf.KDF.Time < argon2Time {
		t.Fatalf("argon2 parameters too weak: %+v", wf.KDF)
	}
	w2, err := Open(path, "argon2-passphrase-1")
	if err != nil {
		t.Fatal(err)
	}
	a, err := w2.Address(0)
	if err != nil {
		t.Fatal(err)
	}
	w2.Close()
	if _, err := Open(path, "wrong-wrong-wrong"); err == nil {
		t.Fatal("wrong passphrase accepted on argon2id wallet")
	}
	if len(a) == 0 {
		t.Fatal("empty address")
	}
}

// TestScryptRaisedParams: v2 default wallets must use N >= 2^17 on disk.
func TestScryptRaisedParams(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wallet.json")
	w, err := Create(path, "scrypt-passphrase-1")
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	raw, _ := os.ReadFile(path)
	var wf walletFile
	if err := json.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	if KDFType(wf.KDF.Type) != KDFScrypt || wf.KDF.N < 1<<17 {
		t.Fatalf("scrypt parameters not raised: %+v", wf.KDF)
	}
}

// TestLegacyV1WalletStillOpens: a hand-built v1-format wallet file (raw seed
// list, weak scrypt) must still open — migration compatibility.
func TestLegacyV1WalletStillOpens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wallet.json")

	kp, err := cryptography.NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	legacy := map[string]interface{}{
		"version":  1,
		"scrypt_n": legacyScryptN,
		"scrypt_r": legacyScryptR,
		"scrypt_p": legacyScryptP,
		"salt":     "00112233445566778899aabbccddeeff",
		"iv":       "00112233445566778899aabb",
		"blob":     "",
	}
	// Encrypt the legacy plaintext manually: reuse the container format.
	salt, _ := hex.DecodeString(legacy["salt"].(string))
	iv, _ := hex.DecodeString(legacy["iv"].(string))
	kdf := kdfParams{Type: string(KDFScrypt), N: legacyScryptN, R: legacyScryptR, P: legacyScryptP}
	key, err := kdf.deriveKey("legacy-pass-1234", salt)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := json.Marshal(map[string]interface{}{
		"keys":       []map[string]string{{"priv_hex": hex.EncodeToString(kp.Private.Seed())}},
		"next_index": 1,
	})
	block := newAESGCM(t, key)
	blob := block.Seal(nil, iv, plain, nil)
	legacy["blob"] = hex.EncodeToString(blob)
	b, _ := json.MarshalIndent(legacy, "", "  ")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	w, err := Open(path, "legacy-pass-1234")
	if err != nil {
		t.Fatalf("legacy v1 wallet rejected: %v", err)
	}
	defer w.Close()
	if w.KeyCount() != 1 {
		t.Fatalf("legacy keys = %d", w.KeyCount())
	}
	want := cryptography.AddressFromPubKey(kp.Public)
	got, err := w.Address(0)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("legacy key address mismatch")
	}
	// Re-saving upgrades to the v2 container with raised scrypt.
	if err := w.AddWatchAddress("legacy-pass-1234", want, "self"); err != nil {
		t.Fatal(err)
	}
	w.Close()
	raw, _ := os.ReadFile(path)
	var wf walletFile
	if err := json.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	if wf.Version != walletVersion || wf.KDF.N < scryptN {
		t.Fatalf("legacy wallet not upgraded on re-save: v%d n=%d", wf.Version, wf.KDF.N)
	}
}

// TestCloseWipesKeys: after Close, signing must be impossible and the
// in-memory key material must be zeroed.
func TestCloseWipesKeys(t *testing.T) {
	dir := t.TempDir()
	w, err := Create(dir+"/wallet.json", "wipe-test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.MnemonicWords(); err != nil {
		t.Fatal(err)
	}
	kp := w.keys[0].pair
	seedCopy := make([]byte, 32)
	copy(seedCopy, kp.Private.Seed())
	w.Close()

	if !w.closed {
		t.Fatal("wallet not marked closed")
	}
	if w.seed != nil || w.mnemonic != nil {
		t.Fatal("secret buffers not released")
	}
	if _, err := w.Address(0); err == nil {
		t.Fatal("Address succeeded after Close")
	}
	if _, err := w.MnemonicWords(); err == nil {
		t.Fatal("MnemonicWords succeeded after Close")
	}
	// The Ed25519 private key buffer must be zeroized (the wallet controls
	// this buffer directly; see SECURITY.md for the GC caveat).
	still := kp.Private.Seed()
	allZero := true
	for _, b := range still {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Fatal("private key buffer was not zeroized on Close")
	}
	_ = seedCopy
}

// TestMnemonicToSeedMatchesHD: the wallet's derivation must match the hd
// package directly (the seed->address chain is auditable end to end).
func TestMnemonicToSeedMatchesHD(t *testing.T) {
	dir := t.TempDir()
	w, err := Create(dir+"/wallet.json", "hd-consistency-pass")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	phrase, _ := w.MnemonicWords()
	seed, err := hd.MnemonicToSeed(phrase, "")
	if err != nil {
		t.Fatal(err)
	}
	k, err := hd.DerivePath(seed, hd.AddressPath(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	want, err := cryptography.KeyPairFromSeed(k.Key[:])
	if err != nil {
		t.Fatal(err)
	}
	got, err := w.Address(0)
	if err != nil {
		t.Fatal(err)
	}
	if got != cryptography.AddressFromPubKey(want.Public) {
		t.Fatal("wallet derivation diverges from the hd package")
	}
}

func newAESGCM(t *testing.T, key []byte) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return g
}
