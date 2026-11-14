// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

// Package wallet implements the ANONYMCOIN keystore, version 2:
//
//   - BIP-39 24-word mnemonic generation, validation and recovery
//     (via the hd package), with an optional BIP-39 passphrase.
//   - SLIP-0010 Ed25519 hierarchical derivation in BIP-44 style
//     (m/44'/2026'/account'/0'/index'), multiple accounts.
//   - Encryption at rest with AES-256-GCM under a strong KDF
//     (scrypt N=2^17 default, Argon2id option) — see kdf.go.
//   - Watch-only address entries (no private material, cannot sign).
//   - Encrypted backup/export under a second passphrase.
//   - Explicit zeroization of private material on Close (see kdf.go).
//
// Version 1 keystore files (raw seed list) remain openable for migration;
// any re-save upgrades them to the v2 format.
package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/anonymcoin/anonymcoin/blockdag"
	"github.com/anonymcoin/anonymcoin/cryptography"
	"github.com/anonymcoin/anonymcoin/hd"
	"github.com/anonymcoin/anonymcoin/transactions"
)

var (
	ErrWrongPassphrase = errors.New("wallet: wrong passphrase")
	ErrNoWallet        = errors.New("wallet: keystore not found")
	ErrNoFunds         = errors.New("wallet: insufficient mature balance")
	ErrBadPassphrase   = errors.New("wallet: passphrase must be at least 12 characters")
	ErrBadMnemonic     = errors.New("wallet: recovery phrase is not a valid BIP-39 phrase")
	ErrClosed          = errors.New("wallet: keystore is closed")
	ErrBadAccount      = errors.New("wallet: unknown account")
	ErrCorrupt         = errors.New("wallet: keystore file is corrupt")
	ErrNotHD           = errors.New("wallet: keystore has no recovery phrase (legacy seed storage)")
)

// minPassphraseLen is the production minimum for the wallet file passphrase.
// It was raised from 8 to 12 characters for v2: the wallet encrypts the
// recovery phrase itself, so the passphrase is the last line of defense.
const minPassphraseLen = 12

// walletVersion is the current on-disk format version.
const walletVersion = 2

// ---------------------------------------------------------------------------
// On-disk format
// ---------------------------------------------------------------------------

// walletFile is the encrypted container (v2).
type walletFile struct {
	Version int       `json:"version"`
	KDF     kdfParams `json:"kdf"`
	Salt    string    `json:"salt"`
	IV      string    `json:"iv"`
	Blob    string    `json:"blob"` // AES-256-GCM ciphertext of keyFile JSON
}

// legacyWalletFile mirrors the v1 container layout (flat scrypt fields).
type legacyWalletFile struct {
	Version int    `json:"version"`
	ScryptN int    `json:"scrypt_n"`
	ScryptR int    `json:"scrypt_r"`
	ScryptP int    `json:"scrypt_p"`
	Salt    string `json:"salt"`
	IV      string `json:"iv"`
	Blob    string `json:"blob"`
}

// legacyKeyFile mirrors the v1 plaintext layout (raw seed list).
type legacyKeyFile struct {
	Keys []struct {
		PrivHex string `json:"priv_hex"` // ed25519 seed (32 bytes)
	} `json:"keys"`
	NextIndex int `json:"next_index"`
}

// watchEntry is a watch-only address: balance is tracked, nothing can sign.
type watchEntry struct {
	Label   string `json:"label"`
	Address string `json:"address"`
}

// keyFile is the plaintext (decrypted) wallet content.
type keyFile struct {
	Kind      string       `json:"kind"` // "hd" (v2) or "legacy" (v1 migration)
	Mnemonic  string       `json:"mnemonic,omitempty"`
	Bip39Pass string       `json:"bip39_pass,omitempty"`
	Accounts  int          `json:"accounts"`
	NextIndex map[int]int  `json:"next_index"` // account -> next unused address index
	Legacy    []string     `json:"legacy_keys,omitempty"`
	Watch     []watchEntry `json:"watch,omitempty"`
}

// AddressLookahead is the BIP-44-style gap limit: on open, every account
// derives its used addresses PLUS this many unused ones, so funds received
// at not-yet-"allocated" addresses stay visible after a mnemonic recovery
// (the counter alone would hide them). The wallet derives no keys beyond
// used+lookahead, bounding derivation work.
const AddressLookahead = 20

// signingKey is one spend-capable derived key held in memory while the
// wallet is open.
type signingKey struct {
	pair    cryptography.KeyPair
	account int
	index   int
}

// Wallet is an opened keystore. Private material lives only in memory while
// the wallet is open; Close zeroizes it.
type Wallet struct {
	path       string
	mnemonic   []byte       // secret; zeroized on Close
	bip39Pass  []byte       // optional 25th word; zeroized on Close
	seed       []byte       // BIP-39 seed; zeroized on Close
	keys       []signingKey // sorted by (account, index); used + lookahead
	maxDerived map[int]int  // account -> highest derived index (exclusive)
	nextIdx    map[int]int  // account -> next unused address index (persisted)
	accounts   int
	watch      []watchEntry
	closed     bool
}

// deriveAccountKeys extends the in-memory key set of account a to indexes
// [0, upto). Keys are derived deterministically from the phrase; callers
// must hold no expectations about ordering beyond (account, index) sort.
func (w *Wallet) deriveAccountKeys(a, upto int) error {
	from := w.maxDerived[a]
	if upto <= from {
		return nil
	}
	for i := from; i < upto; i++ {
		kp, err := w.deriveKey(a, i)
		if err != nil {
			return err
		}
		w.keys = append(w.keys, signingKey{pair: kp, account: a, index: i})
	}
	w.maxDerived[a] = upto
	w.sortKeys()
	return nil
}

// sortKeys keeps the (account, index) order stable for deterministic
// address listing and coin selection.
func (w *Wallet) sortKeys() {
	for a := 1; a < len(w.keys); a++ {
		for b := a; b > 0; b-- {
			x, y := w.keys[b-1], w.keys[b]
			if x.account > y.account || (x.account == y.account && x.index > y.index) {
				w.keys[b-1], w.keys[b] = y, x
			} else {
				break
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Creation and recovery
// ---------------------------------------------------------------------------

// checkPassphrase enforces the production minimum length.
func checkPassphrase(passphrase string) error {
	if len(passphrase) < minPassphraseLen {
		return ErrBadPassphrase
	}
	return nil
}

// Create makes a new encrypted keystore backed by a freshly generated BIP-39
// 24-word recovery phrase. The returned *Wallet exposes the phrase exactly
// once through MnemonicWords before Close — the caller MUST display it and
// instruct the user to write it down (see README, "Recovery").
func Create(path, passphrase string) (*Wallet, error) {
	if err := checkPassphrase(passphrase); err != nil {
		return nil, err
	}
	phrase, err := hd.NewMnemonic()
	if err != nil {
		return nil, err
	}
	return createFromMnemonic(path, passphrase, phrase, "", scryptParams())
}

// CreateWithKDF is Create with an explicit KDF choice
// (KDFScrypt or KDFArgon2id).
func CreateWithKDF(path, passphrase string, kdf KDFType) (*Wallet, error) {
	if err := checkPassphrase(passphrase); err != nil {
		return nil, err
	}
	phrase, err := hd.NewMnemonic()
	if err != nil {
		return nil, err
	}
	switch kdf {
	case KDFScrypt:
		return createFromMnemonic(path, passphrase, phrase, "", scryptParams())
	case KDFArgon2id:
		return createFromMnemonic(path, passphrase, phrase, "", argon2Params())
	default:
		return nil, fmt.Errorf("wallet: unknown KDF %q", kdf)
	}
}

// Restore creates a keystore from an existing BIP-39 recovery phrase
// (24 words for ANONYMCOIN; other BIP-39 lengths validate too). The phrase
// is checksum-validated BEFORE any file is written, so a mistyped recovery
// always fails loudly instead of silently creating a wallet that cannot see
// its funds. bip39Pass is the optional BIP-39 passphrase; losing it loses
// the funds — see SECURITY.md.
func Restore(path, passphrase, mnemonic, bip39Pass string) (*Wallet, error) {
	if err := checkPassphrase(passphrase); err != nil {
		return nil, err
	}
	if err := hd.ValidateMnemonic(mnemonic); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadMnemonic, err)
	}
	return createFromMnemonic(path, passphrase, normalizePhrase(mnemonic), bip39Pass, scryptParams())
}

// normalizePhrase canonicalizes a phrase to the canonical single-space
// lowercase form before storage.
func normalizePhrase(m string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(m))), " ")
}

func createFromMnemonic(path, passphrase, phrase, bip39Pass string, kdf kdfParams) (*Wallet, error) {
	if err := hd.ValidateMnemonic(phrase); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadMnemonic, err)
	}
	seed, err := hd.MnemonicToSeed(phrase, bip39Pass)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadMnemonic, err)
	}
	// Derive the first address plus the lookahead window so funds received
	// at any not-yet-allocated address are visible from the start (BIP-44
	// gap semantics).
	w := &Wallet{
		path:       path,
		mnemonic:   []byte(phrase),
		bip39Pass:  []byte(bip39Pass),
		seed:       seed,
		maxDerived: map[int]int{},
		nextIdx:    map[int]int{0: 1},
		accounts:   1,
	}
	if err := w.deriveAccountKeys(0, 1+AddressLookahead); err != nil {
		w.Close()
		return nil, err
	}

	if err := w.saveTo(path, passphrase, kdf); err != nil {
		w.Close()
		return nil, err
	}
	return w, nil
}

// deriveKey derives the SLIP-0010 key for (account, index) and turns it into
// an Ed25519 key pair.
func (w *Wallet) deriveKey(account, index int) (cryptography.KeyPair, error) {
	if w.seed == nil {
		return cryptography.KeyPair{}, ErrClosed
	}
	k, err := hd.DerivePath(w.seed, hd.AddressPath(uint32(account), uint32(index)))
	if err != nil {
		return cryptography.KeyPair{}, err
	}
	return cryptography.KeyPairFromSeed(k.Key[:])
}

// ---------------------------------------------------------------------------
// Open / Close
// ---------------------------------------------------------------------------

// Open decrypts the keystore. Both v1 (legacy seed list) and v2 (HD)
// formats are supported; v1 wallets are upgraded in memory and on the next
// re-save.
func Open(path, passphrase string) (*Wallet, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoWallet
		}
		return nil, err
	}

	var wf walletFile
	if err := json.Unmarshal(b, &wf); err != nil {
		return nil, fmt.Errorf("%w: parse: %v", ErrCorrupt, err)
	}

	var kdf kdfParams
	var salt, iv, blob []byte
	switch wf.Version {
	case 0:
		// Try the legacy v1 container (flat scrypt fields, no version tag).
		var lw legacyWalletFile
		if err := json.Unmarshal(b, &lw); err != nil || lw.Blob == "" {
			return nil, fmt.Errorf("%w: unrecognized layout", ErrCorrupt)
		}
		n, r, p := lw.ScryptN, lw.ScryptR, lw.ScryptP
		if n == 0 {
			n, r, p = legacyScryptN, legacyScryptR, legacyScryptP
		}
		kdf = kdfParams{Type: string(KDFScrypt), N: n, R: r, P: p}
		salt, err = hex.DecodeString(lw.Salt)
		if err != nil {
			return nil, fmt.Errorf("%w: salt: %v", ErrCorrupt, err)
		}
		iv, err = hex.DecodeString(lw.IV)
		if err != nil {
			return nil, fmt.Errorf("%w: iv: %v", ErrCorrupt, err)
		}
		blob, err = hex.DecodeString(lw.Blob)
		if err != nil {
			return nil, fmt.Errorf("%w: blob: %v", ErrCorrupt, err)
		}
	case 1:
		// v1 container with explicit (flat) scrypt parameters.
		var lw legacyWalletFile
		if err := json.Unmarshal(b, &lw); err != nil {
			return nil, fmt.Errorf("%w: legacy parse: %v", ErrCorrupt, err)
		}
		n, r, p := lw.ScryptN, lw.ScryptR, lw.ScryptP
		if n == 0 {
			n, r, p = legacyScryptN, legacyScryptR, legacyScryptP
		}
		kdf = kdfParams{Type: string(KDFScrypt), N: n, R: r, P: p}
		salt, iv, blob, err = decodeContainer(&wf)
		if err != nil {
			return nil, err
		}
	case walletVersion:
		kdf = wf.KDF
		salt, iv, blob, err = decodeContainer(&wf)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: unsupported version %d", ErrCorrupt, wf.Version)
	}
	if err := kdf.validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if len(salt) < 16 || len(iv) != 12 {
		return nil, fmt.Errorf("%w: bad container fields", ErrCorrupt)
	}

	key, err := kdf.deriveKey(passphrase, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		zeroize(key)
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		zeroize(key)
		return nil, err
	}
	// The derived key is wiped immediately after the cipher instances are
	// built; the AES key schedule inside the cipher keeps its own copy.
	zeroize(key)
	plain, err := gcm.Open(nil, iv, blob, nil)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	defer zeroize(plain)

	// Route the decrypted content: v2 plaintexts carry "kind"; v1
	// plaintexts are {"keys": [...], "next_index": N}. Detection order
	// matters: the legacy layout fails keyFile unmarshalling outright
	// (numeric next_index), so try the legacy shape first when the v2 probe
	// is inconclusive.
	var probe keyFile
	legacyStyle := false
	if err := json.Unmarshal(plain, &probe); err != nil {
		legacyStyle = true
	} else if probe.Kind == "" && probe.Mnemonic == "" && probe.Legacy == nil {
		legacyStyle = true
	}
	if legacyStyle {
		var lk legacyKeyFile
		if err := json.Unmarshal(plain, &lk); err != nil {
			return nil, fmt.Errorf("%w: legacy inner parse: %v", ErrCorrupt, err)
		}
		if len(lk.Keys) == 0 {
			return nil, fmt.Errorf("%w: no keys in keystore", ErrCorrupt)
		}
		kf := keyFile{Kind: "legacy", Accounts: 1, NextIndex: map[int]int{0: lk.NextIndex}}
		for i := range lk.Keys {
			kf.Legacy = append(kf.Legacy, lk.Keys[i].PrivHex)
		}
		return newWalletFromKeyFile(path, &kf)
	}
	var kf keyFile
	if err := json.Unmarshal(plain, &kf); err != nil {
		return nil, fmt.Errorf("%w: inner parse: %v", ErrCorrupt, err)
	}
	return newWalletFromKeyFile(path, &kf)
}

// decodeContainer hex-decodes the three container fields of a v2 wallet.
func decodeContainer(wf *walletFile) (salt, iv, blob []byte, err error) {
	salt, err = hex.DecodeString(wf.Salt)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: salt: %v", ErrCorrupt, err)
	}
	iv, err = hex.DecodeString(wf.IV)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: iv: %v", ErrCorrupt, err)
	}
	blob, err = hex.DecodeString(wf.Blob)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: blob: %v", ErrCorrupt, err)
	}
	return salt, iv, blob, nil
}

// newWalletFromKeyFile materializes the in-memory wallet from decrypted
// content, deriving every signing key from the mnemonic (or legacy seeds).
func newWalletFromKeyFile(path string, kf *keyFile) (*Wallet, error) {
	w := &Wallet{
		path:       path,
		nextIdx:    map[int]int{},
		maxDerived: map[int]int{},
		accounts:   kf.Accounts,
	}
	switch kf.Kind {
	case "hd":
		if err := hd.ValidateMnemonic(kf.Mnemonic); err != nil {
			return nil, fmt.Errorf("%w: stored phrase: %v", ErrCorrupt, err)
		}
		w.mnemonic = []byte(kf.Mnemonic)
		w.bip39Pass = []byte(kf.Bip39Pass)
		seed, err := hd.MnemonicToSeed(kf.Mnemonic, kf.Bip39Pass)
		if err != nil {
			return nil, fmt.Errorf("%w: seed derivation: %v", ErrCorrupt, err)
		}
		w.seed = seed
		if w.accounts <= 0 {
			w.accounts = 1
		}
		w.maxDerived = map[int]int{}
		for a := 0; a < w.accounts; a++ {
			next, ok := kf.NextIndex[a]
			if !ok || next < 1 {
				next = 1
			}
			w.nextIdx[a] = next
			// Used addresses plus the gap-limit lookahead window
			// (see AddressLookahead) so recovery always sees funds.
			if err := w.deriveAccountKeys(a, next+AddressLookahead); err != nil {
				w.Close()
				return nil, err
			}
		}
	case "legacy", "":
		// v1 migration: raw seeds.
		for i, seedHex := range kf.Legacy {
			seed, err := hex.DecodeString(seedHex)
			if err != nil {
				return nil, fmt.Errorf("%w: legacy key %d: %v", ErrCorrupt, i, err)
			}
			kp, err := cryptography.KeyPairFromSeed(seed)
			if err != nil {
				return nil, err
			}
			zeroize(seed)
			w.keys = append(w.keys, signingKey{pair: kp, account: 0, index: i})
		}
		// Legacy wallets carry their next index flat.
		w.nextIdx[0] = len(w.keys)
		if kf.NextIndex != nil {
			if n, ok := kf.NextIndex[0]; ok && n > len(w.keys) {
				w.nextIdx[0] = n
			}
		}
		w.maxDerived[0] = len(w.keys)
		w.accounts = 1
	default:
		return nil, fmt.Errorf("%w: unknown kind %q", ErrCorrupt, kf.Kind)
	}
	w.watch = append([]watchEntry(nil), kf.Watch...)
	if len(w.keys) == 0 {
		return nil, fmt.Errorf("%w: keystore has no signing keys", ErrCorrupt)
	}
	return w, nil
}

// Close zeroizes every piece of private material held in memory. The wallet
// is unusable afterwards; reopen it from disk.
func (w *Wallet) Close() {
	if w == nil {
		return
	}
	for i := range w.keys {
		if w.keys[i].pair.Private != nil {
			wipeKey(w.keys[i].pair.Private)
		}
	}
	w.keys = nil
	if w.seed != nil {
		zeroize(w.seed)
		w.seed = nil
	}
	if w.mnemonic != nil {
		zeroize(w.mnemonic)
		w.mnemonic = nil
	}
	if w.bip39Pass != nil {
		zeroize(w.bip39Pass)
		w.bip39Pass = nil
	}
	w.closed = true
}

func (w *Wallet) assertOpen() error {
	if w == nil || w.closed {
		return ErrClosed
	}
	return nil
}

// ---------------------------------------------------------------------------
// Queries and account management
// ---------------------------------------------------------------------------

// MnemonicWords returns the recovery phrase for display. Call this exactly
// once at wallet creation, print it, and have the operator write it down:
// the phrase IS the wallet. Legacy (v1) keystores have no phrase.
func (w *Wallet) MnemonicWords() (string, error) {
	if err := w.assertOpen(); err != nil {
		return "", err
	}
	if w.mnemonic == nil {
		return "", ErrNotHD
	}
	return string(w.mnemonic), nil
}

// Accounts returns the number of HD accounts.
func (w *Wallet) Accounts() int { return w.accounts }

// NewAccount derives and persists a new HD account root
// (m/44'/2026'/account') with its first address. Returns the new account
// index.
func (w *Wallet) NewAccount(passphrase string) (int, error) {
	if err := w.assertOpen(); err != nil {
		return 0, err
	}
	acct := w.accounts
	w.accounts++
	w.nextIdx[acct] = 1
	if err := w.deriveAccountKeys(acct, 1+AddressLookahead); err != nil {
		w.accounts--
		delete(w.nextIdx, acct)
		return 0, err
	}
	if err := w.save(passphrase); err != nil {
		w.keys = w.keys[:len(w.keys)-1]
		w.accounts--
		delete(w.nextIdx, acct)
		return 0, err
	}
	return acct, nil
}

// NewAddress derives the next address of account 0 and persists it.
func (w *Wallet) NewAddress(passphrase string) (string, error) {
	return w.NewAddressIn(passphrase, 0)
}

// NewAddressIn derives the next address of the given account and persists
// the wallet (the key is deterministic from the phrase; only the counter is
// stored).
func (w *Wallet) NewAddressIn(passphrase string, account int) (string, error) {
	if err := w.assertOpen(); err != nil {
		return "", err
	}
	if account < 0 || account >= w.accounts {
		return "", ErrBadAccount
	}
	idx := w.nextIdx[account]
	if w.seed == nil {
		// Legacy (v1) keystore: no phrase to derive from — v1 semantics
		// generated a fresh random key per address. Preserve that.
		kp, err := cryptography.NewKeyPair()
		if err != nil {
			return "", err
		}
		idx = w.maxDerived[account]
		w.keys = append(w.keys, signingKey{pair: kp, account: account, index: idx})
		w.maxDerived[account] = idx + 1
		w.nextIdx[account] = idx + 1
		if err := w.save(passphrase); err != nil {
			w.keys = w.keys[:len(w.keys)-1]
			w.maxDerived[account] = idx
			w.nextIdx[account] = idx
			return "", err
		}
		return cryptography.AddressFromPubKey(kp.Public), nil
	}
	// The key at idx is usually already in memory (lookahead window);
	// extend only if the counter ran past it.
	if err := w.deriveAccountKeys(account, idx+1); err != nil {
		return "", err
	}
	w.nextIdx[account] = idx + 1
	if err := w.save(passphrase); err != nil {
		w.nextIdx[account] = idx
		return "", err
	}
	// The key for (account, idx) is in memory after deriveAccountKeys.
	for i := range w.keys {
		if w.keys[i].account == account && w.keys[i].index == idx {
			return cryptography.AddressFromPubKey(w.keys[i].pair.Public), nil
		}
	}
	return "", fmt.Errorf("wallet: derived key (%d,%d) missing", account, idx)
}

// Address returns the address of signing key i (global order: account
// ascending, index ascending). Bounds-checked; no panic path.
func (w *Wallet) Address(i int) (string, error) {
	if i < 0 || i >= len(w.keys) {
		return "", fmt.Errorf("wallet: key index %d out of range (%d keys)", i, len(w.keys))
	}
	return cryptography.AddressFromPubKey(w.keys[i].pair.Public), nil
}

// Addresses lists all controlled signing addresses.
func (w *Wallet) Addresses() []string {
	out := make([]string, 0, len(w.keys))
	for i := range w.keys {
		a, _ := w.Address(i)
		out = append(out, a)
	}
	return out
}

// AccountAddresses lists the signing addresses of one account.
func (w *Wallet) AccountAddresses(account int) ([]string, error) {
	if err := w.assertOpen(); err != nil {
		return nil, err
	}
	if account < 0 || account >= w.accounts {
		return nil, ErrBadAccount
	}
	out := []string{}
	for i := range w.keys {
		if w.keys[i].account == account {
			out = append(out, cryptography.AddressFromPubKey(w.keys[i].pair.Public))
		}
	}
	return out, nil
}

// KeyCount returns the number of controlled signing keys.
func (w *Wallet) KeyCount() int { return len(w.keys) }

// WatchAddresses returns the watch-only entries (label, address).
func (w *Wallet) WatchAddresses() []watchEntry {
	return append([]watchEntry(nil), w.watch...)
}

// AddWatchAddress registers a watch-only address. Watch-only entries carry
// no key material and can never sign.
func (w *Wallet) AddWatchAddress(passphrase, addr, label string) error {
	if err := w.assertOpen(); err != nil {
		return err
	}
	if !cryptography.IsValidAddress(addr) {
		return fmt.Errorf("wallet: watch address invalid: %s", addr)
	}
	for _, e := range w.watch {
		if e.Address == addr {
			return fmt.Errorf("wallet: address already watched: %s", addr)
		}
	}
	w.watch = append(w.watch, watchEntry{Label: label, Address: addr})
	if err := w.save(passphrase); err != nil {
		w.watch = w.watch[:len(w.watch)-1]
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

// save re-encrypts the wallet under a fresh salt/IV and the raised scrypt
// profile, writes atomically (temp file + rename), and keeps the file at
// 0600.
func (w *Wallet) save(passphrase string) error {
	return w.saveTo(w.path, passphrase, DefaultKDF())
}

// saveTo re-encrypts the wallet content to an arbitrary path (used by
// Export). The caller's wallet state is not modified.
func (w *Wallet) saveTo(path, passphrase string, kdf kdfParams) error {
	kf := keyFile{
		Kind:      "hd",
		Mnemonic:  string(w.mnemonic),
		Bip39Pass: string(w.bip39Pass),
		Accounts:  w.accounts,
		NextIndex: w.nextIdx,
		Watch:     w.watch,
	}
	// Legacy migration: if this wallet has no mnemonic (v1 opened), persist
	// the legacy seeds so nothing is lost.
	if kf.Mnemonic == "" {
		kf.Kind = "legacy"
		for i := range w.keys {
			seed := w.keys[i].pair.Private.Seed()
			kf.Legacy = append(kf.Legacy, hex.EncodeToString(seed))
		}
		if kf.NextIndex == nil {
			kf.NextIndex = map[int]int{}
		}
		kf.NextIndex[0] = len(w.keys)
	}
	plain, err := json.Marshal(kf)
	if err != nil {
		return err
	}

	salt := make([]byte, 32)
	iv := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	if _, err := rand.Read(iv); err != nil {
		return err
	}
	key, err := kdf.deriveKey(passphrase, salt)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		zeroize(key)
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		zeroize(key)
		return err
	}
	zeroize(key)
	blob := gcm.Seal(nil, iv, plain, nil)
	zeroize(plain)

	wf := walletFile{
		Version: walletVersion,
		KDF:     kdf,
		Salt:    hex.EncodeToString(salt),
		IV:      hex.EncodeToString(iv),
		Blob:    hex.EncodeToString(blob),
	}
	b, err := json.MarshalIndent(wf, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	// Atomic replace: a crash mid-write can never destroy the wallet.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ---------------------------------------------------------------------------
// Encrypted backup / export
// ---------------------------------------------------------------------------

// Export writes a full encrypted backup of the wallet (mnemonic, accounts,
// counters, watch entries) to outPath, encrypted under exportPassphrase —
// which SHOULD be different from the wallet passphrase. The backup opens
// with wallet.Open(outPath, exportPassphrase). The wallet passphrase is
// verified against the source file first.
func Export(outPath, srcPath, walletPass, exportPass string) error {
	if err := checkPassphrase(exportPass); err != nil {
		return err
	}
	w, err := Open(srcPath, walletPass)
	if err != nil {
		return err
	}
	defer w.Close()
	return w.saveTo(outPath, exportPass, DefaultKDF())
}

// ---------------------------------------------------------------------------
// Transaction building
// ---------------------------------------------------------------------------

// UTXOKeyAlias avoids importing blockdag's UTXOKey type name here.
type UTXOKeyAlias = utxoKey
type utxoKey struct {
	TxID  cryptography.Hash
	Index uint32
}

func lessUTXOKey(a, b utxoKey) bool {
	for i := 0; i < 32; i++ {
		if a.TxID[i] != b.TxID[i] {
			return a.TxID[i] < b.TxID[i]
		}
	}
	return a.Index < b.Index
}

// BuildTx constructs and signs a payment from controlled UTXOs to addr.
// Coin selection considers every signing key of every account (watch-only
// entries never sign). Selection: first-fit over mature controlled outputs
// in deterministic order (value desc, txid asc, index asc). Change returns
// to the first controlled key (deterministic; documented in the wallet
// docs). fee is explicit (no fee estimation in v1).
func (w *Wallet) BuildTx(dag *blockdag.DAG, addr string, amount, fee uint64) (*transactions.Tx, error) {
	if err := w.assertOpen(); err != nil {
		return nil, err
	}
	pkh, err := cryptography.AddressToPubKeyHash(addr)
	if err != nil {
		return nil, err
	}
	if amount+fee < amount { // overflow
		return nil, fmt.Errorf("wallet: amount+fee overflow")
	}
	// Collect controlled mature outputs.
	type coin struct {
		key   cryptography.KeyPair
		key_  UTXOKeyAlias
		entry blockdag.UTXOEntry
	}
	var coins []coin
	for i := range w.keys {
		want := cryptography.Hash160Of(w.keys[i].pair.Public)
		_, ids, entries := dag.Balance(want)
		for j := range ids {
			coins = append(coins, coin{key: w.keys[i].pair, key_: UTXOKeyAlias(ids[j]), entry: entries[j]})
		}
	}
	// Sort deterministically: value desc, txid asc, index asc.
	for a := 1; a < len(coins); a++ {
		for b := a; b > 0; b-- {
			x, y := coins[b-1], coins[b]
			if x.entry.Value > y.entry.Value ||
				(x.entry.Value == y.entry.Value && lessUTXOKey(x.key_, y.key_)) {
				coins[b-1], coins[b] = y, x
			} else {
				break
			}
		}
	}
	var selected []coin
	var sum uint64
	var sumOvf bool
	for _, c := range coins {
		if sum >= amount+fee {
			break
		}
		selected = append(selected, c)
		sum, sumOvf = checkedAddWallet(sum, c.entry.Value)
		if sumOvf {
			break
		}
	}
	if sum < amount+fee {
		return nil, ErrNoFunds
	}
	tx := &transactions.Tx{Version: 1}
	var inSum uint64
	for _, c := range selected {
		tx.Inputs = append(tx.Inputs, transactions.TxIn{
			PrevTx:    c.key_.TxID,
			PrevIndex: c.key_.Index,
			PubKey:    func() [32]byte { var k [32]byte; copy(k[:], c.key.Public); return k }(),
		})
		var ovf bool
		inSum, ovf = checkedAddWallet(inSum, c.entry.Value)
		if ovf {
			return nil, fmt.Errorf("wallet: input sum overflow")
		}
	}
	if amount+fee > inSum {
		return nil, ErrNoFunds
	}
	change := inSum - amount - fee
	tx.Outputs = append(tx.Outputs, transactions.TxOut{Value: amount, PubKeyHash: pkh})
	if change >= dag.Params().DustLimit {
		changePKH := cryptography.Hash160Of(w.keys[0].pair.Public)
		tx.Outputs = append(tx.Outputs, transactions.TxOut{Value: change, PubKeyHash: changePKH})
	}
	d := tx.Digest(dag.ChainTag())
	for i := range tx.Inputs {
		var key cryptography.KeyPair
		for _, c := range selected {
			if c.key_.TxID == tx.Inputs[i].PrevTx && c.key_.Index == tx.Inputs[i].PrevIndex {
				key = c.key
			}
		}
		if key.Private == nil {
			return nil, fmt.Errorf("wallet: no signing key for input %d", i)
		}
		copy(tx.Inputs[i].Sig[:], key.Sign(d[:]))
	}
	return tx, nil
}

func checkedAddWallet(a, b uint64) (uint64, bool) {
	s := a + b
	return s, s < a
}
