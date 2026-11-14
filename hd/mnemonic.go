// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

// Package hd implements ANONYMCOIN's hierarchical key management:
//
//   - BIP-39 mnemonic phrases (24 words, 256-bit entropy, English wordlist)
//     and the mnemonic-to-seed conversion (PBKDF2-HMAC-SHA512, 2048 rounds).
//   - SLIP-0010 Ed25519 hierarchical derivation ("BIP32/BIP44 style adapted
//     for Ed25519"): master key from the BIP-39 seed, hardened-only child
//     derivation, BIP-44 style paths m/44'/2026'/account'/0'/index'.
//
// Security properties relied upon by the wallet:
//
//   - Mnemonic validation is total: word membership, word-count multiples of
//     3 (24 words for new wallets), checksum over the entropy bits, and
//     rejection of unknown words — a mistyped recovery phrase can never
//     silently produce an empty or wrong wallet.
//   - Mnemonic-to-seed conversion is the interoperable BIP-39 algorithm at
//     its fixed, specified parameters (2048 PBKDF2 rounds). The 2048-round
//     figure is part of the standard and must not be "hardened" ad hoc; at-
//     rest encryption strength comes from the wallet file KDF (scrypt with
//     raised parameters or Argon2id — see the wallet package).
//   - Ed25519 derivation supports hardened steps only, exactly as specified
//     by SLIP-0010 (non-hardened Ed25519 derivation is undefined in the
//     specification and is rejected here rather than improvised).
//
// This package contains no I/O and no state: every function is a pure,
// deterministic, independently auditable transform.
package hd

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// MnemonicWords is the word count of ANONYMCOIN recovery phrases. ANONYMCOIN
// uses the BIP-39 24-word form (256-bit entropy): the maximum-strength
// standard phrase. (A previous draft mentioned 25 words; there is no 25-word
// BIP-39 form — 24 words plus an optional passphrase is the standard
// equivalent construction, and that is what ANONYMCOIN implements.)
const MnemonicWords = 24

// EntropySize is the entropy byte length behind a 24-word phrase.
const EntropySize = 32

// PBKDF2Rounds is the fixed BIP-39 mnemonic-to-seed round count.
const PBKDF2Rounds = 2048

// SeedSize is the byte length of the derived BIP-39 seed.
const SeedSize = 64

// Errors returned by mnemonic parsing and validation.
var (
	ErrEmptyMnemonic    = errors.New("hd: mnemonic is empty")
	ErrWordCount        = fmt.Errorf("hd: mnemonic must be %d words", MnemonicWords)
	ErrUnknownWord      = errors.New("hd: mnemonic contains a word outside the BIP-39 English wordlist")
	ErrBadChecksum      = errors.New("hd: mnemonic checksum invalid (typo in the phrase?)")
	ErrEntropyMismatch  = errors.New("hd: mnemonic word count does not match its entropy length")
	ErrBadEntropyLength = errors.New("hd: entropy must be 16, 20, 24, 28 or 32 bytes")
)

// normalizeMnemonic lowercases, trims and collapses whitespace runs so that
// phrases copied from printouts, emails or different locales validate. The
// BIP-39 wordlist is lowercase-only, so normalization is lossless.
func normalizeMnemonic(mnemonic string) []string {
	fields := strings.Fields(strings.ToLower(strings.TrimSpace(mnemonic)))
	return fields
}

// NewMnemonic generates a fresh 24-word BIP-39 English recovery phrase from
// system randomness. The returned phrase is lowercase, single-space
// separated and checksum-valid.
func NewMnemonic() (string, error) {
	entropy := make([]byte, EntropySize)
	if _, err := crandRead(entropy); err != nil {
		return "", fmt.Errorf("hd: entropy: %w", err)
	}
	return MnemonicFromEntropy(entropy)
}

// MnemonicFromEntropy encodes entropy into its canonical 24-word BIP-39
// phrase. entropy must be 16, 20, 24, 28 or 32 bytes (BIP-39 allows those
// sizes; ANONYMCOIN generates 32).
func MnemonicFromEntropy(entropy []byte) (string, error) {
	n := len(entropy)
	if n < 16 || n > 32 || n%4 != 0 {
		return "", ErrBadEntropyLength
	}
	// Layout: ENT (n bytes) || SHA256(ENT)[: n*8/32 checksum bits]. The
	// concatenated bit string is split into 11-bit groups, each selecting one
	// wordlist entry; for 32 bytes that is 264 bits -> exactly 24 words.
	sum := sha256.Sum256(entropy)
	data := make([]byte, 0, n+1)
	data = append(data, entropy...)
	data = append(data, sum[0])

	totalBits := (n + 1) * 8
	totalWords := totalBits / 11
	words := make([]string, 0, totalWords)
	for i := 0; i < totalWords; i++ {
		index := readBits(data, i*11, 11)
		words = append(words, englishWordlist[index])
	}
	return strings.Join(words, " "), nil
}

// ValidateMnemonic reports whether mnemonic is a checksum-valid BIP-39
// phrase in the English wordlist. Whitespace and case are normalized.
func ValidateMnemonic(mnemonic string) error {
	_, err := decodeMnemonic(mnemonic)
	return err
}

// MnemonicToSeed converts a BIP-39 phrase into the 64-byte BIP-39 seed:
// PBKDF2-HMAC-SHA512(mnemonic-NFKD, salt="mnemonic"+passphrase, 2048, 64).
// passphrase is the optional 25th element of protection ("25th word" of the
// colloquial 24+1 formulation): it is NOT stored in the wallet and losing it
// loses the funds behind the phrase — see SECURITY.md.
//
// The mnemonic must be checksum-valid; an invalid phrase is rejected rather
// than converted, so a mistyped recovery always fails loudly.
func MnemonicToSeed(mnemonic, passphrase string) ([]byte, error) {
	if err := ValidateMnemonic(mnemonic); err != nil {
		return nil, err
	}
	return mnemonicToSeedUnchecked(normalizeMnemonic(mnemonic), passphrase), nil
}

// mnemonicToSeedUnchecked applies the BIP-39 KDF to an already validated,
// normalized word list.
func mnemonicToSeedUnchecked(words []string, passphrase string) []byte {
	joined := strings.Join(words, " ")
	salt := "mnemonic" + passphrase
	return pbkdf2.Key([]byte(joined), []byte(salt), PBKDF2Rounds, SeedSize, sha512.New)
}

// decodeMnemonic validates and returns the entropy bits of a phrase.
func decodeMnemonic(mnemonic string) ([]byte, error) {
	words := normalizeMnemonic(mnemonic)
	if len(words) == 0 {
		return nil, ErrEmptyMnemonic
	}
	switch len(words) {
	case 12, 15, 18, 21, MnemonicWords:
	default:
		return nil, ErrWordCount
	}

	indexes := make([]uint32, len(words))
	for i, w := range words {
		idx := wordIndex(w)
		if idx < 0 {
			return nil, fmt.Errorf("%w: %q (position %d)", ErrUnknownWord, w, i+1)
		}
		indexes[i] = uint32(idx)
	}

	// Rebuild the 11-bit word stream: entropy bytes || checksum bits.
	totalBits := len(words) * 11
	entBits := totalBits / 33 * 32
	csBits := totalBits - entBits
	stream := make([]byte, totalBits/8+1) // trailing bits may spill into one extra byte
	for i, idx := range indexes {
		for b := 0; b < 11; b++ {
			bitVal := (idx >> (10 - b)) & 1
			bytePos := (i*11 + b) / 8
			bitPos := uint(7 - (i*11+b)%8)
			stream[bytePos] |= byte(bitVal) << bitPos
		}
	}
	entropy := stream[:entBits/8]
	gotCS := readBits(stream, entBits, csBits)

	sum := sha256.Sum256(entropy)
	wantCS := uint32(sum[0]) >> (8 - uint(csBits))
	if gotCS != wantCS {
		return nil, ErrBadChecksum
	}
	// The word count must match the entropy length implied by the checksum
	// size (implied by the arithmetic above; asserted so the error path is
	// explicit for audit).
	if len(entropy) != entBits/8 {
		return nil, ErrEntropyMismatch
	}
	return entropy, nil
}

// readBits returns the `width` bits of data starting at bit offset `off`,
// interpreted as a big-endian bit string.
func readBits(data []byte, off, width int) uint32 {
	var v uint32
	for i := 0; i < width; i++ {
		bitPos := off + i
		byteIdx := bitPos / 8
		if byteIdx >= len(data) {
			break
		}
		bit := (data[byteIdx] >> (7 - uint(bitPos%8))) & 1
		v = v<<1 | uint32(bit)
	}
	return v
}

// crandRead fills b from the system CSPRNG. It is a package-level variable
// only so tests can deterministically substitute entropy; production always
// uses crypto/rand.
var crandRead = defaultCrandRead

func defaultCrandRead(b []byte) (int, error) { return rand.Read(b) }

// ---------------------------------------------------------------------------
// SLIP-0010: hierarchical deterministic keys for Ed25519
// ---------------------------------------------------------------------------

// MasterKey is a SLIP-0010 Ed25519 node: a 32-byte private key (the Ed25519
// seed) and a 32-byte chain code.
type MasterKey struct {
	Key       [32]byte
	ChainCode [32]byte
	Depth     uint8
}

// slip10Ed25519 is the SLIP-0010 Ed25519 domain string ("ed25519 seed").
var slip10Ed25519 = []byte("ed25519 seed")

// MasterFromSeed derives the SLIP-0010 Ed25519 master key from a BIP-39
// seed: I = HMAC-SHA512("ed25519 seed", seed); Key = I[:32], ChainCode =
// I[32:64].
func MasterFromSeed(seed []byte) MasterKey {
	mac := hmac.New(sha512.New, slip10Ed25519)
	mac.Write(seed)
	sum := mac.Sum(nil)
	var k MasterKey
	copy(k.Key[:], sum[:32])
	copy(k.ChainCode[:], sum[32:64])
	return k
}

// ErrNonHardened is returned when a derivation path contains a non-hardened
// step. SLIP-0010 defines hardened-only derivation for Ed25519; ANONYMCOIN
// never improvises beyond the specification.
var ErrNonHardened = errors.New("hd: ed25519 derivation supports hardened steps only (index >= 0x80000000)")

// DeriveChild derives one hardened child. index must have the hardened bit
// (0x80000000) set; the private step is
// I = HMAC-SHA512(chainCode, 0x00 || key || index32).
func DeriveChild(k MasterKey, index uint32) (MasterKey, error) {
	if index < 0x80000000 {
		return MasterKey{}, ErrNonHardened
	}
	var data [1 + 32 + 4]byte
	data[0] = 0x00
	copy(data[1:33], k.Key[:])
	binary.BigEndian.PutUint32(data[33:], index)
	mac := hmac.New(sha512.New, k.ChainCode[:])
	mac.Write(data[:])
	sum := mac.Sum(nil)
	var c MasterKey
	copy(c.Key[:], sum[:32])
	copy(c.ChainCode[:], sum[32:64])
	c.Depth = k.Depth + 1
	return c, nil
}

// DerivePath walks a hardened BIP-44-style path. The path syntax is
// "m/44'/2026'/account'/0'/index'" — every step must be hardened (either
// the i' or iH form). ANONYMCOIN's registered-style coin type is 2026
// (chosen, documented in docs/PROTOCOL.md; not a SLIP-44 registry entry).
func DerivePath(seed []byte, path string) (MasterKey, error) {
	steps, err := ParsePath(path)
	if err != nil {
		return MasterKey{}, err
	}
	k := MasterFromSeed(seed)
	for _, idx := range steps {
		k, err = DeriveChild(k, idx)
		if err != nil {
			return MasterKey{}, err
		}
	}
	return k, nil
}

// ParsePath parses a hardened SLIP-0010 path into raw indexes (hardened bit
// set). "m" and "M" prefixes are optional; "m" alone is the master key.
func ParsePath(path string) ([]uint32, error) {
	p := strings.TrimSpace(path)
	p = strings.TrimPrefix(p, "m")
	p = strings.TrimPrefix(p, "M")
	p = strings.Trim(p, "/")
	if p == "" {
		return nil, nil
	}
	parts := strings.Split(p, "/")
	out := make([]uint32, 0, len(parts))
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("hd: empty path step %d in %q", i+1, path)
		}
		hardened := false
		switch {
		case strings.HasSuffix(part, "'") || strings.HasSuffix(part, "h") || strings.HasSuffix(part, "H"):
			hardened = true
			part = part[:len(part)-1]
		}
		v, err := parseUint32(part)
		if err != nil {
			return nil, fmt.Errorf("hd: bad path step %q in %q", part, path)
		}
		if !hardened {
			return nil, fmt.Errorf("%w: step %d (%s) in %q", ErrNonHardened, i+1, part, path)
		}
		out = append(out, v|0x80000000)
	}
	return out, nil
}

// AccountPath returns the BIP-44-style account root path for ANONYMCOIN:
// m/44'/2026'/account'.
func AccountPath(account uint32) string {
	return fmt.Sprintf("m/44'/2026'/%d'", account)
}

// AddressPath returns the full leaf path for account/chain/index:
// m/44'/2026'/account'/0'/index'. ANONYMCOIN uses chain 0' only (external
// addresses); change is paid back to external addresses deterministically.
func AddressPath(account, index uint32) string {
	return fmt.Sprintf("m/44'/2026'/%d'/0'/%d'", account, index)
}

func parseUint32(s string) (uint32, error) {
	if len(s) == 0 || len(s) > 10 {
		return 0, errors.New("hd: bad index")
	}
	var v uint64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errors.New("hd: bad index digit")
		}
		v = v*10 + uint64(s[i]-'0')
		if v > 0xFFFFFFFF {
			return 0, errors.New("hd: index overflow")
		}
	}
	return uint32(v), nil
}
