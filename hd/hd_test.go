// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package hd

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// BIP-39 official test vectors (trezor test-vector set, subset embedded for
// independent verification; the vectors are public and cross-checkable).
// ---------------------------------------------------------------------------

// TestBIP39OfficialVectors verifies MnemonicFromEntropy and MnemonicToSeed
// against the official BIP-39 test vectors for the 24-word (256-bit entropy)
// form. Vector source: trezor/python-mnemonic vectors.json (English), which
// uses the passphrase "TREZOR" throughout; values cross-checked against an
// independent PBKDF2 implementation.
func TestBIP39OfficialVectors(t *testing.T) {
	vectors := []struct {
		name     string
		entropy  []byte
		mnemonic string
		seedTrez string // seed with passphrase "TREZOR"
	}{
		{
			name:    "entropy 0x00*32",
			entropy: make([]byte, 32),
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
				"abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
				"abandon abandon abandon abandon abandon art",
			seedTrez: "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
		},
		{
			name:    "entropy 0x7f*32",
			entropy: bytes.Repeat([]byte{0x7f}, 32),
			mnemonic: "legal winner thank year wave sausage worth useful legal winner thank year " +
				"wave sausage worth useful legal winner thank year wave sausage worth title",
			seedTrez: "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
		},
		{
			name:    "entropy 0xff*32",
			entropy: bytes.Repeat([]byte{0xff}, 32),
			mnemonic: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo " +
				"zoo zoo zoo zoo zoo zoo zoo vote",
			seedTrez: "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
		},
	}

	for _, v := range vectors {
		got, err := MnemonicFromEntropy(v.entropy)
		if err != nil {
			t.Fatalf("%s: encode: %v", v.name, err)
		}
		if got != v.mnemonic {
			t.Fatalf("%s: mnemonic mismatch:\n got: %s\nwant: %s", v.name, got, v.mnemonic)
		}
		if err := ValidateMnemonic(v.mnemonic); err != nil {
			t.Fatalf("%s: validate: %v", v.name, err)
		}
		seed, err := MnemonicToSeed(v.mnemonic, "TREZOR")
		if err != nil {
			t.Fatalf("%s: seed: %v", v.name, err)
		}
		if hex.EncodeToString(seed) != v.seedTrez {
			t.Fatalf("%s: seed mismatch:\n got: %x\nwant: %s", v.name, seed, v.seedTrez)
		}
		// Canonical roundtrip through normalization.
		if err := ValidateMnemonic("  " + strings.ToUpper(v.mnemonic) + "\n"); err != nil {
			t.Fatalf("%s: normalized validate: %v", v.name, err)
		}
	}

	// The optional passphrase must change the derived seed (it is the
	// "25th word" of the colloquial 24+1 formulation).
	m := vectors[0].mnemonic
	seedEmpty, err := MnemonicToSeed(m, "")
	if err != nil {
		t.Fatal(err)
	}
	seedPass, err := MnemonicToSeed(m, "TREZOR")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(seedEmpty, seedPass) {
		t.Fatal("passphrase must change the derived seed")
	}
}

// TestMnemonicRoundtripProperty derives mnemonics from deterministic entropy
// values and verifies full roundtrip stability and seed determinism.
func TestMnemonicRoundtripProperty(t *testing.T) {
	for i := 0; i < 64; i++ {
		entropy := make([]byte, 32)
		for b := range entropy {
			entropy[b] = byte(i*31 + b)
		}
		m, err := MnemonicFromEntropy(entropy)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateMnemonic(m); err != nil {
			t.Fatalf("roundtrip %d: %v", i, err)
		}
		s1, err := MnemonicToSeed(m, "")
		if err != nil {
			t.Fatal(err)
		}
		s2, err := MnemonicToSeed(m, "")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(s1, s2) {
			t.Fatalf("seed not deterministic at %d", i)
		}
		if len(s1) != SeedSize {
			t.Fatalf("seed size %d", len(s1))
		}
	}
}

// TestMnemonicRejections covers the loud-failure guarantees: unknown words,
// wrong word counts, corrupted checksums, non-hardened path steps.
func TestMnemonicRejections(t *testing.T) {
	valid := "abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon art"

	if err := ValidateMnemonic(valid); err != nil {
		t.Fatalf("baseline phrase must validate: %v", err)
	}

	// Unknown word.
	bad := strings.Replace(valid, "abandon art", "abandon zzzz", 1)
	if _, err := MnemonicToSeed(bad, ""); err == nil {
		t.Fatal("unknown word accepted")
	}
	// Corrupted checksum: swap the last word to a same-length alternative
	// that encodes different checksum bits.
	bad2 := strings.Replace(valid, " abandon art", " abandon asset", 1)
	if _, err := MnemonicToSeed(bad2, ""); err == nil {
		t.Fatal("corrupt checksum accepted")
	}
	// Wrong word count (23 words).
	bad3 := strings.TrimSpace(strings.Replace(valid, " art", "", 1))
	if _, err := MnemonicToSeed(bad3, ""); err == nil {
		t.Fatal("23-word phrase accepted")
	}
	// Empty.
	if _, err := MnemonicToSeed("", ""); err == nil {
		t.Fatal("empty phrase accepted")
	}
	// Extra whitespace and mixed case must still validate (normalization).
	norm := "  " + strings.ToUpper(valid) + "\n"
	if err := ValidateMnemonic(norm); err != nil {
		t.Fatalf("normalized phrase rejected: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SLIP-0010 official Ed25519 test vectors (satoshilabs/slips slip-0010.md,
// "Test vector 1" for the ed25519 default schema).
// ---------------------------------------------------------------------------

func TestSLIP0010Ed25519Vectors(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	vectors := []struct {
		path      string
		chainCode string
		key       string
	}{
		{"m", "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb", "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"},
		{"m/0'", "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69", "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"},
		{"m/0'/1'", "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14", "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2"},
		{"m/0'/1'/2'", "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c", "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9"},
		{"m/0'/1'/2'/2'", "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc", "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662"},
		{"m/0'/1'/2'/2'/1000000000'", "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230", "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793"},
	}
	for _, v := range vectors {
		k, err := DerivePath(seed, v.path)
		if err != nil {
			t.Fatalf("%s: derive: %v", v.path, err)
		}
		if hex.EncodeToString(k.Key[:]) != v.key {
			t.Fatalf("%s: key mismatch:\n got: %x\nwant: %s", v.path, k.Key, v.key)
		}
		if hex.EncodeToString(k.ChainCode[:]) != v.chainCode {
			t.Fatalf("%s: chain code mismatch:\n got: %x\nwant: %s", v.path, k.ChainCode, v.chainCode)
		}
	}
}

func TestDeriveRejectsNonHardened(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	for _, path := range []string{"m/0", "m/0'/1", "m/44/2026"} {
		if _, err := DerivePath(seed, path); !errors.Is(err, ErrNonHardened) {
			t.Fatalf("path %s: expected ErrNonHardened, got %v", path, err)
		}
	}
	// Direct child call with a plain index.
	master := MasterFromSeed(seed)
	if _, err := DeriveChild(master, 1); !errors.Is(err, ErrNonHardened) {
		t.Fatal("non-hardened child accepted")
	}
	// Harden bit arithmetic: index 0 hardened == 0x80000000.
	if _, err := DeriveChild(master, 0x80000000); err != nil {
		t.Fatalf("hardened index 0 rejected: %v", err)
	}
}

func TestDerivationDeterminismAndBranching(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")

	// Determinism.
	a, err := DerivePath(seed, AddressPath(0, 7))
	if err != nil {
		t.Fatal(err)
	}
	b, err := DerivePath(seed, AddressPath(0, 7))
	if err != nil {
		t.Fatal(err)
	}
	if a.Key != b.Key {
		t.Fatal("derivation not deterministic")
	}

	// Different accounts branch away from each other.
	c, _ := DerivePath(seed, AddressPath(1, 7))
	if a.Key == c.Key {
		t.Fatal("account 0 and account 1 collide")
	}

	// Different indexes under the same account differ.
	d, _ := DerivePath(seed, AddressPath(0, 8))
	if a.Key == d.Key {
		t.Fatal("index 7 and index 8 collide")
	}

	// Depth is tracked.
	e, _ := DerivePath(seed, AccountPath(2))
	if e.Depth != 3 {
		t.Fatalf("account root depth = %d, want 3", e.Depth)
	}
}

func TestGenerateProduces24Words(t *testing.T) {
	for i := 0; i < 8; i++ {
		m, err := NewMnemonic()
		if err != nil {
			t.Fatal(err)
		}
		words := strings.Fields(m)
		if len(words) != MnemonicWords {
			t.Fatalf("generated %d words, want %d", len(words), MnemonicWords)
		}
		if err := ValidateMnemonic(m); err != nil {
			t.Fatalf("generated phrase invalid: %v", err)
		}
		// Every generated phrase must derive a usable master key.
		s, err := MnemonicToSeed(m, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(s) != SeedSize {
			t.Fatal("bad seed size")
		}
	}
}
