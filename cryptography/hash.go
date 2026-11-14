// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

// Package cryptography provides the hashing, addressing and node-identity
// primitives of ANONYMCOIN:
//
//   - BLAKE2b-256 as the network hash function (via golang.org/x/crypto).
//   - Ed25519 for transaction signatures and TLS 1.3 node certificates.
//   - Falcon-512 (FN-DSA-512, FIPS 206) for post-quantum node identity in
//     the P2P handshake, via github.com/lattice-safe/falcon-go (pure Go).
//
// Third-party components and their licenses are listed in
// THIRD_PARTY_NOTICES.md at the repository root.
package cryptography

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

// Hash is a 256-bit BLAKE2b digest.
type Hash = [32]byte

// Hash160 is a truncated 160-bit digest used for address scripts.
type Hash160 = [20]byte

// Hash256 concatenates the inputs and returns their BLAKE2b-256 digest.
func Hash256(parts ...[]byte) Hash {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic("cryptography: blake2b unavailable: " + err.Error())
	}
	for _, p := range parts {
		h.Write(p)
	}
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// Hash256Single digests a single byte slice.
func Hash256Single(b []byte) Hash {
	s := blake2b.Sum256(b)
	return Hash(s)
}

// Hash160Of returns the truncated 20-byte digest of b.
func Hash160Of(b []byte) Hash160 {
	s := blake2b.Sum256(b)
	var out Hash160
	copy(out[:], s[:20])
	return out
}

// HashHex renders a hash in canonical lowercase hex.
func HashHex(h Hash) string { return hex.EncodeToString(h[:]) }

// ParseHexHash parses a 64-char lowercase/uppercase hex string into a Hash.
func ParseHexHash(s string) (Hash, error) {
	var h Hash
	b, err := hex.DecodeString(s)
	if err != nil {
		return h, fmt.Errorf("invalid hash hex: %w", err)
	}
	if len(b) != 32 {
		return h, fmt.Errorf("hash hex must be 64 characters, got %d bytes", len(b))
	}
	copy(h[:], b)
	return h, nil
}
