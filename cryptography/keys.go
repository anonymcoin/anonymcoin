// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package cryptography

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
)

// KeyPair is an Ed25519 signing key pair used for transaction signatures and
// TLS node certificates.
type KeyPair struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// NewKeyPair generates a fresh Ed25519 key pair from system randomness.
func NewKeyPair() (KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("ed25519 keygen: %w", err)
	}
	return KeyPair{Private: priv, Public: pub}, nil
}

// KeyPairFromSeed deterministically derives a key pair from a 32-byte seed.
func KeyPairFromSeed(seed []byte) (KeyPair, error) {
	if len(seed) != ed25519.SeedSize {
		return KeyPair{}, errors.New("ed25519: seed must be 32 bytes")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return KeyPair{Private: priv, Public: priv.Public().(ed25519.PublicKey)}, nil
}

// Sign returns the Ed25519 signature of msg under the key pair's private key.
func (k KeyPair) Sign(msg []byte) []byte {
	return ed25519.Sign(k.Private, msg)
}

// AddressFromPubKey derives the canonical ANONYMCOIN address string for a
// compressed Ed25519 public key: Base58Check(version=0x1d,
// BLAKE2b-256(pubkey) truncated to 20 bytes).
func AddressFromPubKey(pub []byte) string {
	h := Hash160Of(pub)
	return Base58Check(AddrVersion, h[:])
}

// AddressToPubKeyHash decodes an address string into its 20-byte public key
// hash, validating the version byte and checksum.
func AddressToPubKeyHash(addr string) ([20]byte, error) {
	var out [20]byte
	version, payload, err := Base58CheckDecode(addr)
	if err != nil {
		return out, err
	}
	if version != AddrVersion {
		return out, fmt.Errorf("address: unknown version byte 0x%02x", version)
	}
	if len(payload) != 20 {
		return out, errors.New("address: payload must be 20 bytes")
	}
	copy(out[:], payload)
	return out, nil
}

// IsValidAddress reports whether addr is a structurally valid ANONYMCOIN
// address (checksum and version validated).
func IsValidAddress(addr string) bool {
	_, err := AddressToPubKeyHash(addr)
	return err == nil
}

// Fingerprint returns the canonical fingerprint string of a public key or
// certificate blob: "AN" + first 16 bytes of BLAKE2b-256, hex encoded.
func Fingerprint(blob []byte) string {
	h := Hash256Single(blob)
	return "AN" + fmt.Sprintf("%x", h[:16])
}
