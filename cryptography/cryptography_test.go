// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package cryptography

import (
	"bytes"
	"testing"
)

func TestBlake2bVector(t *testing.T) {
	// Official BLAKE2b-256("") digest from the RFC 7693 test set.
	got := Hash256Single(nil)
	want := "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
	if hexsprintf(got[:]) != want {
		t.Fatalf("blake2b-256(nil) = %s, want %s", hexsprintf(got[:]), want)
	}
	// BLAKE2b-256("abc") reference.
	got2 := Hash256Single([]byte("abc"))
	want2 := "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
	if hexsprintf(got2[:]) != want2 {
		t.Fatalf("blake2b-256(abc) = %s, want %s", hexsprintf(got2[:]), want2)
	}
}

func hexsprintf(b []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexd[c>>4], hexd[c&0x0f])
	}
	return string(out)
}

func TestHashConcat(t *testing.T) {
	a := Hash256([]byte("ab"), []byte("c"))
	b := Hash256Single([]byte("abc"))
	if a != b {
		t.Fatal("Hash256 concat mismatch")
	}
}

func TestBase58Roundtrip(t *testing.T) {
	cases := [][]byte{
		{},
		{0x00},
		{0x00, 0x00, 0xff},
		[]byte("hello world"),
		{0xff, 0xff, 0xff, 0xff, 0xff},
	}
	for i, c := range cases {
		s := Base58Encode(c)
		back, err := Base58Decode(s)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if !bytes.Equal(back, c) {
			t.Fatalf("case %d: roundtrip mismatch %x != %x", i, back, c)
		}
	}
	if _, err := Base58Decode("0OIl"); err == nil {
		t.Fatal("invalid base58 characters accepted")
	}
}

func TestBase58Check(t *testing.T) {
	payload := []byte("anonymcoin-address-payload")
	s := Base58Check(AddrVersion, payload)
	version, out, err := Base58CheckDecode(s)
	if err != nil {
		t.Fatal(err)
	}
	if version != AddrVersion || !bytes.Equal(out, payload) {
		t.Fatal("base58check roundtrip failed")
	}
	// Flip one character -> checksum failure.
	bad := []byte(s)
	if bad[2] == 'a' {
		bad[2] = 'b'
	} else {
		bad[2] = 'a'
	}
	if _, _, err := Base58CheckDecode(string(bad)); err == nil {
		t.Fatal("corrupted base58check accepted")
	}
}

func TestAddressRoundtrip(t *testing.T) {
	kp, _ := NewKeyPair()
	addr := AddressFromPubKey(kp.Public)
	pkh, err := AddressToPubKeyHash(addr)
	if err != nil {
		t.Fatal(err)
	}
	if pkh != Hash160Of(kp.Public) {
		t.Fatal("address pubkey hash mismatch")
	}
	if !IsValidAddress(addr) {
		t.Fatal("valid address rejected")
	}
	if IsValidAddress(addr[:len(addr)-1]) {
		t.Fatal("truncated address accepted")
	}
}

func TestEd25519KeyPairFromSeed(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	kp1, _ := KeyPairFromSeed(seed)
	kp2, _ := KeyPairFromSeed(seed)
	if !bytes.Equal(kp1.Public, kp2.Public) {
		t.Fatal("seed derivation not deterministic")
	}
	sig := kp1.Sign([]byte("msg"))
	if !bytes.Equal(sig, kp2.Sign([]byte("msg"))) {
		t.Fatal("deterministic signing broken")
	}
}

func TestFalcon512SignVerify(t *testing.T) {
	pub, priv, err := FalconGenerate()
	if err != nil {
		t.Fatalf("falcon keygen: %v", err)
	}
	if len(pub) != 897 {
		t.Fatalf("falcon public key size = %d, want 897", len(pub))
	}
	msg := []byte("ANONYMCOIN handshake transcript — THE BLOCKDAG IS THE HEART")
	sig, err := FalconSign(priv, msg)
	if err != nil {
		t.Fatalf("falcon sign: %v", err)
	}
	if !FalconVerify(pub, msg, sig) {
		t.Fatal("valid falcon signature rejected")
	}
	// Tampered message must fail.
	if FalconVerify(pub, []byte("tampered transcript"), sig) {
		t.Fatal("falcon signature accepted over tampered message")
	}
	// Wrong public key must fail.
	pub2, priv2, _ := FalconGenerate()
	if FalconVerify(pub2, msg, sig) {
		t.Fatal("falcon signature accepted under foreign key")
	}
	_ = priv2
	// Public key derivable from private key.
	derived, err := FalconPublicKeyFromPrivate(priv)
	if err != nil || !bytes.Equal(derived, pub) {
		t.Fatal("falcon public key derivation mismatch")
	}
}
