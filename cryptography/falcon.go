// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package cryptography

import (
	"errors"
	"fmt"

	falcon "github.com/lattice-safe/falcon-go"
)

// Falcon512 support.
//
// ANONYMCOIN uses FN-DSA-512 (FIPS 206, the NIST standardization of the
// Falcon lattice signature scheme) with logn = 9, which corresponds to the
// classic Falcon-512 parameter set (897-byte public keys, ~666-809 byte
// signatures). It signs the P2P handshake transcript so node identity remains
// verifiable against future quantum adversaries.
//
// The implementation is the pure-Go github.com/lattice-safe/falcon-go
// package (MIT), whose cryptographic core is adapted from Thomas Pornin's
// public-domain go-fn-dsa. Full attribution in THIRD_PARTY_NOTICES.md.

// FalconLogN is the FN-DSA log2(degree) parameter for Falcon-512.
const FalconLogN = 9

// ErrFalcon wraps falcon errors for the cryptography package.
var ErrFalcon = errors.New("falcon512: operation failed")

// FalconGenerate creates a fresh Falcon-512 key pair. Returns (publicKey,
// privateKey) in the package's encoded formats (897-byte public key,
// 1281-byte private key).
func FalconGenerate() (pub, priv []byte, err error) {
	kp, err := falcon.Generate(FalconLogN)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: keygen: %v", ErrFalcon, err)
	}
	return kp.PublicKey(), kp.PrivateKey(), nil
}

// FalconSign signs msg with an encoded Falcon-512 private key.
func FalconSign(priv, msg []byte) ([]byte, error) {
	kp, err := falcon.FromPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("%w: private key: %v", ErrFalcon, err)
	}
	sig, err := kp.Sign(msg, falcon.DomainNone())
	if err != nil {
		return nil, fmt.Errorf("%w: sign: %v", ErrFalcon, err)
	}
	return sig.Bytes(), nil
}

// FalconVerify checks a Falcon-512 signature. It returns true only for a
// valid signature over msg under pub.
func FalconVerify(pub, msg, sig []byte) bool {
	err := falcon.Verify(sig, pub, msg, falcon.DomainNone())
	return err == nil
}

// FalconPublicKeyFromPrivate recomputes the encoded public key of an encoded
// private key.
func FalconPublicKeyFromPrivate(priv []byte) ([]byte, error) {
	pub, err := falcon.PublicKeyFromPrivate(priv)
	if err != nil {
		return nil, fmt.Errorf("%w: derive public key: %v", ErrFalcon, err)
	}
	return pub, nil
}

// FalconMaxSignatureSize bounds the encoded signature length for allocation.
func FalconMaxSignatureSize() int {
	n, err := falcon.SignatureSize(FalconLogN)
	if err != nil {
		return 2048
	}
	return n
}
