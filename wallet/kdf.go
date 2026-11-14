// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package wallet

import (
	"errors"
	"fmt"
	"runtime"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// ---------------------------------------------------------------------------
// Key derivation for wallet encryption at rest.
//
// ANONYMCOIN supports two audited KDFs for the wallet file:
//
//   - scrypt (RFC 7914) with raised parameters: N=2^17 (131072), r=8, p=1 —
//     128 MiB of memory per derivation. The v1 parameters (N=2^15, 32 MiB)
//     are still accepted for opening legacy wallet files but are no longer
//     written; re-saving upgrades them.
//   - Argon2id (RFC 9106), the winner of the Password Hashing Competition:
//     64 MiB memory, t=3 passes, 4 lanes — the OWASP-recommended profile
//     class for high-value secrets. Selected with KDFArgon2id.
//
// The KDF type and all parameters are stored inside the wallet file, so
// upgrades never break compatibility and every file is self-describing for
// audit.
// ---------------------------------------------------------------------------

// KDFType identifies the key derivation function of a wallet file.
type KDFType string

const (
	KDFScrypt   KDFType = "scrypt"
	KDFArgon2id KDFType = "argon2id"
)

// Raised scrypt parameters (v2 default).
const (
	scryptN = 1 << 17 // 131072: 128 MiB, ~0.5-1 s on a laptop
	scryptR = 8
	scryptP = 1
)

// Legacy v1 parameters — kept ONLY so old files still open.
const (
	legacyScryptN = 1 << 15
	legacyScryptR = 8
	legacyScryptP = 1
)

// Argon2id parameters (v2 option).
const (
	argon2MemoryKiB = 64 * 1024 // 64 MiB
	argon2Time      = 3         // passes
	argon2Threads   = 4         // lanes
)

// kdfParams is the serialized KDF description inside the wallet file.
type kdfParams struct {
	Type    string `json:"type"` // "scrypt" | "argon2id"
	N       int    `json:"n,omitempty"`
	R       int    `json:"r,omitempty"`
	P       int    `json:"p,omitempty"`
	Memory  uint32 `json:"memory_kib,omitempty"`
	Time    uint32 `json:"time,omitempty"`
	Threads uint8  `json:"threads,omitempty"`
}

func scryptParams() kdfParams {
	return kdfParams{Type: string(KDFScrypt), N: scryptN, R: scryptR, P: scryptP}
}

func argon2Params() kdfParams {
	return kdfParams{Type: string(KDFArgon2id), Memory: argon2MemoryKiB, Time: argon2Time, Threads: argon2Threads}
}

// validate rejects absurd or incomplete KDF parameters before they are used
// (the parameters are attacker-visible file content for Open).
func (k kdfParams) validate() error {
	switch KDFType(k.Type) {
	case KDFScrypt:
		if k.N < legacyScryptN || k.N > 1<<22 {
			return fmt.Errorf("wallet: scrypt N out of range: %d", k.N)
		}
		if k.R < 1 || k.R > 64 || k.P < 1 || k.P > 8 {
			return errors.New("wallet: scrypt r/p out of range")
		}
		// Memory cost sanity: N * 128 * r bytes must stay under 2 GiB so a
		// hostile wallet file cannot OOM the node.
		if uint64(k.N)*128*uint64(k.R) > 2<<30 {
			return errors.New("wallet: scrypt memory cost too high")
		}
	case KDFArgon2id:
		if k.Memory < 8*1024 || k.Memory > 4*1024*1024 {
			return fmt.Errorf("wallet: argon2 memory out of range: %d KiB", k.Memory)
		}
		if k.Time < 1 || k.Time > 16 {
			return fmt.Errorf("wallet: argon2 time out of range: %d", k.Time)
		}
		if k.Threads < 1 || k.Threads > 16 {
			return fmt.Errorf("wallet: argon2 threads out of range: %d", k.Threads)
		}
	default:
		return fmt.Errorf("wallet: unknown KDF type %q", k.Type)
	}
	return nil
}

// deriveKey computes the 32-byte AES key from the passphrase under the
// given parameters. The passphrase is never retained.
func (k kdfParams) deriveKey(passphrase string, salt []byte) ([]byte, error) {
	switch KDFType(k.Type) {
	case KDFScrypt:
		return scrypt.Key([]byte(passphrase), salt, k.N, k.R, k.P, 32)
	case KDFArgon2id:
		return argon2.IDKey([]byte(passphrase), salt, k.Time, k.Memory, k.Threads, 32), nil
	default:
		return nil, fmt.Errorf("wallet: unknown KDF type %q", k.Type)
	}
}

// DefaultKDF returns the v2 default KDF (raised scrypt).
func DefaultKDF() kdfParams { return scryptParams() }

// ---------------------------------------------------------------------------
// Secure memory handling helpers.
// ---------------------------------------------------------------------------

// zeroize overwrites a byte slice with zeroes in a way the compiler may not
// optimize away (the KeepAlive barrier pins liveness past the loop). Every
// private-key buffer, seed and derived master secret goes through this on
// Close.
//
// Honest limitation, documented in SECURITY.md: Go's garbage collector may
// retain transient copies of byte slices it has moved; zeroization is
// best-effort defense in depth (it reliably clears the buffers the wallet
// controls for the wallet's lifetime), not a hard guarantee against a
// compromised process, a core dump or a swap file. Operators handling
// high-value keys should disable swap and use full-disk encryption.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// wipeKey wipes an Ed25519 private key buffer.
func wipeKey(k []byte) { zeroize(k) }
