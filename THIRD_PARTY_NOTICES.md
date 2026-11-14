# Third-Party Notices

**ANONYMCOIN — Original Project Author and Founder: Iury Lee — Copyright © 2026 Iury Lee**

ANONYMCOIN distinguishes clearly between original work and third-party
components. All original code carries the project header. The third-party
components below are used unmodified except for vendoring, and their license
notices are preserved verbatim inside the vendored dependency tree.

## 1. lattice-safe/falcon-go (Falcon-512 / FN-DSA-512)

- **Used for:** the post-quantum handshake signature (`cryptography/falcon.go`
  is a thin adapter).
- **Upstream:** https://github.com/lattice-safe/falcon-go (v0.1.1)
- **License:** MIT (see `vendor/github.com/lattice-safe/falcon-go/LICENSE`).
- **Attribution chain:** the package's internal FN-DSA core is adapted from
  Thomas Pornin's **public-domain** go-fn-dsa implementation; the vendored
  public-domain notice is kept inside the package. FN-DSA is the NIST FIPS
  206 standardization of the Falcon lattice signature scheme
  (https://falcon-sign.info).

## 2. golang.org/x/crypto

- **Used for:** BLAKE2b (`blake2b`), scrypt and Argon2id (wallet KDFs),
  PBKDF2-HMAC-SHA512 (BIP-39 mnemonic-to-seed conversion).
- **Upstream:** https://pkg.go.dev/golang.org/x/crypto (v0.40.0)
- **License:** BSD-3-Clause (see `vendor/golang.org/x/crypto/LICENSE`).
- Copyright of the original authors preserved per that file.

## 2a. BIP-39 specification and English wordlist

- **Used for:** the 24-word recovery phrase format and its canonical English
  wordlist, embedded in generated form in `hd/wordlist.go` (with the source
  SHA-256 recorded in that file).
- **Upstream:** https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
  and the BIP-39 specification
  https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
- **License:** the BIP-39 document and wordlist are distributed by the
  Bitcoin BIP repository under the MIT license; the official test vectors
  used in `hd/hd_test.go` are published by Trezor
  (https://github.com/trezor/python-mnemonic) under MIT terms.
- **Modifications:** none to the list itself; the Go embedding and the
  checksum/entropy bit-slicing are original ANONYMCOIN code validated
  against the published vectors.

## 2b. SLIP-0010 specification

- **Used for:** hierarchical deterministic derivation for Ed25519
  (hardened-only), implemented in `hd/mnemonic.go` and validated against
  the official test vectors published in
  https://github.com/satoshilabs/slips/blob/master/slip-0010.md.
- **License:** SLIPs are distributed by SatoshiLabs under an open
  documentation license; no specification text was copied into the
  repository — only the published test-vector values are embedded in the
  test file, quoted as facts.

## 3. golang.org/x/sys (indirect)

- **License:** BSD-3-Clause (see `vendor/golang.org/x/sys/LICENSE`).

## 4. Go standard library

- **License:** BSD-style Go license, copyright The Go Authors
  (https://go.dev/LICENSE).

## 5. Studied designs (no code copied)

- **AstroBWT** as used by Kaspa (kaspad, ISC License): studied as the
  technical starting point for the ANONYMBWT design fork. No source was
  copied; see ANONYMBWT.md §1 for the documented differences. Kaspad is
  distributed under the ISC license; the authoritative license text is
  published in the upstream repository (github.com/kaspanet/kaspad, file
  LICENSE) and is not reproduced here to avoid transcription drift. No
  AstroBWT code, binary or test vector was incorporated into ANONYMCOIN.

## 6. Design references

- FIPS 206 (FN-DSA) and the Falcon specification by Fouque, Hoffstein,
  Kirchner, Lepoint, Nagarajan, Pornin, Prest, Ravi, Ryckelink, Tibouchi,
  Yu — studied as the specification of the signature scheme provided by
  falcon-go.
- The Burrows-Wheeler transform (Burrows & Wheeler, 1994) and the
  Manber-Myers suffix-array construction — public academic algorithms,
  implemented from their descriptions.

This file will be updated whenever the dependency set changes. No third-party
component is claimed as original ANONYMCOIN work, and no legitimate original
credit has been replaced or erased.
