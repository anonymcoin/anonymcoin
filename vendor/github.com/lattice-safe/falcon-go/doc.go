// Package falcon implements FN-DSA (FIPS 206), the NIST post-quantum
// digital signature standard based on the Falcon lattice scheme.
//
// This package provides a high-level, type-safe Go API for key generation,
// signing, and verification at the two standard security levels:
//
//   - FN-DSA-512  (logn = 9, NIST Level I)
//   - FN-DSA-1024 (logn = 10, NIST Level V)
//
// # Quick Start
//
// Generate a key pair, sign a message, and verify:
//
//	kp, _ := falcon.Generate(9) // FN-DSA-512
//	sig, _ := kp.Sign([]byte("hello"), falcon.DomainNone())
//	err := falcon.Verify(sig.Bytes(), kp.PublicKey(), []byte("hello"), falcon.DomainNone())
//
// # Domain Separation
//
// FIPS 206 defines three domain modes:
//
//   - [DomainNone]: pure FN-DSA, no application context.
//   - [DomainContext]: pure FN-DSA bound to an application context string (≤255 bytes).
//   - [DomainPrehashed]: HashFN-DSA with SHA-256 or SHA-512 pre-hashing.
//
// # Expanded Keys
//
// For repeated signing with the same key, use [KeyPair.Expand] to amortize
// the key decoding cost:
//
//	ek, _ := kp.Expand()
//	sig1, _ := ek.Sign(msg1, falcon.DomainNone())
//	sig2, _ := ek.Sign(msg2, falcon.DomainNone())
//
// # Signature Format
//
// This package produces constant-time (CT) format signatures by default,
// which provide side-channel resistance during encoding. The [Verify]
// function accepts both CT (0x50) and padded/compressed (0x30) formats.
//
// # Implementation
//
// The cryptographic core is a pure Go port of Thomas Pornin's go-fn-dsa,
// with ARM64 and AMD64 assembly for hot-path floating-point intrinsics.
// All outputs are verified byte-for-byte against FIPS 206 Known Answer Tests.
//
// The low-level C-reference-style API is available in the [native] subpackage
// for applications that need streamed hashing or transcript-recording semantics.
package falcon
