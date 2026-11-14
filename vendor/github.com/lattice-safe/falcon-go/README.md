# falcon-go

[![Go Reference](https://pkg.go.dev/badge/github.com/lattice-safe/falcon-go.svg)](https://pkg.go.dev/github.com/lattice-safe/falcon-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Hardware-accelerated Go implementation (ARM64/AMD64 assembly) of **FN-DSA (FIPS 206)**, formerly Falcon — a lattice-based post-quantum digital signature scheme.

Byte-for-byte compatible with [`github.com/lattice-safe/falcon-rs`](https://github.com/lattice-safe/falcon-rs).

## Features

- **FN-DSA-512** and **FN-DSA-1024** key generation, signing, and verification
- **FIPS 206 domain separation** — `DomainNone`, `DomainContext`, `DomainPrehashed`
- **HashFN-DSA** — SHA-256, SHA-384, SHA-512, SHA-512/256, SHA3-256, SHA3-384, SHA3-512
- **Deterministic signing** for reproducible FIPS 206 test vectors
- **Expanded key** handle for amortized multi-signature workloads
- **Key import/export** — private key, public key, signature serialization round-trips
- **Native low-level API** — C-reference-style `falcon_*` wrappers in `native/`
- **Comprehensive test suite** — Verified against FIPS KAT vectors with high test coverage and race detection
- **No CGo** — pure Go, single dependency (`golang.org/x/crypto`)

## Install

```bash
go get github.com/lattice-safe/falcon-go
```

## Quick Start

```go
package main

import "github.com/lattice-safe/falcon-go"

func main() {
    // Generate an FN-DSA-512 key pair
    kp, err := falcon.Generate(9)
    if err != nil {
        panic(err)
    }

    // Sign a message
    sig, err := kp.Sign([]byte("hello"), falcon.DomainNone())
    if err != nil {
        panic(err)
    }

    // Verify
    err = falcon.Verify(sig.Bytes(), kp.PublicKey(), []byte("hello"), falcon.DomainNone())
    if err != nil {
        panic("verification failed")
    }
}
```

## Examples

See the [`examples/`](examples/) directory for complete programs:

| Example | Description |
|---------|-------------|
| [`keygen`](examples/keygen) | Generate keys for both security levels, inspect sizes |
| [`sign_verify`](examples/sign_verify) | All FIPS 206 domain modes with cross-domain rejection |
| [`expand_key`](examples/expand_key) | Amortized multi-signature with expanded key |
| [`serialize`](examples/serialize) | Key and signature serialization round-trips |

Run any example:

```bash
go run ./examples/sign_verify
```

## Sizes

| Parameter | FN-DSA-512 | FN-DSA-1024 |
|-----------|------------|-------------|
| Private key | 1,281 B | 2,305 B |
| Public key | 897 B | 1,793 B |
| Signature (CT) | 809 B | 1,577 B |

```go
skLen, _ := falcon.PrivateKeySize(9)   // 1281
pkLen, _ := falcon.PublicKeySize(9)    // 897
sigLen, _ := falcon.SignatureSize(9)   // 809, CT format
```

## Benchmarks

Run on Apple M1 Max:

```
BenchmarkKeygen512              163        7.09 ms/op
BenchmarkSign512_None          3205      371 µs/op
BenchmarkVerify512_None       42313       27.6 µs/op
BenchmarkKeygen1024              49       24.4 ms/op
BenchmarkSign1024_None         1580      753 µs/op
BenchmarkVerify1024_None      20439       58.5 µs/op
BenchmarkExpand512            13639       87.9 µs/op
BenchmarkSignExpanded512       4165      287 µs/op
```

Run benchmarks yourself:

```bash
go test -bench=. -benchmem -benchtime=3s -count=1 -run=^$ .
```

## Security

See [SECURITY.md](SECURITY.md) for the security policy and responsible disclosure process.

## Attribution

The internal FN-DSA core is adapted from Thomas Pornin's public-domain
[`go-fn-dsa`](https://github.com/pornin/go-fn-dsa) implementation, with
package-level changes for the Rust `falcon-rs` FIPS 206 domain separation
and CT-signature wire format. The vendored public-domain notice is kept at
[`internal/fndsa/LICENSE`](internal/fndsa/LICENSE).

## License

[MIT](LICENSE)
