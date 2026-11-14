# AnonymBWT-V3

AnonymBWT-V3 is a 100% rebranded fork of **AstroBWT-V3**, the CPU proof-of-work
hash algorithm originally created by the DERO Project. The package was renamed
end to end: the Go package is now `anonymbwtv3` and the public entry point is
`AnonymBWTv3(input []byte) (outputhash [32]byte)`. The algorithm itself is
unchanged - it produces exactly the same hashes as AstroBWT-V3, and the
original test vectors in `pow_test.go` pass unchanged.

## Usage

```go
import "anonymbwt-v3"

hash := AnonymBWTv3(data)
```

A minimal `go.mod` is included so the package builds and tests standalone.

Run the test suite (compiles the package and verifies the reference hashes):

```
go test
```

## Credits

This fork exists thanks to the original authors. All credit for the algorithm
and the code belongs to them; this fork only carries a new name.

- **AstroBWT-V3 algorithm and implementation** - Copyright (c) 2022 DERO
  Foundation (DERO Project), BSD-3-Clause license. See `LICENSE.txt`.
- **Suffix-array code** (`sais.go`, `sais2.go`, `suffixarray.go`, and the
  `gen.go` / `gen16.go` generators) - derived from the Go standard library's
  `index/suffixarray` package, Copyright (c) 2019 The Go Authors, BSD-style
  license noted in each file header.
- **Fork renamed and repackaged as AnonymBWT-V3** - Copyright (c) 2026
  Z User.

The BSD-3-Clause license requires that the original copyright notice be
retained; it is reproduced in full in `LICENSE.txt`, followed by the fork
attribution.
