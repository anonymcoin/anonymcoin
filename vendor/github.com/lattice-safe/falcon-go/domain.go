package falcon

import (
	"crypto/sha256"
	"crypto/sha512"

	"golang.org/x/crypto/sha3"
)

// PreHashAlgorithm selects the hash used by HashFN-DSA.
type PreHashAlgorithm uint8

const (
	// PreHashSHA256 selects SHA-256 for HashFN-DSA.
	PreHashSHA256 PreHashAlgorithm = iota + 1
	// PreHashSHA384 selects SHA-384 for HashFN-DSA.
	PreHashSHA384
	// PreHashSHA512 selects SHA-512 for HashFN-DSA.
	PreHashSHA512
	// PreHashSHA512_256 selects SHA-512/256 for HashFN-DSA.
	PreHashSHA512_256
	// PreHashSHA3_256 selects SHA3-256 for HashFN-DSA.
	PreHashSHA3_256
	// PreHashSHA3_384 selects SHA3-384 for HashFN-DSA.
	PreHashSHA3_384
	// PreHashSHA3_512 selects SHA3-512 for HashFN-DSA.
	PreHashSHA3_512
)

// Domain captures the FIPS 206 domain separation mode used for signing.
type Domain struct {
	context []byte
	alg     PreHashAlgorithm
	prehash bool
}

// DomainNone returns pure FN-DSA with no context.
func DomainNone() Domain {
	return Domain{}
}

// DomainContext returns pure FN-DSA bound to an application context.
func DomainContext(ctx []byte) (Domain, error) {
	if len(ctx) > 255 {
		return Domain{}, ErrBadArgument
	}
	return Domain{context: cloneBytes(ctx)}, nil
}

// DomainPrehashed returns HashFN-DSA with the selected pre-hash algorithm.
func DomainPrehashed(alg PreHashAlgorithm, ctx []byte) (Domain, error) {
	if len(ctx) > 255 {
		return Domain{}, ErrBadArgument
	}
	switch alg {
	case PreHashSHA256, PreHashSHA384, PreHashSHA512, PreHashSHA512_256, PreHashSHA3_256, PreHashSHA3_384, PreHashSHA3_512:
		return Domain{context: cloneBytes(ctx), alg: alg, prehash: true}, nil
	default:
		return Domain{}, ErrBadArgument
	}
}

func (d Domain) validate() error {
	if len(d.context) > 255 {
		return ErrBadArgument
	}
	if d.prehash {
		switch d.alg {
		case PreHashSHA256, PreHashSHA384, PreHashSHA512, PreHashSHA512_256, PreHashSHA3_256, PreHashSHA3_384, PreHashSHA3_512:
			// valid
		default:
			return ErrBadArgument
		}
	}
	return nil
}

func (d Domain) messageForHash(message []byte) []byte {
	if !d.prehash {
		return message
	}
	switch d.alg {
	case PreHashSHA256:
		h := sha256.Sum256(message)
		return h[:]
	case PreHashSHA384:
		h := sha512.Sum384(message)
		return h[:]
	case PreHashSHA512:
		h := sha512.Sum512(message)
		return h[:]
	case PreHashSHA512_256:
		h := sha512.Sum512_256(message)
		return h[:]
	case PreHashSHA3_256:
		h := sha3.Sum256(message)
		return h[:]
	case PreHashSHA3_384:
		h := sha3.Sum384(message)
		return h[:]
	case PreHashSHA3_512:
		h := sha3.Sum512(message)
		return h[:]
	default:
		return nil
	}
}

func cloneBytes(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}
