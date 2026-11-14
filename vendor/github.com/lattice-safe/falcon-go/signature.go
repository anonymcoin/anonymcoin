package falcon

import (
	"crypto"
	"crypto/rand"
	"io"

	"github.com/lattice-safe/falcon-go/internal/fndsa"
)

// Signature is an encoded FN-DSA signature.
type Signature struct {
	data []byte
}

// FromSignatureBytes validates and wraps encoded signature bytes.
func FromSignatureBytes(data []byte) (*Signature, error) {
	if len(data) < 41 {
		return nil, ErrFormat
	}
	hdr := data[0] & 0xF0
	if hdr != 0x30 && hdr != 0x50 {
		return nil, ErrFormat
	}
	logn := uint(data[0] & 0x0F)
	if !isFIPSLogN(logn) {
		return nil, ErrBadArgument
	}
	return &Signature{data: cloneBytes(data)}, nil
}

// Sign signs a message with system randomness.
func (kp *KeyPair) Sign(message []byte, domain Domain) (*Signature, error) {
	var seed [40]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return nil, ErrRandom
	}
	return kp.SignDeterministic(message, seed[:], domain)
}

// SignDeterministic signs a message with an explicit deterministic seed.
func (kp *KeyPair) SignDeterministic(message []byte, seed []byte, domain Domain) (*Signature, error) {
	if kp == nil || !isFIPSLogN(kp.logn) {
		return nil, ErrBadArgument
	}
	ctx, id, data, err := domainInputs(domain, message)
	if err != nil {
		return nil, err
	}
	sig, err := fndsa.SignCTDeterministic(seed, kp.privateKey, ctx, id, data)
	if err != nil {
		return nil, translateError(err)
	}
	return &Signature{data: sig}, nil
}

// Verify checks a signature against a public key, message, and domain.
func Verify(signature []byte, publicKey []byte, message []byte, domain Domain) error {
	if len(signature) == 0 || len(publicKey) == 0 {
		return ErrFormat
	}
	ctx, id, data, err := domainInputs(domain, message)
	if err != nil {
		return err
	}
	var ok bool
	switch signature[0] & 0xF0 {
	case 0x50:
		ok = fndsa.VerifyCT(publicKey, ctx, id, data, signature)
	case 0x30:
		ok = fndsa.Verify(publicKey, ctx, id, data, signature)
	default:
		return ErrFormat
	}
	if !ok {
		return ErrBadSignature
	}
	return nil
}

// Verify checks this signature against a public key, message, and domain.
func (s *Signature) Verify(publicKey []byte, message []byte, domain Domain) error {
	if s == nil {
		return ErrFormat
	}
	return Verify(s.data, publicKey, message, domain)
}

// Bytes returns a copy of the encoded signature bytes.
func (s *Signature) Bytes() []byte {
	if s == nil {
		return nil
	}
	return cloneBytes(s.data)
}

// Len returns the encoded signature length.
func (s *Signature) Len() int {
	if s == nil {
		return 0
	}
	return len(s.data)
}

func domainInputs(domain Domain, message []byte) (fndsa.DomainContext, crypto.Hash, []byte, error) {
	if err := domain.validate(); err != nil {
		return nil, 0, nil, err
	}
	ctx := fndsa.DomainContext(cloneBytes(domain.context))
	if !domain.prehash {
		return ctx, 0, message, nil
	}
	switch domain.alg {
	case PreHashSHA256:
		return ctx, crypto.SHA256, domain.messageForHash(message), nil
	case PreHashSHA384:
		return ctx, crypto.SHA384, domain.messageForHash(message), nil
	case PreHashSHA512:
		return ctx, crypto.SHA512, domain.messageForHash(message), nil
	case PreHashSHA512_256:
		return ctx, crypto.SHA512_256, domain.messageForHash(message), nil
	case PreHashSHA3_256:
		return ctx, crypto.SHA3_256, domain.messageForHash(message), nil
	case PreHashSHA3_384:
		return ctx, crypto.SHA3_384, domain.messageForHash(message), nil
	case PreHashSHA3_512:
		return ctx, crypto.SHA3_512, domain.messageForHash(message), nil
	default:
		return nil, 0, nil, ErrBadArgument
	}
}
