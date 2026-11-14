package falcon

import (
	"crypto/rand"
	"io"

	"github.com/lattice-safe/falcon-go/internal/fndsa"
)

// ExpandedKey is a reusable signing key handle.
//
// The current Go backend stores a decoded signing key for repeated signatures.
// Future versions can add the full LDL-tree precomputation behind this type
// without changing callers.
type ExpandedKey struct {
	prepared *fndsa.PreparedKey
}

// Expand returns a reusable signing handle for this key pair.
func (kp *KeyPair) Expand() (*ExpandedKey, error) {
	if kp == nil {
		return nil, ErrBadArgument
	}
	prepared, err := fndsa.PrepareSigningKey(kp.privateKey)
	if err != nil {
		return nil, translateError(err)
	}
	return &ExpandedKey{prepared: prepared}, nil
}

// Sign signs a message with system randomness.
func (ek *ExpandedKey) Sign(message []byte, domain Domain) (*Signature, error) {
	if ek == nil || ek.prepared == nil {
		return nil, ErrBadArgument
	}
	var seed [40]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return nil, ErrRandom
	}
	return ek.SignDeterministic(message, seed[:], domain)
}

// SignDeterministic signs a message with an explicit deterministic seed.
func (ek *ExpandedKey) SignDeterministic(message []byte, seed []byte, domain Domain) (*Signature, error) {
	if ek == nil || ek.prepared == nil {
		return nil, ErrBadArgument
	}
	ctx, id, data, err := domainInputs(domain, message)
	if err != nil {
		return nil, err
	}
	sig, err := ek.prepared.SignCTDeterministic(seed, ctx, id, data)
	if err != nil {
		return nil, translateError(err)
	}
	return &Signature{data: sig}, nil
}

// PublicKey returns a copy of the encoded public key.
func (ek *ExpandedKey) PublicKey() []byte {
	if ek == nil || ek.prepared == nil {
		return nil
	}
	return ek.prepared.PublicKey()
}

// LogN returns the logarithmic degree parameter.
func (ek *ExpandedKey) LogN() uint {
	if ek == nil || ek.prepared == nil {
		return 0
	}
	return ek.prepared.LogN()
}
