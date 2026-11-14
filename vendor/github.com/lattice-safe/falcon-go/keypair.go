package falcon

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/lattice-safe/falcon-go/internal/fndsa"
)

// KeyPair is an FN-DSA private/public key pair.
type KeyPair struct {
	privateKey []byte
	publicKey  []byte
	logn       uint
}

// Generate creates a fresh FN-DSA key pair for logn 9 or 10.
func Generate(logn uint) (*KeyPair, error) {
	if !isFIPSLogN(logn) {
		return nil, ErrBadArgument
	}
	var seed [32]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return nil, ErrRandom
	}
	return GenerateDeterministic(seed[:], logn)
}

// GenerateDeterministic creates an FN-DSA key pair from an explicit seed.
func GenerateDeterministic(seed []byte, logn uint) (*KeyPair, error) {
	if !isFIPSLogN(logn) {
		return nil, ErrBadArgument
	}
	sk, pk, err := fndsa.KeyGenDeterministic(logn, seed)
	if err != nil {
		return nil, translateError(err)
	}
	return &KeyPair{privateKey: sk, publicKey: pk, logn: logn}, nil
}

// FromKeys reconstructs a key pair from encoded private and public key bytes.
func FromKeys(privateKey []byte, publicKey []byte) (*KeyPair, error) {
	if len(privateKey) == 0 || len(publicKey) == 0 {
		return nil, ErrFormat
	}
	logn, err := logNFromPrivate(privateKey)
	if err != nil {
		return nil, err
	}
	pkLogn, err := logNFromPublic(publicKey)
	if err != nil {
		return nil, err
	}
	if logn != pkLogn {
		return nil, ErrFormat
	}
	if len(privateKey) != fndsa.SigningKeySize(logn) || len(publicKey) != fndsa.VerifyingKeySize(logn) {
		return nil, ErrFormat
	}
	recomputed, err := fndsa.MakePublic(privateKey)
	if err != nil {
		return nil, translateError(err)
	}
	if string(recomputed) != string(publicKey) {
		return nil, ErrFormat
	}
	return &KeyPair{privateKey: cloneBytes(privateKey), publicKey: cloneBytes(publicKey), logn: logn}, nil
}

// FromPrivateKey reconstructs a key pair and recomputes its public key.
func FromPrivateKey(privateKey []byte) (*KeyPair, error) {
	logn, err := logNFromPrivate(privateKey)
	if err != nil {
		return nil, err
	}
	if len(privateKey) != fndsa.SigningKeySize(logn) {
		return nil, ErrFormat
	}
	publicKey, err := fndsa.MakePublic(privateKey)
	if err != nil {
		return nil, translateError(err)
	}
	return &KeyPair{privateKey: cloneBytes(privateKey), publicKey: publicKey, logn: logn}, nil
}

// PublicKeyFromPrivate computes the public key for an encoded private key.
func PublicKeyFromPrivate(privateKey []byte) ([]byte, error) {
	kp, err := FromPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return kp.PublicKey(), nil
}

// PrivateKey returns a copy of the encoded private key.
func (kp *KeyPair) PrivateKey() []byte {
	if kp == nil {
		return nil
	}
	return cloneBytes(kp.privateKey)
}

// PublicKey returns a copy of the encoded public key.
func (kp *KeyPair) PublicKey() []byte {
	if kp == nil {
		return nil
	}
	return cloneBytes(kp.publicKey)
}

// LogN returns the logarithmic degree parameter.
func (kp *KeyPair) LogN() uint {
	if kp == nil {
		return 0
	}
	return kp.logn
}

// VariantName returns the FIPS variant name.
func (kp *KeyPair) VariantName() string {
	if kp == nil {
		return "FN-DSA-unknown"
	}
	switch kp.logn {
	case 9:
		return "FN-DSA-512"
	case 10:
		return "FN-DSA-1024"
	default:
		return fmt.Sprintf("FN-DSA-%d", 1<<kp.logn)
	}
}

func isFIPSLogN(logn uint) bool {
	return logn == 9 || logn == 10
}

func logNFromPrivate(privateKey []byte) (uint, error) {
	if len(privateKey) == 0 || (privateKey[0]&0xF0) != 0x50 {
		return 0, ErrFormat
	}
	logn := uint(privateKey[0] & 0x0F)
	if !isFIPSLogN(logn) {
		return 0, ErrBadArgument
	}
	return logn, nil
}

func logNFromPublic(publicKey []byte) (uint, error) {
	if len(publicKey) == 0 || (publicKey[0]&0xF0) != 0x00 {
		return 0, ErrFormat
	}
	logn := uint(publicKey[0] & 0x0F)
	if !isFIPSLogN(logn) {
		return 0, ErrBadArgument
	}
	return logn, nil
}

func translateError(err error) error {
	if err == nil {
		return nil
	}
	return ErrFormat
}
