package falcon

import "github.com/lattice-safe/falcon-go/internal/fndsa"

// PrivateKeySize returns the encoded private key size for a FIPS logn.
func PrivateKeySize(logn uint) (int, error) {
	if !isFIPSLogN(logn) {
		return 0, ErrBadArgument
	}
	return fndsa.SigningKeySize(logn), nil
}

// PublicKeySize returns the encoded public key size for a FIPS logn.
func PublicKeySize(logn uint) (int, error) {
	if !isFIPSLogN(logn) {
		return 0, ErrBadArgument
	}
	return fndsa.VerifyingKeySize(logn), nil
}

// SignatureSize returns the CT-format signature size for a FIPS logn.
func SignatureSize(logn uint) (int, error) {
	if !isFIPSLogN(logn) {
		return 0, ErrBadArgument
	}
	// CT size = 41 + ceil(maxSigBits[logn] * n / 8)
	maxBits := [11]int{0, 10, 11, 11, 12, 12, 12, 12, 12, 12, 12}
	return 41 + ((maxBits[logn]<<logn)+7)>>3, nil
}

// PaddedSignatureSize returns the FIPS/Rust padded signature size.
func PaddedSignatureSize(logn uint) (int, error) {
	if !isFIPSLogN(logn) {
		return 0, ErrBadArgument
	}
	return fndsa.SignatureSize(logn), nil
}
