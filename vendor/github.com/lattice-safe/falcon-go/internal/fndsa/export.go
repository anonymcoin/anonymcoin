package fndsa

import (
	"crypto"
	"errors"
)

// PreparedKey is a decoded signing key suitable for repeated signing.
type PreparedKey struct {
	f         []int8
	g         []int8
	F         []int8
	G         []int8
	logn      uint
	verifying []byte
	hashedVK  [64]byte
}

// KeyGenDeterministic generates a key pair from an explicit seed.
func KeyGenDeterministic(logn uint, seed []byte) (skey []byte, vkey []byte, err error) {
	if logn < 2 || logn > 10 {
		return nil, nil, errors.New("invalid degree")
	}
	n := 1 << logn
	f := make([]int8, n)
	g := make([]int8, n)
	F := make([]int8, n)
	G := make([]int8, n)
	tmp := make([]uint32, 6*n)
	tmpFxr := make([]fxr, 5*(n>>1))
	tmpU16 := make([]uint16, 2*n)
	keygen_inner(logn, seed, f, g, F, G, tmp, tmpFxr, tmpU16)
	skey, vkey = encode_keypair(logn, f, g, F, tmpU16)
	return skey, vkey, nil
}

// MakePublic recomputes the verifying key from a signing key.
func MakePublic(skey []byte) ([]byte, error) {
	f, g, F, _, logn, err := decodeSigningKey(2, 10, skey)
	if err != nil {
		return nil, err
	}
	return makePublicFromDecoded(logn, f, g, F)
}

// SignCTDeterministic signs with an explicit seed and returns Falcon CT format.
func SignCTDeterministic(seed []byte, skey []byte, ctx DomainContext, id crypto.Hash, data []byte) ([]byte, error) {
	prepared, err := PrepareSigningKey(skey)
	if err != nil {
		return nil, err
	}
	return prepared.SignCTDeterministic(seed, ctx, id, data)
}

// PrepareSigningKey decodes a FIPS signing key once for repeated signing.
func PrepareSigningKey(skey []byte) (*PreparedKey, error) {
	f, g, F, G, logn, err := decodeSigningKey(9, 10, skey)
	if err != nil {
		return nil, err
	}
	vrfyKey, err := makePublicFromDecoded(logn, f, g, F)
	if err != nil {
		return nil, err
	}
	return &PreparedKey{
		f:         f,
		g:         g,
		F:         F,
		G:         G,
		logn:      logn,
		verifying: vrfyKey,
		hashedVK:  hash_verifying_key(vrfyKey),
	}, nil
}

// SignCTDeterministic signs with an already decoded key.
func (pk *PreparedKey) SignCTDeterministic(seed []byte, ctx DomainContext, id crypto.Hash, data []byte) ([]byte, error) {
	if pk == nil {
		return nil, errors.New("Invalid signing key")
	}
	n := 1 << pk.logn
	tmpI16 := make([]int16, n)
	tmpU16 := make([]uint16, n)
	tmpF64 := make([]f64, n*9)
	sig := make([]byte, signatureSizeCT(pk.logn))
	err := sign_core(pk.logn, pk.f, pk.g, pk.F, pk.G, pk.hashedVK[:], ctx, id, data, seed, sig, tmpI16, tmpU16, tmpF64, true)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// SignCTWithNonceSampler signs with an explicit nonce and raw sampler stream.
func (pk *PreparedKey) SignCTWithNonceSampler(nonce []byte, samplerStream []byte, ctx DomainContext, id crypto.Hash, data []byte) ([]byte, error) {
	if pk == nil {
		return nil, errors.New("Invalid signing key")
	}
	n := 1 << pk.logn
	tmpI16 := make([]int16, n)
	tmpU16 := make([]uint16, n)
	tmpF64 := make([]f64, n*9)
	sig := make([]byte, signatureSizeCT(pk.logn))
	err := sign_core_ext(pk.logn, pk.f, pk.g, pk.F, pk.G, pk.hashedVK[:], ctx, id, data, nil, nonce, samplerStream, sig, tmpI16, tmpU16, tmpF64, true)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// SignPaddedDeterministic signs with an explicit seed and returns padded compressed format.
func (pk *PreparedKey) SignPaddedDeterministic(seed []byte, ctx DomainContext, id crypto.Hash, data []byte) ([]byte, error) {
	if pk == nil {
		return nil, errors.New("Invalid signing key")
	}
	n := 1 << pk.logn
	tmpI16 := make([]int16, n)
	tmpU16 := make([]uint16, n)
	tmpF64 := make([]f64, n*9)
	sig := make([]byte, SignatureSize(pk.logn))
	err := sign_core(pk.logn, pk.f, pk.g, pk.F, pk.G, pk.hashedVK[:], ctx, id, data, seed, sig, tmpI16, tmpU16, tmpF64, false)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// SignPaddedWithNonceSampler signs with an explicit nonce and returns padded compressed format.
func (pk *PreparedKey) SignPaddedWithNonceSampler(nonce []byte, samplerStream []byte, ctx DomainContext, id crypto.Hash, data []byte) ([]byte, error) {
	if pk == nil {
		return nil, errors.New("Invalid signing key")
	}
	n := 1 << pk.logn
	tmpI16 := make([]int16, n)
	tmpU16 := make([]uint16, n)
	tmpF64 := make([]f64, n*9)
	sig := make([]byte, SignatureSize(pk.logn))
	err := sign_core_ext(pk.logn, pk.f, pk.g, pk.F, pk.G, pk.hashedVK[:], ctx, id, data, nil, nonce, samplerStream, sig, tmpI16, tmpU16, tmpF64, false)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// PublicKey returns a copy of the prepared key's verifying key.
func (pk *PreparedKey) PublicKey() []byte {
	if pk == nil {
		return nil
	}
	out := make([]byte, len(pk.verifying))
	copy(out, pk.verifying)
	return out
}

// LogN returns the logarithmic degree.
func (pk *PreparedKey) LogN() uint {
	if pk == nil {
		return 0
	}
	return pk.logn
}

// VerifyCT verifies a Falcon CT-format signature.
func VerifyCT(vkey []byte, ctx DomainContext, id crypto.Hash, data []byte, sig []byte) bool {
	if len(vkey) == 0 || len(sig) == 0 {
		return false
	}
	head1 := vkey[0]
	head2 := sig[0]
	if (head1&0xF0) != 0x00 || (head2&0xF0) != 0x50 {
		return false
	}
	logn := uint(head1 & 0x0F)
	if logn != uint(head2&0x0F) || logn < 9 || logn > 10 {
		return false
	}
	if len(vkey) != VerifyingKeySize(logn) || len(sig) != signatureSizeCT(logn) {
		return false
	}

	n := 1 << logn
	s2 := make([]int16, n)
	t1 := make([]uint16, n)
	t2 := make([]uint16, n)
	if _, err := modq_decode(logn, vkey[1:], t1); err != nil {
		return false
	}
	if _, err := trim_i16_decode(logn, sig[41:], s2, maxSigBits[logn]); err != nil {
		return false
	}
	nonce := sig[1:41]

	norm2 := signed_poly_sqnorm(logn, s2)

	mqpoly_ext_to_int(logn, t1)
	mqpoly_int_to_ntt(logn, t1)
	mqpoly_signed_to_int(logn, s2, t2)
	mqpoly_int_to_ntt(logn, t2)
	mqpoly_mul_ntt(logn, t1, t2)
	mqpoly_ntt_to_int(logn, t1)

	hvk := hash_verifying_key(vkey)
	if err := hash_to_point(logn, nonce, hvk[:], ctx, id, data, t2); err != nil {
		return false
	}
	mqpoly_ext_to_int(logn, t2)
	mqpoly_sub_int(logn, t2, t1)
	norm1 := mqpoly_sqnorm(logn, t2)

	return norm1 < -norm2 && mqpoly_sqnorm_is_acceptable(logn, norm1+norm2)
}

func decodeSigningKey(lognMin uint, lognMax uint, skey []byte) ([]int8, []int8, []int8, []int8, uint, error) {
	if len(skey) == 0 {
		return nil, nil, nil, nil, 0, errors.New("Invalid private key")
	}
	head := skey[0]
	if (head & 0xF0) != 0x50 {
		return nil, nil, nil, nil, 0, errors.New("Invalid private key")
	}
	logn := uint(head & 0x0F)
	if logn < lognMin || logn > lognMax {
		return nil, nil, nil, nil, 0, errors.New("Invalid private key")
	}
	if len(skey) != SigningKeySize(logn) {
		return nil, nil, nil, nil, 0, errors.New("Invalid private key")
	}

	n := 1 << logn
	f := make([]int8, n)
	g := make([]int8, n)
	F := make([]int8, n)
	off := 1
	j, err := trim_i8_decode(logn, skey[off:], f, nbits_fg(logn))
	if err != nil {
		return nil, nil, nil, nil, 0, err
	}
	off += j
	j, err = trim_i8_decode(logn, skey[off:], g, nbits_fg(logn))
	if err != nil {
		return nil, nil, nil, nil, 0, err
	}
	off += j
	_, err = trim_i8_decode(logn, skey[off:], F, 8)
	if err != nil {
		return nil, nil, nil, nil, 0, err
	}

	G := make([]int8, n)
	t0 := make([]uint16, n)
	t1 := make([]uint16, n)
	mqpoly_small_to_int(logn, g, t0)
	mqpoly_small_to_int(logn, f, t1)
	mqpoly_int_to_ntt(logn, t0)
	mqpoly_int_to_ntt(logn, t1)
	if !mqpoly_div_ntt(logn, t0, t1) {
		return nil, nil, nil, nil, 0, errors.New("Invalid signing key (f not invertible)")
	}
	mqpoly_small_to_int(logn, F, t1)
	mqpoly_int_to_ntt(logn, t1)
	mqpoly_mul_ntt(logn, t1, t0)
	mqpoly_ntt_to_int(logn, t1)
	if !mqpoly_int_to_small(logn, t1, G) {
		return nil, nil, nil, nil, 0, errors.New("Invalid signing key (G is out-of-range)")
	}
	return f, g, F, G, logn, nil
}

func makePublicFromDecoded(logn uint, f []int8, g []int8, F []int8) ([]byte, error) {
	n := 1 << logn
	t0 := make([]uint16, n)
	t1 := make([]uint16, n)

	mqpoly_small_to_int(logn, g, t0)
	mqpoly_small_to_int(logn, f, t1)
	mqpoly_int_to_ntt(logn, t0)
	mqpoly_int_to_ntt(logn, t1)
	if !mqpoly_div_ntt(logn, t0, t1) {
		return nil, errors.New("Invalid signing key (f not invertible)")
	}

	// Validate that G = h*F is encodable as small coefficients. This mirrors
	// the full signing-key validation path used before signing.
	mqpoly_small_to_int(logn, F, t1)
	mqpoly_int_to_ntt(logn, t1)
	mqpoly_mul_ntt(logn, t1, t0)
	mqpoly_ntt_to_int(logn, t1)
	G := make([]int8, n)
	if !mqpoly_int_to_small(logn, t1, G) {
		return nil, errors.New("Invalid signing key (G is out-of-range)")
	}

	mqpoly_ntt_to_int(logn, t0)
	mqpoly_int_to_ext(logn, t0)
	vkey := make([]byte, VerifyingKeySize(logn))
	vkey[0] = byte(logn)
	_ = modq_encode(logn, t0, vkey[1:])
	return vkey, nil
}
