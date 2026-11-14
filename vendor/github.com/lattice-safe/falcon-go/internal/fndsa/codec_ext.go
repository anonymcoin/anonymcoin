package fndsa

import "errors"

var (
	errTruncatedInput     = errors.New("Truncated input")
	errInvalidCoefficient = errors.New("Invalid coefficient value")
	errNonZeroPaddingBits = errors.New("Non-zero padding bits")
)

var maxSigBits = [11]int{0, 10, 11, 11, 12, 12, 12, 12, 12, 12, 12}

func signatureSizeCT(logn uint) int {
	return 41 + ((maxSigBits[logn]<<logn)+7)>>3
}

func trim_i16_encode(logn uint, f []int16, nbits int, dst []byte) bool {
	n := 1 << logn
	maxv := (int32(1) << (nbits - 1)) - 1
	minv := -maxv
	for i := 0; i < n; i++ {
		v := int32(f[i])
		if v < minv || v > maxv {
			return false
		}
	}
	needed := ((nbits << logn) + 7) >> 3
	if len(dst) < needed {
		return false
	}
	acc := uint32(0)
	accLen := 0
	mask := (uint32(1) << nbits) - 1
	j := 0
	for i := 0; i < n; i++ {
		acc = (acc << nbits) | (uint32(uint16(f[i])) & mask)
		accLen += nbits
		for accLen >= 8 {
			accLen -= 8
			dst[j] = uint8(acc >> accLen)
			j++
		}
	}
	if accLen > 0 {
		dst[j] = uint8(acc << (8 - accLen))
		j++
	}
	for j < len(dst) {
		dst[j] = 0
		j++
	}
	return true
}

func trim_i16_decode(logn uint, src []byte, f []int16, nbits int) (int, error) {
	needed := ((nbits << logn) + 7) >> 3
	if len(src) < needed {
		return 0, errTruncatedInput
	}
	n := 1 << logn
	j := 0
	acc := uint32(0)
	accLen := 0
	mask1 := (uint32(1) << nbits) - 1
	mask2 := uint32(1) << (nbits - 1)
	for i := 0; i < needed; i++ {
		acc = (acc << 8) | uint32(src[i])
		accLen += 8
		for accLen >= nbits {
			accLen -= nbits
			w := (acc >> accLen) & mask1
			w |= -(w & mask2)
			if w == -mask2 {
				return 0, errInvalidCoefficient
			}
			f[j] = int16(int32(w))
			j++
			if j >= n {
				break
			}
		}
	}
	if (acc & ((uint32(1) << accLen) - 1)) != 0 {
		return 0, errNonZeroPaddingBits
	}
	return needed, nil
}
