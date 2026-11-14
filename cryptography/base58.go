// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package cryptography

import (
	"errors"
	"math/big"
)

// base58 alphabet (Bitcoin-style, no 0/O/I/l characters).
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var decodeBase58 [128]int8

func init() {
	for i := range decodeBase58 {
		decodeBase58[i] = -1
	}
	for i := 0; i < len(base58Alphabet); i++ {
		decodeBase58[base58Alphabet[i]] = int8(i)
	}
}

// Base58Encode encodes b in Base58.
func Base58Encode(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	num := new(big.Int).SetBytes(b)
	radix := big.NewInt(58)
	mod := new(big.Int)
	out := make([]byte, 0, len(b)*137/100+1)
	for num.Sign() > 0 {
		num.DivMod(num, radix, mod)
		out = append(out, base58Alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		out = append(out, base58Alphabet[0])
	}
	// reverse
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// Base58Decode decodes a Base58 string. It rejects embedded characters that
// are not part of the alphabet.
func Base58Decode(s string) ([]byte, error) {
	num := new(big.Int)
	radix := big.NewInt(58)
	for i := 0; i < len(s); i++ {
		v := int8(-1)
		if s[i] < 128 {
			v = decodeBase58[s[i]]
		}
		if v < 0 {
			return nil, errors.New("base58: invalid character")
		}
		num.Mul(num, radix)
		num.Add(num, big.NewInt(int64(v)))
	}
	b := num.Bytes()
	// leading zeros
	zeros := 0
	for zeros < len(s) && s[zeros] == base58Alphabet[0] {
		zeros++
	}
	out := make([]byte, zeros+len(b))
	copy(out[zeros:], b)
	return out, nil
}

// Address version byte for single-signature pay-to-public-key-hash outputs.
const AddrVersion byte = 0x1d

// Base58Check appends a 4-byte BLAKE2b checksum (first 4 bytes of the double
// hash) and encodes in Base58.
func Base58Check(version byte, payload []byte) string {
	body := append([]byte{version}, payload...)
	chk := checksum(body)
	full := append(body, chk[:]...)
	return Base58Encode(full)
}

// Base58CheckDecode decodes a Base58Check string and returns the version byte
// and payload, verifying the checksum.
func Base58CheckDecode(s string) (byte, []byte, error) {
	full, err := Base58Decode(s)
	if err != nil {
		return 0, nil, err
	}
	if len(full) < 6 {
		return 0, nil, errors.New("base58check: too short")
	}
	body := full[:len(full)-4]
	var want [4]byte
	copy(want[:], full[len(full)-4:])
	if checksum(body) != want {
		return 0, nil, errors.New("base58check: bad checksum")
	}
	return body[0], body[1:], nil
}

func checksum(body []byte) [4]byte {
	inner := Hash256Single(body)
	h := Hash256Single(inner[:])
	var out [4]byte
	copy(out[:], h[:4])
	return out
}
