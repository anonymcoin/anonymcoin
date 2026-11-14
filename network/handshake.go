// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package network

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/anonymcoin/anonymcoin/cryptography"
)

// Hello is the post-TLS handshake message, signed with Falcon-512. It binds
// the sender's Falcon public key to this specific TLS session (nonce pair)
// and announces the sender's canonical tip for synchronization.
//
// Payload layout: magic(4) | version(2) | falconPubLen(2) | falconPub |
// nonce(32) | tipIndex(8) | tipScore(8) | tipHash(32) | sigLen(2) | sig
//
// The signature covers the full payload with the sigLen/sig fields zeroed.
type Hello struct {
	Magic     [4]byte
	Version   uint16
	FalconPub []byte
	Nonce     [32]byte
	TipIndex  uint64
	TipScore  uint64
	TipHash   [32]byte
	Sig       []byte
}

// NetMagic derives the wire magic from the genesis hash (first four bytes).
func NetMagic(genesis cryptography.Hash) [4]byte {
	var m [4]byte
	copy(m[:], genesis[:4])
	return m
}

// Encode serializes the Hello with its Falcon signature.
func (h *Hello) Encode() ([]byte, error) {
	body := make([]byte, 0, 4+2+2+len(h.FalconPub)+32+8+8+32+2+len(h.Sig))
	body = append(body, h.Magic[:]...)
	body = append(body, byte(h.Version>>8), byte(h.Version))
	body = append(body, byte(len(h.FalconPub)>>8), byte(len(h.FalconPub)))
	body = append(body, h.FalconPub...)
	body = append(body, h.Nonce[:]...)
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], h.TipIndex)
	body = append(body, e[:]...)
	binary.BigEndian.PutUint64(e[:], h.TipScore)
	body = append(body, e[:]...)
	body = append(body, h.TipHash[:]...)
	body = append(body, byte(len(h.Sig)>>8), byte(len(h.Sig)))
	body = append(body, h.Sig...)
	return body, nil
}

// DecodeHello parses a strict Hello encoding.
func DecodeHello(b []byte) (*Hello, error) {
	pos := 0
	need := func(n int) error {
		if pos+n > len(b) {
			return errors.New("hello: truncated")
		}
		return nil
	}
	h := &Hello{}
	if err := need(4 + 2 + 2); err != nil {
		return nil, err
	}
	copy(h.Magic[:], b[pos:])
	pos += 4
	h.Version = uint16(b[pos])<<8 | uint16(b[pos+1])
	pos += 2
	pubLen := int(b[pos])<<8 | int(b[pos+1])
	pos += 2
	if pubLen != 897 { // Falcon-512 encoded public key size
		return nil, fmt.Errorf("hello: unexpected falcon public key size %d", pubLen)
	}
	if err := need(pubLen + 32 + 8 + 8 + 32 + 2); err != nil {
		return nil, err
	}
	h.FalconPub = make([]byte, pubLen)
	copy(h.FalconPub, b[pos:])
	pos += pubLen
	copy(h.Nonce[:], b[pos:])
	pos += 32
	h.TipIndex = binary.BigEndian.Uint64(b[pos:])
	pos += 8
	h.TipScore = binary.BigEndian.Uint64(b[pos:])
	pos += 8
	copy(h.TipHash[:], b[pos:])
	pos += 32
	sigLen := int(b[pos])<<8 | int(b[pos+1])
	pos += 2
	if err := need(sigLen); err != nil {
		return nil, err
	}
	h.Sig = make([]byte, sigLen)
	copy(h.Sig, b[pos:])
	pos += sigLen
	if pos != len(b) {
		return nil, errors.New("hello: trailing bytes")
	}
	return h, nil
}

// Unsigned returns the payload with signature fields zeroed — the exact
// bytes the Falcon-512 signature covers.
func (h *Hello) Unsigned() ([]byte, error) {
	c := *h
	c.Sig = nil
	body, err := c.Encode()
	if err != nil {
		return nil, err
	}
	// append the zeroed sigLen field so layout matches the signed form
	body = append(body, 0, 0)
	return body, nil
}

// SignHello fills h.Sig with a Falcon-512 signature over the unsigned body.
func SignHello(h *Hello, falconPriv []byte) error {
	body, err := h.Unsigned()
	if err != nil {
		return err
	}
	sig, err := cryptography.FalconSign(falconPriv, body)
	if err != nil {
		return err
	}
	h.Sig = sig
	return nil
}

// VerifyHello checks the Falcon-512 signature over the unsigned body under
// h.FalconPub.
func VerifyHello(h *Hello) bool {
	body, err := h.Unsigned()
	if err != nil {
		return false
	}
	return cryptography.FalconVerify(h.FalconPub, body, h.Sig)
}
