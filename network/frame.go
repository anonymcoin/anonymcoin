// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

// Package network implements ANONYMCOIN's private peer-to-peer layer.
//
// Design (see docs/PROTOCOL.md for the full wire specification):
//
//   - Transport: TLS 1.3 only, with fixed node keys. Each node holds a
//     long-lived Ed25519 certificate (self-signed, pinned by fingerprint)
//     and a Falcon-512 key pair. Peers are configured explicitly; there is
//     no public peer directory and no address gossip.
//   - Handshake: after the TLS handshake both sides exchange a Hello message
//     signed with Falcon-512 (FN-DSA-512, FIPS 206) so node identity stays
//     verifiable against post-quantum adversaries. Fingerprints of the TLS
//     certificate and the Falcon public key are pinned per peer.
//   - Transports: plain TCP, Tor onion services via a SOCKS5 proxy, and I2P
//     via the SAM v3 API. All three share the same framing and handshake.
//   - Framing: magic | version | type | length | payload, hard size limits,
//     strict decoders.
package network

import (
	"errors"
	"fmt"
	"io"
)

// Protocol version of the wire format.
const ProtocolVersion uint16 = 1

// Message types.
const (
	MsgHello    byte = 1 // Falcon-512 signed handshake
	MsgPing     byte = 2
	MsgPong     byte = 3
	MsgBlock    byte = 4 // full serialized block
	MsgTx       byte = 5 // full serialized transaction
	MsgGetRange byte = 6 // request canonical blocks [from, to)
	MsgRange    byte = 7 // response: count + blocks
)

// Frame layout: magic(4) | version(2) | type(1) | reserved(1) | length(4 LE)
// | payload. MaxPayload bounds every message (blocks are <= MaxBlockSize +
// overhead; ranges stream one block per frame inside a Range exchange).
var (
	FrameMagic = [4]byte{'A', 'N', 'W', '1'}
	MaxPayload = 9 * 1024 * 1024

	ErrFrameTooLarge   = errors.New("network: frame payload too large")
	ErrFrameBadMagic   = errors.New("network: bad frame magic")
	ErrFrameBadVersion = errors.New("network: bad frame version")
	ErrFrameTruncated  = errors.New("network: truncated frame")
	ErrUnknownMessage  = errors.New("network: unknown message type")
)

// WriteFrame writes one framed message.
func WriteFrame(w io.Writer, msgType byte, payload []byte) error {
	if len(payload) > MaxPayload {
		return ErrFrameTooLarge
	}
	buf := make([]byte, 12+len(payload))
	copy(buf[0:4], FrameMagic[:])
	buf[4] = byte(ProtocolVersion >> 8)
	buf[5] = byte(ProtocolVersion)
	buf[6] = msgType
	buf[7] = 0
	buf[8] = byte(len(payload))
	buf[9] = byte(len(payload) >> 8)
	buf[10] = byte(len(payload) >> 16)
	buf[11] = byte(len(payload) >> 24)
	copy(buf[12:], payload)
	n, err := w.Write(buf)
	if err != nil {
		return err
	}
	if n != len(buf) {
		return io.ErrShortWrite
	}
	return nil
}

// ReadFrame reads one framed message. maxPayload bounds the accepted size
// (callers pass MaxPayload or a tighter limit).
func ReadFrame(r io.Reader, maxPayload int) (msgType byte, payload []byte, err error) {
	hdr := make([]byte, 12)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, nil, fmt.Errorf("%w: header: %v", ErrFrameTruncated, err)
	}
	if hdr[0] != FrameMagic[0] || hdr[1] != FrameMagic[1] ||
		hdr[2] != FrameMagic[2] || hdr[3] != FrameMagic[3] {
		return 0, nil, ErrFrameBadMagic
	}
	version := uint16(hdr[4])<<8 | uint16(hdr[5])
	if version != ProtocolVersion {
		return 0, nil, fmt.Errorf("%w: %d", ErrFrameBadVersion, version)
	}
	msgType = hdr[6]
	length := int(hdr[8]) | int(hdr[9])<<8 | int(hdr[10])<<16 | int(hdr[11])<<24
	if length < 0 || length > maxPayload {
		return 0, nil, ErrFrameTooLarge
	}
	payload = make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, fmt.Errorf("%w: payload: %v", ErrFrameTruncated, err)
	}
	return msgType, payload, nil
}
