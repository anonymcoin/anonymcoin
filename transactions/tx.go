// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

// Package transactions defines the ANONYMCOIN transaction format: a compact
// single-signature UTXO model with Ed25519 signatures, cross-network replay
// protection via the chain tag, and strict deterministic encoding.
package transactions

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/anonymcoin/anonymcoin/consensus"
	"github.com/anonymcoin/anonymcoin/cryptography"
)

// TxIn references a previous output and carries the spending signature.
type TxIn struct {
	PrevTx    cryptography.Hash
	PrevIndex uint32
	PubKey    [ed25519.PublicKeySize]byte
	Sig       [ed25519.SignatureSize]byte
}

// TxOut is a payable output.
type TxOut struct {
	Value      uint64
	PubKeyHash cryptography.Hash160
}

// Tx is a signed transaction. A Tx with zero Inputs is a coinbase; coinbases
// are constructed by block production, never relayed as regular transactions.
// Aux carries up to MaxAuxBytes of coinbase-only auxiliary data (it makes the
// coinbase txid unique per block).
type Tx struct {
	Version  uint16
	Inputs   []TxIn
	Outputs  []TxOut
	LockTime uint64
	Aux      []byte
}

// Errors returned by decoding and validation.
var (
	ErrTruncated   = errors.New("tx: truncated encoding")
	ErrTrailing    = errors.New("tx: trailing bytes after transaction")
	ErrNoInputs    = errors.New("tx: regular transaction must have at least one input")
	ErrNoOutputs   = errors.New("tx: transaction must have at least one output")
	ErrTooManyIns  = errors.New("tx: too many inputs")
	ErrTooManyOuts = errors.New("tx: too many outputs")
	ErrOverflow    = errors.New("tx: output value overflow")
	ErrDust        = errors.New("tx: output below dust limit")
	ErrAuxInTx     = errors.New("tx: auxiliary payload is only allowed on coinbases")
)

const (
	sigPubKeyOffset = 0
	sigSigOffset    = ed25519.PublicKeySize
)

// txDigestDomain separates transaction signatures from every other protocol
// hash in the system (domain separation) and binds them to the ANONYMCOIN
// transaction digest format. Signatures computed for any other purpose, or
// under any future digest revision, can never be replayed as transaction
// signatures.
var txDigestDomain = []byte("ANONYMCOIN/TX-DIGEST/1")

// Encode produces the canonical deterministic serialization:
//
//	version(2) | nIn(4) | inputs ( prevTx(32) prevIndex(4) pubkey(32) sig(64) )
//	           | nOut(4) | outputs ( value(8) pkh(20) ) | lockTime(8) | auxLen(2) | aux
func (t *Tx) Encode() []byte {
	auxLen := len(t.Aux)
	size := 2 + 4 + len(t.Inputs)*(32+4+32+64) + 4 + len(t.Outputs)*(8+20) + 8 + 2 + auxLen
	buf := make([]byte, 0, size)
	var scratch [8]byte

	binary.LittleEndian.PutUint16(scratch[:2], t.Version)
	buf = append(buf, scratch[:2]...)
	binary.LittleEndian.PutUint32(scratch[:4], uint32(len(t.Inputs)))
	buf = append(buf, scratch[:4]...)
	for i := range t.Inputs {
		in := &t.Inputs[i]
		buf = append(buf, in.PrevTx[:]...)
		binary.LittleEndian.PutUint32(scratch[:4], in.PrevIndex)
		buf = append(buf, scratch[:4]...)
		buf = append(buf, in.PubKey[:]...)
		buf = append(buf, in.Sig[:]...)
	}
	binary.LittleEndian.PutUint32(scratch[:4], uint32(len(t.Outputs)))
	buf = append(buf, scratch[:4]...)
	for i := range t.Outputs {
		out := &t.Outputs[i]
		binary.LittleEndian.PutUint64(scratch[:8], out.Value)
		buf = append(buf, scratch[:8]...)
		buf = append(buf, out.PubKeyHash[:]...)
	}
	binary.LittleEndian.PutUint64(scratch[:8], t.LockTime)
	buf = append(buf, scratch[:8]...)
	binary.LittleEndian.PutUint16(scratch[:2], uint16(auxLen))
	buf = append(buf, scratch[:2]...)
	buf = append(buf, t.Aux...)
	return buf
}

// Decode parses a strict canonical encoding. Trailing bytes are rejected.
func Decode(b []byte) (*Tx, error) {
	r := reader{b: b}
	t := &Tx{}
	var err error
	if t.Version, err = r.u16(); err != nil {
		return nil, err
	}
	nIn, err := r.u32()
	if err != nil {
		return nil, err
	}
	// Allocation and work bounds: fixed-size field reads fail fast on a
	// truncated buffer, and slice capacities are capped at 1024. Real count
	// limits are enforced against Params during structural validation.
	if nIn > 1<<20 {
		return nil, ErrTooManyIns
	}
	t.Inputs = make([]TxIn, 0, min64(uint64(nIn), 1024))
	for i := uint32(0); i < nIn; i++ {
		in := TxIn{}
		if err := r.bytes(in.PrevTx[:]); err != nil {
			return nil, err
		}
		if in.PrevIndex, err = r.u32(); err != nil {
			return nil, err
		}
		if err := r.bytes(in.PubKey[:]); err != nil {
			return nil, err
		}
		if err := r.bytes(in.Sig[:]); err != nil {
			return nil, err
		}
		t.Inputs = append(t.Inputs, in)
	}
	nOut, err := r.u32()
	if err != nil {
		return nil, err
	}
	t.Outputs = make([]TxOut, 0, min64(uint64(nOut), 1024))
	for i := uint32(0); i < nOut; i++ {
		out := TxOut{}
		if out.Value, err = r.u64(); err != nil {
			return nil, err
		}
		if err := r.bytes(out.PubKeyHash[:]); err != nil {
			return nil, err
		}
		t.Outputs = append(t.Outputs, out)
	}
	if t.LockTime, err = r.u64(); err != nil {
		return nil, err
	}
	auxLen, err := r.u16()
	if err != nil {
		return nil, err
	}
	if auxLen > 0 {
		t.Aux = make([]byte, auxLen)
		if err := r.bytes(t.Aux); err != nil {
			return nil, err
		}
	}
	if r.pos != len(b) {
		return nil, ErrTrailing
	}
	return t, nil
}

type reader struct {
	b   []byte
	pos int
}

func (r *reader) bytes(dst []byte) error {
	if r.pos+len(dst) > len(r.b) {
		return ErrTruncated
	}
	copy(dst, r.b[r.pos:r.pos+len(dst)])
	r.pos += len(dst)
	return nil
}

func (r *reader) u16() (uint16, error) {
	var b [2]byte
	if err := r.bytes(b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b[:]), nil
}

func (r *reader) u32() (uint32, error) {
	var b [4]byte
	if err := r.bytes(b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

func (r *reader) u64() (uint64, error) {
	var b [8]byte
	if err := r.bytes(b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b[:]), nil
}

func min64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

// IsCoinbase reports whether t is structured as a coinbase (no inputs).
func (t *Tx) IsCoinbase() bool { return len(t.Inputs) == 0 }

// ID is the full transaction identifier: BLAKE2b-256 of the canonical
// encoding including signatures.
func (t *Tx) ID() cryptography.Hash {
	return cryptography.Hash256Single(t.Encode())
}

// Digest computes the message that must be signed by every input:
//
//	BLAKE2b-256( "ANONYMCOIN/TX-DIGEST/1" || chainTag(4) || encoding-with-
//	             signature-fields-zeroed )
//
// Replay protection has two layers:
//
//   - The domain string guarantees the digest cannot collide with any other
//     BLAKE2b-256 usage in the protocol (cross-protocol signature replay).
//   - The chain tag is derived from the genesis hash of the specific
//     ANONYMCOIN network (mainnet, testnet, private deployments), so signed
//     transactions can never be replayed across independent networks even
//     when every other consensus parameter matches.
func (t *Tx) Digest(chainTag [4]byte) cryptography.Hash {
	body := t.Encode()
	// zero signature fields in the encoded copy
	off := 2 + 4
	for range t.Inputs {
		copy(body[off+32+4+32:off+32+4+32+64], make([]byte, 64))
		off += 32 + 4 + 32 + 64
	}
	return cryptography.Hash256(txDigestDomain, chainTag[:], body)
}

// Fee computes input sum minus output sum given the referenced output values.
// It returns an error if any referenced value is unknown (caller must supply
// every input's value in input order) or if outputs exceed inputs.
func (t *Tx) Fee(inputValues []uint64) (uint64, error) {
	if len(inputValues) != len(t.Inputs) {
		return 0, fmt.Errorf("tx: fee needs %d input values, got %d", len(t.Inputs), len(inputValues))
	}
	var in, out uint64
	for _, v := range inputValues {
		nv := in + v
		if nv < in {
			return 0, ErrOverflow
		}
		in = nv
	}
	for i := range t.Outputs {
		nv := out + t.Outputs[i].Value
		if nv < out {
			return 0, ErrOverflow
		}
		out = nv
	}
	if out > in {
		return 0, ErrOverflow
	}
	return in - out, nil
}

// CheckStructure enforces static, state-independent rules:
//   - size bound, input/output count bounds, aux bound
//   - every output above dust, every output value within MaxMoney
//   - no duplicate inputs (prevents trivial double-spend inside one tx)
//   - coinbase structure rules (aux only on coinbase)
//
// Signature and UTXO checks live in validation (state-dependent).
func CheckStructure(t *Tx, p *consensus.Params, chainTag [4]byte) error {
	if len(t.Encode()) > p.MaxTxSize {
		return fmt.Errorf("tx: size %d exceeds limit %d", len(t.Encode()), p.MaxTxSize)
	}
	if len(t.Outputs) == 0 && !t.IsCoinbase() {
		return ErrNoOutputs
	}
	if len(t.Outputs) > p.MaxTxOutputs {
		return ErrTooManyOuts
	}
	if len(t.Aux) > p.MaxAuxBytes {
		return fmt.Errorf("tx: aux payload %d exceeds %d", len(t.Aux), p.MaxAuxBytes)
	}
	if !t.IsCoinbase() {
		if len(t.Inputs) == 0 {
			return ErrNoInputs
		}
		if len(t.Inputs) > p.MaxTxInputs {
			return ErrTooManyIns
		}
		if len(t.Aux) > 0 {
			return ErrAuxInTx
		}
	}
	seen := make(map[[36]byte]struct{}, len(t.Inputs))
	for i := range t.Inputs {
		var k [36]byte
		copy(k[:32], t.Inputs[i].PrevTx[:])
		binary.LittleEndian.PutUint32(k[32:], t.Inputs[i].PrevIndex)
		if _, dup := seen[k]; dup {
			return fmt.Errorf("tx: duplicate input %d", i)
		}
		seen[k] = struct{}{}
	}
	var total uint64
	for i := range t.Outputs {
		o := t.Outputs[i].Value
		if o > p.MaxMoney {
			return fmt.Errorf("tx: output %d value exceeds MaxMoney", i)
		}
		// Coinbase outputs are minted by consensus and exempt from the dust
		// rule (a canonical second with no owed emission produces a
		// zero-value claim).
		if !t.IsCoinbase() && o < p.DustLimit {
			return fmt.Errorf("tx: output %d below dust limit", i)
		}
		nv := total + o
		if nv < total {
			return ErrOverflow
		}
		total = nv
	}
	// Verify every signature against the digest (static check: the signature
	// binds pubkey and outputs; UTXO existence is checked separately).
	d := t.Digest(chainTag)
	for i := range t.Inputs {
		in := &t.Inputs[i]
		if !ed25519.Verify(ed25519.PublicKey(in.PubKey[:]), d[:], in.Sig[:]) {
			return fmt.Errorf("tx: invalid signature on input %d", i)
		}
	}
	return nil
}
