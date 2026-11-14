// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package blockdag

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/anonymcoin/anonymcoin/anonymbwt"
	"github.com/anonymcoin/anonymcoin/cryptography"
	"github.com/anonymcoin/anonymcoin/transactions"
)

// Header is the ANONYMCOIN block header. Parents reference up to MaxParents
// known blocks; Parents[0] must be the selected parent (highest PathScore,
// ties by smallest hash) and the whole slice must be canonically sorted —
// this makes the header encoding canonical and its hash deterministic.
//
// The serialized form is exactly:
//
//	version(2 LE) | nParents(1) | parents(32B each) | time(8 LE)
//	| difficulty(8 LE) | txMerkle(32) | nonce(8 LE)
//
// The nonce is the final field so miners can patch it in place.
type Header struct {
	Version    uint16
	Parents    []cryptography.Hash
	Time       uint64
	Difficulty uint64
	TxMerkle   cryptography.Hash
	Nonce      uint64
}

// Block couples a header with its transaction list. The first transaction is
// the coinbase.
type Block struct {
	Header *Header
	Txs    []transactions.Tx
}

var (
	ErrTruncatedHeader  = errors.New("block: truncated header")
	ErrTrailingHeader   = errors.New("block: trailing bytes in header")
	ErrNoParents        = errors.New("block: header must reference at least one parent")
	ErrDupParent        = errors.New("block: duplicate parent reference")
	ErrParentOrder      = errors.New("block: parents are not in canonical order")
	ErrTruncatedBlock   = errors.New("block: truncated block encoding")
	ErrTrailingBlock    = errors.New("block: trailing bytes in block encoding")
	ErrBadTxCount       = errors.New("block: transaction count out of bounds")
	ErrNoCoinbase       = errors.New("block: first transaction must be a coinbase")
	ErrCoinbaseNotFirst = errors.New("block: only the first transaction may be a coinbase")
	ErrDupTxID          = errors.New("block: duplicate transaction id")
)

// Encode produces the canonical header encoding.
func (h *Header) Encode() []byte {
	buf := make([]byte, 0, 2+1+32*len(h.Parents)+8+8+32+8)
	var s [8]byte
	binary.LittleEndian.PutUint16(s[:2], h.Version)
	buf = append(buf, s[:2]...)
	buf = append(buf, byte(len(h.Parents)))
	for i := range h.Parents {
		buf = append(buf, h.Parents[i][:]...)
	}
	binary.LittleEndian.PutUint64(s[:8], h.Time)
	buf = append(buf, s[:8]...)
	binary.LittleEndian.PutUint64(s[:8], h.Difficulty)
	buf = append(buf, s[:8]...)
	buf = append(buf, h.TxMerkle[:]...)
	binary.LittleEndian.PutUint64(s[:8], h.Nonce)
	buf = append(buf, s[:8]...)
	return buf
}

// DecodeHeader parses a strict canonical header encoding.
func DecodeHeader(b []byte) (*Header, error) {
	pos := 0
	need := func(n int) error {
		if pos+n > len(b) {
			return ErrTruncatedHeader
		}
		return nil
	}
	h := &Header{}
	if err := need(2); err != nil {
		return nil, err
	}
	h.Version = binary.LittleEndian.Uint16(b[pos:])
	pos += 2
	if err := need(1); err != nil {
		return nil, err
	}
	n := int(b[pos])
	pos++
	if n == 0 {
		return nil, ErrNoParents
	}
	if err := need(32 * n); err != nil {
		return nil, err
	}
	h.Parents = make([]cryptography.Hash, n)
	for i := 0; i < n; i++ {
		copy(h.Parents[i][:], b[pos:])
		pos += 32
	}
	if err := need(8 + 8 + 32 + 8); err != nil {
		return nil, err
	}
	h.Time = binary.LittleEndian.Uint64(b[pos:])
	pos += 8
	h.Difficulty = binary.LittleEndian.Uint64(b[pos:])
	pos += 8
	copy(h.TxMerkle[:], b[pos:])
	pos += 32
	h.Nonce = binary.LittleEndian.Uint64(b[pos:])
	pos += 8
	if pos != len(b) {
		return nil, ErrTrailingHeader
	}
	return h, nil
}

// Hash is the block identity: BLAKE2b-256 of the canonical header encoding.
func (h *Header) Hash() cryptography.Hash {
	return cryptography.Hash256Single(h.Encode())
}

// BlockHash returns the hash of the block's header.
func (b *Block) BlockHash() cryptography.Hash { return b.Header.Hash() }

// EncodeBlock serializes the full block:
//
//	headerLen(4 LE) | header | nTxs(4 LE) | txLen(4 LE) tx ... (first = coinbase)
func EncodeBlock(b *Block) ([]byte, error) {
	hb := b.Header.Encode()
	body := make([][]byte, len(b.Txs))
	total := 4 + len(hb) + 4
	for i := range b.Txs {
		body[i] = b.Txs[i].Encode()
		total += 4 + len(body[i])
	}
	buf := make([]byte, 0, total)
	var s [4]byte
	binary.LittleEndian.PutUint32(s[:4], uint32(len(hb)))
	buf = append(buf, s[:4]...)
	buf = append(buf, hb...)
	binary.LittleEndian.PutUint32(s[:4], uint32(len(b.Txs)))
	buf = append(buf, s[:4]...)
	for i := range body {
		binary.LittleEndian.PutUint32(s[:4], uint32(len(body[i])))
		buf = append(buf, s[:4]...)
		buf = append(buf, body[i]...)
	}
	return buf, nil
}

// DecodeBlock parses a strict block encoding, enforcing the block size limit
// and the transaction count/coinbase structural rules.
func DecodeBlock(data []byte, p ParamsView) (*Block, error) {
	if len(data) > p.MaxBlockSizeLimit() {
		return nil, fmt.Errorf("block: size %d exceeds limit %d", len(data), p.MaxBlockSizeLimit())
	}
	pos := 0
	need := func(n int) error {
		if pos+n > len(data) {
			return ErrTruncatedBlock
		}
		return nil
	}
	if err := need(4); err != nil {
		return nil, err
	}
	hl := int(binary.LittleEndian.Uint32(data[pos:]))
	pos += 4
	if hl < 4 || hl > 4096 {
		return nil, fmt.Errorf("block: implausible header length %d", hl)
	}
	if err := need(hl); err != nil {
		return nil, err
	}
	h, err := DecodeHeader(data[pos : pos+hl])
	if err != nil {
		return nil, err
	}
	pos += hl
	if err := need(4); err != nil {
		return nil, err
	}
	nTxs := int(binary.LittleEndian.Uint32(data[pos:]))
	pos += 4
	if nTxs < 1 || nTxs > (p.MaxBlockSizeLimit()/32) {
		return nil, ErrBadTxCount
	}
	blk := &Block{Header: h, Txs: make([]transactions.Tx, 0, nTxs)}
	seen := make(map[cryptography.Hash]struct{}, nTxs)
	for i := 0; i < nTxs; i++ {
		if err := need(4); err != nil {
			return nil, err
		}
		tl := int(binary.LittleEndian.Uint32(data[pos:]))
		pos += 4
		if tl < 2 || tl > p.MaxTxSizeLimit() {
			return nil, fmt.Errorf("block: transaction %d length %d out of bounds", i, tl)
		}
		if err := need(tl); err != nil {
			return nil, err
		}
		tx, err := transactions.Decode(data[pos : pos+tl])
		if err != nil {
			return nil, fmt.Errorf("block: transaction %d: %w", i, err)
		}
		pos += tl
		if tx.IsCoinbase() != (i == 0) {
			if i == 0 {
				return nil, ErrNoCoinbase
			}
			return nil, ErrCoinbaseNotFirst
		}
		id := tx.ID()
		if _, dup := seen[id]; dup {
			return nil, ErrDupTxID
		}
		seen[id] = struct{}{}
		blk.Txs = append(blk.Txs, *tx)
	}
	if pos != len(data) {
		return nil, ErrTrailingBlock
	}
	return blk, nil
}

// ParamsView is the minimal consensus-parameter accessor used by decoding,
// so the wire layer does not need the whole consensus package.
type ParamsView interface {
	MaxBlockSizeLimit() int
	MaxTxSizeLimit() int
}

// ComputeMerkle builds the binary BLAKE2b merkle tree over transaction IDs
// (odd last node duplicated, Bitcoin-style). An empty list yields the hash of
// the empty byte string.
func ComputeMerkle(ids []cryptography.Hash) cryptography.Hash {
	if len(ids) == 0 {
		return cryptography.Hash256Single(nil)
	}
	level := make([]cryptography.Hash, len(ids))
	copy(level, ids)
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([]cryptography.Hash, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next = append(next, cryptography.Hash256(level[i][:], level[i+1][:]))
		}
		level = next
	}
	return level[0]
}

// TxIDs extracts the transaction id list of a block.
func (b *Block) TxIDs() []cryptography.Hash {
	ids := make([]cryptography.Hash, len(b.Txs))
	for i := range b.Txs {
		ids[i] = b.Txs[i].ID()
	}
	return ids
}

// CoinbaseValue returns the coinbase output total of the block.
func (b *Block) CoinbaseValue() (uint64, error) {
	if len(b.Txs) == 0 || !b.Txs[0].IsCoinbase() {
		return 0, ErrNoCoinbase
	}
	var sum uint64
	for i := range b.Txs[0].Outputs {
		nv := sum + b.Txs[0].Outputs[i].Value
		if nv < sum {
			return 0, transactions.ErrOverflow
		}
		sum = nv
	}
	return sum, nil
}

// HeaderMeetsTarget reports whether the header satisfies its own ANONYMBWT
// proof-of-work target. Used by tests and the miner.
func HeaderMeetsTarget(h *Header) bool {
	target := targetForDifficulty(h.Difficulty)
	d := powDigest(h)
	return powMeetsDigest(d, target)
}

func targetForDifficulty(difficulty uint64) [32]byte {
	return anonymbwt.TargetBytes(difficulty)
}

func powDigest(h *Header) [32]byte {
	return anonymbwt.Digest(h.Encode())
}

func powMeetsDigest(d, target [32]byte) bool {
	return anonymbwt.MeetsTarget(d, target)
}
