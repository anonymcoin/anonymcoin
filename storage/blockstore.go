// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

// Package storage implements the persistent block store: a self-describing,
// append-only, CRC-protected file of accepted blocks in acceptance order.
//
// Format per record:
//
//	magic(4) | length(4 LE) | crc32(4 LE) | payload(block encoding)
//
// The index (hash -> offset) is rebuilt by scanning the file on open, which
// also validates every record; a torn tail (partial write) is truncated.
// Replay of the file in order deterministically rebuilds the whole DAG
// state, so no separate chain-state database is required (see
// BLOCKDAG_ARCHITECTURE.md, "Storage model").
package storage

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"sync"

	"github.com/anonymcoin/anonymcoin/blockdag"
	"github.com/anonymcoin/anonymcoin/cryptography"
)

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

var (
	storeMagic = [4]byte{'A', 'N', 'M', '1'}

	ErrCorrupt      = errors.New("storage: corrupt record")
	ErrUnknownBlock = errors.New("storage: unknown block")
)

// BlockStore persists accepted blocks. Safe for concurrent use.
type BlockStore struct {
	mu     sync.RWMutex
	path   string
	f      *os.File
	index  map[cryptography.Hash]int64
	order  []cryptography.Hash
	syncOn bool
}

// Open opens (or creates) a block store and rebuilds the in-memory index by
// scanning and CRC-checking every record. A torn trailing record is
// truncated to the last good offset.
func Open(path string, p blockdag.ParamsView, syncOn bool) (*BlockStore, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("storage: open: %w", err)
	}
	bs := &BlockStore{path: path, f: f, index: make(map[cryptography.Hash]int64), syncOn: syncOn}
	if err := bs.scan(p); err != nil {
		f.Close()
		return nil, err
	}
	return bs, nil
}

func (bs *BlockStore) scan(p blockdag.ParamsView) error {
	st, err := bs.f.Stat()
	if err != nil {
		return err
	}
	var good int64 = 0
	buf := make([]byte, 4)
	for {
		off := good
		if _, err := bs.f.ReadAt(buf, off); err != nil {
			break // EOF: clean end
		}
		if !bytesEqual(buf, storeMagic[:]) {
			break // torn tail or foreign data: stop here
		}
		var hdr [8]byte
		if _, err := bs.f.ReadAt(hdr[:], off+4); err != nil {
			break
		}
		length := binary.LittleEndian.Uint32(hdr[0:4])
		if length > uint32(p.MaxBlockSizeLimit())*2+4096 {
			break // implausible record
		}
		payload := make([]byte, length)
		if _, err := bs.f.ReadAt(payload, off+12); err != nil {
			break // torn tail
		}
		want := binary.LittleEndian.Uint32(hdr[4:8])
		if crc32.ChecksumIEEE(payload) != want {
			break // torn tail
		}
		blk, err := blockdag.DecodeBlock(payload, p)
		if err != nil {
			break // undecodable record: stop the index here
		}
		h := blk.BlockHash()
		bs.index[h] = off
		bs.order = append(bs.order, h)
		good = off + 12 + int64(length)
	}
	if good < st.Size() {
		// Truncate torn tail.
		if err := bs.f.Truncate(good); err != nil {
			return fmt.Errorf("storage: truncate: %w", err)
		}
	}
	if _, err := bs.f.Seek(good, io.SeekStart); err != nil {
		return err
	}
	return nil
}

// Append persists a block. Duplicate appends of a known hash are no-ops.
func (bs *BlockStore) Append(b *blockdag.Block) error {
	payload, err := blockdag.EncodeBlock(b)
	if err != nil {
		return fmt.Errorf("storage: encode: %w", err)
	}
	rec := make([]byte, 0, 12+len(payload))
	rec = append(rec, storeMagic[:]...)
	var hdr [8]byte
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(len(payload)))
	binary.LittleEndian.PutUint32(hdr[4:8], crc32.ChecksumIEEE(payload))
	rec = append(rec, hdr[:]...)
	rec = append(rec, payload...)

	bs.mu.Lock()
	defer bs.mu.Unlock()
	h := b.BlockHash()
	if _, ok := bs.index[h]; ok {
		return nil
	}
	off, err := bs.f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	if _, err := bs.f.Write(rec); err != nil {
		return fmt.Errorf("storage: write: %w", err)
	}
	if bs.syncOn {
		if err := bs.f.Sync(); err != nil {
			return fmt.Errorf("storage: sync: %w", err)
		}
	}
	bs.index[h] = off
	bs.order = append(bs.order, h)
	return nil
}

// Has reports whether the hash is stored.
func (bs *BlockStore) Has(h cryptography.Hash) bool {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	_, ok := bs.index[h]
	return ok
}

// Count returns the number of stored blocks.
func (bs *BlockStore) Count() int {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return len(bs.order)
}

// Get loads a block by hash.
func (bs *BlockStore) Get(h cryptography.Hash, p blockdag.ParamsView) (*blockdag.Block, error) {
	bs.mu.RLock()
	off, ok := bs.index[h]
	bs.mu.RUnlock()
	if !ok {
		return nil, ErrUnknownBlock
	}
	var hdr [8]byte
	if _, err := bs.f.ReadAt(hdr[:], off+4); err != nil {
		return nil, err
	}
	length := binary.LittleEndian.Uint32(hdr[0:4])
	payload := make([]byte, length)
	if _, err := bs.f.ReadAt(payload, off+12); err != nil {
		return nil, err
	}
	if crc32.ChecksumIEEE(payload) != binary.LittleEndian.Uint32(hdr[4:8]) {
		return nil, ErrCorrupt
	}
	return blockdag.DecodeBlock(payload, p)
}

// ForEach replays stored blocks in acceptance order.
func (bs *BlockStore) ForEach(p blockdag.ParamsView, cb func(*blockdag.Block) error) error {
	bs.mu.RLock()
	order := make([]cryptography.Hash, len(bs.order))
	copy(order, bs.order)
	bs.mu.RUnlock()
	for _, h := range order {
		blk, err := bs.Get(h, p)
		if err != nil {
			return err
		}
		if err := cb(blk); err != nil {
			return err
		}
	}
	return nil
}

// Path returns the backing file path.
func (bs *BlockStore) Path() string { return bs.path }

// Close flushes and closes the file.
func (bs *BlockStore) Close() error {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	return bs.f.Close()
}
