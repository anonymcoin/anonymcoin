// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

// Package blockdag implements the ANONDAG-1 consensus engine: the heart of
// ANONYMCOIN.
//
// ANONDAG-1 in one paragraph: blocks may reference 1..MaxParents known
// parents, forming a directed acyclic blockDAG rooted at the genesis. Every
// block carries cumulative PathScore(B) = work(B) + max PathScore(parents).
// The canonical order is the deterministic priority-topological order with
// priority key (PathScore ascending, hash ascending): equivalently, repeat-
// edly emit the ready block (all parents emitted) with the smallest key.
// Because PathScore strictly increases along every parent edge, ancestors
// always precede descendants automatically, and the order of incomparable
// blocks depends only on their own keys — never on arrival order. New
// blocks are inserted at their comparator position inside a bounded
// unfinalized window (FinalizedDepth); an insertion that would land before
// the finalized prefix (a "late" block) is rejected. Older blocks are
// immutable. Conflicting transactions (double spends across parallel
// branches) are resolved deterministically by canonical order: the first
// application consumes the UTXO, later conflicting transactions are skipped
// and their fees vanish (deflationary). All of it is integer-only.
//
// See CONSENSUS.md at the repository root for the full specification and
// BLOCKDAG_ARCHITECTURE.md for the engine internals.
package blockdag

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/anonymcoin/anonymcoin/consensus"
	"github.com/anonymcoin/anonymcoin/cryptography"
)

// Sentinel errors returned by AcceptBlock. Use errors.Is to classify.
var (
	ErrDuplicate      = errors.New("blockdag: block already known")
	ErrKnownInvalid   = errors.New("blockdag: block previously rejected as invalid")
	ErrOrphan         = errors.New("blockdag: missing parent(s), parked as orphan")
	ErrLateBlock      = errors.New("blockdag: block would reorder finalized history")
	ErrBadPoW         = errors.New("blockdag: proof-of-work does not meet target")
	ErrBadDifficulty  = errors.New("blockdag: header difficulty != expected difficulty")
	ErrBadTimestamp   = errors.New("blockdag: block timestamp violates virtual-time rules")
	ErrFutureBlock    = errors.New("blockdag: block timestamp too far in the future (local policy)")
	ErrInvalidBlock   = errors.New("blockdag: block invalid")
	ErrNoTips         = errors.New("blockdag: no tips")
	ErrUnknownBlock   = errors.New("blockdag: unknown block")
	ErrOrphanOverflow = errors.New("blockdag: orphan pool full")
)

// blockNode is the in-memory representation of one accepted block.
type blockNode struct {
	header     *Header
	hash       cryptography.Hash
	block      *Block // nil once finalized (header and metadata are kept)
	parents    []*blockNode
	pathScore  uint64
	vt         uint64
	diff       uint64
	childCount int
	undo       *UndoRecord // non-nil while the node is inside the unfinalized window
}

// Hooks let the embedding application react to consensus events. All hooks
// are invoked while the DAG write lock is held; hooks must not call back
// into the DAG.
type Hooks struct {
	// OnAccepted fires after a block is accepted and applied.
	OnAccepted func(b *Block, canonicalIndex int64)
	// OnReorg fires when a block is inserted before the canonical tip
	// (bounded window reorganization).
	OnReorg func()
}

// DAG is the consensus engine. It is safe for concurrent use.
type DAG struct {
	p        *consensus.Params
	chainTag [4]byte

	mu             sync.RWMutex
	nodes          map[cryptography.Hash]*blockNode
	canonical      []*blockNode
	finalizedCount int
	maxFinScore    uint64
	minFinHash     cryptography.Hash // smallest hash among finalized blocks at maxFinScore

	tips                map[cryptography.Hash]*blockNode
	orphans             map[cryptography.Hash]*orphanEntry
	orphansByParent     map[cryptography.Hash]map[cryptography.Hash]struct{}
	invalid             map[cryptography.Hash]struct{}
	lastOrphanSweepUnix uint64

	utxo          *UTXOSet
	recentlySpent map[UTXOKey]struct{}
	issued        uint64
	lastMTP       uint64
	yearIndex     uint64 // canonical year of the current supply snapshot
	yearBase      uint64 // circulating supply snapshot at the start of yearIndex

	hooks Hooks
}

type orphanEntry struct {
	block   *Block
	hash    cryptography.Hash
	missing []cryptography.Hash
	addedAt time.Time
}

// New creates a DAG seeded with the deterministic genesis for the params.
func New(p *consensus.Params, hooks Hooks) (*DAG, error) {
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("blockdag: params: %w", err)
	}
	gen := Genesis(p)
	genHash := gen.Header.Hash()
	genNode := &blockNode{
		header:    gen.Header,
		hash:      genHash,
		block:     gen,
		pathScore: 0,
		vt:        p.GenesisTime,
		diff:      p.GenesisDifficulty,
	}
	d := &DAG{
		p:               p,
		chainTag:        ChainTag(p),
		nodes:           map[cryptography.Hash]*blockNode{genHash: genNode},
		canonical:       []*blockNode{genNode},
		finalizedCount:  1,
		maxFinScore:     0,
		minFinHash:      genHash,
		tips:            map[cryptography.Hash]*blockNode{genHash: genNode},
		orphans:         make(map[cryptography.Hash]*orphanEntry),
		orphansByParent: make(map[cryptography.Hash]map[cryptography.Hash]struct{}),
		invalid:         make(map[cryptography.Hash]struct{}),
		utxo:            NewUTXOSet(),
		recentlySpent:   make(map[UTXOKey]struct{}),
		issued:          0,
		lastMTP:         p.GenesisTime,
		yearIndex:       0,
		yearBase:        0,
		hooks:           hooks,
	}
	return d, nil
}

// Params returns the consensus parameters.
func (d *DAG) Params() *consensus.Params { return d.p }

// ChainTag returns the replay-protection tag.
func (d *DAG) ChainTag() [4]byte { return d.chainTag }

// ---------------------------------------------------------------------------
// Queries (read lock)
// ---------------------------------------------------------------------------

// TipInfo returns the canonical tip index, tip PathScore and tip hash.
func (d *DAG) TipInfo() (index uint64, score uint64, tip cryptography.Hash) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	t := d.canonical[len(d.canonical)-1]
	return uint64(len(d.canonical) - 1), t.pathScore, t.hash
}

// CanonicalCount returns the number of canonical blocks (including genesis).
func (d *DAG) CanonicalCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.canonical)
}

// FinalizedCount returns the size of the immutable canonical prefix.
func (d *DAG) FinalizedCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.finalizedCount
}

// CanonicalHashAt returns the canonical block hash at index i.
func (d *DAG) CanonicalHashAt(i int) (cryptography.Hash, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if i < 0 || i >= len(d.canonical) {
		return cryptography.Hash{}, fmt.Errorf("%w: index %d", ErrUnknownBlock, i)
	}
	return d.canonical[i].hash, nil
}

// LastCanonicalHashes returns up to n most recent canonical hashes, newest
// first. Used as a sync locator.
func (d *DAG) LastCanonicalHashes(n int) []cryptography.Hash {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if n > len(d.canonical) {
		n = len(d.canonical)
	}
	out := make([]cryptography.Hash, 0, n)
	for i := len(d.canonical) - 1; i >= len(d.canonical)-n; i-- {
		out = append(out, d.canonical[i].hash)
	}
	return out
}

// TipsSorted returns up to max tip hashes sorted by (PathScore desc, hash
// asc) — the mining parent selection order; TipsSorted(...)[0] is the
// selected parent.
func (d *DAG) TipsSorted(max int) []cryptography.Hash {
	d.mu.RLock()
	defer d.mu.RUnlock()
	list := make([]*blockNode, 0, len(d.tips))
	for _, n := range d.tips {
		list = append(list, n)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].pathScore != list[j].pathScore {
			return list[i].pathScore > list[j].pathScore
		}
		return lessHash(list[i].hash, list[j].hash)
	})
	if max > 0 && len(list) > max {
		list = list[:max]
	}
	out := make([]cryptography.Hash, len(list))
	for i, n := range list {
		out[i] = n.hash
	}
	return out
}

// HasBlock reports whether the hash is a known, accepted block.
func (d *DAG) HasBlock(h cryptography.Hash) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, ok := d.nodes[h]
	return ok
}

// BlockHeader returns the header of an accepted block.
func (d *DAG) BlockHeader(h cryptography.Hash) (*Header, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	n, ok := d.nodes[h]
	if !ok {
		return nil, false
	}
	return n.header, true
}

// BlockBody returns the full block if it is still inside the unfinalized
// window (finalized bodies are served from the block store, not the DAG).
func (d *DAG) BlockBody(h cryptography.Hash) (*Block, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	n, ok := d.nodes[h]
	if !ok || n.block == nil {
		return nil, false
	}
	return n.block, true
}

// CirculatingSupply returns the total issued coinbase value (atoms).
func (d *DAG) CirculatingSupply() uint64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.issued
}

// MTP returns the canonical median-time-past watermark.
func (d *DAG) MTP() uint64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.lastMTP
}

// OrphanCount returns the current orphan pool size.
func (d *DAG) OrphanCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.orphans)
}

// StateSummary is a snapshot for RPC getinfo.
type StateSummary struct {
	CanonicalCount int
	FinalizedCount int
	TipIndex       uint64
	TipScore       uint64
	TipHash        cryptography.Hash
	Circulating    uint64
	MTP            uint64
	UTXOEntries    int
	Orphans        int
}

// Summary returns a state snapshot.
func (d *DAG) Summary() StateSummary {
	d.mu.RLock()
	defer d.mu.RUnlock()
	t := d.canonical[len(d.canonical)-1]
	return StateSummary{
		CanonicalCount: len(d.canonical),
		FinalizedCount: d.finalizedCount,
		TipIndex:       uint64(len(d.canonical) - 1),
		TipScore:       t.pathScore,
		TipHash:        t.hash,
		Circulating:    d.issued,
		MTP:            d.lastMTP,
		UTXOEntries:    len(d.utxo.m),
		Orphans:        len(d.orphans),
	}
}

// Balance returns the mature balance and UTXO list of a public key hash.
func (d *DAG) Balance(pkh cryptography.Hash160) (uint64, []UTXOKey, []UTXOEntry) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	tipIdx := uint64(len(d.canonical) - 1)
	var total uint64
	var keys []UTXOKey
	var entries []UTXOEntry
	for k, e := range d.utxo.m {
		if e.PubKeyHash != pkh {
			continue
		}
		if e.IsCoinbase && tipIdx-e.CanonicalIndex < d.p.CoinbaseMaturity {
			continue
		}
		total += e.Value
		keys = append(keys, k)
		entries = append(entries, e)
	}
	return total, keys, entries
}

// MempoolView returns a SpendView over the live canonical UTXO state for
// mempool validation.
func (d *DAG) MempoolView() *UTXOView {
	d.mu.RLock()
	defer d.mu.RUnlock()
	tipIdx := uint64(len(d.canonical) - 1)
	return &UTXOView{set: d.utxo, recentlySpent: d.recentlySpent, tipIndex: tipIdx, maturity: d.p.CoinbaseMaturity}
}

func lessHash(a, b cryptography.Hash) bool {
	for i := 0; i < 32; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func maxHash(a, b cryptography.Hash) cryptography.Hash {
	if lessHash(b, a) {
		return b
	}
	return a
}

func minHash(a, b cryptography.Hash) cryptography.Hash {
	if lessHash(a, b) {
		return a
	}
	return b
}
