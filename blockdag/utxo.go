// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package blockdag

import (
	"github.com/anonymcoin/anonymcoin/cryptography"
	"github.com/anonymcoin/anonymcoin/transactions"
)

// UTXOKey identifies an unspent output.
type UTXOKey struct {
	TxID  cryptography.Hash
	Index uint32
}

// UTXOEntry is the consensus state of one unspent output.
type UTXOEntry struct {
	Value          uint64
	PubKeyHash     cryptography.Hash160
	IsCoinbase     bool
	CanonicalIndex uint64 // canonical index of the creating block
}

// UTXOSet is the canonical unspent transaction output set. It is mutated
// only by the DAG engine during canonical application and is rolled back via
// UndoRecords when a new block is inserted into the unfinalized window.
type UTXOSet struct {
	m map[UTXOKey]UTXOEntry
}

// NewUTXOSet creates an empty set.
func NewUTXOSet() *UTXOSet {
	return &UTXOSet{m: make(map[UTXOKey]UTXOEntry)}
}

// Add inserts an output. The caller guarantees the key is not present
// (duplicate coinbase txids are rejected upstream by block structure checks;
// identical-value duplicate coinbases are overwritten deterministically).
func (u *UTXOSet) Add(k UTXOKey, e UTXOEntry) { u.m[k] = e }

// Remove deletes an output and reports whether it existed.
func (u *UTXOSet) Remove(k UTXOKey) (UTXOEntry, bool) {
	e, ok := u.m[k]
	if ok {
		delete(u.m, k)
	}
	return e, ok
}

// Get returns the entry for a key.
func (u *UTXOSet) Get(k UTXOKey) (UTXOEntry, bool) {
	e, ok := u.m[k]
	return e, ok
}

// Has reports presence.
func (u *UTXOSet) Has(k UTXOKey) bool { _, ok := u.m[k]; return ok }

// Len returns the number of unspent outputs.
func (u *UTXOSet) Len() int { return len(u.m) }

// Clone deep-copies the set (used by tests).
func (u *UTXOSet) Clone() *UTXOSet {
	c := NewUTXOSet()
	for k, v := range u.m {
		c.m[k] = v
	}
	return c
}

// ForEach iterates deterministically is NOT provided — map order is random.
// Callers needing ordered views must sort keys themselves.
func (u *UTXOSet) Entries() map[UTXOKey]UTXOEntry { return u.m }

// ---------------------------------------------------------------------------
// Undo journal
// ---------------------------------------------------------------------------

type undoRemoved struct {
	k UTXOKey
	e UTXOEntry
}

// UndoRecord captures everything needed to revert one block's canonical
// application: UTXO additions/removals and the monetary/time scalars.
type UndoRecord struct {
	Added         []UTXOKey
	Removed       []undoRemoved
	PrevMTP       uint64
	PrevIssued    uint64
	PrevYearIndex uint64
	PrevYearBase  uint64
	// SpentKeys records UTXO keys whose spend tombstones were added by this
	// block (conflict tracking), so rollback can un-tombstone them.
	SpentKeys []UTXOKey
}

// ---------------------------------------------------------------------------
// Spend view for transaction validation
// ---------------------------------------------------------------------------

// UTXOView adapts the UTXO set (plus coinbase maturity and conflict
// tombstones) to the transactions.SpendView interface.
type UTXOView struct {
	set           *UTXOSet
	recentlySpent map[UTXOKey]struct{}
	tipIndex      uint64 // current canonical tip index
	maturity      uint64
}

// NewUTXOView constructs a spend view.
func NewUTXOView(set *UTXOSet, recentlySpent map[UTXOKey]struct{}, tipIndex, maturity uint64) *UTXOView {
	return &UTXOView{set: set, recentlySpent: recentlySpent, tipIndex: tipIndex, maturity: maturity}
}

// Lookup implements transactions.SpendView.
func (v *UTXOView) Lookup(prev cryptography.Hash, index uint32) (transactions.OutputView, bool) {
	k := UTXOKey{TxID: prev, Index: index}
	if _, spent := v.recentlySpent[k]; spent {
		return transactions.OutputView{}, false
	}
	e, ok := v.set.Get(k)
	if !ok {
		return transactions.OutputView{}, false
	}
	if e.IsCoinbase && v.tipIndex >= e.CanonicalIndex && v.tipIndex-e.CanonicalIndex < v.maturity {
		return transactions.OutputView{}, false // coinbase not yet mature
	}
	if e.IsCoinbase && v.tipIndex < e.CanonicalIndex {
		return transactions.OutputView{}, false // defensive: cannot happen in canonical order
	}
	return transactions.OutputView{Value: e.Value, PubKeyHash: e.PubKeyHash}, true
}
