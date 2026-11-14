// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

// Package mining implements the ANONYMCOIN CPU mining stack: the
// transaction memory pool and the multi-worker ANONYMBWT miner that assembles
// BlockDAG templates from the current tips.
package mining

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/anonymcoin/anonymcoin/blockdag"
	"github.com/anonymcoin/anonymcoin/consensus"
	"github.com/anonymcoin/anonymcoin/cryptography"
	"github.com/anonymcoin/anonymcoin/transactions"
)

// MemPool holds validated, relayable transactions awaiting inclusion. It is
// rebased by the node whenever the canonical UTXO state changes.
type MemPool struct {
	mu      sync.RWMutex
	p       *consensus.Params
	entries map[cryptography.Hash]*poolEntry
}

type poolEntry struct {
	tx  *transactions.Tx
	fee uint64
	at  time.Time
}

var (
	ErrMempoolFull    = errors.New("mempool: full")
	ErrMempoolUnknown = errors.New("mempool: transaction not found")
	MaxMempoolEntries = 5000
)

// NewMemPool creates an empty pool.
func NewMemPool(p *consensus.Params) *MemPool {
	return &MemPool{p: p, entries: make(map[cryptography.Hash]*poolEntry)}
}

// Add validates a transaction against the provided spend view and fee
// calculator, then stores it. The spend view must reflect the live canonical
// state (dag.MempoolView()).
func (m *MemPool) Add(tx *transactions.Tx, view transactions.SpendView) error {
	if tx.IsCoinbase() {
		return errors.New("mempool: coinbase transactions are never relayed")
	}
	if err := transactions.ValidateSpendable(tx, m.p, blockdag.ChainTag(m.p), view); err != nil {
		return err
	}
	// Fee recomputation with the view (ValidateSpendable already checked
	// existence; recompute for ordering). Checked adds: pool arithmetic
	// never wraps.
	values := make([]uint64, len(tx.Inputs))
	var inSum uint64
	for i := range tx.Inputs {
		out, _ := view.Lookup(tx.Inputs[i].PrevTx, tx.Inputs[i].PrevIndex)
		values[i] = out.Value
		s, ovf := checkedAddPool(inSum, out.Value)
		if ovf {
			return fmt.Errorf("mempool: input sum overflow")
		}
		inSum = s
	}
	var outSum uint64
	for i := range tx.Outputs {
		s, ovf := checkedAddPool(outSum, tx.Outputs[i].Value)
		if ovf {
			return fmt.Errorf("mempool: output sum overflow")
		}
		outSum = s
	}
	if outSum > inSum {
		return errors.New("mempool: outputs exceed inputs")
	}
	fee := inSum - outSum

	m.mu.Lock()
	defer m.mu.Unlock()
	id := tx.ID()
	if _, ok := m.entries[id]; ok {
		return nil // already pooled
	}
	if len(m.entries) >= MaxMempoolEntries {
		// Evict the lowest-fee, oldest entry.
		var victim cryptography.Hash
		var victimFee uint64 = ^uint64(0)
		var victimAt time.Time
		for h, e := range m.entries {
			if e.fee < victimFee || (e.fee == victimFee && e.at.Before(victimAt)) {
				victim, victimFee, victimAt = h, e.fee, e.at
			}
		}
		delete(m.entries, victim)
	}
	m.entries[id] = &poolEntry{tx: tx, fee: fee, at: time.Now()}
	return nil
}

// Remove drops a transaction (after it was mined into a block).
func (m *MemPool) Remove(id cryptography.Hash) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, id)
}

// Has reports membership.
func (m *MemPool) Has(id cryptography.Hash) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.entries[id]
	return ok
}

// Len returns the pool size.
func (m *MemPool) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.entries)
}

// PoolEntry couples a pooled transaction with its recorded fee.
type PoolEntry struct {
	Tx  *transactions.Tx
	Fee uint64
}

// Top returns up to n entries ordered by fee descending (ties by arrival
// time asc), suitable for template assembly.
func (m *MemPool) Top(n int) []PoolEntry {
	m.mu.RLock()
	list := make([]*poolEntry, 0, len(m.entries))
	for _, e := range m.entries {
		list = append(list, e)
	}
	m.mu.RUnlock()
	sort.Slice(list, func(i, j int) bool {
		if list[i].fee != list[j].fee {
			return list[i].fee > list[j].fee
		}
		return list[i].at.Before(list[j].at)
	})
	if n > 0 && len(list) > n {
		list = list[:n]
	}
	out := make([]PoolEntry, 0, len(list))
	for _, e := range list {
		out = append(out, PoolEntry{Tx: e.tx, Fee: e.fee})
	}
	return out
}

func checkedAddPool(a, b uint64) (uint64, bool) {
	s := a + b
	return s, s < a
}

// IDs returns all pooled transaction ids.
func (m *MemPool) IDs() []cryptography.Hash {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]cryptography.Hash, 0, len(m.entries))
	for h := range m.entries {
		out = append(out, h)
	}
	return out
}

// Rebase drops transactions that no longer validate against the given view
// (after a window reorganization or block application).
func (m *MemPool) Rebase(view transactions.SpendView) {
	m.mu.Lock()
	var doomed []cryptography.Hash
	for h, e := range m.entries {
		if err := transactions.ValidateSpendable(e.tx, m.p, blockdag.ChainTag(m.p), view); err != nil {
			doomed = append(doomed, h)
		}
	}
	for _, h := range doomed {
		delete(m.entries, h)
	}
	m.mu.Unlock()
}
