// ANONYMCOIN — Private BlockDAG Cryptocurrency
// Original Project Author and Founder: Iury Lee
// Copyright © 2026 Iury Lee
//
// This file is part of the ANONYMCOIN reference implementation.
// See the LICENSE file at the repository root for license terms.

package blockdag

import (
	"fmt"
	"sort"
	"time"

	"github.com/anonymcoin/anonymcoin/anonymbwt"
	"github.com/anonymcoin/anonymcoin/consensus"
	"github.com/anonymcoin/anonymcoin/cryptography"
	"github.com/anonymcoin/anonymcoin/difficulty"
	"github.com/anonymcoin/anonymcoin/transactions"
)

// AcceptBlock runs the full ANONDAG-1 validation and application pipeline:
//
//  1. structural validation (parents, merkle, transactions, sizes)
//  2. parent resolution (unknown parents -> bounded orphan pool)
//  3. canonical parent-order check (selected parent first)
//  4. expected-difficulty check along the selected-parent chain
//  5. timestamp rules against parent virtual time
//  6. ANONYMBWT proof-of-work against the header's target
//  7. canonical insertion: O(1) finalized-boundary test, O(window) position
//     scan, bounded rollback + reapplication of the affected window range
//  8. tip/orphan maintenance and hooks
//
// The whole state-dependent phase runs under the DAG write lock, so the
// engine is safe for concurrent RPC, network and mining use.
func (d *DAG) AcceptBlock(b *Block) error {
	if err := d.validateStructure(b); err != nil {
		return err
	}

	// PoW is state-independent: verify it before taking the write lock.
	target := anonymbwt.TargetBytes(b.Header.Difficulty)
	powHash := anonymbwt.Digest(b.Header.Encode())
	if !anonymbwt.MeetsTarget(powHash, target) {
		return fmt.Errorf("%w: hash %x", ErrBadPoW, powHash[:8])
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	return d.acceptLocked(b)
}

// acceptLocked is the stateful acceptance core. Caller must hold the write
// lock; orphan redrive recurses through this function (never through the
// public AcceptBlock, which would re-lock and self-deadlock).
func (d *DAG) acceptLocked(b *Block) error {
	hash := b.BlockHash()

	if _, ok := d.nodes[hash]; ok {
		return ErrDuplicate
	}
	if _, ok := d.invalid[hash]; ok {
		return ErrKnownInvalid
	}

	// Parent resolution.
	parents := make([]*blockNode, 0, len(b.Header.Parents))
	var missing []cryptography.Hash
	for _, ph := range b.Header.Parents {
		pn, ok := d.nodes[ph]
		if !ok {
			missing = append(missing, ph)
			continue
		}
		parents = append(parents, pn)
	}
	if len(missing) > 0 {
		d.parkOrphan(b, hash, missing)
		return fmt.Errorf("%w: %d missing", ErrOrphan, len(missing))
	}

	// Canonical parent order: (PathScore desc, hash asc), Parents[0] is the
	// selected parent. This makes the header encoding canonical.
	for i := 0; i+1 < len(parents); i++ {
		a, c := parents[i], parents[i+1]
		if a.pathScore < c.pathScore ||
			(a.pathScore == c.pathScore && lessHash(a.hash, c.hash) == false && !equalHash(a.hash, c.hash)) {
			return fmt.Errorf("%w: parents must be sorted by (pathScore desc, hash asc)", ErrInvalidBlock)
		}
	}

	// Expected difficulty along the selected-parent chain.
	expDiff := d.expectedDifficultyLocked(parents[0])
	if b.Header.Difficulty != expDiff {
		return fmt.Errorf("%w: header %d, expected %d", ErrBadDifficulty, b.Header.Difficulty, expDiff)
	}

	// Timestamp rules.
	var maxParentVT uint64
	parentVTs := make([]uint64, len(parents))
	for i, pn := range parents {
		parentVTs[i] = pn.vt
		if pn.vt > maxParentVT {
			maxParentVT = pn.vt
		}
	}
	if b.Header.Time < maxParentVT {
		return fmt.Errorf("%w: time %d < max parent VT %d", ErrBadTimestamp, b.Header.Time, maxParentVT)
	}
	now := uint64(time.Now().Unix())
	if b.Header.Time > now+d.p.MaxFutureTimeSec {
		return fmt.Errorf("%w: time %d is more than %ds ahead", ErrFutureBlock, b.Header.Time, d.p.MaxFutureTimeSec)
	}

	// Node metadata.
	node := &blockNode{
		header:  b.Header,
		hash:    hash,
		block:   b,
		parents: parents,
		vt:      consensus.VirtualTime(b.Header.Time, parentVTs, d.p),
		diff:    b.Header.Difficulty,
	}
	var maxParentScore uint64
	for _, pn := range parents {
		if pn.pathScore > maxParentScore {
			maxParentScore = pn.pathScore
		}
	}
	node.pathScore = b.Header.Difficulty + maxParentScore

	// Register before insertion so lookups see the new node; the invalid
	// paths below remove it again on rejection.
	d.nodes[hash] = node

	// Canonical insertion (may partially roll back and reapply the window).
	if err := d.insertCanonical(node); err != nil {
		// insertCanonical removes the node itself on the applyInvalid
		// path; every other rejection (late block) must also deregister,
		// otherwise the node stays known-but-uncanonical and a resubmit
		// would return ErrDuplicate forever (inconsistent DAG state).
		delete(d.nodes, hash)
		return err
	}

	// Topology maintenance.
	for _, pn := range parents {
		pn.childCount++
		delete(d.tips, pn.hash)
	}
	d.tips[hash] = node

	// Orphan redrive: blocks that were waiting for this hash.
	d.redriveOrphans(hash)
	d.sweepOrphansIfNeeded(now)

	if d.hooks.OnAccepted != nil {
		idx := int64(-1)
		for i, n := range d.canonical {
			if n == node {
				idx = int64(i)
				break
			}
		}
		d.hooks.OnAccepted(b, idx)
	}
	return nil
}

// validateStructure enforces state-independent block rules.
func (d *DAG) validateStructure(b *Block) error {
	h := b.Header
	if h.Version != d.p.ProtocolVersion {
		return fmt.Errorf("%w: version %d", ErrInvalidBlock, h.Version)
	}
	if len(h.Parents) < 1 || len(h.Parents) > d.p.MaxParents {
		return fmt.Errorf("%w: %d parents (limit %d)", ErrInvalidBlock, len(h.Parents), d.p.MaxParents)
	}
	seenParents := make(map[cryptography.Hash]struct{}, len(h.Parents))
	for _, ph := range h.Parents {
		if _, dup := seenParents[ph]; dup {
			return fmt.Errorf("%w: duplicate parent", ErrInvalidBlock)
		}
		seenParents[ph] = struct{}{}
	}
	if len(b.Txs) == 0 || !b.Txs[0].IsCoinbase() {
		return ErrNoCoinbase
	}
	for i := 1; i < len(b.Txs); i++ {
		if b.Txs[i].IsCoinbase() {
			return ErrCoinbaseNotFirst
		}
	}
	ids := b.TxIDs()
	if ComputeMerkle(ids) != h.TxMerkle {
		return fmt.Errorf("%w: header merkle root mismatch", ErrInvalidBlock)
	}
	for i := range b.Txs {
		if err := transactions.CheckStructure(&b.Txs[i], d.p, d.chainTag); err != nil {
			return fmt.Errorf("%w: tx %d: %v", ErrInvalidBlock, i, err)
		}
	}
	return nil
}

// expectedDifficultyLocked walks the selected-parent chain of sp and applies
// the retarget rule. Caller holds the write lock (or knows the chain is
// stable).
func (d *DAG) expectedDifficultyLocked(sp *blockNode) uint64 {
	n := int(d.p.DifficultyWindow)
	window := make([]difficulty.ChainPoint, 0, n)
	cur := sp
	for i := 0; i < n && len(cur.parents) > 0; i++ {
		cur = cur.parents[0]
		window = append(window, difficulty.ChainPoint{VT: cur.vt, Difficulty: cur.diff})
	}
	tip := difficulty.ChainPoint{VT: sp.vt, Difficulty: sp.diff}
	return difficulty.Next(d.p, tip, window)
}

// ExpectedDifficulty is the exported form used by the miner.
func (d *DAG) ExpectedDifficulty(parents []cryptography.Hash) (uint64, error) {
	if len(parents) == 0 {
		return 0, ErrNoTips
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	sp, ok := d.nodes[parents[0]]
	if !ok {
		return 0, fmt.Errorf("%w: parent %x", ErrUnknownBlock, parents[0][:8])
	}
	return d.expectedDifficultyLocked(sp), nil
}

// ForecastReward computes the exact coinbase subsidy a block appending at
// the canonical tip right now with the given timestamp would receive:
// perSecond * clamped MTP delta. Deterministic and identical to the value
// recomputed at application time as long as the block appends at the tip
// with this timestamp.
func (d *DAG) ForecastReward(parents []cryptography.Hash, blockTime uint64) (uint64, error) {
	if len(parents) == 0 {
		return 0, ErrNoTips
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	var maxParentVT uint64
	for _, ph := range parents {
		pn, ok := d.nodes[ph]
		if !ok {
			return 0, fmt.Errorf("%w: parent %x", ErrUnknownBlock, ph[:8])
		}
		if pn.vt > maxParentVT {
			maxParentVT = pn.vt
		}
	}
	vt := consensus.VirtualTime(blockTime, []uint64{maxParentVT}, d.p)
	// Mirror applyNode exactly for the append-at-end case: the median runs
	// over the last (k-1) canonical VTs plus the hypothetical node's VT,
	// with k = min(MTPWindow, len(canonical)+1).
	kF := d.p.MTPWindow
	if kF > len(d.canonical)+1 {
		kF = len(d.canonical) + 1
	}
	vts := make([]uint64, 0, kF)
	for i := len(d.canonical) - (kF - 1); i < len(d.canonical); i++ {
		if i >= 0 {
			vts = append(vts, d.canonical[i].vt)
		}
	}
	vts = append(vts, vt)
	m := consensus.Median(vts)
	mtp := d.lastMTP
	if m > mtp {
		mtp = m
	}
	dt := consensus.ClampGap(d.p, mtp-d.lastMTP)
	year := consensus.ScheduleYear(d.p, mtp)
	base := d.yearBase
	if year != d.yearIndex {
		base = d.issued // year boundary crossed by this very block
	}
	perSec := consensus.EmissionPerSecond(d.p, mtp, base, year)
	return consensus.RewardForSpan(perSec, dt), nil
}

// ---------------------------------------------------------------------------
// Canonical insertion, application and rollback
// ---------------------------------------------------------------------------

// insertCanonical performs the finalized-boundary test, finds the insertion
// position inside the unfinalized window, rolls back the affected range,
// splices the node in and re-applies. Caller holds the write lock.
func (d *DAG) insertCanonical(node *blockNode) error {
	// O(1) finalized-boundary test: a block that would order before the
	// finalized prefix is late. Ancestors always score strictly less than
	// their descendants, so heavier finalized blocks can never be ancestors
	// of the new block and the test needs no reachability data.
	if node.pathScore < d.maxFinScore ||
		(node.pathScore == d.maxFinScore && lessHash(node.hash, d.minFinHash)) {
		return fmt.Errorf("%w: score %d vs finalized max %d", ErrLateBlock, node.pathScore, d.maxFinScore)
	}

	// Window scan: first unfinalized block the node orders before.
	pos := len(d.canonical)
	for i := d.finalizedCount; i < len(d.canonical); i++ {
		x := d.canonical[i]
		if node.pathScore < x.pathScore ||
			(node.pathScore == x.pathScore && lessHash(node.hash, x.hash)) {
			pos = i
			break
		}
	}

	if pos < len(d.canonical) && d.hooks.OnReorg != nil {
		d.hooks.OnReorg()
	}

	// Roll back the tail from the end down to pos.
	for i := len(d.canonical) - 1; i >= pos; i-- {
		d.rollbackNode(d.canonical[i])
	}

	// Splice the node in.
	d.canonical = append(d.canonical, nil)
	copy(d.canonical[pos+1:], d.canonical[pos:])
	d.canonical[pos] = node

	// Apply the node (first pass), then re-apply the shifted tail.
	status, undo, reason := d.applyNode(node, pos, true)
	if status == applyInvalid {
		d.rollbackRecord(undo)
		d.spliceOut(pos)
		d.invalid[node.hash] = struct{}{}
		delete(d.nodes, node.hash)
		return fmt.Errorf("%w: %s", ErrInvalidBlock, reason)
	}
	node.undo = undo
	d.reapplyFrom(pos + 1)

	// Advance finalization while the unfinalized region exceeds its budget.
	d.maybeFinalize()
	return nil
}

// spliceOut removes canonical[pos] and closes the gap. Caller holds the lock.
func (d *DAG) spliceOut(pos int) {
	copy(d.canonical[pos:], d.canonical[pos+1:])
	d.canonical[len(d.canonical)-1] = nil
	d.canonical = d.canonical[:len(d.canonical)-1]
}

// reapplyFrom re-applies canonical blocks from pos onward after a rollback.
// Coinbases are clamped to their entitled value at every application, so a
// block never needs to be dropped; conflicting transactions are skipped.
func (d *DAG) reapplyFrom(pos int) {
	for pos < len(d.canonical) {
		node := d.canonical[pos]
		_, undo, _ := d.applyNode(node, pos, false)
		node.undo = undo
		pos++
	}
}

const (
	applyOK = iota
	applySkipTxs
	applyInvalid
)

// applyInvalidReason is returned with applyInvalid so rejection diagnostics
// name the exact consensus rule that fired (auditability requirement).
type applyInvalidReason string

const (
	invalidUnknownInput      applyInvalidReason = "input references unknown canonical output"
	invalidPubKeyHashBinding applyInvalidReason = "input pubkey does not match output pubkey hash (pay-to-pubkey-hash binding)"
	invalidInputOverflow     applyInvalidReason = "input value sum overflow"
	invalidOutputOverflow    applyInvalidReason = "output value sum overflow"
	invalidUnbalanced        applyInvalidReason = "outputs exceed inputs (value conservation)"
)

// applyNode integrates one canonical block into the UTXO state and the
// monetary scalars. On first application, an input that never existed in
// canonical state marks the block invalid; on reapplication missing inputs
// are conflicts (the transaction is skipped). Coinbase claims are clamped to
// the entitled value in both paths.
//
// Two consensus-critical checks live here and nowhere else (the mempool path
// checks them in transactions.ValidateSpendable, but blocks are NOT required
// to contain mempool-validated transactions — a miner can assemble any
// structurally valid block, so the application path must independently
// enforce):
//
//  1. Pay-to-public-key-hash binding: every input's embedded public key
//     must hash to the pubkey hash the referenced output is locked to.
//     CheckStructure only proves the signature was made by the embedded
//     key; without this check a miner could spend ANY existing UTXO by
//     re-signing the digest under its own key.
//  2. Output conservation: outputs <= inputs for every regular
//     transaction. Without this check an unbalanced transaction wraps the
//     uint64 fee arithmetic (inSum - outSum underflow) and inflates the
//     coinbase budget, minting arbitrary value out of thin air.
func (d *DAG) applyNode(node *blockNode, pos int, first bool) (int, *UndoRecord, applyInvalidReason) {
	undo := &UndoRecord{}
	undo.PrevMTP = d.lastMTP
	undo.PrevIssued = d.issued
	undo.PrevYearIndex = d.yearIndex
	undo.PrevYearBase = d.yearBase

	// MTP watermark over the last MTPWindow canonical VTs including this one.
	k := d.p.MTPWindow
	if k > pos+1 {
		k = pos + 1
	}
	vts := make([]uint64, 0, k)
	for i := pos - k + 1; i <= pos; i++ {
		vts = append(vts, d.canonical[i].vt)
	}
	m := consensus.Median(vts)
	mtp := d.lastMTP
	if m > mtp {
		mtp = m
	}
	dt := consensus.ClampGap(d.p, mtp-d.lastMTP)

	// Canonical-year supply snapshot: when the canonical median time enters
	// a new year the current issued supply becomes the year's emission base,
	// making realized annual inflation exactly the schedule rate.
	year := consensus.ScheduleYear(d.p, mtp)
	if year != d.yearIndex {
		d.yearBase = d.issued
		d.yearIndex = year
	}
	perSec := consensus.EmissionPerSecond(d.p, mtp, d.yearBase, year)
	reward := consensus.RewardForSpan(perSec, dt)

	tipIdx := uint64(len(d.canonical) - 1)
	view := &UTXOView{set: d.utxo, recentlySpent: d.recentlySpent, tipIndex: tipIdx, maturity: d.p.CoinbaseMaturity}

	txs := node.block.Txs
	feesApplied := uint64(0)
	var cbAdded uint64

	// Regular transactions in block order; the canonical order resolves
	// conflicts: the first application consumes the UTXO, later conflicting
	// transactions are skipped (their fees vanish — deflationary).
	for i := 1; i < len(txs); i++ {
		tx := &txs[i]
		inputKeys := make([]UTXOKey, 0, len(tx.Inputs))
		inSum := uint64(0)
		ok := true
		hadConflict := false
		for j := range tx.Inputs {
			key := UTXOKey{TxID: tx.Inputs[j].PrevTx, Index: tx.Inputs[j].PrevIndex}
			out, exists := view.Lookup(key.TxID, key.Index)
			if !exists {
				_, tombstoned := d.recentlySpent[key]
				if tombstoned {
					hadConflict = true
				}
				ok = false
				break
			}
			// Consensus-critical (1): pay-to-public-key-hash binding.
			if cryptography.Hash160Of(tx.Inputs[j].PubKey[:]) != out.PubKeyHash {
				// Not a state conflict: this is invalid no matter what the
				// UTXO state looks like, on first application AND on
				// reapplication. Skipping would be a silent theft path.
				return applyInvalid, undo, invalidPubKeyHashBinding
			}
			s, ovf := checkedAddU64(inSum, out.Value)
			if ovf {
				// Input sum overflow: impossible for validated params
				// (MaxMoney x MaxTxInputs << 2^64) but consensus arithmetic
				// must never wrap under operator-supplied params.
				return applyInvalid, undo, invalidInputOverflow
			}
			inSum = s
			inputKeys = append(inputKeys, key)
		}
		if !ok {
			if first && !hadConflict {
				// At least one input never existed in canonical state:
				// structurally spendable but factually bogus -> invalid block.
				return applyInvalid, undo, invalidUnknownInput
			}
			continue // conflict: skipped deterministically
		}
		// Apply: remove inputs, tombstone them, add outputs.
		outSum := uint64(0)
		for _, key := range inputKeys {
			e, _ := d.utxo.Remove(key)
			undo.Removed = append(undo.Removed, undoRemoved{k: key, e: e})
			d.recentlySpent[key] = struct{}{}
			undo.SpentKeys = append(undo.SpentKeys, key)
		}
		txID := tx.ID()
		var ovfOut bool
		for j := range tx.Outputs {
			outSum, ovfOut = checkedAddU64(outSum, tx.Outputs[j].Value)
			if ovfOut {
				break
			}
			key := UTXOKey{TxID: txID, Index: uint32(j)}
			d.utxo.Add(key, UTXOEntry{
				Value:          tx.Outputs[j].Value,
				PubKeyHash:     tx.Outputs[j].PubKeyHash,
				IsCoinbase:     false,
				CanonicalIndex: uint64(pos),
			})
			undo.Added = append(undo.Added, key)
		}
		if ovfOut {
			// Roll back the partial application above and reject the block:
			// output overflow must never be absorbed as a "conflict" because
			// on the first pass it is a minting attempt.
			d.rollbackRecord(undo)
			return applyInvalid, undo, invalidOutputOverflow
		}
		// Consensus-critical (2): output conservation. An unbalanced
		// transaction would underflow the fee arithmetic below and mint
		// value through the coinbase budget.
		if outSum > inSum {
			d.rollbackRecord(undo)
			return applyInvalid, undo, invalidUnbalanced
		}
		feesApplied += inSum - outSum
	}

	// Coinbase last. The entitled value is the emission reward at this
	// canonical position plus the fees of the transactions applied here.
	// Coinbase transactions are minted by consensus and carry no signature,
	// so consensus defines their effective value: each output is paid
	// min(claimed, remaining budget), walking outputs in order. Over-claims
	// are clamped (deflationary dust), blocks are never dropped, and the
	// invariant issued <= time integral always holds. Under-claims are the
	// miner's loss. This keeps application reorganization-proof.
	cb := &txs[0]
	budget, budgetOvf := checkedAddU64(reward, feesApplied)
	if budgetOvf {
		// Deterministic saturation; unreachable for validated params
		// (feesApplied is bounded by circulating supply) but consensus
		// arithmetic must be total under any operator-supplied params.
		budget = ^uint64(0)
	}
	// Duplicate coinbase txids (same miner, same second, no aux) collide on
	// the same UTXO keys; the deterministic rule is: first canonical
	// application keeps the output, later duplicates are burned.
	cbID := cb.ID()
	for j := range cb.Outputs {
		key := UTXOKey{TxID: cbID, Index: uint32(j)}
		if d.utxo.Has(key) {
			continue // burned deterministically
		}
		pay := cb.Outputs[j].Value
		if pay > budget {
			pay = budget
		}
		d.utxo.Add(key, UTXOEntry{
			Value:          pay,
			PubKeyHash:     cb.Outputs[j].PubKeyHash,
			IsCoinbase:     true,
			CanonicalIndex: uint64(pos),
		})
		undo.Added = append(undo.Added, key)
		cbAdded += pay
		budget -= pay
	}

	d.issued += cbAdded
	d.lastMTP = mtp
	return applyOK, undo, ""
}

// rollbackNode reverts one canonical application using its undo record.
func (d *DAG) rollbackNode(node *blockNode) {
	if node.undo != nil {
		d.rollbackRecord(node.undo)
		node.undo = nil
	}
}

func (d *DAG) rollbackRecord(undo *UndoRecord) {
	for _, k := range undo.Added {
		d.utxo.Remove(k)
	}
	for _, r := range undo.Removed {
		d.utxo.Add(r.k, r.e)
	}
	for _, k := range undo.SpentKeys {
		delete(d.recentlySpent, k)
	}
	d.lastMTP = undo.PrevMTP
	d.issued = undo.PrevIssued
	d.yearIndex = undo.PrevYearIndex
	d.yearBase = undo.PrevYearBase
}

// maybeFinalize advances the immutable prefix while the unfinalized region
// exceeds 2x FinalizedDepth. Caller holds the write lock.
func (d *DAG) maybeFinalize() {
	excess := len(d.canonical) - d.finalizedCount - 2*d.p.FinalizedDepth
	for i := 0; i < excess; i++ {
		f := d.canonical[d.finalizedCount]
		f.block = nil // body served from block storage from here on
		f.undo = nil  // finality: never rolled back again
		if f.pathScore > d.maxFinScore {
			d.maxFinScore = f.pathScore
			d.minFinHash = f.hash
		} else if f.pathScore == d.maxFinScore {
			d.minFinHash = minHash(d.minFinHash, f.hash)
		}
		d.finalizedCount++
	}
}

// ---------------------------------------------------------------------------
// Orphan pool
// ---------------------------------------------------------------------------

func (d *DAG) parkOrphan(b *Block, hash cryptography.Hash, missing []cryptography.Hash) {
	if len(d.orphans) >= d.p.OrphanPoolSize {
		// Evict the oldest entry.
		var oldestHash cryptography.Hash
		var oldest time.Time
		first := true
		for h, e := range d.orphans {
			if first || e.addedAt.Before(oldest) {
				oldestHash, oldest, first = h, e.addedAt, false
			}
		}
		d.evictOrphan(oldestHash)
	}
	d.orphans[hash] = &orphanEntry{block: b, hash: hash, missing: missing, addedAt: time.Now()}
	for _, m := range missing {
		set, ok := d.orphansByParent[m]
		if !ok {
			set = make(map[cryptography.Hash]struct{})
			d.orphansByParent[m] = set
		}
		set[hash] = struct{}{}
	}
}

func (d *DAG) evictOrphan(h cryptography.Hash) {
	e, ok := d.orphans[h]
	if !ok {
		return
	}
	delete(d.orphans, h)
	for _, m := range e.missing {
		if set, ok := d.orphansByParent[m]; ok {
			delete(set, h)
			if len(set) == 0 {
				delete(d.orphansByParent, m)
			}
		}
	}
}

// redriveOrphans retries parked orphans that referenced the accepted hash.
func (d *DAG) redriveOrphans(accepted cryptography.Hash) {
	set, ok := d.orphansByParent[accepted]
	if !ok {
		return
	}
	candidates := make([]cryptography.Hash, 0, len(set))
	for h := range set {
		candidates = append(candidates, h)
	}
	sort.Slice(candidates, func(i, j int) bool { return lessHash(candidates[i], candidates[j]) })
	for _, h := range candidates {
		e, ok := d.orphans[h]
		if !ok {
			continue
		}
		// Re-check that all parents are now known.
		ready := true
		for _, m := range e.missing {
			if _, known := d.nodes[m]; !known {
				ready = false
				break
			}
		}
		if !ready {
			continue
		}
		d.evictOrphan(h)
		// Recursion is bounded by the orphan pool size and goes through the
		// lock-free core.
		_ = d.acceptLocked(e.block)
	}
}

// sweepOrphansIfNeeded drops expired orphans at most once per minute.
func (d *DAG) sweepOrphansIfNeeded(now uint64) {
	if now-d.lastOrphanSweepUnix < 60 {
		return
	}
	d.lastOrphanSweepUnix = now
	cutoff := time.Now().Add(-time.Duration(d.p.OrphanTTLSec) * time.Second)
	for h, e := range d.orphans {
		if e.addedAt.Before(cutoff) {
			d.evictOrphan(h)
		}
	}
}

func equalHash(a, b cryptography.Hash) bool { return a == b }

// checkedAddU64 returns a+b and reports whether the addition wrapped.
// Consensus arithmetic is total: every sum that could conceivably overflow
// under operator-supplied parameters is checked, and the caller's behavior
// on overflow is deterministic (reject or saturate), never wrapping.
func checkedAddU64(a, b uint64) (uint64, bool) {
	s := a + b
	return s, s < a
}
