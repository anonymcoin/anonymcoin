# ANONDAG-1 — The ANONYMCOIN Consensus Specification

**ANONYMCOIN — Original Project Author and Founder: Iury Lee — Copyright © 2026 Iury Lee**

**THE BLOCKDAG IS THE HEART OF ANONYMCOIN.**

ANONDAG-1 is the original BlockDAG consensus engine of ANONYMCOIN. It is
designed to be exactly reproducible: every independently operated node, given
the same set of blocks, computes the same canonical order, the same monetary
state and the same validation verdicts, using integer arithmetic only.

---

## 1. Data model

- A **block** contains a header and a transaction list (first transaction is
  the coinbase).
- The header references **1..MaxParents (8) parent hashes** (the genesis has
  none). Parents must be canonically sorted by `(PathScore descending, hash
  ascending)`, so `Parents[0]` is the **selected parent** — this makes the
  header encoding canonical and its hash deterministic.
- `Hash(B) = BLAKE2b-256(canonical header encoding)`; the nonce is the final
  header field so miners patch it in place.
- Every transaction id commits to the **chain tag** — the first four bytes of
  the genesis hash — giving replay protection across independent networks.

## 2. Scoring

For every block B with parents P(B):

    work(B)  = B.Difficulty                 (validated expected difficulty)
    PathScore(B) = work(B) + max_{p in P(B)} PathScore(p)

PathScore strictly increases along every parent edge (work >= 1 for all
non-genesis blocks). Genesis has PathScore 0. This single property replaces
explicit reachability bookkeeping throughout the engine.

## 3. Virtual time

    VT(B) = max( max_{p in P(B)} VT(p),
                 min( blockTime(B), max_{p} VT(p) + VTDriftCap ) )

Properties (all proven by construction, tested in `consensus` and
`blockdag`):

- VT is monotonically non-decreasing along every edge and along the whole
  canonical order.
- VT can advance by at most VTDriftCap (60 s) per block, bounding the damage
  a timestamp-inflating miner can do to emission and difficulty.
- VT(B) depends only on B's ancestors and its own block time — arrival order
  and reorgs elsewhere cannot change it.

A block's timestamp must satisfy `blockTime(B) >= max_{p} VT(p)` (hard
consensus rule) and `blockTime(B) <= now + MaxFutureTimeSec` (local DoS
policy, not consensus; VT clamping makes the difference immaterial).

## 4. Canonical order

The canonical order is the **priority-topological order with key
`(PathScore ascending, hash ascending)`**: repeatedly emit, among the blocks
whose parents are all already emitted, the one with the smallest key.

Because PathScore strictly increases along ancestry, every ancestor is
lighter than its descendants and therefore always ordered before them —
topological validity is automatic, with no reachability checks. The relative
order of any two incomparable blocks depends only on their own keys, never
on arrival order.

Incremental implementation:

1. **Finalized prefix.** The first `finalizedCount` entries of the canonical
   list are immutable. Finalization advances when the unfinalized region
   exceeds `2 × FinalizedDepth` (2000), which leaves ~33 minutes of
   reorganizable window at the one-second target.
2. **O(1) late test.** A new block is **late** (rejected) iff
   `node.pathScore < maxFinScore` or
   (`node.pathScore == maxFinScore` and `node.hash < minFinHashAtMaxScore`),
   where `maxFinScore` is the largest finalized PathScore and `minFinHash`
   the smallest hash among finalized blocks at that score. Correctness
   follows from score monotonicity: a heavier finalized block can never be
   an ancestor of the new block, so the ancestor branch of the comparator
   can never apply to it.
3. **O(window) insertion scan.** Otherwise the block is inserted at the
   first unfinalized position where it orders before the resident block
   (`(score asc, hash asc)` among incomparable pairs). The affected tail is
   rolled back with undo journals and re-applied.

The finalized prefix equals the comparator order of the blocks that aged
out, provided blocks propagate well within the finalization delay — the
standard probabilistic-finality assumption, shared with other BlockDAG
systems and stated openly here rather than hidden.

## 5. Difficulty

Difficulty retargets once per block along the **selected-parent chain** (the
DAG analogue of a chain window):

    ActualSpan = VT(tip) - VT(tip - DifficultyWindow along SP chain)   (128 s target)
    newDiff    = tipDiff * ActualSpan / TargetSpan
    clamped to [tipDiff/4, tipDiff*4] and [DifficultyMin, DifficultyMax]

Until the window is full, children inherit the parent difficulty (bootstrap
ramp). The rule is a pure function of the DAG structure: all nodes compute
the same expected difficulty for the same parent set, independent of arrival
order. Resistance to timestamp manipulation comes from VT monotonicity and
the per-block drift cap.

## 6. Transactions, UTXO and conflicts

- Single-signature pay-to-public-key-hash UTXO model, Ed25519 signatures.
- Transaction digest = `BLAKE2b-256(chainTag || encoding with signature
  fields zeroed)`. Every input's pubkey must hash to the referenced output's
  pubkey hash. Duplicate inputs inside one transaction are rejected.
- Block-level rules: exactly one coinbase (first position, no inputs, aux
  payload allowed for uniqueness), all other transactions have inputs, no
  duplicate transaction ids in a block, merkle root matches the header.

**Canonical application.** Blocks are applied in canonical order. Within a
block, transactions are applied in listed order:

- An input that exists in the canonical UTXO set is consumed (maturity of
  `CoinbaseMaturity = 10` canonical blocks applies to coinbases).
- An input consumed by an earlier canonical block or by an earlier
  transaction of the same block is a **conflict**: the transaction is
  *skipped*, deterministically. Its fee simply never materializes (the
  winning transaction already consumed the inputs) — a deflationary bias,
  never an inflation.
- An input that never existed marks the block **invalid** on first
  application.

**Coinbase clamping.** The entitled coinbase value at a canonical position
is `emissionReward(position) + fees(applied transactions)`. Coinbase
transactions are minted by consensus and carry no signature, so consensus
defines their effective value: outputs are paid `min(claimed, remaining
budget)` in order. Consequences: over-claims are clamped (deflationary),
blocks are never dropped over reward disputes, and the global invariant

    circulating supply  <=  time integral of the emission schedule

always holds, with equality when miners claim exactly the forecast reward
(the common case; `ForecastReward` mirrors the application-time computation
exactly for blocks appending at the tip).

**Duplicate coinbase txids** (identical coinbase content in two blocks)
collide on one UTXO key; the first canonical application keeps the output,
later duplicates are burned. Miners avoid this by putting unique entropy in
the coinbase aux payload.

## 7. Orphans and invalid blocks

Blocks with unknown parents are parked in a bounded FIFO orphan pool (2048
entries, 2 h TTL) and re-driven (recursively, through the lock-free
acceptance core) as soon as their missing parents are accepted. Blocks that
fail structural, difficulty, timestamp or PoW validation are rejected and
remembered as invalid.

## 8. Determinism statement and what it does not cover

Every consensus function above is a pure function of the DAG structure and
the consensus parameters. The test suite proves this property directly:
random DAGs replayed in multiple shuffled arrival orders produce byte-
identical canonical orders (`TestCanonicalOrderIndependentOfArrivalOrder`),
and storage replay rebuilds identical state
(`TestEndToEndMineStoreRestartSpend`).

What ANONDAG-1 does **not** claim:

- No formal security proof of the 51 %-attack threshold is provided. The
  security argument is the standard work-based one: reordering the
  unfinalized window requires out-competing honest PathScore growth.
- Finality is probabilistic (propagation delay << finalization window).
- The UTXO model is position-dependent ("first canonical application
  wins"), not the full per-past multiset model of GHOSTDAG-family systems.
  This is a deliberate v1 simplification; see docs/ROADMAP.md.

## 9. Parameters

All constants live in `consensus.Params` (see MONETARY_POLICY.md for the
monetary ones):

| Constant | Value | Meaning |
| --- | --- | --- |
| BlockIntervalSec | 1 | target interval |
| MaxParents | 8 | parent references per block |
| MaxBlockSize | 1,000,000 | bytes |
| VTDriftCap | 60 s | max virtual-time advance per block |
| MTPWindow | 11 | median window of the emission clock |
| DifficultyWindow | 128 | retarget window on the SP chain |
| FinalizedDepth | 2000 | immutable canonical prefix |
| CoinbaseMaturity | 10 | canonical blocks before a coinbase is spendable |
| OrphanPoolSize / TTL | 2048 / 2 h | orphan parking |

---

*ANONYMCOIN — IURY LEE © 2026 — THE BLOCKDAG IS THE HEART.*
