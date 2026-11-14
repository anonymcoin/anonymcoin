# BLOCKDAG Architecture — The Heart of ANONYMCOIN

**ANONYMCOIN — Original Project Author and Founder: Iury Lee — Copyright © 2026 Iury Lee**

**THE BLOCKDAG IS THE HEART OF ANONYMCOIN.**

**BCB EM PÂNICO.**

**ASICs EM PÂNICO.**

**ANONYMCOIN RODA LIVRE EM QUALQUER CPU.**

This document describes how the heart actually beats: the engine modules,
their invariants, the memory model, and how independent nodes validate the
network.

---

## 1. Module map

```
            ┌────────────┐   templates   ┌──────────┐
   tips ───▶│  /mining   │──────────────▶│ /anonymbwt│──▶ PoW search
            │ mempool    │               │  (CPU PoW)│
            └─────┬──────┘               └──────────┘
                  │ mined blocks
                  ▼
        ┌───────────────────┐    accepts     ┌──────────────┐
        │  /blockdag engine │◀───────────────│  /network    │
        │  ANONDAG-1        │   gossip/sync  │ TLS1.3+Falcon│
        │  canonical order  │───────────────▶│ Tor / I2P    │
        │  UTXO + journal   │   broadcasts   └──────────────┘
        └───────┬───────────┘
                │ canonical events
                ▼
        ┌───────────────┐     ┌─────────────┐     ┌─────────┐
        │ /storage      │     │ /consensus  │     │ /rpc    │
        │ blocks.dat    │     │ params, TIE │     │ loopback│
        └───────────────┘     └─────────────┘     └─────────┘
```

## 2. In-memory representation

- `blockNode`: header, hash, block body (window only), parent pointers,
  `pathScore`, `vt`, `difficulty`, child count, and — while the block is
  inside the unfinalized window — an undo record.
- `DAG`: hash → node index, the canonical list, the finalized prefix, the
  tip set, the orphan pool, the invalid set, the UTXO set, spend tombstones
  (conflict tracking), and the monetary scalars (`issued`, `lastMTP`,
  `yearIndex`, `yearBase`).
- A single writer lock guards all state; the PoW check runs outside it.

## 3. Block lifecycle

1. **Arrival** (mined locally or received). Structural validation, then
   PoW — state-independent, cheap to reject early.
2. **Parent resolution.** Unknown parents → bounded orphan pool with
   recursive redrive. Known parents → canonical parent-order check
   (selected parent first), expected-difficulty check along the
   selected-parent chain, timestamp checks against parent virtual time.
3. **Canonical insertion.** O(1) finalized-boundary test, O(window) position
   scan, rollback of the affected tail via undo journals, splice, re-apply.
4. **Application.** Transactions applied in canonical order; conflicts
   skipped; coinbase clamped to the entitled value; monetary scalars and the
   MTP watermark advanced.
5. **Maintenance.** Tips updated, orphans re-driven, hooks fired (persist to
   the block store, rebase the mempool, broadcast), finalization advanced.

## 4. UTXO state and reorganization

The canonical UTXO set is a plain map; every block application writes an
**undo record** (UTXO additions, removals, spend tombstones, previous
monetary scalars). A mid-window insertion rolls back the tail by replaying
undo records in reverse, then re-applies it in the new order. The
unfinalized region is bounded by `2 × FinalizedDepth`, so the cost of a
reorganization is bounded and small.

## 5. Storage model

`storage.BlockStore` is a CRC-protected append-only file of accepted blocks
in acceptance order. The in-memory index (hash → offset) is rebuilt by a
scanning open that validates every record and truncates torn tails. On
restart the node replays the file through the same acceptance pipeline;
because acceptance is deterministic given the same arrival order (and the
file preserves that order), the rebuilt DAG is byte-identical — proven by
`TestEndToEndMineStoreRestartSpend`. No separate chainstate database, no
embedded KV store, no cgo: the block store is the database.

## 6. Synchronization

- New blocks are flooded to all connected peers (no address gossip exists).
- On connect, the handshake announces each side's canonical tip (index,
  PathScore, hash). The side that is behind pulls canonical ranges
  (`GetRange[from,to)`) in batches of up to 256 blocks until caught up.
- A single-reader rule governs each connection: the syncing side consumes
  frames synchronously before handing the connection to its read loop.
- Serving finalized block bodies beyond the in-memory window is delegated to
  the block store by the node layer.

## 7. Networking model (privacy)

- **TLS 1.3 only**, self-signed Ed25519 node certificates, verified against
  a **pinned fingerprint set** (strict pins or opt-in trust-on-first-use).
- **Falcon-512** (FN-DSA-512, FIPS 206) signs the handshake hello, binding
  the node's post-quantum identity to the session nonces.
- Peers are configured explicitly (`config.json`). There is **no peers
  message on the wire at all** — address enumeration by peers is
  structurally impossible, not merely discouraged.
- Transports: plain TCP, **Tor** via a local SOCKS5 proxy (onion services are
  advertised by the operator out of band), **I2P** via the SAM v3 API with
  transient destinations. See docs/PROTOCOL.md.

## 8. How independent nodes validate the network

A node that receives a block performs, in order:

1. structural checks (encoding, parent count/order, merkle, transaction
   structure, sizes);
2. ANONYMBWT PoW against the header's difficulty target;
3. parent availability and canonical parent order;
4. expected difficulty recomputed along the selected-parent chain;
5. timestamp rules against parent virtual time;
6. canonical insertion with the O(1) late-block test;
7. transaction application against the canonical UTXO state (conflicts
   skipped, coinbase clamped).

Every step is a pure function of (DAG, params). Two nodes that hold the same
blocks reach the same verdicts — including the verdicts on conflicting
parallel blocks, which canonical order resolves deterministically.

## 9. Resource profile

- Memory: the working set is dominated by the window (2000 × ~0.5 KB), the
  UTXO set, and per-hash PoW workspaces (~1 MB per miner thread).
- Hash rate: see docs/BENCHMARKS.md — ~5.4 ms per ANONYMBWT hash per core on
  the reference machine, zero allocations in the mining hot loop.
- No background services, no cloud dependencies, no telemetry. A node is one
  static binary and one data directory.

---

*ANONYMCOIN — IURY LEE © 2026 — ANONYMCOIN RODA LIVRE EM QUALQUER CPU.*
