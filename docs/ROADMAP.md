# ANONYMCOIN Roadmap — honest future work

**ANONYMCOIN — Original Project Author and Founder: Iury Lee — Copyright © 2026 Iury Lee**

v1.0.0 is a complete, tested reference implementation of the master
specification. The items below are the known limits, stated plainly, with
the intended direction for each.

## Consensus

1. **Formal security analysis of ANONDAG-1.** The current argument is
   work-based and qualitative. Goal: an explicit adversary model and a
   documented liveness/persistence argument for the windowed greedy order.
2. **Per-past UTXO resolution.** v1 resolves conflicting transactions by
   canonical position ("first application wins"); the GHOSTDAG-family
   multiset model validates blocks purely against their past, which removes
   the (rare, deflationary) skipped-transaction semantics. Goal: a
   multiset-based UTXO view per selected-parent chain.
3. **Time-warp hardening.** The emission clock is median-based and clamped,
   but a sustained majority can still inflate virtual time gradually.
   Goal: compare VT progression against difficulty-adjusted block pacing and
   penalize divergence.
4. **Header pruning.** Full-node memory grows with chain history. Goal:
   prune pre-window headers while keeping the block store authoritative.
5. **Compact block relay** (transaction-id short ids + reconstruction) to
   cut bandwidth during bursts.

## Cryptography

6. **Hybrid TLS.** TLS 1.3 with Ed25519 today; goal: hybrid post-quantum key
   exchange (e.g., ML-KEM + X25519) so recorded traffic is not
   retroactively decryptable, complementing the Falcon-512 handshake
   identity.
7. **Constant-time review** of address derivation and wallet encryption
   paths.

## Networking

8. **Peer reputation/ban scores** for protocol-violating peers.
9. **NAT traversal helpers** for TCP (uPnP is deliberately absent; onion/
   eepsite remain the privacy-preserving route).

## Wallet / UX

10. **Hierarchical deterministic keys** (seed-phrase wallet) replacing the
    per-key keystore.
11. **Fee estimation** from recent canonical blocks instead of a fixed
    default fee.

## Tooling

12. **Header-first synchronization** (headers then bodies) for faster
    initial block download.
13. **Block explorer** as a separate read-only RPC consumer.

---

Each roadmap item must land with the same discipline as v1: integer-only
consensus math, deterministic outputs, tests first, attribution preserved.
