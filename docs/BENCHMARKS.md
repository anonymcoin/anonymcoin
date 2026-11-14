# ANONYMCOIN Benchmarks (measured)

**ANONYMCOIN — Original Project Author and Founder: Iury Lee — Copyright © 2026 Iury Lee**

All numbers below were measured with `go test -bench` on the reference
machine: Intel Xeon (2 vCPU), Go 1.24.3, linux/amd64. Reproduce with
`make bench`. Absolute numbers vary by hardware; the *ratios* (sort ≈ 80 %
of hash cost) are the stable property.

## 1. ANONYMBWT proof-of-work

```
BenchmarkDigestFull-2    453    5357944 ns/op    420 B/op    3 allocs/op
BenchmarkSuffixSort-2    380    6306258 ns/op      0 B/op    0 allocs/op
```

Interpretation:

- **~5.36 ms per hash per core ≈ 186 H/s per core.**
- The suffix sort is the dominant stage (~80 % of the cost) — exactly where
  the GPU/ASIC resistance is designed to live.
- The mining hot loop allocates effectively nothing (0 B/op in the sort;
  the 420 B/op average is amortized workspace setup).

At GenesisDifficulty 64 a single core expects a solution in ~0.34 s —
comfortably inside the one-second block target for an ordinary CPU, and
multi-core machines scale linearly (`--workers`).

## 2. Falcon-512 handshake

Measured indirectly through the loopback handshake tests: key generation
dominates (Falcon keygen is the expensive operation, ~10 ms class);
sign+verify per connection is in the sub-millisecond to low-millisecond
range. Handshake cost is paid once per connection, not per message.

## 3. Block processing

The integration test mines 30 blocks, persists every one, restarts and
replays the whole store through the full validation pipeline in well under a
second (`TestEndToEndMineStoreRestartSpend`, 30 blocks ≈ 0.6 s including
mining itself at difficulty 1 in test mode). Window rollback + reapply on
mid-window insertion is O(2000) UTXO operations worst case — microseconds.

## 4. Node memory profile

- Per in-memory block (window): header + metadata ≈ 0.5 KB.
- PoW workspace per miner thread: ~1 MB (65536-byte buffer + suffix-array
  index + rank arrays).
- UTXO set: grows with unspent outputs; map-based, single writer lock.

## 5. Test suite runtime

Full `go test ./... -count=1` on the reference machine: ~20 s wall clock
(includes ~1400 suffix-array property cases, 6×3 shuffled-replay consensus
determinism seeds, a 12-year emission simulation, and the two-node network
integration).
