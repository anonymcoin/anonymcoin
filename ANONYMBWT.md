# ANONYMBWT — The ANONYMCOIN Proof-of-Work

**ANONYMCOIN — Original Project Author and Founder: Iury Lee — Copyright © 2026 Iury Lee**

**ASICs EM PÂNICO. ANONYMCOIN RODA LIVRE EM QUALQUER CPU.**

---

## 1. Lineage and attribution

ANONYMBWT is an independently developed fork of the **AstroBWT** proof-of-work
in the sense of design lineage: we studied the publicly available AstroBWT
algorithm as used by Kaspa (kaspad, ISC License) and used its *shape* —
seed → expand to a ~64 KiB buffer → Burrows-Wheeler transform → hash — as the
technical starting point for a new construction.

**No source code was copied.** The implementation in `/anonymbwt` was written
from scratch in Go with different primitives and a different sorter:

| Component | AstroBWT (Kaspa) | ANONYMBWT-1 |
| --- | --- | --- |
| Outer hash | SHA3-256 | BLAKE2b-256 |
| Expansion | PRNG-based `rand.Expand` | documented 8-lane xorshift64* mixing |
| Sorter | SA-IS suffix sort (SIMD-assisted) | Manber-Myers prefix doubling with counting sort |
| BWT indexing | 64 KiB buffer, index-word addressing | 64 KiB buffer, implicit −1 sentinel second key |
| Digest mix | SHA3-256 of BWT output | BLAKE2b-256 of BWT output + three suffix indices |

The ISC license notice of the studied implementation is preserved in
THIRD_PARTY_NOTICES.md. Every modification relative to the studied design is
the table above; nothing has been removed or obscured.

## 2. Specification (ANONYMBWT-1)

```
Input:  preimage (the canonical header encoding; the nonce is its last field)

1. seed = BLAKE2b-256(preimage)                                (32 bytes)

2. buf = expand(seed)                                          (65536 bytes)
     lanes[0..3] = LE64(seed[8j .. 8j+8])
     lanes[4..7] = LE64(seed[8(j-4) ..]) ^ 0xA5A5A5A5A5A5A5A5 ^ j
     for i in 0..8191:
         j = i & 7
         x = lanes[j]; x ^= x<<13; x ^= x>>7; x ^= x<<17; lanes[j] = x
         word = x ^ rotl64(lanes[(j+1) & 7], 23) ^ uint64(i) * 0x9E3779B97F4A7C15
         LE64-store word at buf[8i]
         if i % 1024 == 0: lanes[(i>>10) & 7] ^= LE64(seed[((i>>10)*8) % 32 ..])

3. sa = suffixArray(buf)     // Manber-Myers prefix doubling; counting
                             // sort per round; -1 sentinel second key for
                             // suffixes that reach past the buffer end

4. bwt[i] = buf[(sa[i] + 65535) % 65536]                       (the BWT)

5. out = BLAKE2b-256( bwt || LE32(sa[0]) || LE32(sa[32768]) || LE32(sa[65535]) )
```

**PoW check.** `out` read as a big-endian 256-bit integer must be `<=`
`target`, where `target = floor((2^256 − 1) / difficulty)`. Difficulty is an
unsigned 64-bit consensus value.

All steps are integer operations on little-endian-decoded words with a fixed
byte layout — the digest is bit-identical on any platform.

## 3. Why this shape resists specialized hardware — honestly

The Burrows-Wheeler transform requires **suffix sorting**: a branchy,
data-dependent, memory-treading pass over the whole 64 KiB buffer whose
access pattern depends on the buffer contents, which depend on the nonce.
That is the property that made AstroBWT attractive for CPU mining, and it is
preserved here:

- **CPU-friendly.** ~5.4 ms/hash per core on the reference machine
  (docs/BENCHMARKS.md), zero allocations in the hot loop, ~1 MB working set
  per thread — a laptop CPU saturates the one-second block target
  comfortably at GenesisDifficulty 64 (~0.34 s/hash-target per core).
- **GPU-unfriendly (qualitatively).** Suffix sorting parallelizes poorly;
  the frequent data-dependent branches defeat wide SIMD lanes, and each
  independent hash needs its own ~1 MB working set.
- **ASIC-unfriendly (qualitatively).** The dominant cost is a general-purpose
  sort with random memory traffic, not a fixed arithmetic pipeline.

**What we do not claim:** no absolute, quantitative ASIC/GPU-resistance
guarantee is made. The claim "designed to resist" is honest design intent;
measuring it requires adversarial hardware work that has not been performed.
What is measured and published: CPU hash rate, per-stage timings, memory
footprint (docs/BENCHMARKS.md). The suffix sort is ~80 % of the runtime —
the property we rely on is exactly where the time goes.

## 4. Implementation notes

- `Workspace` reuses all buffers across hashes; mining never allocates in
  the hot loop (`BenchmarkDigestFull`: 3 allocs/op total, 420 B — all in
  setup amortization, 0 B/op in steady state for the sort itself).
- The prefix-doubling sorter terminates when all ranks are distinct
  (≤ 17 rounds for 64 KiB) and is verified against a naive suffix
  comparator over 200 randomized adversarial buffers (runs, low-entropy
  repetition, all-equal bytes) plus fixed strings.
- Digest determinism is asserted across independent workspaces; the
  cross-platform guarantee follows from the fixed byte layout.

## 5. Test and benchmark inventory

| Test | What it proves |
| --- | --- |
| `TestSuffixArrayMatchesNaive` | suffix order equals the naive comparator order |
| `TestDigestDeterministic` | same input + independent workspace → same digest |
| `TestTargetAndPoWRoundtrip` | target encoding at difficulty 1 and 2^32 |
| `TestMineAndVerify` | a mined solution verifies with an independent workspace |
| `BenchmarkDigestFull` | the end-to-end hash rate |
| `BenchmarkSuffixSort` | the dominant stage in isolation |

---

*ANONYMCOIN — IURY LEE © 2026 — BCB EM PÂNICO.*
