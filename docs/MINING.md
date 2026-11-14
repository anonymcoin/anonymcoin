# ANONYMCOIN CPU Mining Guide

**ANONYMCOIN — Original Project Author and Founder: Iury Lee — Copyright © 2026 Iury Lee**

<div align="center">

**THE BLOCKDAG IS THE HEART OF ANONYMCOIN.**

**BCB EM PÂNICO.**

**ASICs EM PÂNICO.**

**ANONYMCOIN RODA LIVRE EM QUALQUER CPU.**

</div>

---

## 1. The mining philosophy

A decentralized monetary network should not belong exclusively to
corporations, specialized hardware manufacturers or industrial mining farms.
ANONYMCOIN aims to return mining opportunities to ordinary people. No
permission from ASIC manufacturers should be necessary to participate. No
privileged mining infrastructure should be required. A regular CPU should be
able to participate in the network — and with ANONYMBWT, it does: the PoW is
a suffix-sorting Burrows-Wheeler transform that runs at full speed on an
ordinary laptop core.

## 2. Quick start

```sh
./anonymcoin wallet --datadir ./data create     # prints your payout address
./anonymcoin node --config config.json --datadir ./data \
                 --mine --workers "$(nproc)" --payout <address>
```

That is the whole setup. The miner:

1. reads the current DAG tips (heaviest first, up to 8 parents per block —
   parallel blocks are *wanted* in a BlockDAG);
2. assembles a template: coinbase (emission reward + fees) and mempool
   transactions;
3. searches ANONYMBWT nonces across all workers;
4. submits solved blocks to the DAG and relays them to peers.

## 3. Benchmark your CPU

```sh
./anonymcoin bench --iters 100
# or
make bench
```

Reference numbers (see docs/BENCHMARKS.md): ~5.36 ms per hash per core
(~186 H/s) on an Intel Xeon vCPU, zero allocations in the hot loop. At
`GenesisDifficulty = 64` one core finds a block roughly every 0.34 s — a
single laptop CPU comfortably covers the one-second network target.

## 4. What your work buys

Your blocks:

- carry the selected-parent chain forward (difficulty retargets along it),
- widen the DAG (parallel honest blocks are free capacity, not competition —
  the canonical order includes them all),
- earn the emission integral (see MONETARY_POLICY.md): during bootstrap,
  up to the gap-clamped 60 s × 50 Coin per block; afterwards the
  supply-based schedule (0.86 % → 0.80 % → →0).

Fees on relayed transactions go to the block that applies them canonically.

## 5. Honest hardware claims

ANONYMBWT is *designed* to resist ASIC/GPU centralization: the dominant cost
(~80 % of hash time) is a branchy, data-dependent suffix sort. No absolute
resistance guarantee is made — measured numbers only, in
docs/BENCHMARKS.md. What is guaranteed: a regular CPU is a first-class
network participant from block one, at genesis difficulty.

## 6. Mining etiquette

- Set `--workers` to your real core count; the miner re-templates every
  2 seconds so tips stay fresh.
- Include the coinbase aux payload (automatic) — it keeps coinbase txids
  unique.
- Do not pre-mine with withheld blocks; withheld blocks lose their emission
  position to the canonical order like any other block.

---

*ANONYMCOIN — IURY LEE © 2026 — ANONYMCOIN RODA LIVRE EM QUALQUER CPU.*
