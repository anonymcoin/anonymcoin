# ANONYMCOIN Monetary Policy — TIE (Time Integral Emission)

**ANONYMCOIN — Original Project Author and Founder: Iury Lee — Copyright © 2026 Iury Lee**

---

## 1. Design goals (from the master specification)

1. **Infinite supply.** There is no maximum-supply cap. Anonymity networks
   live for a long time; a hard cap creates a terminal security-funding
   cliff.
2. **Infinite supply must never mean uncontrolled inflation.** The annual
   inflation rate is bounded by an absolute permanent ceiling **below 1 %**,
   targets the band **0.80 % – 0.86 %**, and decays asymptotically toward
   zero — approaching it without necessarily reaching it.
3. **The initial mining reward parameter is 50 Coin**, explicitly documented
   and reconciled with the inflation controller.
4. **Deterministic and independently verifiable by every node**, using
   **integer arithmetic only** — floating point is never used in consensus.

## 2. The core invariant

BlockDAG block production is not a fixed-rate stream: parallel blocks widen
the DAG, so paying a constant reward per block would let DAG width inflate
the money supply. ANONYMCOIN therefore pays emission as a **time integral**
over canonical median time:

    reward(B) = emissionPerSecond(B) × dt(B)
    dt(B)     = clamp( MTP(B) − MTP(prev), 0, MaxGapSeconds = 60 )

where MTP is the monotone median-time watermark computed from the last
`MTPWindow = 11` canonical virtual times. Summing rewards telescopes exactly:

    Σ rewards  =  emissionPerSecond × (MTP_final − MTP_initial)

regardless of how many parallel blocks the DAG produced in the same
wall-clock second. A burst of twenty blocks in one second pays one second of
emission (plus a bounded median catch-up of at most ~`MTPWindow/2 + 1`
seconds). Idle periods defer — never multiply — emission, and the per-block
gap clamp (60 s) forgives extreme gaps instead of crediting them.

The full invariant proven by tests:

    circulating supply  <=  Σ integral of the schedule   (equality in the common case)

Coinbase over-claims are clamped by consensus, under-claims are the miner's
loss (see CONSENSUS.md §6).

**Canonical time, not wall time.** The integral runs over *canonical virtual
time* — the manipulation-bounded DAG clock — not over wall clocks. Virtual
time advances at most `VTDriftCap` (60 s) per block, so if the network starts
mining long after genesis, virtual time runs at up to 60 s per block until it
catches up to wall-clock. During catch-up a block may claim up to
`MaxGapSeconds` (60 s) × the per-second rate (up to 3,000 Coin per block in
the bootstrap era); the **totals** remain exactly on schedule because the
schedule is expressed in canonical seconds throughout: the bootstrap phase
always mints exactly 3,153,600,000 Coin, and every calendar year of canonical
time always mints exactly `rate × year-start supply`. While the MTP window
fills (first ~11 blocks) the median lags and alternating blocks may claim 0 —
the telescoping integral is exact regardless.

## 3. Phase I — bootstrap and the 50 Coin reconciliation

During the first `BootstrapSeconds = 2 years` of canonical time:

    emissionPerSecond = 50 Coin   (5,000,000,000 atoms, 1 Coin = 1e8 "anon")

At the one-second target interval this is **exactly the 50 Coin initial
reward parameter per block**, explicitly reconciled with the controller: the
"50 Coin reward" is not a special case in the code — it is the emission
**rate** of the bootstrap phase, and the block reward falls out of the same
integral formula that governs the whole schedule. Bootstrap total:

    3,153,600,000 Coin   (50 Coin/s × 31,536,000 s × 2 years)

## 4. Phase II — supply-based schedule with asymptotic decay

After bootstrap:

    year              = floor((MTP − GenesisTime) / SecondsPerYear)
    rate(year)        = RateBase + RateExcess × 2^(−year / 20)     [integer microBP]
    base(year)        = circulating supply snapshot at the start of `year`
    emissionPerSecond = base × rate / 1e8 / SecondsPerYear         [integer floor]

with `RateBase = 800000` microBP (0.80 %), `RateExcess = 60000` microBP
(0.06 %). The **year-start supply snapshot** makes the realized annual
inflation exactly the schedule rate — no compounding overshoot. A long-tail
clause decays the whole rate toward zero after year 320 (halving every 100
years). All arithmetic is integer (`math/big` is used only to avoid overflow
in the `supply × rate` product; there are no floats).

### Schedule table (measured by the integer simulation)

| Year | Annual rate | Base supply (Coin) | Emission (Coin/year) |
| ---: | ---: | ---: | ---: |
| 0–1 (bootstrap) | 50 Coin per canonical second | — | 1,576,800,000 / year |
| 2 | 0.86 % | 3,153,600,000 | 27,120,960 |
| 3 | 0.86 % | 3,180,720,960 | 27,354,200 |
| 4 | 0.86 % | 3,208,075,160 | 27,589,446 |
| 20 | 0.83 % | 3,263,491,322 | 27,086,978 |
| 40 | 0.815 % | 3,317,890,099 | 27,040,804 |
| 60 | 0.8075 % | 3,372,192,090 | 27,230,451 |
| 80 | 0.80375 % | 3,399,422,541 | 27,322,859 |
| 100 | 0.801875 % | 3,426,745,400 | 27,478,215 |
| 320 | 0.80 % | 3,652,410,229 | 29,219,282 |
| 420 | 0.40 % | 3,711,082,546 | 14,844,330 |
| 520 | 0.20 % | 3,725,926,876 | 7,451,854 |
| 1020 | ≈0.000625 % | 3,733,378,730 | 233,336 |
| → ∞ | → 0 | ~3.74 billion | → 0 |

Properties (all asserted by tests):

- The rate is **monotonically non-increasing** forever.
- It never exceeds **0.86 %** — permanently below the 1 % ceiling.
- It decays **asymptotically**: 0.86 % → 0.83 % → 0.815 % → … → 0.80 %, and
  after year 320 the whole rate halves every century toward zero.
- Realized annual inflation equals the schedule rate within integer
  truncation (`TestEmissionLongHorizon`, `TestInflationYearOneInBand`).

## 5. Rounding dust and other deflationary leaks

- The per-second emission division floors: at most one atom of rounding dust
  per canonical block is never minted.
- Skipped (conflicting) transactions' fees are never credited to anyone.
- Under-claimed coinbases are the miner's loss.
- Duplicate coinbase txids burn duplicates.
Every leak is strictly deflationary; none is inflationary.

## 6. What the supply is used for

The emission base is the **circulating supply** — the sum of all applied
coinbase outputs. Fees are not part of the base (they are transfers, not
issuance). The snapshot is taken when the canonical MTP crosses a year
boundary and is carried through reorgs by the undo journal, so the schedule
is fully determined by the canonical DAG.

## 7. Unit of account

1 Coin = 100,000,000 **anon** (atoms). Supply arithmetic is in atoms
(uint64), which accommodates ≈1.8 × 10^11 Coin — roughly 48,000 years of
schedule headroom.

---

*ANONYMCOIN — IURY LEE © 2026 — BCB EM PÂNICO.*
