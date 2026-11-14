<div align="center">

# ANONYMCOIN

**A private, lightweight, CPU-minable BlockDAG cryptocurrency, written from scratch in Go.**

**THE BLOCKDAG IS THE HEART OF ANONYMCOIN.**

**BCB EM PÂNICO.**

**ASICs EM PÂNICO.**

**ANONYMCOIN RODA LIVRE EM QUALQUER CPU.**

</div>

---

**Original Project Author and Founder: Iury Lee**
**Copyright © 2026 Iury Lee**

---

## What is ANONYMCOIN?

ANONYMCOIN is an independent cryptocurrency built entirely from scratch in Go.
It is not a fork of any existing implementation. It combines:

- **ANONDAG-1** — an original BlockDAG consensus engine: blocks reference
  multiple parents, parallel blocks are accepted, and every node derives the
  identical canonical order deterministically from the DAG alone.
- **ANONYMBWT** — an original CPU-oriented proof-of-work forked in design
  from AstroBWT (studied from its public use in Kaspa) and reimplemented from
  zero: BLAKE2b → deterministic 64 KiB expansion → suffix-array
  Burrows-Wheeler transform → BLAKE2b. A regular CPU is a first-class miner.
- **TIE — Time Integral Emission** — an infinite-supply monetary policy with
  an inflation controller: a 50-Coin-per-canonical-second bootstrap phase
  (the explicit reconciliation of the initial 50 Coin reward parameter),
  then supply-based emission whose annual rate starts at 0.86 %, decays
  asymptotically toward 0.80 % and ultimately toward zero — permanently
  below the 1 % ceiling. Integer-only, no floating point in consensus.
- **Private networking** — TLS 1.3 with fixed, pinned node keys, a
  Falcon-512 (FN-DSA-512, FIPS 206) post-quantum handshake signature,
  explicit peer configuration only: **no public peer directory, no address
  gossip**. Optional Tor (SOCKS5) and I2P (SAM v3) transports.
- **One-second block target** with a deterministic retarget rule along the
  selected-parent chain.

A decentralized monetary network should not belong exclusively to
corporations, specialized hardware manufacturers or industrial mining farms.
ANONYMCOIN aims to return mining opportunities to ordinary people. No
permission from ASIC manufacturers should be necessary to participate. No
privileged mining infrastructure should be required. A regular CPU should be
able to participate in the network.

## Status

Version 1.0.0 **hardening release** — production-readiness baseline for the
external audit. This release adds BIP-39 mnemonic wallets (24 words, SLIP-0010
Ed25519 derivation), raised KDF parameters (scrypt 128 MiB default, Argon2id
option), replay-hardened transaction digests, rate limiting on RPC and P2P,
secure key wipe, and two consensus-critical fixes (see SECURITY.md §3). All
consensus-critical components are implemented and tested, including the race
detector over the full suite. This software has **not** received an
independent security audit; do not trust it with real value until it has —
read [SECURITY.md](SECURITY.md) first.

## Quick start

```sh
# Build (Go 1.24 or newer, no cgo, vendored dependencies included)
make build
# or: go build -o anonymcoin ./cmd/anonymcoin

# Create a wallet — prints the 24-word recovery phrase ONCE. Write it down.
./anonymcoin wallet --datadir ./data create

# Run a node (creates ./data, config.json)
./anonymcoin node --mine --workers 4 --payout <address>

# Mine a benchmark
./anonymcoin bench --iters 100

# Run the full test suite
make test
```

### Wallet commands

```sh
./anonymcoin wallet --datadir ./data create            # new 24-word phrase (shown once)
./anonymcoin wallet --datadir ./data restore           # recover from an existing phrase
./anonymcoin wallet --datadir ./data show-mnemonic     # print the stored phrase again
./anonymcoin wallet --datadir ./data newaddress        # next address of account 0
./anonymcoin wallet --datadir ./data newaccount        # HD account N
./anonymcoin wallet --datadir ./data addresses         # all controlled addresses
./anonymcoin wallet --datadir ./data watch --address A # watch-only (cannot sign)
./anonymcoin wallet --datadir ./data export --out backup.json  # encrypted backup
```

**PRODUCTION WARNING:** the 24-word phrase IS the wallet. Anyone holding it
holds the funds. There is no reset and no support channel. The optional BIP-39
passphrase is not stored and cannot be recovered. Recovery procedures and the
full threat model are in [SECURITY.md](SECURITY.md §7).

## Repository layout

| Module | Purpose |
| --- | --- |
| `/blockdag` | ANONDAG-1 engine: canonical order, UTXO, conflicts, orphans |
| `/consensus` | Consensus constants, virtual time, TIE emission controller |
| `/difficulty` | Selected-parent-chain retarget rule |
| `/anonymbwt` | ANONYMBWT proof-of-work (expansion, suffix sort, BWT) |
| `/mining` | Mempool and multi-worker CPU miner |
| `/network` | TLS 1.3 + pinned keys, Falcon-512 handshake, Tor/I2P transports |
| `/privacy` | Privacy policy enforcement and address validation |
| `/transactions` | Wire format, digests, signatures, spend rules |
| `/cryptography` | BLAKE2b, Ed25519, Falcon-512 adapter, addresses |
| `/hd` | BIP-39 24-word mnemonics, SLIP-0010 Ed25519 hierarchical derivation |
| `/wallet` | HD keystore (mnemonic + BIP-44-style accounts), KDF (scrypt/Argon2id) + AES-256-GCM, watch-only, encrypted export |
| `/internal/limit` | shared token-bucket rate limiters (RPC + P2P DoS defense) |
| `/storage` | CRC-protected append-only block store with replay |
| `/config` | Node configuration |
| `/rpc` | Loopback JSON control interface |
| `/tests` | Integration suite and fuzz targets |
| `/cmd/anonymcoin` | The node, wallet and benchmark binary |
| `/docs` | Protocol, benchmarks, roadmap |

## Documentation

- [CONSENSUS.md](CONSENSUS.md) — the ANONDAG-1 specification
- [MONETARY_POLICY.md](MONETARY_POLICY.md) — TIE emission and the 50 Coin reconciliation
- [BLOCKDAG_ARCHITECTURE.md](BLOCKDAG_ARCHITECTURE.md) — engine internals
- [ANONYMBWT.md](ANONYMBWT.md) — the PoW algorithm and its AstroBWT lineage
- [BUILD.md](BUILD.md) — compilation and operation
- [SECURITY.md](SECURITY.md) — threat model and reporting
- [CONTRIBUTING.md](CONTRIBUTING.md) — development workflow
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) — third-party components
- [docs/PROTOCOL.md](docs/PROTOCOL.md) — wire protocol
- [docs/BENCHMARKS.md](docs/BENCHMARKS.md) — measured numbers
- [docs/ROADMAP.md](docs/ROADMAP.md) — honest future work

## Test matrix

| Area | Coverage |
| --- | --- |
| Consensus determinism | identical canonical order across shuffled arrival orders, 6 seeds × 3 shuffles |
| Emission | telescoping integral exactness, burst bounded catch-up, gap clamp, 12-year horizon inside the 0.80–0.86 % band |
| Difficulty | retarget clamps, timestamp-manipulation bounds |
| ANONYMBWT | suffix-array property tests vs. naive comparator (200 cases), cross-workspace determinism, PoW roundtrip |
| Conflicts | double-spend resolution by canonical order, coinbase clamping, coinbase maturity |
| DAG safety | late-block rejection, orphan redrive, duplicate/invalid handling |
| Networking | pinned TLS 1.3 mutual auth (honest pair accepted, strangers rejected), Falcon-512 hello sign/verify + zero-nonce replay guard, SOCKS5 and SAM clients against fake bridges, full two-node sync, ping amplification cap |
| Rate limiting | token buckets, per-IP tables with bounded memory, RPC connection flood shedding, overflow-rejecting amount parsing |
| Mnemonic / HD | official BIP-39 vectors (encode + seed), checksum rejection of typos, official SLIP-0010 Ed25519 vectors, hardened-only enforcement, full create→restore roundtrip with retyped phrases |
| Security regressions | foreign-pubkey theft block rejected with reason, unbalanced transaction cannot mint, late block leaves no ghost node, cross-network + domain-separated replay protection |
| Wallet | encrypted-at-rest checks (phrase, windows, seed), raised-scrypt/Argon2id parameters on disk, encrypted export roundtrip, legacy v1 open + upgrade, key wipe on Close, watch-only cannot sign |
| Storage | roundtrip, torn-tail truncation, deterministic replay |
| Concurrency | the entire suite under `-race` |
| Fuzzing | transaction and block decoders (`go test -fuzz`) |

## License

Copyright © 2026 Iury Lee. See [LICENSE](LICENSE). Third-party components and
their licenses are preserved in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

---

**ANONYMCOIN — IURY LEE © 2026**

**THE BLOCKDAG IS THE HEART.**

**ASICs EM PÂNICO.**

**BCB EM PÂNICO.**

**ANONYMCOIN RODA LIVRE EM QUALQUER CPU.**
