# Contributing to ANONYMCOIN

**ANONYMCOIN — Original Project Author and Founder: Iury Lee — Copyright © 2026 Iury Lee**

---

## Ground rules

1. **Consensus changes are protocol changes.** Anything touching
   `/blockdag`, `/consensus`, `/difficulty`, `/anonymbwt` or the wire format
   in `/network` must preserve determinism and be accompanied by a parameter
   justification. Nodes that disagree on parameters are different networks.
2. **Integer-only consensus.** No floating point in consensus code paths.
   `math/big` is acceptable where overflow requires it.
3. **No feature is implemented until its tests pass.** PRs must include
   tests that fail without the change.
4. **Preserve attribution.** The copyright header
   (`ANONYMCOIN — Original Project Author and Founder: Iury Lee — Copyright
   © 2026 Iury Lee`) stays on every file; third-party code keeps its own
   notices and is listed in THIRD_PARTY_NOTICES.md. Never erase legitimate
   credits.

## Developer workflow

```sh
git clone <this repository> anonymcoin-main && cd anonymcoin-main
go build ./...           # vendored deps, offline
go vet ./...             # must be clean
gofmt -l .               # must be empty
go test ./... -count=1   # must pass
```

For consensus work, the property tests are your friend:

- `blockdag.TestCanonicalOrderIndependentOfArrivalOrder` — determinism under
  shuffled arrival.
- `consensus.*` — emission band and schedule monotonicity.
- `tests.TestEndToEndMineStoreRestartSpend` — storage replay determinism.

Add a case there before changing the rule it protects.

## Style

- Standard Go style (`gofmt`), no linter suppressions.
- Comments explain *why*; the package docs explain *what*.
- Errors are wrapped with context (`fmt.Errorf("...: %w", err)`).
- Bounded everything: every decode loop has explicit limits.

## Fuzzing

Before merging decoder or wire changes, run each target for a few minutes:

```sh
go test ./tests/ -run '^$' -fuzz FuzzTxDecode    -fuzztime 120s
go test ./tests/ -run '^$' -fuzz FuzzBlockDecode -fuzztime 120s
```

Any crash is a release blocker.

## Reporting issues

Open an issue with: what you did, what you expected, what happened, and the
output of `anonymcoin version`. Security issues follow SECURITY.md.

---

*THE BLOCKDAG IS THE HEART OF ANONYMCOIN.*
