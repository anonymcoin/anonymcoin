# Building ANONYMCOIN

**ANONYMCOIN — Original Project Author and Founder: Iury Lee — Copyright © 2026 Iury Lee**

---

## 1. Requirements

- **Go 1.24 or newer** (any platform Go supports; the reference build used
  Go 1.24.3 on linux/amd64).
- **No cgo.** The build is pure Go.
- **No network access needed to build.** All third-party dependencies are
  vendored in `vendor/` and the build uses them automatically.

## 2. Build

```sh
make build            # builds ./anonymcoin
# or, without make:
go build -o anonymcoin ./cmd/anonymcoin
```

Cross-compile examples:

```sh
GOOS=windows GOARCH=amd64 go build -o anonymcoin.exe ./cmd/anonymcoin
GOOS=darwin  GOARCH=arm64 go build -o anonymcoin      ./cmd/anonymcoin
GOOS=linux   GOARCH=arm64 go build -o anonymcoin-arm  ./cmd/anonymcoin
```

Reproducibility: `go vet ./...` and `gofmt -l .` must be clean; the module
graph is pinned in `go.mod` and vendored under `vendor/`.

## 3. Test, vet, fuzz, benchmark

```sh
make test             # go test ./... -count=1 -timeout 400s
make vet              # go vet ./...
make bench            # PoW benchmarks
# targeted fuzzing (write corpus under tests/testdata):
go test ./tests/ -run '^$' -fuzz FuzzTxDecode    -fuzztime 60s
go test ./tests/ -run '^$' -fuzz FuzzBlockDecode -fuzztime 60s
```

The full suite takes well under a minute on a laptop and includes the
consensus determinism property tests, the emission schedule proofs and the
two-node network integration.

## 4. Running a node

```sh
./anonymcoin node --help
```

Minimal private-node flow:

```sh
# 1. Wallet — prints the 24-word recovery phrase ONCE; write it on paper.
./anonymcoin wallet --datadir ./data create
# enter a passphrase (>= 12 chars, confirmed); the first address is printed

# 2. Config: copy config.example.json to config.json and set
#    mining.payout_address to the printed address.

# 3. Run and mine
./anonymcoin node --config config.json --datadir ./data \
                  --mine --workers "$(nproc)" --payout <address>

# 4. Observe (token is generated into config.json on first run)
./anonymcoin version
```

Flags: `--config`, `--datadir`, `--mine`, `--workers`, `--payout`,
`--listen`, `--no-rpc`. Subcommands: `node`, `wallet
create|restore|show-mnemonic|newaddress|newaccount|addresses|keycount|watch|export`,
`send`, `bench`, `version`.

The `send` subcommand builds and signs a transaction offline against the
local block store, prints the raw hex, and (when the node's RPC is
reachable) submits it with the `sendraw` RPC method.

### Wallet hardening notes (hardening release)

- The wallet file is **version 2**: the encrypted content is the BIP-39
  24-word phrase plus per-account counters, AES-256-GCM under **scrypt
  N=2^17 (128 MiB, r=8, p=1)** by default, or **Argon2id (64 MiB, t=3,
  4 lanes)** via `wallet.CreateWithKDF` in Go. Legacy v1 files still open
  and are upgraded on re-save.
- Keys derive as `m/44'/2026'/account'/0'/index'` (SLIP-0010 Ed25519,
  hardened-only). On open every account derives its used addresses plus a
  20-address lookahead window, so mnemonic recovery sees funds received at
  not-yet-allocated addresses.
- `restore` re-creates a wallet from an existing phrase (checksum-validated
  before anything is written). `show-mnemonic` re-prints the stored phrase.
- `watch` registers a watch-only address: balance visibility, no signing
  capability, survives export.
- `export --out FILE` writes a full encrypted backup under a NEW passphrase
  (must differ from the wallet passphrase).
- Recovery procedures and production warnings: [SECURITY.md §7](SECURITY.md).

## 5. Configuration

Copy `config.example.json` to `config.json`. Notable fields:

- `p2p.listen_addr` — inbound TCP listener (`""` disables inbound);
  onion/eepsite operators forward their service to this address.
- `p2p.peers` — the explicit private peer list. Every entry carries the
  peer's pinned `cert_fingerprint` / `falcon_fingerprint` (or
  `trust_on_first_use: true` to learn them on first contact).
- `p2p.tor_socks_addr` / `p2p.i2p_sam_addr` — local proxy endpoints
  (defaults `127.0.0.1:9050` and `127.0.0.1:7656`).
- `rpc.listen_addr` / `rpc.token` — loopback-only control interface.
- `consensus` — full parameter set. **Nodes with different consensus
  parameters will not converge**; treat them as different networks.

## 6. Tor and I2P setup (simple mode)

**Tor.** Run tor with `SocksPort 9050` and expose the node through an onion
service whose `HiddenServicePort` forwards to the node's `p2p.listen_addr`.
Add remote operators as peers with `kind: "tor"`, address `<onion>.onion:8611`.
Outbound connections to onion peers go through the SOCKS5 proxy; Tor resolves
`.onion` names at the proxy, so nothing leaks to the local resolver.

**I2P.** Run i2pd with the SAM bridge enabled (default `127.0.0.1:7656`).
Outbound: peers configured with `kind: "i2p"` and the destination base64.
Inbound: the node opens a SAM session with a fresh **transient** destination
per accept-loop iteration and logs it at startup — publish that destination
to your peers out of band.

## 7. Data directory layout

```
data/
  identity.json   node TLS + Falcon-512 keys (0600, unencrypted by design)
  blocks.dat      CRC-protected append-only block store
  wallet.json     KDF (scrypt/Argon2id) + AES-256-GCM encrypted HD keystore (0600)
```

Back up `wallet.json` AND the 24-word recovery phrase together — the phrase
alone is sufficient to recover funds (the file alone is not, if you forget
the passphrase); the file plus passphrase recovers everything including
account counters. `identity.json` may be copied to migrate a node identity
between machines.

## 8. Packaging

`make zip` produces `anonymcoin-main.zip` containing the complete source
tree (including `vendor/`), documentation, configuration example and tests —
independently compilable and auditable offline.
