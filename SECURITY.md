# ANONYMCOIN Security Policy and Threat Model

**ANONYMCOIN — Original Project Author and Founder: Iury Lee — Copyright © 2026 Iury Lee**

---

## 1. Honest position

ANONYMCOIN v1.0.0 (hardening release) is a **reference implementation that has
not received an independent security audit**. Nothing in this document, the
source code or the tests should be read as a claim that the software is
completely secure. It must pass an external audit **before** it is trusted
with real value. This release is the audit-readiness baseline: constant-time
authentication, no panics on the consensus path, checked integer arithmetic,
bounded resources, and regression tests that encode every security-critical
rule.

## 2. Assets and adversaries

| Asset | Adversary capability considered |
| --- | --- |
| Canonical ledger / consensus | hashrate up to ~50 % of the network; block withholding; timestamp games |
| Funds (UTXO) | key theft, transaction forgery, replay across networks, mempool DoS |
| Wallet secrets | disk access (at-rest encryption), memory scraping (best-effort wipe), mistyped recovery |
| Node operation | resource exhaustion, eclipse attempts, peer enumeration, RPC abuse |
| Network privacy | traffic observers, malicious peers, quantum-capable identity forgery (future) |

## 3. Consensus attacks

**Majority hashrate.** As with all PoW systems, an adversary with > 50 % of
the work can dominate PathScore growth and reorder the unfinalized window.
Finalization (`FinalizedDepth = 2000`, ~33 min) is probabilistic. **No formal
security proof is provided**; the argument is the standard work-based one.

**Parallel-block inflation.** DAG width does not multiply emission: rewards
are the integral of the schedule over canonical median time, and parallel
blocks in the same second share that second (tested: 20-block burst pays a
bounded catch-up, never 20 seconds).

**Timestamp manipulation.** Virtual time advances at most `VTDriftCap` (60 s)
per block; the emission gap is clamped to 60 s per canonical block; the
difficulty retarget reads monotone VT along the selected-parent chain.
Residual risk: a sustained majority attacker can still push virtual time
forward gradually — the standard time-warp exposure, mitigated but not
eliminated, and worse for emission than in a chain because the emission
clock *is* the median time. Documented openly; see docs/ROADMAP.md.

**Conflicting transactions.** Double spends resolve deterministically by
canonical order: first application consumes the UTXO, later conflicts are
skipped, conflicting fees vanish (deflationary). Coinbase over-claims are
clamped to the entitled value. `TestDoubleSpendConflictResolution` proves a
single payment lands.

**Consensus-critical application checks (hardening release).** The block
application path independently enforces, for every regular transaction:

1. **Pay-to-public-key-hash binding** — the input's embedded public key must
   hash to the pubkey hash the referenced output is locked to. A miner can
   assemble any structurally valid block, so this check cannot live only in
   the mempool path. A block spending a foreign UTXO under the attacker's
   key is rejected (`TestRegressTheftViaForeignPubKeyRejected`).
2. **Output conservation** — outputs ≤ inputs per transaction. An unbalanced
   transaction would wrap the uint64 fee arithmetic (`inSum - outSum`
   underflow) and inflate the coinbase budget, minting value
   (`TestRegressUnbalancedTxCannotMint`).

Every sum that could conceivably overflow under operator-supplied parameters
is checked; overflow behavior is deterministic (reject or saturate), never
wrapping. A block rejected during application leaves no ghost node in the
block index (`TestRegressLateBlockLeavesNoGhostNode`).

**Replay across networks.** Every transaction digest is
`BLAKE2b-256("ANONYMCOIN/TX-DIGEST/1" ‖ chainTag ‖ sig-zeroed-encoding)`.
Two layers: the domain string separates transaction signatures from every
other hash in the protocol; the chain tag (first 4 bytes of the genesis
hash) separates independent ANONYMCOIN networks.
`TestReplayProtectionChainTagBinding` and
`TestReplayProtectionDomainSeparation` prove both layers.

**Block spam / orphan floods.** Every block must satisfy full PoW and
validation before touching state; the orphan pool is bounded (2048, 2 h TTL);
invalid blocks are remembered.

## 4. Cryptography

- BLAKE2b-256 hashing (RFC 7693 vectors tested), Ed25519 (Go standard
  library) for funds, TLS 1.3 transport.
- **Falcon-512 / FN-DSA-512 (FIPS 206)** signs the P2P handshake with a fresh
  CSPRNG session nonce per connection — a captured hello can never be
  replayed; zero-nonce greetings are refused (`TestHelloRejectsZeroNonce`).
  Honest caveat: the TLS transport itself uses classical Ed25519
  certificates; the post-quantum layer protects *handshake identity*, not
  the TLS key exchange. A quantum adversary recording traffic today could in
  principle attack the classical transport later — this is disclosed, not
  hidden (see docs/ROADMAP.md for the hybrid-TLS migration path).
- **Recovery phrases: BIP-39 24-word English**, verified against the official
  test vectors (`hd` package). Mnemonic-to-seed uses the standard fixed
  PBKDF2-HMAC-SHA512 / 2048 rounds — this figure is part of the BIP-39
  interoperability contract and must not be "hardened" ad hoc; at-rest
  strength comes from the wallet-file KDF below.
- **Hierarchical keys: SLIP-0010 Ed25519** (hardened-only, spec vectors
  tested), BIP-44-style paths `m/44'/2026'/account'/0'/index'`. Non-hardened
  Ed25519 steps are rejected, never improvised.
- **Wallet at rest (v2): AES-256-GCM under a strong KDF** — scrypt
  **N=2^17 (128 MiB), r=8, p=1** by default, or **Argon2id (64 MiB, t=3,
  4 lanes)** via `wallet create-with-kdf`-style options; parameters are
  stored in the file and validated on open (a hostile wallet file cannot
  OOM the node). Legacy v1 files (N=2^15) still open and are upgraded on
  re-save. `TestEncryptedAtRest` proves no phrase, seed or key material at
  rest; `TestScryptRaisedParams` / `TestArgon2idOption` pin the parameters.
- **Secure memory handling:** the wallet zeroizes private keys, the BIP-39
  seed and the phrase buffer on `Close()`. **Honest limitation:** Go's
  garbage collector may retain transient copies; zeroization clears the
  buffers the wallet controls for its lifetime — it is defense in depth,
  not a guarantee against a compromised process, core dumps or swap.
  High-value operators should disable swap and use full-disk encryption.
- The wallet passphrase minimum is **12 characters** (raised from 8): the
  file encrypts the recovery phrase itself.
- Node identity keys are stored unencrypted (0600) by design — they identify
  the node, not funds.

## 5. Network privacy — what is enforced vs. claimed

**Enforced in code:** no public peer directory; no address-gossip message
exists on the wire; explicit peer configuration with pinned certificate and
Falcon-512 fingerprints (strict pins, or opt-in TOFU); TLS 1.3 only;
loopback-only RPC with token auth; optional Tor/I2P transports.

**Not claimed:** anonymity against a global passive observer, protection
from a malicious ISP correlating traffic, or invisibility of public TCP
listeners. Privacy is implemented through verifiable networking protections
(pinning, no gossip, onion/eepsite transports), not through claims of
absolute invisibility. A node operator chooses its own peers and owns its
exposure.

## 6. Resource safety and DoS limits (hardening release)

**Consensus/storage:** hard bounds on block size (1 MB), transaction size,
input/output counts, aux payload; strict decoders reject trailing bytes and
non-canonical encodings (fuzz targets exercise them); every storage record
is CRC-protected and torn tails are truncated on open; KDF parameters from
files are range-checked before use; consensus params are range-checked
(`Params.Validate`) so every overflow guard above is a true last resort.

**RPC (loopback only):** constant-time token comparison; one request per
connection capped at 64 KiB with a 10 s whole-exchange deadline; per-source
connection rate limiting (8/s, burst 16) with a bounded IP table (idle
eviction); global concurrency cap (16 connections, load shed above it);
`ParseAmount` rejects overflow instead of wrapping.

**P2P:** handshake (TLS + Falcon hello) runs under a hard 15 s deadline
(slowloris defense); per-frame read deadline of 120 s in steady state; every
frame rate-limited per peer (50 msg/s, 8 MiB/s with bursts — exceed it and
the peer is disconnected); ping payloads above 1 KiB are a protocol
violation (echo-amplification cap); inbound connections beyond `MaxPeers`
are refused at the registry; sync sessions are capped at 200k blocks per
peer and re-request after; peer writes carry a 10 s deadline so a stalled
reader cannot hold the peer lock.

## 7. Recovery procedures

**Recovery phrase (24 words).** The phrase IS the wallet. `anonymcoin wallet
create` prints it **exactly once** — write it on paper, store offline, never
photograph it. To recover on any machine:

```
anonymcoin wallet --datadir DIR restore
recovery phrase (24 words): <paste the 24 words>
optional BIP-39 passphrase (empty if none): <empty unless you set one>
```

The phrase is checksum-validated **before** any file is written, so a typo
fails loudly instead of silently creating an empty wallet. Restored wallets
re-derive used addresses plus a 20-address lookahead window (BIP-44 gap
semantics), so funds received at any not-yet-allocated address remain
visible.

**BIP-39 passphrase ("25th word").** Optional, not stored, not recoverable.
If you set one, losing it loses the funds behind the phrase even with the
words intact. Empty is the default.

**Encrypted backup.** `anonymcoin wallet --out FILE export` re-encrypts the
full keystore (phrase, counters, accounts, watch entries) under a **new**
passphrase. The backup opens with `wallet.Open(FILE, backup-passphrase)`;
the backup passphrase must differ from the wallet passphrase and the tool
refuses identical ones. Losing the backup passphrase loses the backup
contents (the original wallet file still opens).

**Watch-only entries** hold no keys and can never sign; they survive export
and recovery only if re-added (they are part of the wallet file, not the
phrase).

**Lost wallet.json, phrase intact** → restore from the phrase (above).
**Lost phrase, wallet.json intact** → `wallet show-mnemonic` (needs the
passphrase) and re-record it immediately. **Both lost** → the funds are
unrecoverable; there is no reset, no support channel, no backdoor.

## 8. Reporting

Report vulnerabilities to the project maintainer privately and allow a
reasonable coordinated-disclosure window. Please include reproduction steps
and affected components. Do not test attacks against networks you do not
operate.

## 9. Known limitations (summary)

1. No independent security audit yet — required before real-value use.
2. No formal consensus security proof.
3. Classical TLS key exchange (PQ handshake identity only).
4. Time-warp exposure bounded but not eliminated.
5. UTXO model is canonical-position-dependent (not per-past multiset).
6. Full-node memory grows with chain history (no header pruning yet).
7. Go GC retention makes memory wipe best-effort (see §4).
8. BIP-39 seed derivation is fixed at the standard 2048 PBKDF2 rounds for
   interoperability; passphrase strength carries the remaining entropy.

Each item is tracked in docs/ROADMAP.md with the intended direction.

---

*ANONYMCOIN — IURY LEE © 2026.*
