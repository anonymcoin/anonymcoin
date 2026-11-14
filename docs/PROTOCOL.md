# ANONYMCOIN Wire Protocol (ANONDAG/1)

**ANONYMCOIN — Original Project Author and Founder: Iury Lee — Copyright © 2026 Iury Lee**

---

## 1. Transport

Every connection is **TLS 1.3** (no downgrade) over one of:

- plain TCP;
- Tor: client dials through a local SOCKS5 proxy (RFC 1928, no-auth);
  inbound arrives through the operator's onion service;
- I2P: SAM v3 (`HELLO` → `SESSION CREATE ... DESTINATION=TRANSIENT` →
  `STREAM CONNECT/ACCEPT`), one transient destination per accept round.

Mutual authentication: both sides present self-signed Ed25519 certificates
whose fingerprints must be pinned (strict pin or opt-in TOFU). After TLS,
both sides send the Falcon-512-signed Hello (§3).

## 2. Framing

```
magic(4) 'ANW1' | version(2 BE) | type(1) | reserved(1) | length(4 LE) | payload
```

`length <= 9 MiB`. Version 1. Unknown types are a protocol error (connection
closed). Types:

| Type | Name | Payload |
| ---: | --- | --- |
| 1 | Hello | Falcon-signed handshake (§3) |
| 2 | Ping | echo payload (hard cap 1 KiB — larger pings are a protocol violation, never echoed) |
| 3 | Pong | echo payload |
| 4 | Block | full canonical block encoding |
| 5 | Tx | full transaction encoding |
| 6 | GetRange | 16 bytes: from(8 BE) to(8 BE), canonical index range [from, to) |
| 7 | Range | 2 bytes BE: block count, followed by that many Block frames |

### Resource limits (hardening release)

| Limit | Value | Rationale |
| --- | --- | --- |
| Handshake (TLS + hello) deadline | 15 s | slowloris defense |
| Steady-state read deadline | 120 s per frame | idle peers release memory |
| Peer write deadline | 10 s per frame | a stalled reader cannot hold the peer lock |
| Per-peer message rate | 50 msg/s, burst 100 | exceeded → disconnect |
| Per-peer byte rate | 8 MiB/s, burst 16 MiB | exceeded → disconnect |
| Ping payload | ≤ 1024 bytes | echo-amplification cap |
| Inbound peer cap | `p2p.max_peers` | refused at the registry |
| Sync session cap | 200,000 blocks per peer session | the peer re-requests after; no pinned goroutine |
| RPC request line | 64 KiB, one per connection, 10 s deadline | loopback DoS bound |
| RPC auth | constant-time token compare | no timing side channel |
| RPC connection rate | 8/s per source IP, burst 16, bounded IP table | flood shedding |

## 3. Hello (Falcon-512 signed)

```
magic(4, = first 4 bytes of genesis hash)
version(2 BE)
falconPubLen(2 BE) | falconPub (897 bytes)
nonce(32)          random per connection
tipIndex(8 BE) | tipScore(8 BE) | tipHash(32)
sigLen(2 BE) | sig (Falcon-512 CT format, ~666-809 bytes)
```

The signature covers the payload with the `sigLen/sig` fields zeroed.
Receivers verify the magic, the version, the Falcon signature, and the
Falcon public key fingerprint against the pin set. The tip announcement
drives synchronization.

The 32-byte nonce is a fresh CSPRNG value per connection and binds the
hello to this TLS session: a captured hello can never be replayed as a
fresh handshake, and a hello carrying an all-zero nonce is refused before
signature verification.

## 4. Session flow

1. TLS handshake (pinned).
2. Hello exchange (Falcon-512 verified both ways).
3. If the remote tip index exceeds the local one, the local side pulls
   ranges; otherwise it serves. One reader per connection at any time.
4. Steady state: `Block`/`Tx` broadcast frames, `Ping`/`Pong` keepalives.

## 5. Synchronization

`GetRange [from, to)` requests canonical blocks by index. The serving side
clamps `to` to its canonical count, answers with a `Range` header (count) —
0 means "nothing beyond your tip; you are synchronized" — followed by up to
256 `Block` frames. The requesting side accepts each block through its full
validation pipeline (identical to locally mined blocks). Repeat until the
header count is 0.

Ranges are canonical-index based, which is possible exactly because the
canonical order is deterministic: both sides agree on what "index i" means.

## 6. Privacy properties of the protocol

- There is **no peers/addr message**. A compromised peer cannot enumerate
  the network beyond its own configured peers.
- Peer addresses live only in operator configuration; discovery happens out
  of band.
- Onion/eepsite transports mean a node can receive connections without
  exposing its IP.

## 7. Error handling

Any protocol violation (bad magic, bad version, unknown type, oversized
frame, oversized ping, failed handshake, failed pin check, rate-limit
exceedance) closes the connection. Blocks or transactions that fail local
validation are dropped silently (the sender is not punished beyond the
failed relay; ANONYMCOIN v1 has no ban score).

## 8. Transaction digest and replay protection

The message signed by every transaction input is

```
BLAKE2b-256( "ANONYMCOIN/TX-DIGEST/1" || chainTag(4) || encoding-with-
             signature-fields-zeroed )
```

Two independent replay guards:

1. **Domain separation** — the literal domain string makes transaction
   digests distinct from every other BLAKE2b usage in the protocol, so a
   signature produced for any other purpose can never validate as a
   transaction signature.
2. **Chain tag** — the first 4 bytes of the genesis hash of the specific
   network. Independent ANONYMCOIN deployments (mainnet, testnet, private
   networks) have different genesis parameters and therefore different
   tags; signed transactions cannot be replayed across them.

Both layers are regression-tested (`TestReplayProtectionDomainSeparation`,
`TestReplayProtectionChainTagBinding`).
