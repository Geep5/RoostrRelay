# RoostrRelay

A Nostr relay in Odin. One process, one Fly.io machine, an append-only log on a
volume. Backs [Roostr](https://getroostr.fly.dev) sync - writes are
restricted to allowlisted pubkeys, reads are open (payloads are NIP-44
encrypted upstream anyway).

Live at `wss://roostr-relay.fly.dev`.

## Shape

```
Fly proxy (TLS)  →  plaintext :7777
  ├── HTTP: NIP-11 on GET /  (Accept: application/nostr+json), /health
  └── WebSocket (RFC 6455, hand-rolled)
        ├── NIP-01 dispatch: EVENT / REQ / CLOSE
        ├── canonical ID serializer (hand-rolled; core JSON parses only)
        ├── BIP-340 Schnorr verify (pure Odin; optional libsecp256k1 cross-check)
        ├── in-memory subscription registry, live matching
        └── CRC-framed event log + in-memory lookup  →  /data/relay.db
```

- One reader and one joined sender per WebSocket, with a bounded outbound queue;
  no blocking socket writes under the subscription registry lock. The store is
  serialized under one mutex. `DB_PATH` contains an event log, not SQLite.
- Kinds: regular stored; 0/3/1xxxx replaceable; 2xxxx ephemeral
  (broadcast only); 3xxxx addressable per (pubkey, kind, d). NIP-09
  deletion honored for the author's own events.
- Caps: 1 MiB inbound message/serialized event, 900 KiB content, 32 subscriptions
  per connection, 10 filters/REQ, limit ≤ 1000, and 8 MiB total query response
  budget. Filter arrays and retained filter bytes are bounded. Inbound JSON
  nesting is depth-capped before parsing, and each connection may publish at
  most 30 EVENTs per second (excess gets `OK false "rate-limited"`). Budget exhaustion
  returns `CLOSED`, not a false `EOSE`. Outbound queues include in-flight bytes
  and are capped at 10 MiB; slow consumers have a total write deadline.
  At most 512 connections are served; excess sockets close on accept. Every
  socket has a 125 s receive deadline that only silent peers can trip - the
  ping loop pongs keep any healthy subscriber well clear of it.
- Control frames require FIN and ≤125 bytes, and per-frame scratch memory is
  reclaimed even for control-only traffic. Fragment counts and bytes are bounded.

## Storage upgrades and recovery

Back up the log before upgrading. The reader accepts legacy `E`/`T` records;
new `A` records atomically describe an event and its derived deletion/replacement
effects. Their CRC covers header and payload. Writes must complete and sync
before memory changes; an I/O failure latches the writer closed until recovery.
An incomplete EOF tail is ALWAYS truncated at boot (and the truncation is
logged): bytes past a torn append are untrustworthy, even when some suffix of
them happens to decode as a complete CRC-valid frame. Mid-log damage - a bad
CRC on a complete-sized record - still preserves the original file untouched
and fails startup for operator recovery.

Compaction preserves deleted IDs and deletion requests so removed events cannot
be restored by republishing them. It checks file and directory sync/rename errors.
It is boot-triggered after sufficient tombstones; canonical history has no TTL.

**Never roll back to the pre-`A` binary against an upgraded log:** the old reader
would treat new records as a torn tail. Restore a matching pre-upgrade backup or
use an explicit conversion when rolling back.

Anonymous (non-allowlisted) writers are fenced in: a single event is capped at
64 KiB (residents keep the 1 MiB record cap), their aggregate retained size is
capped at 32 MiB of wire bytes (further writes are rejected until their old
events are deleted or superseded), and each resident recipient retains at most
64 kind-1059 gift envelopes - further stranger gifts are rejected outright,
none are evicted. These are doorknob quotas, not a public subscription system.

## Config (env)

| var | meaning |
|---|---|
| `PORT` | listen port (7777) |
| `DB_PATH` | event log (`/data/relay.db` on Fly) |
| `RELAY_ALLOWED_PUBKEYS` | comma-separated hex pubkeys; empty = open writes |
| `RELAY_NAME` / `RELAY_DESCRIPTION` / `RELAY_PUBKEY` / `RELAY_CONTACT` | NIP-11 |

## Build

```sh
odin build src -o:speed -out:roostr-relay
```

The default binary uses pure-Odin storage and BIP-340 verification, with no
SQLite or libsecp256k1 link dependency. It still uses the platform OS runtime;
"pure Odin" does not mean a freestanding binary without system libraries.

Verification is stack-only and reentrant. Its arithmetic is **variable-time**
and accepts public inputs only; it must not be reused for signing or secrets.
The binary verifier accepts arbitrary message bytes; the Nostr adapter requires
a 32-byte event ID, 32-byte x-only public key, and 64-byte signature in hex.

Production and default local builds select pure Odin (`VERIFY_DUAL=false`).
Set `VERIFY_DUAL=true` in `fly.toml` to restore differential diagnosis: both
Odin and libsecp256k1 check each signature, and any disagreement logs
`VERIFIER DISAGREEMENT` and rejects the event. Production switched to pure-only
for user testing before an extended dual-mode soak completed. Passing vectors
and differential tests is not a cryptographic audit.

Deploy: `fly deploy --remote-only`. The Dockerfile builds libsecp256k1 v0.6.0
only when `VERIFY_DUAL=true`; the default image build needs neither C library.
The runtime is debian-slim with one relay binary.

### Verification tests

```sh
# No external crypto library needed:
odin test src -o:speed
# Deterministic differential oracle, requires libsecp256k1 with schnorrsig:
odin test src -o:speed -define:VERIFY_DIFFERENTIAL=true
# Also exercise the optional dual-mode adapter:
odin test src -o:speed -define:VERIFY_DIFFERENTIAL=true -define:VERIFY_DUAL=true
```

Use `-extra-linker-flags:"-L/opt/homebrew/lib"` if needed on Homebrew macOS.
Tests include all 19 [official BIP-340 vectors](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv),
297 independent field-arithmetic oracle rows, group exceptional cases, malformed
hex and sizes, per-byte mutations, and 6,019 optional libsecp256k1 comparisons.
Test signing code and fixture loads are excluded from ordinary relay builds.
Group formulas follow [EFD Jacobian a=0](https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html).

## Test drive

```sh
nak event --sec <key> -k 1 -c hello wss://roostr-relay.fly.dev
nak req -k 1 -l 10 wss://roostr-relay.fly.dev
curl -H 'Accept: application/nostr+json' https://roostr-relay.fly.dev/
```
