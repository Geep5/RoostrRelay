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

- Thread per connection (blocking `core:net`), one store mutex at personal
  scale. The historical `DB_PATH` filename now contains an event log, not SQLite.
- Kinds: regular stored; 0/3/1xxxx replaceable; 2xxxx ephemeral
  (broadcast only); 3xxxx addressable per (pubkey, kind, d). NIP-09
  deletion honored for the author's own events.
- Caps: 1 MiB message, 900 KiB content (Roostr snapshots fit), 32
  subs/conn, 10 filters/REQ, limit ≤ 1000. Server pings every 30s,
  drops silent connections, 10s send timeout bounds slow consumers.

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

Production currently selects `VERIFY_DUAL=true` through `fly.toml`: every
signature is checked by both Odin and libsecp256k1. A disagreement logs
`VERIFIER DISAGREEMENT` and rejects the event. Default local builds use Odin
alone. Keep the production oracle during the soak; absence of test failures
is not a cryptographic audit. Switching production to pure-only is an explicit
change to that build argument after reviewing soak logs.

Deploy: `fly deploy --remote-only`. The Dockerfile builds libsecp256k1 v0.6.0
only when `VERIFY_DUAL=true`; the default image build needs neither C library.
The runtime is debian-slim with one relay binary.

### Verification tests

```sh
# No external crypto library needed:
odin test src -o:speed
# Deterministic differential oracle, requires libsecp256k1 with schnorrsig:
odin test src -o:speed -define:VERIFY_DIFFERENTIAL=true
# Also exercise the production dual-mode adapter:
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
