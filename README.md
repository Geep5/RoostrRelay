# RoostrRelay

A Nostr relay in Odin. One process, one Fly.io machine, SQLite on a
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
        ├── BIP-340 schnorr verify  →  libsecp256k1 (static)
        ├── in-memory subscription registry, live matching
        └── SQLite (static amalgamation, WAL)  →  /data/relay.db
```

- Thread per connection (blocking `core:net`), one DB connection under a
  mutex - deliberately boring at personal scale. The storage seam
  (`store_event` / `query_filter`) is where a reader pool or a
  libsql/Turso swap would land later.
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
| `DB_PATH` | sqlite file (`/data/relay.db` on Fly) |
| `RELAY_ALLOWED_PUBKEYS` | comma-separated hex pubkeys; empty = open writes |
| `RELAY_NAME` / `RELAY_DESCRIPTION` / `RELAY_PUBKEY` / `RELAY_CONTACT` | NIP-11 |

## Build

```sh
odin build src -out:roostr-relay \
  -extra-linker-flags:"-L/opt/homebrew/opt/secp256k1/lib -L/opt/homebrew/opt/sqlite/lib"
```

Deploy: `fly deploy --remote-only` (builder compiles Odin + static
libsecp256k1 + static SQLite amalgamation; runtime is debian-slim with
a single binary).

## Test drive

```sh
nak event --sec <key> -k 1 -c hello wss://roostr-relay.fly.dev
nak req -k 1 -l 10 wss://roostr-relay.fly.dev
curl -H 'Accept: application/nostr+json' https://roostr-relay.fly.dev/
```
