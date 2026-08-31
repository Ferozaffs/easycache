<p align="center"><b>Vibe-coded end to end, as a test bed for DeepSeek V4 Flash.</b></p>

<p align="center">
  <img src="assets/logo.svg" alt="EasyCache" width="640"/>
</p>

<h1 align="center">EasyCache</h1>

<p align="center">
  A zero-config, LAN-wide content cache. Node finds it on the network automatically, serves cached blobs back in a flash, and dedupes by content — no API keys, no config file, no registries.
</p>

<p align="center">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.22-00ADD8?logo=go&logoColor=white"/>
  <img alt="License" src="https://img.shields.io/badge/license-MIT-blue"/>
  <img alt="status" src="https://img.shields.io/badge/status-vibecoded-purple"/>
  <img alt="test bed" src="https://img.shields.io/badge/vibecoded-DeepSeek%20V4%20Flash-violet"/>
</p>

---

## What is it?

EasyCache is a tiny **LAN cache server** that announces itself over **zeroconf (mDNS)** and answers two questions:

1. **Is this file already cached?**
2. **Give me the file** (or take it and cache it).

It is **content-addressed**: every blob is stored under its full SHA-256. Two identical bytes under two different URLs, tokens, or hosts are the *same* cache entry. On a cache hit it serves you the local copy instead of re-downloading, and a miss is downloaded once and seeded automatically.

Because it runs on your network, you can blast through 400 MB Blender installers, Node modules, build artifacts, or any repeated downloads — without re-fetching them from the internet each time.

## Quick start

**Run the server** (auto-discovers on the LAN via mDNS):

```sh
cacheserv -addr :8765 -dir ./cachedata
```

**Use it** (auto-discovers the server over zeroconf — `-server host:port` skips discovery):

```sh
cacheget get https://download.blender.org/release/Blender5.2/blender-5.2.1-windows-x64.msi blender.msi
```

First `get` downloads it and seeds the cache; every `get` after is a **cache hit**.

## Commands

| Command | What it does |
|---------|--------------|
| `get <url\|sha256> [out]` | **The one command.** URL: hit→copy from cache, miss→download once + seed. sha256: pull a blob by its exact content hash. |
| `check <file>` | "Is my local file already cached?" (reads ≤128 KB) |
| `put <file>` | Seed a local file (exact-hash check first) |
| `hash <file>` | Print size + partial signature + full SHA-256 |
| `list` | Discover cache servers on the LAN |

Flags: `-server host:port` (also `CACHE_ADDR`) to target a specific server; `-timeout` for look-up.

## The signature trick

A full content hash requires the whole file. To answer "is it cached?" cheaply, EasyCache uses a **partial signature**:

```
sig = sha256( size ‖ sha256(first 64KB) ‖ sha256(last 64KB) )
```

- **Client side** (`cacheget`): sample a remote URL with `HEAD` + two `Range` GETs (~130 KB transferred), or read a local file's head/tail.
- **Server side** (`cacheserv`): the same signature is computed at upload time, but the **authoritative** identity is the full SHA-256.

A partial-only `check` returns a hit **only** when a signature resolves to exactly one stored file; if it's ambiguous the server answers `404` (fail-safe), never a wrong match. This is the "no false positive, ever" guarantee — the signature is a router, the hash is the truth.

## How it works

```
┌─────────────┐   mDNS (zeroconf) ─ _easycache._tcp ─────────┐
│   client    │──────────────────────────────────────►        │
│ cacheget    │   POST /check      (sig|hash)      ┌─────────▼───────┐
│             │   POST /upload     (file bytes)    │  cacheserv      │
└─────────────┘   GET /files/{hash}                │  + zeroconf ad  │
        ▲                                          └─────────┬───────┘
        │ cache hit (no internet)                           │
        └──────────────────────────────────────────────────  │ content-addressed
```

- `internal/cache` — fingerprinting, the content-addressed store, and the HTTP handlers.
- `internal/discovery` — mDNS advertise/browse.
- `internal/client` — the client library (`get`, `check`, `put`, `fetch`, remote sampling, download).
- `cmd/cacheserv` — the server binary.
- `cmd/cacheget` — the CLI.

## Docker

```sh
docker build -t easycache:local .
docker compose up -d --build
```

Use `--network host` (already set in `docker-compose.yml`) so mDNS works on the LAN. On a real Linux host this is fully auto-discoverable; on Docker Desktop (Windows) the VM isolates multicast, so point clients at it with `-server host:port`.

## License

[MIT](LICENSE)
