# MorphVPN Version History

## v0.8.0 (2026-06-13) — Deploy-Ready Release

**82 tests. 39 commits. Production-ready.**

### Added
- **Interactive setup wizard** (`morphvpn setup`) — guided server/client setup with key generation, config creation, systemd installation
- **Deployment infrastructure** — systemd unit, setup scripts, sample configs, deploy guide
- **CI/CD pipeline** — GitHub Actions with Linux/macOS/Windows testing, clippy, security audit
- **Protocol RFC** (`docs/protocol.md`) — full wire format specification for security audit
- **TCP forwarding integration tests** — 4 tests covering roundtrip, multiple packets, large packets, bidirectional
- **IPv6 leak protection** — block IPv6 on TUN interfaces (Linux/Windows/macOS)

---

## v0.7.0 (2026-06-13) — Peer Management & TCP Forwarding

**78 tests. 31 commits.**

### Added
- **Peer management** (`src/peer.rs`) — track connected peers with state (Connecting/Handshaking/Established/Dead), traffic stats, lifecycle
- **TCP tunnel forwarding** — TCP connections now carry tunnel traffic with length-prefixed framing
- **Health endpoint with real data** — HTTP status endpoint returns live metrics and peer snapshots
- **Peer tracking in shard worker** — peers added on handshake, removed on teardown

### Changed
- Health server receives actual MetricsHandle counters
- Shard worker tracks peer state transitions

---

## v0.6.0 (2026-06-13) — Transport, Health & Validation

**65 tests. 27 commits.**

### Added
- **Transport abstraction** (`src/transport.rs`) — UDP/TCP types with length-prefixed TCP framing
- **HTTP health endpoint** (`src/health.rs`) — JSON status with uptime, metrics, version
- **TCP fallback configuration** — TOML config for TCP listener (port, timeout)
- **Config validation** — validate config on startup (required fields, valid addresses, file existence)
- **TCP listener** — accepts TCP connections (forwarding added in v0.7)

---

## v0.5.0 (2026-06-13) — Certificates, Keepalive & Logging

**54 tests. 22 commits.**

### Added
- **X.509 certificate generation** (`src/cert.rs`) — self-signed certs via rcgen, SHA-256 fingerprints
- **Certificate config** — TOML support for cert/key paths, verify_peer flag
- **`certgen` CLI** — generate certificates from command line
- **AuthInit/AuthResp frames** — certificate fingerprint exchange during handshake
- **Bidirectional keepalive** — configurable interval, dead-peer detection (server removes, client reconnects)
- **Structured JSON logging** — configurable format (pretty/json) and level via TOML

### Changed
- Session carries `remote_cert_fingerprint` field
- Keepalive interval no longer hardcoded (profile-driven)

---

## v0.4.0 (2026-06-13) — Metrics, macOS & Shutdown

**44 tests. 17 commits.**

### Added
- **Metrics system** (`src/metrics.rs`) — atomic packet/byte/error counters, periodic logging, delta snapshots
- **macOS platform support** — utun TUN device, ifconfig/route/networksetup networking
- **Graceful shutdown** — 2-second drain period, running flag propagated to all shards
- **Metrics integration** — UDP/TUN send/receive paths counted

### Changed
- Runtime accepts `MetricsHandle` for counter sharing
- Shutdown signal includes drain delay

---

## v0.3.0 (2026-06-13) — PMTUD, DNS & Profiles

**39 tests. 12 commits.**

### Added
- **Path MTU Discovery** (`morphvpn-protocol/src/pmtud.rs`) — probe tracking, MTU estimation, timeout handling
- **PMTUD wire integration** — probes sent on tick, PmtudProbe/PmtudAck handling in server and client
- **DNS leak protection** — iptables DNAT (Linux), netsh DNS (Windows) to route DNS through tunnel
- **Profile presets** — video/gaming/https profiles control keepalive, padding, MTU

### Changed
- `data_tx_nonce` made public for testing
- Cookie master key now configurable (was hardcoded `[0xA5; 32]`)

---

## v0.2.0 (2026-06-13) — Rekey, Config & Tests

**33 tests. 8 commits.**

### Added
- **Rekey mechanism** — derive new epoch keys when nonce space exhausted, RekeyInit/RekeyResp control frames
- **TOML configuration** (`src/config.rs`) — server/client sections, PSK config, cookie key
- **`--config` CLI flag** — load config from file, CLI args override config
- **Cookie master key from config** — replaced hardcoded `[0xA5; 32]` with config-driven key
- **Integration tests** — full handshake, data transfer, keepalive, bootstrap, rekey

### Protocol
- New control frames: `RekeyInit` (0x03), `RekeyResp` (0x04)
- Session handles rekey flow: derive → send → rotate

---

## v0.1.0 (2026-04-09) — Initial Baseline

**21 tests. 1 commit.**

### Features
- Noise XXpsk3_25519_ChaChaPoly_BLAKE2s handshake
- Two-layer encryption (ChaCha20-Poly1305 + XChaCha20-Poly1305)
- Header masking with ChaCha20
- Cookie-based anti-DoS with rate limiting
- Replay window (2048-bit sliding window)
- TUN device integration (Linux/Windows)
- ACL-based peer authorization
- UDP transport
- CLI: keygen, server, client

### Architecture
- `morphvpn-protocol` — pure protocol library (crypto, handshake, wire, session)
- `src/runtime` — shard-based packet processing (per-core)
- `src/sys_net` — cross-platform networking (Linux iptables, Windows netsh)
