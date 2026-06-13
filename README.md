> Disclaimer: This is v0.8.0 pre-release. The project is preparing for v1.0-rc. An internal code audit has been completed (see docs/AUDIT-REPORT.md), but this is NOT a substitute for a professional external security audit. Use at your own risk.

# MorphVPN 🛡️
![Status](https://img.shields.io/badge/status-pre--release-yellow)
![Version](https://img.shields.io/badge/version-0.8.0-blue)
![Tests](https://img.shields.io/badge/tests-82-green)
![License](https://img.shields.io/badge/license-MIT-green.svg)

MorphVPN is a high-performance stealth VPN tunnel written in Rust, utilizing the Noise Protocol and advanced traffic obfuscation.


> Experimental Rust VPN tunnel prototype.  
> Pre-release software. Built by one self-taught developer. Shared as-is.

[Russian version](README.ru.md)

## Overview

MorphVPN is a command-line VPN/tunnel project written in Rust.  
It implements a full Noise XXpsk3 handshake, dual-layer encryption, TUN device integration, ACL-based peer authorization, TCP fallback transport, and cross-platform networking.

The project has gone through 8 iterations (v0.1 → v0.8) with 82 tests and is now preparing for v1.0-rc.

## Important Notice

MorphVPN is still a pre-release project.

- No guarantees
- An internal code audit has been completed, but no external security audit has been performed
- No promise of production readiness
- No claim that this is safe for real-world sensitive traffic

It was written by one self-taught developer. If you have suggestions, corrections, or practical advice, feedback is very welcome.

## What Is Actually In This Repo

- **`src/`** — Main binary and runtime code (server, client, setup wizard)
- **`morphvpn-protocol/`** — Protocol library (crypto, handshake, wire format, session, cookies, replay protection)
- **`tests/`** — 82 unit, integration, and TCP forwarding tests
- **`deploy/`** — Systemd service, setup scripts, sample configs
- **`docs/`** — Protocol RFC, deploy guide, internal audit report

## Features

- **Noise XXpsk3 handshake** — 25519 keys, ChaChaPoly, BLAKE2s
- **Dual-layer encryption** — ChaCha20-Poly1305 (data) + XChaCha20-Poly1305 (outer)
- **Header masking** — ChaCha20-based traffic obfuscation
- **TCP fallback** — Length-prefixed TCP framing for blocked UDP environments
- **IPv6 leak protection** — Blocks IPv6 on TUN interfaces (Linux/Windows/macOS)
- **Peer management** — Track connected peers with state, traffic stats, lifecycle
- **X.509 certificates** — Self-signed cert generation, fingerprint exchange
- **Metrics** — Atomic packet/byte/error counters, periodic logging
- **Health endpoint** — HTTP JSON status with uptime, metrics, peer snapshots
- **Profile presets** — video/gaming/https profiles control keepalive, padding, MTU
- **DNS leak protection** — Routes DNS through tunnel (Linux iptables, Windows netsh)
- **Rekey mechanism** — Automatic key rotation when nonce space exhausted
- **Cookie anti-DoS** — Stateless rate limiting with time-bucketed cookies
- **Replay protection** — 2048-bit sliding window
- **Graceful shutdown** — 2-second drain period
- **TOML configuration** — Server/client sections, PSK config, cookie key
- **Interactive setup wizard** — `morphvpn setup` for guided server/client setup
- **Deployment scripts** — `setup.sh` / `setup-client.sh` with `--dry-run` and confirmation prompts
- **CI/CD** — GitHub Actions with Linux/macOS/Windows testing, clippy, security audit
- **Cross-platform** — Linux, Windows, macOS support

## Quick Start

### Option 1: Interactive Setup Wizard (Recommended)

```bash
# Build
cargo build --release

# Server setup (interactive wizard)
./target/release/morphvpn setup

# Client setup (interactive wizard)
./target/release/morphvpn setup
```

The wizard will guide you through key generation, config creation, and optionally systemd installation.

### Option 2: Deploy Scripts (Linux)

```bash
# Server (run as root)
cd deploy
./setup.sh              # Interactive with confirmation prompts
./setup.sh --dry-run    # Preview changes without applying

# Client (run as root)
./setup-client.sh
./setup-client.sh ---dry-run
```

### Option 3: Manual CLI

Build:

```bash
cargo build --release
```

Generate keys:

```bash
./target/release/morphvpn keygen --private-out server.key --public-out server.pub
./target/release/morphvpn keygen --private-out client.key --public-out client.pub
```

Run the server:

```bash
export MORPHVPN_PSK_FILE=server.psk
./target/release/morphvpn server --bind 0.0.0.0:51820 --private-key server.key --acl deploy/config/acl.example.toml --tun tun0
```

Run the client:

```bash
export MORPHVPN_PSK_FILE=client.psk
./target/release/morphvpn client --server 203.0.113.10:51820 --private-key client.key --server-public-key server.pub --tun tun1 --tun-ip 10.8.0.5
```

The CLI no longer accepts a plaintext `--psk` argument. Use `--psk-file`, `MORPHVPN_PSK_FILE`, or `MORPHVPN_PSK`.

## Requirements

- Rust toolchain with `cargo`
- Administrator or root privileges for TUN and route changes
- Linux, Windows, or macOS

## Repository Layout

```text
morphvpn/
├─ src/                    Main binary/runtime code
│  ├─ runtime/             Shard-based packet processing
│  ├─ sys_net.rs           Cross-platform networking
│  ├─ setup.rs             Interactive setup wizard
│  ├─ transport.rs         UDP/TCP transport abstraction
│  ├─ peer.rs              Peer management
│  ├─ metrics.rs           Metrics system
│  ├─ health.rs            Health endpoint
│  ├─ cert.rs              X.509 certificate generation
│  ├─ config.rs            TOML configuration
│  ├─ acl.rs               Access control list
│  └─ identity.rs          Key generation
├─ morphvpn-protocol/      Protocol library (crypto, handshake, wire, session)
├─ tests/                  Unit, integration, and TCP forwarding tests
├─ deploy/
│  ├─ config/              Sample configs (server, client, ACL)
│  ├─ setup.sh             Server setup script
│  ├─ setup-client.sh      Client setup script
│  └─ morphvpn.service     Systemd unit
├─ docs/
│  ├─ protocol.md          Wire format RFC
│  ├─ deploy.md            Deployment guide
│  └─ AUDIT-REPORT.md      Internal code audit
├─ Cargo.toml
├─ Cargo.lock
└─ README.md
```

## Version History

The project has evolved through 8 versions:

- **v0.1** — Initial baseline: Noise handshake, dual-layer encryption, TUN, ACL, UDP
- **v0.2** — Rekey mechanism, TOML config, integration tests
- **v0.3** — PMTUD, DNS leak protection, profile presets
- **v0.4** — Metrics, macOS support, graceful shutdown
- **v0.5** — X.509 certificates, keepalive, structured logging
- **v0.6** — Transport abstraction, health endpoint, config validation
- **v0.7** — TCP forwarding, peer management
- **v0.8** — Setup wizard, deploy scripts, CI/CD, IPv6 leak protection, protocol RFC

See [VERSIONS.md](VERSIONS.md) for detailed changelog.

## What This Project Does Not Claim

- It does not claim to be production-ready
- It does not claim to have passed a professional security audit
- It does not claim to be finished
- It does not claim to outperform mature VPN solutions

## Why It Is Public

This repository is public because progress matters, feedback matters, and learning in the open matters.

If you are more experienced and see weak spots, bad assumptions, or cleaner approaches, that kind of feedback is appreciated.

## Safety Reminder

Do not commit:

- Real private keys
- Real server IP addresses
- Personal logs
- Tokens, secrets, or local machine data

## License

Released under the MIT License. See [LICENSE](LICENSE).
