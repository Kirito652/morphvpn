# MorphVPN Pre-v1.0-rc Audit Report

**Date:** 2026-06-13
**Version:** v0.8.0
**Auditor:** MiMoCode Agent

---

## Executive Summary

**Recommendation: CONDITIONAL GO for v1.0-rc**

MorphVPN is a well-architected VPN tunnel with solid cryptographic foundations. The codebase compiles cleanly, passes 82 tests, and the core protocol is sound. However, there are several issues that should be addressed before v1.0-rc, and critical e2e testing on Linux is required before production use.

---

## Phase 1: Build & Compilation Audit

### Build Results
- ✅ Debug build: SUCCESS (34s)
- ✅ Release build: SUCCESS (53s)
- ✅ Binary size: 4.36 MB (Windows)
- ✅ All 82 tests pass

### Warnings Summary
- **21 dead_code warnings** - unused functions/fields in transport, peer, metrics, config
- **82 clippy pedantic warnings** - mostly style (uninlined format args, missing #[must_use])
- **2 test warnings** - unused variables in tcp_forwarding_test.rs

### Critical Warnings
None. All warnings are non-blocking.

### Notable Clippy Findings
1. **`cast_possible_truncation`** in `src/transport.rs:56` - `data.len() as u32` could truncate on 64-bit
2. **`cast_possible_truncation`** in `src/runtime/shard.rs:457,656` - `mtu as u16` could truncate
3. **`unused_async`** in `src/runtime/shard.rs:209,373` and `src/sys_net.rs:336` - async functions with no await

---

## Phase 2: Code Review (v0.7-v0.8 Features)

### TCP Forwarding (`src/transport.rs`, `src/main.rs:249-311`)

**Status: FUNCTIONAL WITH CAVEATS**

| Aspect | Status | Notes |
|--------|--------|-------|
| Length-prefix framing | ✅ Correct | 4-byte big-endian length prefix |
| Buffer overflow protection | ✅ Present | Checks `len > buf.len()` before read |
| Resource cleanup | ⚠️ Concern | TCP tasks spawned but no explicit cleanup on server shutdown |
| Backpressure | ✅ Present | `try_send` with drop on full channel |
| Error handling | ✅ Proper | No unwrap/expect in production paths |

**Issues Found:**
1. **MINOR**: TCP accept loop in `main.rs:258-309` spawns tasks without tracking them. Long-lived connections could accumulate if client disconnects ungracefully.
2. **MINOR**: No TCP connection timeout configured (relies on OS defaults).

### IPv6 Leak Protection (`src/sys_net.rs`)

**Status: FUNCTIONAL**

| Platform | Implementation | Status |
|----------|----------------|--------|
| Linux | `sysctl net.ipv6.conf.{iface}.disable_ipv6=1` | ✅ Correct |
| Windows | `netsh interface ipv6 set interface {adapter} disable` | ✅ Correct |
| macOS | `networksetup -setv6off` + removes all IPv6 addresses | ✅ Fixed |

**Issues Found:**
1. ~~**MAJOR**: macOS implementation only disables autoconf, not IPv6 entirely.~~ **FIXED** - Now uses `networksetup -setv6off` to fully disable IPv6, removes all IPv6 addresses, and restores on cleanup.
2. **MINOR**: Cleanup functions (`linux_unblock_ipv6`, `windows_unblock_ipv6`) are best-effort (ignore errors).

### Peer Management (`src/peer.rs`, `src/runtime/shard.rs`)

**Status: FUNCTIONAL**

| Aspect | Status | Notes |
|--------|--------|-------|
| State machine | ✅ Correct | Connecting → Handshaking → Established → Dead |
| Thread safety | ✅ Correct | `Arc<RwLock<PeerManager>>` |
| Dead peer cleanup | ✅ Present | `remove_dead_peers()` with timeout |
| Traffic recording | ✅ Present | `record_rx()`, `record_tx()` |

**Issues Found:**
1. **MINOR**: `Handshaking` and `Dead` enum variants are defined but never constructed in production code (only in tests).
2. **MINOR**: `remove_dead_peers()` is implemented but never called in production code.

### Deploy Scripts (`deploy/setup.sh`, `deploy/setup-client.sh`)

**Status: FUNCTIONAL WITH SAFEGUARDS**

**Irreversible Changes (setup.sh):**
1. `sysctl -w net.ipv4.ip_forward=1` - Enables IP forwarding (persisted to `/etc/sysctl.d/`)
2. `iptables-persistent` installation - Persists firewall rules across reboots
3. Systemd service installation

**Issues Found:**
1. ~~**MAJOR**: `setup.sh` enables IP forwarding without confirmation.~~ **FIXED** - Now requires explicit confirmation before each irreversible change.
2. ~~**MAJOR**: `setup.sh` installs `iptables-persistent` which persists rules across reboots.~~ **FIXED** - Added `--dry-run` flag and confirmation prompts.
3. **MINOR**: No uninstall/cleanup script provided.
4. ~~**MINOR**: `setup-client.sh` reads PSK via `read` but doesn't mask input.~~ **FIXED** - PSK input is now masked with `read -rs`.

**New Features Added:**
- `--dry-run` flag shows all planned changes without applying them
- Confirmation prompts before each irreversible system change
- Automatic backup of current configuration (sysctl, iptables rules)
- Restore instructions printed at end of script

### Setup Wizard (`src/setup.rs`)

**Status: FUNCTIONAL**

| Aspect | Status | Notes |
|--------|--------|-------|
| Interactive prompts | ✅ Working | With defaults |
| Key generation | ✅ Working | X25519 + X.509 cert |
| Config generation | ✅ Working | TOML format |
| Systemd integration | ✅ Working | With confirmation |
| File permissions | ✅ Working | 0o600 on Unix |

**Issues Found:**
1. **MINOR**: No validation of user input (IP addresses, ports).
2. **MINOR**: Generated systemd unit includes `CAP_SYS_ADMIN` which may be overly broad.

---

## Phase 3: Security Audit

### Cryptography

| Component | Implementation | Status |
|-----------|----------------|--------|
| Handshake | Noise XXpsk3_25519_ChaChaPoly_BLAKE2s | ✅ Sound |
| Data encryption | ChaCha20-Poly1305 | ✅ Sound |
| Outer encryption | XChaCha20-Poly1305 | ✅ Sound |
| Key derivation | HKDF-SHA256 | ✅ Sound |
| Replay protection | 2048-bit sliding window | ✅ Sound |
| Nonce management | Counter-based with XOR | ✅ Sound |

**No cryptographic vulnerabilities found.**

### Dependency Audit (cargo audit)

| Crate | Version | Issue | Severity |
|-------|---------|-------|----------|
| paste | 1.0.15 | Unmaintained | Warning |
| rand | 0.8.5 | Unsound with custom logger | Warning |

**No critical vulnerabilities found.**

### Network Security

| Component | Status | Notes |
|-----------|--------|-------|
| ACL authorization | ✅ Correct | Public key lookup |
| Cookie anti-DoS | ✅ Correct | Stateless, time-bucketed |
| Replay window | ✅ Correct | 2048-bit sliding window |
| Key zeroization | ✅ Present | `zeroize` crate used |

---

## Phase 4: End-to-End Testing

### What Was Tested (Windows)

| Test | Status | Notes |
|------|--------|-------|
| Binary builds | ✅ Pass | Release mode |
| `morphvpn --help` | ✅ Pass | All commands listed |
| `morphvpn keygen` | ✅ Pass | Generates keypair |
| `morphvpn certgen` | ✅ Pass | Generates cert+key |
| `morphvpn example` | ✅ Pass | Prints usage example |
| Unit tests (82) | ✅ Pass | All green |

### What Could NOT Be Tested (Requires Linux)

| Test | Reason | Priority |
|------|--------|----------|
| TUN interface creation | Requires root + Linux | Critical |
| UDP tunnel establishment | Requires two endpoints | Critical |
| Traffic forwarding | Requires TUN + UDP | Critical |
| IPv6 leak protection | Requires iptables | High |
| TCP forwarding (live) | Requires two endpoints | High |
| Reconnect/rekey | Requires established session | High |
| Systemd service | Requires Linux | Medium |
| Deploy scripts | Requires root + Ubuntu | Medium |

---

## Issues Summary

### Critical (Blocks v1.0-rc)
None

### Major (Should Fix Before v1.0-rc)
1. ~~**macOS IPv6 leak protection incomplete**~~ **FIXED** - Now fully disables IPv6 via `networksetup -setv6off`
2. ~~**Deploy scripts make irreversible changes without confirmation**~~ **FIXED** - Added `--dry-run`, confirmation prompts, and backup
3. **No e2e testing on Linux** - Cannot verify tunnel establishment, traffic forwarding

### Minor (Can Defer to v1.1)
1. 21 dead_code warnings - unused functions/fields
2. TCP connection cleanup not explicit
3. Setup wizard lacks input validation
4. No uninstall script for deploy
5. `Handshaking`/`Dead` peer states unused in production
6. Systemd unit includes `CAP_SYS_ADMIN` (may be overly broad)

---

## What Works End-to-End

Based on code review and unit tests:
- ✅ Noise XXpsk3 handshake (tested in integration tests)
- ✅ Data encryption/decryption (tested in crypto tests)
- ✅ Rekey mechanism (tested in session tests)
- ✅ Cookie anti-DoS (tested in cookie tests)
- ✅ Replay protection (tested in replay tests)
- ✅ ACL authorization (tested in acl tests)
- ✅ TCP framing (tested in tcp_forwarding tests)
- ✅ Metrics collection (tested in metrics tests)
- ✅ Peer management (tested in peer tests)

## What Needs Linux E2E Verification

- ❓ TUN interface creation and configuration
- ❓ UDP tunnel establishment between server/client
- ❓ Actual traffic forwarding through tunnel
- ❓ IPv6 leak protection (iptables rules)
- ❓ DNS leak protection
- ❓ Systemd service lifecycle
- ❓ Deploy script execution

---

## Conclusion

MorphVPN is a well-designed VPN tunnel with strong cryptographic foundations. The codebase is clean, well-tested at the unit/integration level, and follows good Rust practices.

**Fixes Applied:**
1. ✅ macOS IPv6 leak protection - Now fully disables IPv6 with proper cleanup
2. ✅ Deploy scripts - Added `--dry-run`, confirmation prompts, and backup

**For v1.0-rc, the following is still required:**
1. Run full e2e test suite on Linux (server + client)

**The project is NOT ready for production use until e2e testing on Linux is completed.**
