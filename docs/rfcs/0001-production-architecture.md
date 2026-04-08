# RFC 0001: MorphVPN Production Architecture

Status: Draft

Author: Kirito652

Date: 2026-04-08

## 1. Summary

This RFC moves MorphVPN from a proof of concept to a production-grade design.

The design replaces PSK-centric payload encryption with a Noise-based authenticated key exchange that provides forward secrecy, removes fixed visible protocol metadata from the wire image, introduces a real multi-peer server architecture, adopts Datagram PLPMTUD, and defines operational behavior for NAT keepalive, replay defense, observability, and graceful degradation.

Primary references:

- The Noise Protocol Framework: [noiseprotocol.org/noise_rev34.html](https://noiseprotocol.org/noise_rev34.html)
- RFC 8899 DPLPMTUD: [rfc-editor.org/rfc/rfc8899](https://www.rfc-editor.org/rfc/rfc8899)
- RFC 9000 QUIC transport PMTU and datagram sizing: [rfc-editor.org/rfc/rfc9000](https://www.rfc-editor.org/rfc/rfc9000)
- RFC 9001 QUIC header protection: [rfc-editor.org/rfc/rfc9001.html](https://www.rfc-editor.org/rfc/rfc9001.html)
- RFC 4787 NAT UDP behavior: [rfc-editor.org/rfc/rfc4787](https://www.rfc-editor.org/rfc/rfc4787)
- RFC 5389 STUN keepalive behavior: [rfc-editor.org/rfc/rfc5389.html](https://www.rfc-editor.org/rfc/rfc5389.html)
- WireGuard replay window and counter handling: [wireguard.com/protocol](https://www.wireguard.com/protocol/)

## 2. Goals

1. Provide PFS for initial handshake and every rekey epoch.
2. Ensure wire image exposes only opaque routing information plus high-entropy noise.
3. Tolerate UDP loss and reordering without enabling replay.
4. Keep the tunnel alive behind consumer NATs without noisy periodic spam.
5. Discover usable path MTU dynamically without relying only on ICMP.
6. Scale server-side state to many concurrent peers.
7. Eliminate `Arc<Mutex<SessionContext>>` from the hot path.
8. Emit structured operational logs suitable for production debugging.
9. Fail closed cryptographically and degrade gracefully operationally.

## 3. Non-Goals

1. Full censorship-resistance against active nation-state traffic morphing classifiers in v1.
2. Peer-to-peer NAT hole punching in the first production cut.
3. Full TCP-in-TCP style reliability inside the outer tunnel.
4. Obfuscation that impersonates TLS, QUIC, RTP, or any other real protocol on the wire.

## 4. Threat Model

We assume:

- Passive observers can record all traffic.
- Active attackers can replay, drop, delay, reorder, and inject UDP datagrams.
- Long-term static keys or PSKs may be compromised in the future.
- ICMP PTB messages may be forged or blocked.
- NAT behavior is inconsistent across networks.

We do not assume:

- The network preserves ordering.
- PTB messages are reliable.
- One global MTU works everywhere.
- The server handles only one client.

## 5. Handshake Decision

### 5.1 Primary Handshake

The primary production handshake is:

`Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s`

Rationale:

- `XX` is the most generally useful fundamental interactive pattern and supports mutual authentication with transmitted static keys.
- Compared with `IK`, `XX` provides better identity-hiding properties for the initiator and avoids requiring the initiator to expose its static key immediately.
- `psk3` uses the PSK as an additional blinding and authentication input, not as the sole basis for payload secrecy.
- This satisfies the requirement that future compromise of the PSK alone must not decrypt old traffic.

Per the Noise specification, `XX` is:

- `-> e`
- `<- e, ee, s, es`
- `-> s, se`

And the recommended PSK modifier placement is `XXpsk3`.

### 5.2 Fast Path

`IK` is retained as a future optimization, not the primary v1 handshake.

Reason:

- `IK` reduces latency when the initiator already knows the responder static key.
- `IK` has weaker identity-hiding for the initiator than `XX`.
- Production cut should prefer correctness, privacy, and simpler operational rollout over handshake latency.

## 6. Handshake Flow

### 6.1 Pre-Handshake DoS Control

Before full handshake state is allocated, the server may respond statelessly with a Retry/Cookie frame if:

- Source address is new.
- CPU pressure is high.
- Per-IP handshake rate exceeds thresholds.

Cookie contents:

- Client source IP/port hash.
- Time bucket.
- Original client routing tag.
- HMAC under server secret.

### 6.2 Handshake Messages

Message 1: Client Init

- Client ephemeral X25519 public key.
- Client-selected opaque routing tag.
- Capability bitmap.
- Optional stateless cookie echo.
- No client static identity on wire yet.

Message 2: Server Response

- Server ephemeral key.
- Encrypted server static key.
- Capability selection.
- Server-selected session routing tag.
- Initial path parameters:
  - `base_plpmtu`
  - `max_udp_payload_hint`
  - keepalive hints

Message 3: Client Finish

- Encrypted client static key.
- `psk3` mixed at the end of the third handshake message.
- Channel-binding transcript hash.
- Session confirmation.

Handshake completion:

- Both sides derive transport secrets.
- Both sides derive obfuscation secrets.
- Both sides derive control-plane and data-plane secrets.
- Handshake state is zeroized except transcript hash used for diagnostics/channel binding.

## 7. Key Schedule

The handshake derives:

1. `tx_key_epoch_0`
2. `rx_key_epoch_0`
3. `tx_hp_key_epoch_0`
4. `rx_hp_key_epoch_0`
5. `obfs_secret_epoch_0`
6. `control_secret_epoch_0`
7. `session_exporter_secret`

The PSK:

- Is mixed with Noise `MixKeyAndHash()`.
- Is never used directly as a payload key.
- Must be scoped to one Noise hash choice only.
- Must not be reused outside MorphVPN.

## 8. Rekey Design

Symmetric-only rekey is removed as the primary mechanism.

Production rekey is an authenticated, channel-bound ephemeral DH exchange carried inside the encrypted control channel.

### 8.1 Rekey Flow

1. Initiator sends `REKEY_INIT` with fresh ephemeral X25519 pubkey and next epoch number.
2. Responder replies with `REKEY_RESP` with fresh ephemeral pubkey and confirmation.
3. Both derive next epoch secrets from:
   - fresh `ee`
   - current session exporter secret
   - transcript binding
4. Initiator sends first packet under new epoch.
5. Receiver enters dual-accept window:
   - old epoch accepted briefly
   - new epoch accepted
6. Receiver commits new epoch only after successful authenticated decrypt of new-epoch data/control.
7. Old epoch expires after ACK or grace timer.

### 8.2 Security Properties

- Provides forward secrecy between epochs.
- Avoids instant server-side cutover on `RekeyRequest`.
- Supports overlap so lost ACKs do not kill the tunnel.

## 9. Packet Format

### 9.1 Wire Image Principles

The wire must not expose:

- packet type
- packet number
- payload length
- padding length
- rekey flags
- PMTU probe flags

The wire may expose:

- an opaque routing tag for server demux
- an opaque nonce/salt

Those exposed fields must be:

- high entropy
- semantically meaningless to the observer
- rotated on session establishment and rekey

### 9.2 Datagram Layout

Outer datagram:

1. `routing_tag` (8 or 12 bytes)
2. `nonce_salt` (24 bytes for XChaCha-based outer sealing)
3. `sealed_envelope`
4. `cover_suffix` (0..N random bytes)

Only `routing_tag` and `nonce_salt` are public. Both look random.

### 9.3 Encrypted Envelope

`sealed_envelope = XChaCha20-Poly1305(obfs_secret_epoch_N, nonce_salt, aad=routing_tag, plaintext=envelope)`

Plaintext envelope:

1. `header_len_varint`
2. `protected_header`
3. `payload_ciphertext`
4. `padding`

Protected header fields:

- epoch id
- packet number
- frame class
- ack metadata
- body length
- padding class
- PMTU probe id and target size when present
- connection migration/path id if enabled later

### 9.4 Metadata Obfuscation

The header is fully encrypted. No fixed offsets for `seq`, `len`, or `pad_len` remain visible.

Inside the encrypted envelope, the header itself is additionally masked using a QUIC-style header-protection step derived from `hp_key_epoch_N`, so that even partially decrypted or length-inferred parsing is harder when sampling traffic internally for diagnostics.

This gives two layers:

1. envelope secrecy from the outer AEAD
2. internal header masking against repeated structural patterns after decryption boundaries are known

### 9.5 Routing Tag

The server needs one public demux field.

Production choice:

- `routing_tag` is an opaque random identifier.
- It is assigned per session and rotated on rekey or migration.
- It maps to a session shard, not directly to a user identity.
- It is never derived directly from static public keys.

For initial handshake packets:

- client picks `client_init_tag`
- server replies with `server_session_tag`
- after handshake, traffic moves to `server_session_tag`

## 10. Replay Defense

Data and control need different replay handling.

### 10.1 Data Packets

Each receive key epoch maintains:

- highest authenticated packet number
- sliding bitmap window
- configurable window size, target 2048 packets

Acceptance rule:

- decrypt first
- if authentication succeeds, apply replay window
- reject duplicates
- allow bounded reordering
- reject packets older than the left edge of the window

This mirrors the approach documented in WireGuard and matches Noise guidance for out-of-order transport messages.

### 10.2 Control Packets

Control packets use:

- request IDs
- idempotent reply cache
- short replay cache
- state-aware duplicate acceptance

This avoids breaking retransmissions of:

- handshake init
- cookie retry
- rekey init
- PMTU probe acknowledgments

## 11. NAT Traversal and Keepalive

### 11.1 Base Policy

We do not send blind keepalives on a fixed global timer.

Instead, per path:

- maintain idle timer
- maintain inbound silence timer
- maintain last successful response time
- track whether real data is already refreshing NAT

### 11.2 Keepalive Triggers

Send a keepalive if:

1. no outbound packets were sent for `idle_keepalive_interval`
2. outbound packets continue but no inbound packets are seen for `suspect_mapping_interval`
3. a path just resumed after OS sleep/network change

Keepalive frame:

- encrypted control frame
- ack-eliciting
- piggybacks path status if available

Optional future mode:

- STUN-based external binding discovery for symmetric NAT diagnostics, not required for client-server deployment

### 11.3 Timer Strategy

Defaults:

- start conservative at 25 seconds
- adapt downward on repeated NAT expiry symptoms
- cap within operator-configurable floor/ceiling

RFC 4787 recommends NAT UDP mappings not expire in less than two minutes and recommends five minutes or more by default, but field behavior is often worse, so implementation remains adaptive.

## 12. DPLPMTUD

### 12.1 Decision

Production MorphVPN uses Datagram PLPMTUD per RFC 8899, with optional PTB assistance.

We do not hardcode a single MTU as the steady-state answer.

### 12.2 State

Per path we maintain:

- `BASE_PLPMTU`
- `current_plpmtu`
- `max_confirmed_plpmtu`
- `search_high`
- `search_low`
- probe state
- black-hole suspicion counters

### 12.3 Probe Mechanism

Probe packets are:

- ack-eliciting
- explicitly tagged inside the encrypted control header
- padded to candidate datagram size
- excluded from normal congestion-loss interpretation

Probe confirmation:

- peer sends authenticated `PMTU_ACK(probe_id, observed_size)`
- sender only raises PLPMTU on explicit confirmation

### 12.4 ICMP Handling

ICMP PTB is optional input only.

It must be validated using:

- source/destination IPs
- UDP ports
- routing tag if quoted bytes are sufficient
- session/path lookup

ICMP can lower a candidate provisionally.
ICMP can never raise PLPMTU.

### 12.5 Black-Hole Detection

If probes or regular packets above a threshold fail repeatedly while smaller packets continue to succeed:

- reduce PLPMTU to last confirmed value
- re-enter search later
- log a PMTU black-hole event

### 12.6 Operational Starting Point

Initial safe user-space payload target:

- 1200 byte outer UDP payload floor

This is only the starting base, not the fixed steady-state ceiling.

## 13. Multi-Peer Server Architecture

### 13.1 Session Manager

The server uses sharded session maps keyed by `routing_tag`.

Each shard owns:

- active sessions
- handshake-in-progress entries
- replay caches
- PMTU/path state
- rate-limit buckets

### 13.2 First-Packet Identification

Initial packet routing uses:

- `routing_tag`
- source address tuple
- optional stateless cookie

Not used:

- plain packet type bytes
- source port alone
- decrypted metadata before demux

### 13.3 Scaling Model

- one UDP socket reactor per bound socket
- N worker shards pinned by hash(`routing_tag`)
- lock-free MPSC queues from reactor to shard
- session state remains shard-local

This avoids a global mutex on the hot path.

## 14. Hot-Path Performance Model

### 14.1 Buffering

Use:

- `BytesMut` for receive buffers
- `Bytes` for immutable packet handoff
- slab or pool-backed reusable buffers

Avoid:

- per-packet `Vec` churn
- cross-thread cloning of large plaintext buffers

### 14.2 Execution Model

- TUN RX task
- UDP RX reactor
- worker shard tasks for crypto/state
- UDP TX aggregator
- TUN TX task

No shared `Arc<Mutex<SessionContext>>` in the data path.

## 15. Observability

Every session has:

- stable `session_id`
- current `routing_tag`
- peer address
- current epoch
- current PLPMTU
- keepalive state

Structured events include:

- session created
- handshake started
- handshake completed
- retry cookie issued
- rekey started
- rekey committed
- PMTU probe sent
- PMTU probe confirmed
- PMTU reduced
- NAT suspected dead
- path switched
- session closed

Use `tracing` spans:

- per session
- per path
- per control transaction

## 16. Graceful Degradation

No `unwrap()` or panic on recoverable runtime failures in production paths.

Behavior:

- crypto error on one packet: drop packet, increment counter, preserve session if threshold not exceeded
- repeated decrypt failures: close session cleanly
- UDP socket transient error: backoff and reopen if possible
- TUN failure: log, attempt bounded reinitialize, otherwise drain and shut down cleanly
- PMTUD failure: fall back to base PLPMTU
- replay cache pressure: shrink acceptance window before dropping the session

## 17. Migration and Compatibility

The existing PoC protocol is not wire-compatible with production v1.

Therefore:

- introduce protocol version field inside the encrypted envelope
- during rollout, server listens for legacy and v1 in separate demux paths
- legacy mode must be explicitly enabled and time-bounded

## 18. Hidden Risks and Nuances

1. A public routing tag is still a fixed-position field. It is acceptable only if it is opaque, random, rotated, and unlinkable to static identity.
2. A public nonce is also visible. This is acceptable only if all real metadata is encrypted and the nonce itself is semantically meaningless.
3. `XXpsk3` is safer for identity hiding, but costs one extra message versus `IK`.
4. Rekey overlap adds complexity and memory pressure because two epochs coexist briefly.
5. DPLPMTUD probe loss must not be treated like congestion loss, or throughput will collapse.
6. Host-route pinning must handle multiple default routes and dual-stack asymmetry.
7. PMTU is path-specific, not session-global.
8. Replay windows are per receive epoch and per path, not global.
9. Keepalive timers must not wake the process unnecessarily on mobile or laptops.
10. Server-side shard assignment by routing tag requires collision handling and tag rotation.
11. Encrypted metadata solves DPI regex issues but makes stateless middlebox debugging harder, so observability must be strong internally.
12. Cookie/retry design must avoid creating a reflection vector.

## 19. Atomic Rollout Plan

1. Add `docs/rfcs/0001-production-architecture.md`.
2. Introduce a `protocol` crate/module boundary separating handshake, transport, and wire image.
3. Add typed session epochs and separate send/recv key state.
4. Add `x25519-dalek` or equivalent audited X25519 implementation.
5. Add a Noise handshake state implementation or vetted library integration.
6. Implement `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s` handshake state machine.
7. Zeroize handshake secrets and ephemeral private keys after `Split()`.
8. Replace legacy control handshake with Noise transcript messages.
9. Define `routing_tag` format and rotation rules.
10. Replace visible `seq/len/pad_len` with encrypted envelope metadata.
11. Add outer obfuscation AEAD secret derivation.
12. Add per-epoch replay windows with configurable width.
13. Add idempotent control replay cache keyed by request id.
14. Redesign rekey as channel-bound ephemeral DH with overlap window.
15. Implement dual-epoch receive acceptance and delayed commit.
16. Add per-path state object for NAT timers and PLPMTU.
17. Implement adaptive keepalive trigger logic.
18. Implement DPLPMTUD probe frames and acknowledgments.
19. Add optional validated ICMP PTB input path.
20. Add per-client host-route pinning before default-route switch.
21. Add multi-peer session manager with shard-local ownership.
22. Replace global mutex flow with lock-free queues and shard workers.
23. Move packet buffers to pooled `BytesMut` and `Bytes`.
24. Add structured `tracing` spans and stable session IDs.
25. Add graceful restart/cleanup logic for TUN and UDP failures.
26. Add compatibility layer and explicit protocol versioning.
27. Add property tests for replay window and epoch overlap.
28. Add integration tests for reordered UDP, duplicate packets, and rekey races.
29. Add PMTU black-hole simulation tests.
30. Add soak and benchmark harness for multi-peer throughput and memory growth.

## 20. Critical Review of the Plan

The plan is intentionally aggressive, but its weak spots are:

1. It assumes a clean library choice for Noise. If the chosen library is immature, hand-rolling must stay minimal and spec-faithful.
2. It assumes one public routing tag is acceptable on the wire. If this becomes fingerprintable in field tests, we will need rotating tag families or stateless encrypted demux hints.
3. It assumes DPLPMTUD can be implemented without full congestion-control redesign. Probe accounting must be very careful.
4. It assumes the same concurrency design works across Windows and Linux TUN backends. Backend-specific scheduler behavior may force divergence.
5. It assumes production rollout can tolerate a wire break. If not, a negotiated upgrade path will be required.

## 21. Decision

Proceed with:

- `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s`
- opaque routing tag plus encrypted envelope
- per-epoch replay windows
- channel-bound ephemeral rekey
- adaptive keepalive
- DPLPMTUD as the PMTU mechanism
- sharded multi-peer server
- lock-free hot path

This RFC is the implementation baseline for the next iteration.
