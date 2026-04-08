use crate::acl::AccessControlList;
use crate::crypto::{
    build_initiator_handshake, build_responder_handshake, control_decrypt, control_encrypt,
    decrypt_data, derive_bootstrap_obfs_key, derive_epoch_material_from_dh, encrypt_data,
    finish_handshake, generate_routing_tag, read_handshake_message, write_handshake_message, Role,
    RoutingTag, Seed, StaticIdentity,
};
use crate::stealth::{
    decode_handshake_datagram, encode_handshake_datagram, open_transport_datagram,
    peek_routing_tag, seal_transport_datagram, DecodedTransportPacket, FrameKind, ProtectedHeader,
    TrafficProfile,
};
use anyhow::{anyhow, Result};
use rand::rngs::OsRng;
use snow::{HandshakeState, StatelessTransportState};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tracing::info;
use x25519_dalek::{PublicKey, StaticSecret};

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const HANDSHAKE_MAX_RETRIES: usize = 3;
pub const REKEY_AFTER_PACKETS: u64 = 2_048;
pub const REKEY_RETRY_INTERVAL: Duration = Duration::from_secs(2);
pub const REKEY_MAX_RETRIES: usize = 5;
pub const KEEPALIVE_IDLE: Duration = Duration::from_secs(15);
pub const KEEPALIVE_SUSPECT_NAT: Duration = Duration::from_secs(10);
pub const PMTUD_PROBE_INTERVAL: Duration = Duration::from_secs(30);
pub const PMTUD_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
pub const OLD_EPOCH_GRACE: Duration = Duration::from_secs(5);
pub const BASE_PLPMTU: usize = 1_200;
pub const MAX_PLPMTU: usize = 1_452;
pub const TUN_OVERHEAD_BYTES: usize = 96;

const EPOCH_BOOTSTRAP: u32 = 0;

#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub role: Role,
    pub psk: Seed,
    pub local_identity: StaticIdentity,
    pub expected_remote_static: Option<Seed>,
    pub acl: Option<AccessControlList>,
    pub profile: TrafficProfile,
    pub requested_tun_ip: Option<Ipv4Addr>,
}

impl SessionConfig {
    pub fn client(
        psk: Seed,
        local_identity: StaticIdentity,
        server_public_key: Seed,
        profile: TrafficProfile,
        requested_tun_ip: Ipv4Addr,
    ) -> Result<Self> {
        Ok(Self {
            role: Role::Initiator,
            psk,
            local_identity,
            expected_remote_static: Some(server_public_key),
            acl: None,
            profile,
            requested_tun_ip: Some(requested_tun_ip),
        })
    }

    pub fn server(
        psk: Seed,
        local_identity: StaticIdentity,
        acl: AccessControlList,
        profile: TrafficProfile,
    ) -> Result<Self> {
        Ok(Self {
            role: Role::Responder,
            psk,
            local_identity,
            expected_remote_static: None,
            acl: Some(acl),
            profile,
            requested_tun_ip: None,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct ProcessResult {
    pub outbound: Vec<Vec<u8>>,
    pub tun_payloads: Vec<Vec<u8>>,
    pub became_established: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionStatus {
    Handshaking,
    Bootstrapping,
    Established,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RxEpochCandidate {
    Bootstrap,
    Current,
    Pending,
    Previous,
}

#[derive(Clone, Debug, Default)]
struct ReplayWindow {
    highest: Option<u64>,
    bitmap: u128,
}

impl ReplayWindow {
    fn would_accept(&self, seq: u64) -> bool {
        let Some(highest) = self.highest else {
            return true;
        };
        if seq > highest {
            return true;
        }
        let distance = highest - seq;
        if distance >= 128 {
            return false;
        }
        let mask = 1u128 << distance;
        self.bitmap & mask == 0
    }

    fn observe(&mut self, seq: u64) -> bool {
        if !self.would_accept(seq) {
            return false;
        }
        let Some(highest) = self.highest else {
            self.highest = Some(seq);
            self.bitmap = 1;
            return true;
        };

        if seq > highest {
            let shift = seq - highest;
            self.bitmap = if shift >= 128 {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.highest = Some(seq);
            return true;
        }

        let distance = highest - seq;
        let mask = 1u128 << distance;
        self.bitmap |= mask;
        true
    }
}

#[derive(Debug)]
struct ControlPlane {
    transport: StatelessTransportState,
    tx_nonce: u64,
    rx_replay: ReplayWindow,
}

impl ControlPlane {
    fn new(transport: StatelessTransportState) -> Self {
        Self {
            transport,
            tx_nonce: 0,
            rx_replay: ReplayWindow::default(),
        }
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<(u64, Vec<u8>)> {
        let nonce = self.tx_nonce;
        self.tx_nonce = self.tx_nonce.wrapping_add(1);
        let ciphertext = control_encrypt(&self.transport, nonce, plaintext)?;
        Ok((nonce, ciphertext))
    }

    fn decrypt(&self, nonce: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
        control_decrypt(&self.transport, nonce, ciphertext)
    }
}

#[derive(Clone, Debug)]
struct EpochSecretBundle {
    id: u32,
    data_key: Seed,
    obfs_key: Seed,
    mask_key: Seed,
}

#[derive(Clone, Debug)]
struct TxEpoch {
    secret: EpochSecretBundle,
    next_packet_no: u64,
    data_packets_sent: u64,
}

#[derive(Clone, Debug)]
struct RxEpoch {
    secret: EpochSecretBundle,
    replay: ReplayWindow,
}

#[derive(Clone, Debug)]
struct GraceRxEpoch {
    epoch: RxEpoch,
    expires_at: Instant,
}

#[derive(Clone, Debug)]
struct PendingBootstrap {
    private_key: Seed,
}

#[derive(Clone, Debug)]
struct PendingRekeyInit {
    epoch: u32,
    private_key: Seed,
    request: Vec<u8>,
    attempts: usize,
    last_sent_at: Instant,
}

#[derive(Clone, Debug)]
struct CachedReply {
    nonce: u64,
    datagram: Vec<u8>,
}

#[derive(Clone, Debug)]
struct CachedHandshake {
    init: Vec<u8>,
    reply: Vec<u8>,
}

#[derive(Clone, Debug)]
struct InflightProbe {
    id: u16,
    target_size: usize,
    sent_at: Instant,
    misses: u8,
}

#[derive(Clone, Debug)]
pub struct PathState {
    confirmed_plpmtu: usize,
    ceiling_plpmtu: usize,
    next_probe_id: u16,
    inflight_probe: Option<InflightProbe>,
    last_probe_at: Option<Instant>,
    unanswered_keepalives: u8,
}

impl Default for PathState {
    fn default() -> Self {
        Self {
            confirmed_plpmtu: BASE_PLPMTU,
            ceiling_plpmtu: MAX_PLPMTU,
            next_probe_id: 1,
            inflight_probe: None,
            last_probe_at: None,
            unanswered_keepalives: 0,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct PathTick {
    keepalive: bool,
    new_probe: Option<usize>,
    retry_probe: Option<(u16, usize)>,
}

#[derive(Debug)]
enum Lifecycle {
    HandshakeClient {
        state: HandshakeState,
        hello: Vec<u8>,
        started_at: Instant,
        retries: usize,
    },
    Bootstrapping,
    Established,
    Closed,
}

#[derive(Clone, Debug)]
enum ControlMessage {
    BootstrapInit {
        requested_tun_ip: Ipv4Addr,
        epoch: u32,
        public_key: Seed,
    },
    BootstrapResp {
        assigned_tun_ip: Ipv4Addr,
        epoch: u32,
        public_key: Seed,
        confirmed_plpmtu: u16,
    },
    RekeyInit {
        epoch: u32,
        public_key: Seed,
    },
    RekeyResp {
        epoch: u32,
        public_key: Seed,
    },
    Keepalive,
    KeepaliveAck,
    PmtudProbe {
        probe_id: u16,
        target_size: u16,
    },
    PmtudAck {
        probe_id: u16,
        confirmed_size: u16,
    },
    Close {
        reason: u8,
    },
}

pub struct Session {
    config: SessionConfig,
    status: SessionStatus,
    lifecycle: Lifecycle,
    routing_tag: RoutingTag,
    peer_addr: SocketAddr,
    assigned_tun_ip: Option<Ipv4Addr>,
    handshake_hash: Option<Vec<u8>>,
    bootstrap_obfs_key: Option<Seed>,
    control: Option<ControlPlane>,
    cached_handshake: Option<CachedHandshake>,
    pending_bootstrap: Option<PendingBootstrap>,
    pending_rekey: Option<PendingRekeyInit>,
    cached_bootstrap_reply: Option<CachedReply>,
    cached_rekey_reply: Option<CachedReply>,
    tx_current: Option<TxEpoch>,
    tx_pending: Option<TxEpoch>,
    rx_current: Option<RxEpoch>,
    rx_pending: Option<RxEpoch>,
    rx_previous: Option<GraceRxEpoch>,
    last_inbound: Instant,
    last_outbound: Instant,
    path: PathState,
}

impl TxEpoch {
    fn new(epoch: u32, secret: crate::crypto::EpochSecret) -> Self {
        Self {
            secret: EpochSecretBundle {
                id: epoch,
                data_key: secret.data_key,
                obfs_key: secret.obfs_key,
                mask_key: secret.mask_key,
            },
            next_packet_no: 0,
            data_packets_sent: 0,
        }
    }
}

impl RxEpoch {
    fn new(epoch: u32, secret: crate::crypto::EpochSecret) -> Self {
        Self {
            secret: EpochSecretBundle {
                id: epoch,
                data_key: secret.data_key,
                obfs_key: secret.obfs_key,
                mask_key: secret.mask_key,
            },
            replay: ReplayWindow::default(),
        }
    }
}

impl PathState {
    pub fn max_datagram_size(&self) -> usize {
        self.confirmed_plpmtu
    }

    fn next_probe_target(&self) -> Option<usize> {
        if self.confirmed_plpmtu >= self.ceiling_plpmtu {
            None
        } else {
            Some((self.confirmed_plpmtu + 64).min(self.ceiling_plpmtu))
        }
    }

    fn on_probe_sent(&mut self, target_size: usize, now: Instant) -> (u16, usize) {
        let id = self.next_probe_id;
        self.next_probe_id = self.next_probe_id.wrapping_add(1);
        self.inflight_probe = Some(InflightProbe {
            id,
            target_size,
            sent_at: now,
            misses: 0,
        });
        self.last_probe_at = Some(now);
        (id, target_size)
    }

    fn on_probe_ack(&mut self, probe_id: u16, confirmed_size: usize) -> bool {
        let Some(inflight) = self.inflight_probe.as_ref() else {
            return false;
        };
        if inflight.id != probe_id {
            return false;
        }

        self.confirmed_plpmtu = self
            .confirmed_plpmtu
            .max(confirmed_size.min(self.ceiling_plpmtu));
        self.inflight_probe = None;
        true
    }

    fn on_inbound_activity(&mut self) {
        self.unanswered_keepalives = 0;
    }

    fn on_keepalive_sent(&mut self) {
        self.unanswered_keepalives = self.unanswered_keepalives.saturating_add(1);
    }

    fn on_tick(&mut self, now: Instant, last_inbound: Instant, last_outbound: Instant) -> PathTick {
        let mut tick = PathTick::default();

        if let Some(inflight) = self.inflight_probe.as_mut() {
            if now.duration_since(inflight.sent_at) >= PMTUD_PROBE_TIMEOUT {
                inflight.misses = inflight.misses.saturating_add(1);
                if inflight.misses >= 2 {
                    self.ceiling_plpmtu = self
                        .ceiling_plpmtu
                        .min(inflight.target_size.saturating_sub(1));
                    self.inflight_probe = None;
                } else {
                    inflight.sent_at = now;
                    tick.retry_probe = Some((inflight.id, inflight.target_size));
                }
            }
        }

        if now.duration_since(last_outbound) >= KEEPALIVE_IDLE
            || (now.duration_since(last_outbound) >= KEEPALIVE_SUSPECT_NAT
                && now.duration_since(last_inbound) >= KEEPALIVE_SUSPECT_NAT)
        {
            tick.keepalive = true;
        }

        if self.inflight_probe.is_none()
            && self
                .last_probe_at
                .map(|last| now.duration_since(last) >= PMTUD_PROBE_INTERVAL)
                .unwrap_or(true)
        {
            tick.new_probe = self.next_probe_target();
        }

        tick
    }
}

impl Session {
    pub fn new_client(
        config: SessionConfig,
        peer_addr: SocketAddr,
        now: Instant,
    ) -> Result<(Self, Vec<u8>)> {
        let routing_tag = generate_routing_tag();
        let server_public_key = config
            .expected_remote_static
            .ok_or_else(|| anyhow!("client config is missing server public key"))?;
        let mut handshake =
            build_initiator_handshake(&config.local_identity, &server_public_key, &config.psk)?;
        let hello_body = write_handshake_message(&mut handshake, &[])?;
        let hello = encode_handshake_datagram(routing_tag, &hello_body);

        let session = Self {
            config,
            status: SessionStatus::Handshaking,
            lifecycle: Lifecycle::HandshakeClient {
                state: handshake,
                hello: hello.clone(),
                started_at: now,
                retries: 0,
            },
            routing_tag,
            peer_addr,
            assigned_tun_ip: None,
            handshake_hash: None,
            bootstrap_obfs_key: None,
            control: None,
            cached_handshake: None,
            pending_bootstrap: None,
            pending_rekey: None,
            cached_bootstrap_reply: None,
            cached_rekey_reply: None,
            tx_current: None,
            tx_pending: None,
            rx_current: None,
            rx_pending: None,
            rx_previous: None,
            last_inbound: now,
            last_outbound: now,
            path: PathState::default(),
        };
        Ok((session, hello))
    }

    pub fn new_server_from_client_init(
        config: SessionConfig,
        peer_addr: SocketAddr,
        packet: &[u8],
        now: Instant,
    ) -> Result<(Self, Vec<u8>)> {
        let (routing_tag, handshake_body) = decode_handshake_datagram(packet)?;
        let mut handshake = build_responder_handshake(&config.local_identity, &config.psk)?;
        let _ = read_handshake_message(&mut handshake, handshake_body)?;
        let remote_static = handshake
            .get_remote_static()
            .ok_or_else(|| anyhow!("missing client static key in IK handshake"))?;
        if remote_static.len() != 32 {
            return Err(anyhow!("unexpected client static key length"));
        }
        let mut client_public_key = [0u8; 32];
        client_public_key.copy_from_slice(remote_static);
        let authorized = config
            .acl
            .as_ref()
            .and_then(|acl| acl.authorize(&client_public_key))
            .cloned()
            .ok_or_else(|| anyhow!("client is not authorized by ACL"))?;
        info!(
            "[{}] authorized client '{}' for tunnel_ip={}",
            hex::encode(routing_tag),
            authorized.name,
            authorized.inner_ip
        );
        let reply_body = write_handshake_message(&mut handshake, &[])?;
        let reply = encode_handshake_datagram(routing_tag, &reply_body);
        let output = finish_handshake(handshake)?;

        let mut session = Self {
            config,
            status: SessionStatus::Handshaking,
            lifecycle: Lifecycle::Bootstrapping,
            routing_tag,
            peer_addr,
            assigned_tun_ip: Some(authorized.inner_ip),
            handshake_hash: None,
            bootstrap_obfs_key: None,
            control: None,
            cached_handshake: Some(CachedHandshake {
                init: packet.to_vec(),
                reply: reply.clone(),
            }),
            pending_bootstrap: None,
            pending_rekey: None,
            cached_bootstrap_reply: None,
            cached_rekey_reply: None,
            tx_current: None,
            tx_pending: None,
            rx_current: None,
            rx_pending: None,
            rx_previous: None,
            last_inbound: now,
            last_outbound: now,
            path: PathState::default(),
        };
        session.finish_noise_handshake(
            output.remote_static,
            output.handshake_hash,
            output.control,
        )?;
        Ok((session, reply))
    }

    pub fn status(&self) -> SessionStatus {
        self.status.clone()
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    pub fn assigned_tun_ip(&self) -> Option<Ipv4Addr> {
        self.assigned_tun_ip
    }

    pub fn desired_tun_mtu(&self) -> u32 {
        self.path
            .confirmed_plpmtu
            .saturating_sub(TUN_OVERHEAD_BYTES)
            .max(576) as u32
    }

    pub fn process_datagram(
        &mut self,
        packet: &[u8],
        from: SocketAddr,
        now: Instant,
    ) -> Result<ProcessResult> {
        if let Some(cached) = self.cached_handshake.as_ref() {
            if packet == cached.init {
                if from != self.peer_addr {
                    info!(
                        "[{}] peer path migrated during bootstrap: {} -> {}",
                        self.session_id(),
                        self.peer_addr,
                        from
                    );
                    self.peer_addr = from;
                }
                self.last_inbound = now;
                self.path.on_inbound_activity();
                let mut result = ProcessResult::default();
                result.outbound.push(cached.reply.clone());
                return Ok(result);
            }
        }

        match &self.lifecycle {
            Lifecycle::HandshakeClient { .. } => self.process_handshake_packet(packet, from, now),
            Lifecycle::Bootstrapping | Lifecycle::Established => {
                self.process_transport_packet(packet, from, now)
            }
            Lifecycle::Closed => Ok(ProcessResult::default()),
        }
    }

    pub fn on_tun_packet(&mut self, packet: &[u8], now: Instant) -> Result<Option<Vec<u8>>> {
        self.last_outbound = now;
        if self.status != SessionStatus::Established {
            return Ok(None);
        }

        self.send_data(packet, None).map(Some)
    }

    pub fn on_tick(&mut self, now: Instant) -> Result<ProcessResult> {
        let mut result = ProcessResult::default();

        if let Some(previous) = self.rx_previous.as_ref() {
            if now >= previous.expires_at {
                self.rx_previous = None;
            }
        }

        match &mut self.lifecycle {
            Lifecycle::HandshakeClient {
                hello,
                started_at,
                retries,
                ..
            } => {
                if now.duration_since(*started_at) >= HANDSHAKE_TIMEOUT {
                    if *retries >= HANDSHAKE_MAX_RETRIES {
                        self.status = SessionStatus::Closed;
                        self.lifecycle = Lifecycle::Closed;
                        return Err(anyhow!("client handshake timed out"));
                    }
                    *retries += 1;
                    *started_at = now;
                    result.outbound.push(hello.clone());
                }
                return Ok(result);
            }
            Lifecycle::Closed => return Ok(result),
            Lifecycle::Bootstrapping | Lifecycle::Established => {}
        }

        if let Some(pending) = self.pending_rekey.as_mut() {
            if now.duration_since(pending.last_sent_at) >= REKEY_RETRY_INTERVAL {
                if pending.attempts >= REKEY_MAX_RETRIES {
                    self.status = SessionStatus::Closed;
                    self.lifecycle = Lifecycle::Closed;
                    return Err(anyhow!("rekey timed out"));
                }
                pending.attempts += 1;
                pending.last_sent_at = now;
                result.outbound.push(pending.request.clone());
            }
        }

        if self.should_rekey() {
            if let Some(rekey) = self.start_rekey(now)? {
                result.outbound.push(rekey);
            }
        }

        let tick = self
            .path
            .on_tick(now, self.last_inbound, self.last_outbound);
        if tick.keepalive && self.control.is_some() {
            let keepalive = self.send_control(ControlMessage::Keepalive, None, false)?;
            self.path.on_keepalive_sent();
            result.outbound.push(keepalive);
        }

        if let Some((probe_id, probe_size)) = tick.retry_probe {
            let packet = self.send_control(
                ControlMessage::PmtudProbe {
                    probe_id,
                    target_size: probe_size as u16,
                },
                Some(probe_size),
                false,
            )?;
            result.outbound.push(packet);
        } else if let Some(target) = tick.new_probe {
            let (probe_id, probe_size) = self.path.on_probe_sent(target, now);
            let packet = self.send_control(
                ControlMessage::PmtudProbe {
                    probe_id,
                    target_size: probe_size as u16,
                },
                Some(probe_size),
                false,
            )?;
            result.outbound.push(packet);
        }

        Ok(result)
    }

    fn process_handshake_packet(
        &mut self,
        packet: &[u8],
        from: SocketAddr,
        now: Instant,
    ) -> Result<ProcessResult> {
        let (routing_tag, body) = decode_handshake_datagram(packet)?;
        if routing_tag != self.routing_tag {
            return Ok(ProcessResult::default());
        }
        self.accept_peer(from, now);

        match &mut self.lifecycle {
            Lifecycle::HandshakeClient { state, .. } => {
                let _ = read_handshake_message(state, body)?;
                let server_public_key = self
                    .config
                    .expected_remote_static
                    .ok_or_else(|| anyhow!("client config is missing server public key"))?;
                let placeholder = build_initiator_handshake(
                    &self.config.local_identity,
                    &server_public_key,
                    &self.config.psk,
                )?;
                let output = finish_handshake(std::mem::replace(state, placeholder))?;
                self.finish_noise_handshake(
                    output.remote_static,
                    output.handshake_hash,
                    output.control,
                )?;
                let mut result = ProcessResult::default();
                if let Some(requested_ip) = self.config.requested_tun_ip {
                    result.outbound.push(self.start_bootstrap(requested_ip)?);
                }
                Ok(result)
            }
            _ => Ok(ProcessResult::default()),
        }
    }

    fn process_transport_packet(
        &mut self,
        packet: &[u8],
        from: SocketAddr,
        now: Instant,
    ) -> Result<ProcessResult> {
        let tag = peek_routing_tag(packet)?;
        if tag != self.routing_tag {
            return Ok(ProcessResult::default());
        }

        let mut decoded = None;
        let mut candidate = None;
        for (kind, obfs_key, mask_key, epoch_id) in self.rx_candidates(now) {
            if let Ok(opened) = open_transport_datagram(packet, obfs_key, mask_key) {
                if opened.header.epoch != epoch_id {
                    continue;
                }
                decoded = Some(opened);
                candidate = Some(kind);
                break;
            }
        }

        let Some(decoded) = decoded else {
            return Ok(ProcessResult::default());
        };
        let candidate = candidate.expect("candidate set");
        self.accept_peer(from, now);

        let result = match decoded.header.frame_kind {
            FrameKind::Control => self.handle_control_packet(decoded)?,
            FrameKind::Data => self.handle_data_packet(decoded, candidate, now)?,
        };

        if matches!(candidate, RxEpochCandidate::Pending) {
            self.commit_rx_pending(now);
            self.commit_tx_pending();
        }

        Ok(result)
    }

    fn finish_noise_handshake(
        &mut self,
        remote_static: Option<Seed>,
        handshake_hash: Vec<u8>,
        control: StatelessTransportState,
    ) -> Result<()> {
        self.check_remote_static(remote_static)?;
        self.bootstrap_obfs_key = Some(derive_bootstrap_obfs_key(
            &self.config.psk,
            &handshake_hash,
            &self.routing_tag,
        )?);
        self.handshake_hash = Some(handshake_hash);
        self.control = Some(ControlPlane::new(control));
        self.lifecycle = Lifecycle::Bootstrapping;
        self.status = SessionStatus::Bootstrapping;
        info!(
            "[{}] state transition: Handshaking -> Bootstrapping",
            self.session_id()
        );
        Ok(())
    }

    fn start_bootstrap(&mut self, requested_ip: Ipv4Addr) -> Result<Vec<u8>> {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret).to_bytes();
        let packet = self.send_control(
            ControlMessage::BootstrapInit {
                requested_tun_ip: requested_ip,
                epoch: EPOCH_BOOTSTRAP,
                public_key: public,
            },
            None,
            true,
        )?;
        self.pending_bootstrap = Some(PendingBootstrap {
            private_key: secret.to_bytes(),
        });
        Ok(packet)
    }

    fn send_data(&mut self, payload: &[u8], exact_size: Option<usize>) -> Result<Vec<u8>> {
        let tx = self
            .tx_current
            .as_mut()
            .ok_or_else(|| anyhow!("tx epoch not established"))?;
        let epoch_secret = crate::crypto::EpochSecret {
            data_key: tx.secret.data_key,
            obfs_key: tx.secret.obfs_key,
            mask_key: tx.secret.mask_key,
        };
        let packet_no = tx.next_packet_no;
        tx.next_packet_no = tx.next_packet_no.wrapping_add(1);
        tx.data_packets_sent = tx.data_packets_sent.saturating_add(1);

        let ciphertext = encrypt_data(&epoch_secret, packet_no, payload)?;
        let header = ProtectedHeader {
            epoch: tx.secret.id,
            packet_no,
            frame_kind: FrameKind::Data,
            flags: 0,
            body_len: ciphertext.len() as u16,
            probe_id: 0,
            probe_size: 0,
        };
        seal_transport_datagram(
            self.routing_tag,
            &tx.secret.obfs_key,
            &tx.secret.mask_key,
            &header,
            &ciphertext,
            self.config.profile,
            self.path.max_datagram_size(),
            exact_size,
        )
    }

    fn send_control(
        &mut self,
        message: ControlMessage,
        exact_size: Option<usize>,
        force_bootstrap_wrapper: bool,
    ) -> Result<Vec<u8>> {
        let control = self
            .control
            .as_mut()
            .ok_or_else(|| anyhow!("control plane unavailable"))?;
        let plaintext = serialize_control_message(&message);
        let (packet_no, ciphertext) = control.encrypt(&plaintext)?;

        let (epoch, obfs_key, mask_key) = if force_bootstrap_wrapper || self.tx_current.is_none() {
            let bootstrap = self
                .bootstrap_obfs_key
                .ok_or_else(|| anyhow!("bootstrap obfuscation key missing"))?;
            (EPOCH_BOOTSTRAP, bootstrap, bootstrap)
        } else {
            let tx = self
                .tx_current
                .as_ref()
                .ok_or_else(|| anyhow!("missing tx epoch"))?;
            (tx.secret.id, tx.secret.obfs_key, tx.secret.mask_key)
        };

        let (probe_id, probe_size) = match message {
            ControlMessage::PmtudProbe {
                probe_id,
                target_size,
            } => (probe_id, target_size),
            ControlMessage::PmtudAck {
                probe_id,
                confirmed_size,
            } => (probe_id, confirmed_size),
            _ => (0, 0),
        };

        let header = ProtectedHeader {
            epoch,
            packet_no,
            frame_kind: FrameKind::Control,
            flags: 0,
            body_len: ciphertext.len() as u16,
            probe_id,
            probe_size,
        };
        seal_transport_datagram(
            self.routing_tag,
            &obfs_key,
            &mask_key,
            &header,
            &ciphertext,
            self.config.profile,
            self.path.max_datagram_size(),
            exact_size,
        )
    }

    fn start_rekey(&mut self, now: Instant) -> Result<Option<Vec<u8>>> {
        if self.pending_rekey.is_some() || self.tx_pending.is_some() || self.rx_pending.is_some() {
            return Ok(None);
        }
        let next_epoch = self
            .tx_current
            .as_ref()
            .ok_or_else(|| anyhow!("current tx epoch missing"))?
            .secret
            .id
            + 1;

        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret).to_bytes();
        let request = self.send_control(
            ControlMessage::RekeyInit {
                epoch: next_epoch,
                public_key: public,
            },
            None,
            false,
        )?;
        self.pending_rekey = Some(PendingRekeyInit {
            epoch: next_epoch,
            private_key: secret.to_bytes(),
            request: request.clone(),
            attempts: 0,
            last_sent_at: now,
        });
        info!(
            "[{}] rekey requested; next_epoch={next_epoch}",
            self.session_id()
        );
        Ok(Some(request))
    }

    fn should_rekey(&self) -> bool {
        self.status == SessionStatus::Established
            && self
                .tx_current
                .as_ref()
                .map(|tx| tx.data_packets_sent >= REKEY_AFTER_PACKETS)
                .unwrap_or(false)
    }

    fn handle_control_packet(&mut self, packet: DecodedTransportPacket) -> Result<ProcessResult> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| anyhow!("control channel unavailable"))?;
        let plaintext = control.decrypt(packet.header.packet_no, &packet.body)?;

        if self.is_cached_bootstrap_retry(packet.header.packet_no) {
            let mut result = ProcessResult::default();
            if let Some(reply) = self.cached_bootstrap_reply.as_ref() {
                result.outbound.push(reply.datagram.clone());
            }
            return Ok(result);
        }
        if self.is_cached_rekey_retry(packet.header.packet_no) {
            let mut result = ProcessResult::default();
            if let Some(reply) = self.cached_rekey_reply.as_ref() {
                result.outbound.push(reply.datagram.clone());
            }
            return Ok(result);
        }

        let replay_ok = self
            .control
            .as_ref()
            .map(|control| control.rx_replay.would_accept(packet.header.packet_no))
            .unwrap_or(false);
        if !replay_ok {
            return Ok(ProcessResult::default());
        }
        if let Some(control) = self.control.as_mut() {
            let _ = control.rx_replay.observe(packet.header.packet_no);
        }

        let message = parse_control_message(&plaintext)?;
        self.handle_control_message(message, packet.header.packet_no)
    }

    fn handle_control_message(
        &mut self,
        message: ControlMessage,
        nonce: u64,
    ) -> Result<ProcessResult> {
        let mut result = ProcessResult::default();
        match message {
            ControlMessage::BootstrapInit {
                requested_tun_ip,
                epoch,
                public_key,
            } => {
                if self.config.role != Role::Responder
                    || self.status != SessionStatus::Bootstrapping
                {
                    return Ok(result);
                }
                if epoch != EPOCH_BOOTSTRAP {
                    return Ok(result);
                }

                let secret = StaticSecret::random_from_rng(OsRng);
                let responder_pub = PublicKey::from(&secret).to_bytes();
                let (tx, rx) = derive_epoch_material_from_dh(
                    self.config.role,
                    epoch,
                    &self.config.psk,
                    self.handshake_hash
                        .as_ref()
                        .ok_or_else(|| anyhow!("missing handshake hash"))?,
                    &secret,
                    &public_key,
                )?;
                let assigned_ip = self
                    .assigned_tun_ip
                    .ok_or_else(|| anyhow!("ACL did not assign an inner IP"))?;
                if requested_tun_ip != assigned_ip {
                    info!(
                        "[{}] client requested {}, ACL forced {}",
                        self.session_id(),
                        requested_tun_ip,
                        assigned_ip
                    );
                }
                self.install_current_epoch(epoch, tx, rx);
                self.status = SessionStatus::Established;
                self.lifecycle = Lifecycle::Established;
                info!(
                    "[{}] bootstrap completed on responder; tunnel_ip={}",
                    self.session_id(),
                    assigned_ip
                );

                let reply = self.send_control(
                    ControlMessage::BootstrapResp {
                        assigned_tun_ip: assigned_ip,
                        epoch,
                        public_key: responder_pub,
                        confirmed_plpmtu: self.path.confirmed_plpmtu as u16,
                    },
                    None,
                    true,
                )?;
                self.cached_bootstrap_reply = Some(CachedReply {
                    nonce,
                    datagram: reply.clone(),
                });
                result.outbound.push(reply);
                result.became_established = true;
            }
            ControlMessage::BootstrapResp {
                assigned_tun_ip,
                epoch,
                public_key,
                confirmed_plpmtu,
            } => {
                if self.config.role != Role::Initiator
                    || self.status != SessionStatus::Bootstrapping
                {
                    return Ok(result);
                }
                if epoch != EPOCH_BOOTSTRAP {
                    return Ok(result);
                }
                let pending = self
                    .pending_bootstrap
                    .take()
                    .ok_or_else(|| anyhow!("unexpected bootstrap response"))?;
                let private = StaticSecret::from(pending.private_key);
                let (tx, rx) = derive_epoch_material_from_dh(
                    self.config.role,
                    epoch,
                    &self.config.psk,
                    self.handshake_hash
                        .as_ref()
                        .ok_or_else(|| anyhow!("missing handshake hash"))?,
                    &private,
                    &public_key,
                )?;
                if let Some(expected_ip) = self.config.requested_tun_ip {
                    if assigned_tun_ip != expected_ip {
                        return Err(anyhow!(
                            "server assigned unexpected inner IP {assigned_tun_ip}, expected {expected_ip}"
                        ));
                    }
                }
                self.install_current_epoch(epoch, tx, rx);
                self.assigned_tun_ip = Some(assigned_tun_ip);
                self.path.confirmed_plpmtu = confirmed_plpmtu as usize;
                self.status = SessionStatus::Established;
                self.lifecycle = Lifecycle::Established;
                info!(
                    "[{}] state transition: Bootstrapping -> Established; tunnel_ip={}",
                    self.session_id(),
                    assigned_tun_ip
                );
                result.became_established = true;
            }
            ControlMessage::RekeyInit { epoch, public_key } => {
                if self.config.role != Role::Responder || self.status != SessionStatus::Established
                {
                    return Ok(result);
                }
                let current_epoch = self
                    .tx_current
                    .as_ref()
                    .ok_or_else(|| anyhow!("missing tx epoch"))?
                    .secret
                    .id;
                if epoch != current_epoch + 1 {
                    return Ok(result);
                }

                let secret = StaticSecret::random_from_rng(OsRng);
                let responder_pub = PublicKey::from(&secret).to_bytes();
                let (tx, rx) = derive_epoch_material_from_dh(
                    self.config.role,
                    epoch,
                    &self.config.psk,
                    self.handshake_hash
                        .as_ref()
                        .ok_or_else(|| anyhow!("missing handshake hash"))?,
                    &secret,
                    &public_key,
                )?;
                self.tx_pending = Some(TxEpoch::new(epoch, tx));
                self.rx_pending = Some(RxEpoch::new(epoch, rx));
                info!(
                    "[{}] rekey initiated by peer; pending_epoch={epoch}",
                    self.session_id()
                );

                let reply = self.send_control(
                    ControlMessage::RekeyResp {
                        epoch,
                        public_key: responder_pub,
                    },
                    None,
                    false,
                )?;
                self.cached_rekey_reply = Some(CachedReply {
                    nonce,
                    datagram: reply.clone(),
                });
                result.outbound.push(reply);
            }
            ControlMessage::RekeyResp { epoch, public_key } => {
                let pending = match self.pending_rekey.take() {
                    Some(pending) if pending.epoch == epoch => pending,
                    _ => return Ok(result),
                };
                let private = StaticSecret::from(pending.private_key);
                let (tx, rx) = derive_epoch_material_from_dh(
                    self.config.role,
                    epoch,
                    &self.config.psk,
                    self.handshake_hash
                        .as_ref()
                        .ok_or_else(|| anyhow!("missing handshake hash"))?,
                    &private,
                    &public_key,
                )?;
                self.tx_pending = Some(TxEpoch::new(epoch, tx));
                self.rx_pending = Some(RxEpoch::new(epoch, rx));
                self.commit_tx_pending();
                info!(
                    "[{}] rekey response accepted; tx_epoch={epoch}",
                    self.session_id()
                );
            }
            ControlMessage::Keepalive => {
                result.outbound.push(self.send_control(
                    ControlMessage::KeepaliveAck,
                    None,
                    false,
                )?);
            }
            ControlMessage::KeepaliveAck => {
                self.path.on_inbound_activity();
            }
            ControlMessage::PmtudProbe {
                probe_id,
                target_size,
            } => {
                result.outbound.push(self.send_control(
                    ControlMessage::PmtudAck {
                        probe_id,
                        confirmed_size: target_size,
                    },
                    None,
                    false,
                )?);
            }
            ControlMessage::PmtudAck {
                probe_id,
                confirmed_size,
            } => {
                if self.path.on_probe_ack(probe_id, confirmed_size as usize) {
                    info!("[{}] PMTUD updated: {}", self.session_id(), confirmed_size);
                }
            }
            ControlMessage::Close { .. } => {
                self.status = SessionStatus::Closed;
                self.lifecycle = Lifecycle::Closed;
            }
        }
        Ok(result)
    }

    fn handle_data_packet(
        &mut self,
        packet: DecodedTransportPacket,
        candidate: RxEpochCandidate,
        now: Instant,
    ) -> Result<ProcessResult> {
        if self.status != SessionStatus::Established {
            return Ok(ProcessResult::default());
        }

        let (would_accept, data_key) = match candidate {
            RxEpochCandidate::Current => self
                .rx_current
                .as_ref()
                .map(|epoch| {
                    (
                        epoch.replay.would_accept(packet.header.packet_no),
                        epoch.secret.data_key,
                    )
                })
                .ok_or_else(|| anyhow!("missing current rx epoch"))?,
            RxEpochCandidate::Pending => self
                .rx_pending
                .as_ref()
                .map(|epoch| {
                    (
                        epoch.replay.would_accept(packet.header.packet_no),
                        epoch.secret.data_key,
                    )
                })
                .ok_or_else(|| anyhow!("missing pending rx epoch"))?,
            RxEpochCandidate::Previous => self
                .rx_previous
                .as_ref()
                .map(|epoch| {
                    (
                        epoch.epoch.replay.would_accept(packet.header.packet_no),
                        epoch.epoch.secret.data_key,
                    )
                })
                .ok_or_else(|| anyhow!("missing previous rx epoch"))?,
            RxEpochCandidate::Bootstrap => return Ok(ProcessResult::default()),
        };
        if !would_accept {
            return Ok(ProcessResult::default());
        }

        let secret = crate::crypto::EpochSecret {
            data_key,
            obfs_key: [0u8; 32],
            mask_key: [0u8; 32],
        };
        let payload = decrypt_data(&secret, packet.header.packet_no, &packet.body)?;
        if self.config.role == Role::Responder {
            if let (Some(assigned_ip), Some(source_ip)) =
                (self.assigned_tun_ip, parse_ipv4_source(&payload))
            {
                if source_ip != assigned_ip {
                    info!(
                        "[{}] dropped spoofed inner source {}; assigned={}",
                        self.session_id(),
                        source_ip,
                        assigned_ip
                    );
                    return Ok(ProcessResult::default());
                }
            }
        }
        self.observe_data_replay(candidate, packet.header.packet_no);
        self.last_inbound = now;
        self.path.on_inbound_activity();

        let mut result = ProcessResult::default();
        result.tun_payloads.push(payload);
        Ok(result)
    }

    fn install_current_epoch(
        &mut self,
        epoch: u32,
        tx: crate::crypto::EpochSecret,
        rx: crate::crypto::EpochSecret,
    ) {
        self.tx_current = Some(TxEpoch::new(epoch, tx));
        self.rx_current = Some(RxEpoch::new(epoch, rx));
        self.tx_pending = None;
        self.rx_pending = None;
        self.rx_previous = None;
    }

    fn commit_tx_pending(&mut self) {
        if let Some(pending) = self.tx_pending.take() {
            self.tx_current = Some(pending);
        }
    }

    fn commit_rx_pending(&mut self, now: Instant) {
        let Some(pending) = self.rx_pending.take() else {
            return;
        };
        let epoch = pending.secret.id;
        if let Some(current) = self.rx_current.take() {
            self.rx_previous = Some(GraceRxEpoch {
                epoch: current,
                expires_at: now + OLD_EPOCH_GRACE,
            });
        }
        self.rx_current = Some(pending);
        info!(
            "[{}] inbound epoch committed; epoch={epoch}",
            self.session_id()
        );
    }

    fn check_remote_static(&self, remote: Option<Seed>) -> Result<()> {
        if let Some(expected) = self.config.expected_remote_static {
            let remote = remote.ok_or_else(|| anyhow!("remote static key missing"))?;
            if remote != expected {
                return Err(anyhow!("remote static key mismatch"));
            }
        }
        Ok(())
    }

    fn rx_candidates(&self, now: Instant) -> Vec<(RxEpochCandidate, &Seed, &Seed, u32)> {
        let mut out = Vec::new();
        if let Some(key) = self.bootstrap_obfs_key.as_ref() {
            out.push((RxEpochCandidate::Bootstrap, key, key, EPOCH_BOOTSTRAP));
        }
        if let Some(current) = self.rx_current.as_ref() {
            out.push((
                RxEpochCandidate::Current,
                &current.secret.obfs_key,
                &current.secret.mask_key,
                current.secret.id,
            ));
        }
        if let Some(pending) = self.rx_pending.as_ref() {
            out.push((
                RxEpochCandidate::Pending,
                &pending.secret.obfs_key,
                &pending.secret.mask_key,
                pending.secret.id,
            ));
        }
        if let Some(previous) = self.rx_previous.as_ref() {
            if now < previous.expires_at {
                out.push((
                    RxEpochCandidate::Previous,
                    &previous.epoch.secret.obfs_key,
                    &previous.epoch.secret.mask_key,
                    previous.epoch.secret.id,
                ));
            }
        }
        out
    }

    fn observe_data_replay(&mut self, candidate: RxEpochCandidate, packet_no: u64) {
        match candidate {
            RxEpochCandidate::Current => {
                if let Some(current) = self.rx_current.as_mut() {
                    let _ = current.replay.observe(packet_no);
                }
            }
            RxEpochCandidate::Pending => {
                if let Some(pending) = self.rx_pending.as_mut() {
                    let _ = pending.replay.observe(packet_no);
                }
            }
            RxEpochCandidate::Previous => {
                if let Some(previous) = self.rx_previous.as_mut() {
                    let _ = previous.epoch.replay.observe(packet_no);
                }
            }
            RxEpochCandidate::Bootstrap => {}
        }
    }

    fn is_cached_bootstrap_retry(&self, nonce: u64) -> bool {
        self.cached_bootstrap_reply
            .as_ref()
            .map(|cached| cached.nonce == nonce)
            .unwrap_or(false)
    }

    fn is_cached_rekey_retry(&self, nonce: u64) -> bool {
        self.cached_rekey_reply
            .as_ref()
            .map(|cached| cached.nonce == nonce)
            .unwrap_or(false)
    }

    fn session_id(&self) -> String {
        hex::encode(self.routing_tag)
    }

    fn accept_peer(&mut self, from: SocketAddr, now: Instant) {
        if from != self.peer_addr {
            info!(
                "[{}] peer path migrated: {} -> {}",
                self.session_id(),
                self.peer_addr,
                from
            );
            self.peer_addr = from;
        }
        self.last_inbound = now;
        self.path.on_inbound_activity();
    }
}

fn serialize_control_message(message: &ControlMessage) -> Vec<u8> {
    let mut out = Vec::new();
    match message {
        ControlMessage::BootstrapInit {
            requested_tun_ip,
            epoch,
            public_key,
        } => {
            out.push(0x01);
            out.extend_from_slice(&epoch.to_be_bytes());
            out.extend_from_slice(&requested_tun_ip.octets());
            out.extend_from_slice(public_key);
        }
        ControlMessage::BootstrapResp {
            assigned_tun_ip,
            epoch,
            public_key,
            confirmed_plpmtu,
        } => {
            out.push(0x02);
            out.extend_from_slice(&epoch.to_be_bytes());
            out.extend_from_slice(&assigned_tun_ip.octets());
            out.extend_from_slice(public_key);
            out.extend_from_slice(&confirmed_plpmtu.to_be_bytes());
        }
        ControlMessage::RekeyInit { epoch, public_key } => {
            out.push(0x03);
            out.extend_from_slice(&epoch.to_be_bytes());
            out.extend_from_slice(public_key);
        }
        ControlMessage::RekeyResp { epoch, public_key } => {
            out.push(0x04);
            out.extend_from_slice(&epoch.to_be_bytes());
            out.extend_from_slice(public_key);
        }
        ControlMessage::Keepalive => out.push(0x05),
        ControlMessage::KeepaliveAck => out.push(0x06),
        ControlMessage::PmtudProbe {
            probe_id,
            target_size,
        } => {
            out.push(0x07);
            out.extend_from_slice(&probe_id.to_be_bytes());
            out.extend_from_slice(&target_size.to_be_bytes());
        }
        ControlMessage::PmtudAck {
            probe_id,
            confirmed_size,
        } => {
            out.push(0x08);
            out.extend_from_slice(&probe_id.to_be_bytes());
            out.extend_from_slice(&confirmed_size.to_be_bytes());
        }
        ControlMessage::Close { reason } => {
            out.push(0x09);
            out.push(*reason);
        }
    }
    out
}

fn parse_control_message(raw: &[u8]) -> Result<ControlMessage> {
    let kind = *raw
        .first()
        .ok_or_else(|| anyhow!("empty control message"))?;
    match kind {
        0x01 if raw.len() >= 41 => Ok(ControlMessage::BootstrapInit {
            epoch: u32::from_be_bytes(raw[1..5].try_into().expect("slice len checked")),
            requested_tun_ip: Ipv4Addr::from(
                <[u8; 4]>::try_from(&raw[5..9]).expect("slice len checked"),
            ),
            public_key: raw[9..41].try_into().expect("slice len checked"),
        }),
        0x02 if raw.len() >= 43 => Ok(ControlMessage::BootstrapResp {
            epoch: u32::from_be_bytes(raw[1..5].try_into().expect("slice len checked")),
            assigned_tun_ip: Ipv4Addr::from(
                <[u8; 4]>::try_from(&raw[5..9]).expect("slice len checked"),
            ),
            public_key: raw[9..41].try_into().expect("slice len checked"),
            confirmed_plpmtu: u16::from_be_bytes(
                raw[41..43].try_into().expect("slice len checked"),
            ),
        }),
        0x03 if raw.len() >= 37 => Ok(ControlMessage::RekeyInit {
            epoch: u32::from_be_bytes(raw[1..5].try_into().expect("slice len checked")),
            public_key: raw[5..37].try_into().expect("slice len checked"),
        }),
        0x04 if raw.len() >= 37 => Ok(ControlMessage::RekeyResp {
            epoch: u32::from_be_bytes(raw[1..5].try_into().expect("slice len checked")),
            public_key: raw[5..37].try_into().expect("slice len checked"),
        }),
        0x05 => Ok(ControlMessage::Keepalive),
        0x06 => Ok(ControlMessage::KeepaliveAck),
        0x07 if raw.len() >= 5 => Ok(ControlMessage::PmtudProbe {
            probe_id: u16::from_be_bytes(raw[1..3].try_into().expect("slice len checked")),
            target_size: u16::from_be_bytes(raw[3..5].try_into().expect("slice len checked")),
        }),
        0x08 if raw.len() >= 5 => Ok(ControlMessage::PmtudAck {
            probe_id: u16::from_be_bytes(raw[1..3].try_into().expect("slice len checked")),
            confirmed_size: u16::from_be_bytes(raw[3..5].try_into().expect("slice len checked")),
        }),
        0x09 if raw.len() >= 2 => Ok(ControlMessage::Close { reason: raw[1] }),
        _ => Err(anyhow!("unknown control message kind {kind:#x}")),
    }
}

pub fn parse_ipv4_destination(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 {
        return None;
    }
    if packet[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
}

pub fn parse_ipv4_source(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 {
        return None;
    }
    if packet[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{AccessControlList, AuthorizedClient};
    use crate::crypto::generate_static_identity;

    const TEST_PSK: Seed = [0x11; 32];
    const ASSIGNED_IP: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 5);

    fn ipv4_packet(source: Ipv4Addr, destination: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let total_len = 20 + payload.len();
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20..].copy_from_slice(payload);
        packet
    }

    fn test_acl(client_public: Seed) -> AccessControlList {
        AccessControlList::from_clients([AuthorizedClient {
            name: "client-a".into(),
            public_key: client_public,
            inner_ip: ASSIGNED_IP,
        }])
        .unwrap()
    }

    fn establish_pair() -> (Session, Session) {
        let profile = TrafficProfile::GamingLike;
        let client_identity = generate_static_identity();
        let server_identity = generate_static_identity();
        let client_cfg = SessionConfig::client(
            TEST_PSK,
            client_identity.clone(),
            server_identity.public,
            profile,
            ASSIGNED_IP,
        )
        .unwrap();
        let server_cfg = SessionConfig::server(
            TEST_PSK,
            server_identity,
            test_acl(client_identity.public),
            profile,
        )
        .unwrap();
        let server_addr: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        let client_addr: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let now = Instant::now();

        let (mut client, hello) = Session::new_client(client_cfg, server_addr, now).unwrap();
        let (mut server, reply) =
            Session::new_server_from_client_init(server_cfg, client_addr, &hello, now).unwrap();
        let step = client.process_datagram(&reply, server_addr, now).unwrap();
        for packet in step.outbound {
            let server_step = server.process_datagram(&packet, client_addr, now).unwrap();
            for packet in server_step.outbound {
                let _ = client.process_datagram(&packet, server_addr, now).unwrap();
            }
        }
        (client, server)
    }

    #[test]
    fn test_bootstrap_establishes_session() {
        let (client, server) = establish_pair();
        assert_eq!(client.status(), SessionStatus::Established);
        assert_eq!(server.status(), SessionStatus::Established);
        assert_eq!(client.assigned_tun_ip(), Some(ASSIGNED_IP));
        assert_eq!(server.assigned_tun_ip(), Some(ASSIGNED_IP));
    }

    #[test]
    fn test_data_roundtrip() {
        let (mut client, mut server) = establish_pair();
        let now = Instant::now();
        let packet = client.on_tun_packet(b"hello", now).unwrap().unwrap();
        let received = server
            .process_datagram(&packet, client.peer_addr(), now)
            .unwrap();
        assert_eq!(received.tun_payloads, vec![b"hello".to_vec()]);
    }

    #[test]
    fn test_rekey_roundtrip() {
        let (mut client, mut server) = establish_pair();
        let now = Instant::now();
        client
            .tx_current
            .as_mut()
            .expect("current epoch")
            .data_packets_sent = REKEY_AFTER_PACKETS;
        let first = client.on_tun_packet(b"trigger", now).unwrap().unwrap();
        let server_step = server
            .process_datagram(&first, client.peer_addr(), now)
            .unwrap();
        assert_eq!(server_step.tun_payloads, vec![b"trigger".to_vec()]);

        let tick = client.on_tick(now + Duration::from_secs(1)).unwrap();
        let rekey_init = tick.outbound.first().expect("rekey init").clone();
        let server_step = server
            .process_datagram(&rekey_init, client.peer_addr(), now)
            .unwrap();
        let rekey_resp = server_step.outbound.first().expect("rekey resp").clone();
        let _ = client
            .process_datagram(&rekey_resp, server.peer_addr(), now)
            .unwrap();
        let second = client.on_tun_packet(b"after", now).unwrap().unwrap();
        let server_step = server
            .process_datagram(&second, client.peer_addr(), now)
            .unwrap();
        assert_eq!(server_step.tun_payloads, vec![b"after".to_vec()]);
    }

    #[test]
    fn test_unknown_client_is_rejected_by_acl() {
        let profile = TrafficProfile::GamingLike;
        let rogue_client = generate_static_identity();
        let allowed_client = generate_static_identity();
        let server_identity = generate_static_identity();
        let client_cfg = SessionConfig::client(
            TEST_PSK,
            rogue_client,
            server_identity.public,
            profile,
            ASSIGNED_IP,
        )
        .unwrap();
        let server_cfg = SessionConfig::server(
            TEST_PSK,
            server_identity,
            test_acl(allowed_client.public),
            profile,
        )
        .unwrap();
        let server_addr: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        let client_addr: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let now = Instant::now();

        let (_client, hello) = Session::new_client(client_cfg, server_addr, now).unwrap();
        assert!(
            Session::new_server_from_client_init(server_cfg, client_addr, &hello, now).is_err()
        );
    }

    #[test]
    fn test_spoofed_inner_source_is_dropped() {
        let (mut client, mut server) = establish_pair();
        let now = Instant::now();
        let spoofed = ipv4_packet(
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(10, 8, 0, 99),
            b"payload",
        );
        let packet = client.on_tun_packet(&spoofed, now).unwrap().unwrap();
        let received = server
            .process_datagram(&packet, client.peer_addr(), now)
            .unwrap();
        assert!(received.tun_payloads.is_empty());
    }

    #[test]
    fn test_peer_address_migrates_after_authenticated_packet() {
        let (mut client, mut server) = establish_pair();
        let now = Instant::now();
        let new_client_addr: SocketAddr = "127.0.0.1:40001".parse().unwrap();
        let packet = client
            .on_tun_packet(
                &ipv4_packet(ASSIGNED_IP, Ipv4Addr::new(10, 8, 0, 1), b"migrate"),
                now,
            )
            .unwrap()
            .unwrap();

        let received = server
            .process_datagram(&packet, new_client_addr, now + Duration::from_millis(10))
            .unwrap();

        assert_eq!(received.tun_payloads.len(), 1);
        assert_eq!(server.peer_addr(), new_client_addr);
    }

    #[test]
    fn test_parse_ipv4_destination() {
        let packet = [
            0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 17, 0, 0, 10, 8, 0, 1, 10, 8, 0, 2,
        ];
        assert_eq!(
            parse_ipv4_destination(&packet),
            Some(Ipv4Addr::new(10, 8, 0, 2))
        );
    }
}
