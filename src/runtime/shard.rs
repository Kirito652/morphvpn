use crate::acl::AccessControlList;
use crate::runtime::reactor::{
    extract_routing_tag, parse_ipv4_destination, parse_ipv4_source, shard_for_tag, RouteUpdate,
    ShardEvent, ShardInbound, TunWrite, UdpOutbound,
};
use anyhow::Result;
use bytes::Bytes;
use morphvpn_protocol::cookie::StatelessCookieGenerator;
use morphvpn_protocol::handshake::{Seed, StaticIdentity};
use morphvpn_protocol::session::{
    decode_cookie_reply, generate_routing_tag_for_shard, issue_cookie_reply,
    verify_handshake_packet_mac1, verify_handshake_packet_mac2, EstablishedSession,
    PendingClientHandshake, PendingServerHandshake, SessionEvent,
};
use morphvpn_protocol::wire::{decode_handshake_frame, ControlFrame, HandshakeKind, RoutingTag};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

const SHARD_TICK: Duration = Duration::from_secs(1);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const COOKIE_ROTATION: Duration = Duration::from_secs(60);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const RATE_WINDOW: Duration = Duration::from_secs(1);
const RATE_THRESHOLD: u32 = 8;
const DATA_PADDING: usize = 8;

pub enum ShardModeConfig {
    Server(ServerShardConfig),
    Client(ClientShardConfig),
}

#[derive(Clone)]
pub struct ServerShardConfig {
    pub identity: StaticIdentity,
    pub psk: Seed,
    pub acl: AccessControlList,
}

#[derive(Clone)]
pub struct ClientShardConfig {
    pub identity: StaticIdentity,
    pub psk: Seed,
    pub server_addr: SocketAddr,
    pub server_public_key: Seed,
    pub requested_ip: Ipv4Addr,
}

pub struct ShardWorker {
    shard_id: usize,
    num_shards: usize,
    inbound_rx: mpsc::Receiver<ShardInbound>,
    event_tx: mpsc::Sender<ShardEvent>,
    cookie_generator: StatelessCookieGenerator,
    mode: ShardMode,
}

enum ShardMode {
    Server(Box<ServerShardState>),
    Client(Box<ClientShardState>),
}

struct ServerShardState {
    identity: StaticIdentity,
    psk: Seed,
    acl: AccessControlList,
    pending_server: HashMap<RoutingTag, PendingServerEntry>,
    established: HashMap<RoutingTag, SessionSlot>,
    peer_routes: HashMap<Ipv4Addr, RoutingTag>,
    rate_buckets: HashMap<SocketAddr, SourceRateState>,
}

struct ClientShardState {
    config: ClientShardConfig,
    pending_client: Option<PendingClientHandshake>,
    established: Option<SessionSlot>,
    bootstrap_pending: bool,
}

struct PendingServerEntry {
    handshake: PendingServerHandshake,
    response: Bytes,
    created_at: Instant,
}

struct SessionSlot {
    session: EstablishedSession,
    last_activity: Instant,
    last_keepalive: Instant,
}

struct SourceRateState {
    window_started_at: Instant,
    count: u32,
}

impl ShardWorker {
    pub fn new(
        shard_id: usize,
        num_shards: usize,
        inbound_rx: mpsc::Receiver<ShardInbound>,
        event_tx: mpsc::Sender<ShardEvent>,
        mode: ShardModeConfig,
    ) -> Result<Self> {
        let cookie_generator = StatelessCookieGenerator::new([0xA5; 32], COOKIE_ROTATION)?;
        let mode = match mode {
            ShardModeConfig::Server(config) => ShardMode::Server(Box::new(ServerShardState {
                identity: config.identity,
                psk: config.psk,
                acl: config.acl,
                pending_server: HashMap::new(),
                established: HashMap::new(),
                peer_routes: HashMap::new(),
                rate_buckets: HashMap::new(),
            })),
            ShardModeConfig::Client(config) => ShardMode::Client(Box::new(ClientShardState {
                config,
                pending_client: None,
                established: None,
                bootstrap_pending: false,
            })),
        };

        Ok(Self {
            shard_id,
            num_shards,
            inbound_rx,
            event_tx,
            cookie_generator,
            mode,
        })
    }

    pub async fn run(mut self) -> Result<()> {
        self.bootstrap().await?;
        let mut tick = tokio::time::interval(SHARD_TICK);

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    self.on_tick().await?;
                }
                inbound = self.inbound_rx.recv() => {
                    let Some(inbound) = inbound else {
                        return Ok(());
                    };
                    match inbound {
                        ShardInbound::Udp(packet) => self.handle_udp(packet.source, packet.packet, packet.received_at).await?,
                        ShardInbound::Tun(packet) => self.handle_tun(packet.packet, packet.received_at).await?,
                    }
                }
            }
        }
    }

    async fn bootstrap(&mut self) -> Result<()> {
        let mut outbound = None;
        if let ShardMode::Client(state) = &mut self.mode {
            let routing_tag = generate_routing_tag_for_shard(
                |tag| shard_for_tag(tag, self.num_shards),
                self.shard_id,
            );
            let (pending, init_packet) = PendingClientHandshake::new(
                state.config.identity.clone(),
                state.config.psk,
                state.config.server_public_key,
                state.config.requested_ip,
                routing_tag,
            )?;
            state.pending_client = Some(pending);
            outbound = Some((state.config.server_addr, init_packet));
        }
        if let Some((target, packet)) = outbound {
            Self::emit_udp(&self.event_tx, self.shard_id, target, packet);
        }
        Ok(())
    }

    async fn on_tick(&mut self) -> Result<()> {
        let event_tx = self.event_tx.clone();
        let shard_id = self.shard_id;
        let mut needs_bootstrap = false;
        match &mut self.mode {
            ShardMode::Server(state) => {
                state
                    .pending_server
                    .retain(|_, entry| entry.created_at.elapsed() < HANDSHAKE_TIMEOUT);
                state
                    .rate_buckets
                    .retain(|_, entry| entry.window_started_at.elapsed() < RATE_WINDOW);

                let mut outbound = Vec::new();
                for slot in state.established.values_mut() {
                    if slot.last_keepalive.elapsed() >= KEEPALIVE_INTERVAL {
                        if let Ok(packet) = slot.session.send_keepalive() {
                            outbound.push((slot.session.peer_addr(), packet));
                        }
                        slot.last_keepalive = Instant::now();
                    }
                    if let Some(packet) = slot.session.advance_rekey()? {
                        outbound.push((slot.session.peer_addr(), packet));
                    }
                }
                for (target, packet) in outbound {
                    Self::emit_udp(&event_tx, shard_id, target, packet);
                }
            }
            ShardMode::Client(state) => {
                let mut outbound = Vec::new();
                if state.bootstrap_pending {
                    if let Some(slot) = state.established.as_mut() {
                        if let Some(requested_ip) = slot.session.requested_ip() {
                            outbound.push((state.config.server_addr, slot.session.send_bootstrap_init(requested_ip)?));
                            state.bootstrap_pending = false;
                            slot.last_keepalive = Instant::now();
                        }
                    }
                }

                if let Some(slot) = state.established.as_mut() {
                    if slot.last_keepalive.elapsed() >= KEEPALIVE_INTERVAL {
                        if let Ok(packet) = slot.session.send_keepalive() {
                            outbound.push((state.config.server_addr, packet));
                        }
                        slot.last_keepalive = Instant::now();
                    }
                    if let Some(packet) = slot.session.advance_rekey()? {
                        outbound.push((state.config.server_addr, packet));
                    }
                } else if state.pending_client.is_none() {
                    needs_bootstrap = true;
                }

                for (target, packet) in outbound {
                    Self::emit_udp(&event_tx, shard_id, target, packet);
                }
            }
        }
        if needs_bootstrap {
            self.bootstrap().await?;
        }
        Ok(())
    }

    async fn handle_udp(
        &mut self,
        source: SocketAddr,
        packet: Bytes,
        received_at: Instant,
    ) -> Result<()> {
        let event_tx = self.event_tx.clone();
        let shard_id = self.shard_id;
        let num_shards = self.num_shards;
        let cookie_generator = self.cookie_generator.clone();
        match &mut self.mode {
            ShardMode::Server(state) => {
                Self::handle_server_udp_with(
                    shard_id,
                    &event_tx,
                    &cookie_generator,
                    state,
                    source,
                    packet,
                    received_at,
                )
                .await
            }
            ShardMode::Client(state) => {
                Self::handle_client_udp_with(
                    shard_id,
                    num_shards,
                    &event_tx,
                    state,
                    source,
                    packet,
                    received_at,
                )
                .await
            }
        }
    }

    async fn handle_tun(&mut self, packet: Bytes, received_at: Instant) -> Result<()> {
        let event_tx = self.event_tx.clone();
        let shard_id = self.shard_id;
        match &mut self.mode {
            ShardMode::Server(state) => {
                let Some(destination) = parse_ipv4_destination(&packet) else {
                    return Ok(());
                };
                let Some(routing_tag) = state.peer_routes.get(&destination).copied() else {
                    return Ok(());
                };
                let Some(slot) = state.established.get_mut(&routing_tag) else {
                    state.peer_routes.remove(&destination);
                    return Ok(());
                };
                let outbound = slot.session.send_data(packet, DATA_PADDING)?;
                slot.last_activity = received_at;
                Self::emit_udp(&event_tx, shard_id, slot.session.peer_addr(), outbound);
            }
            ShardMode::Client(state) => {
                let Some(slot) = state.established.as_mut() else {
                    return Ok(());
                };
                let outbound = slot.session.send_data(packet, DATA_PADDING)?;
                slot.last_activity = received_at;
                Self::emit_udp(&event_tx, shard_id, state.config.server_addr, outbound);
            }
        }
        Ok(())
    }

    async fn handle_server_udp_with(
        shard_id: usize,
        event_tx: &mpsc::Sender<ShardEvent>,
        cookie_generator: &StatelessCookieGenerator,
        state: &mut ServerShardState,
        source: SocketAddr,
        packet: Bytes,
        received_at: Instant,
    ) -> Result<()> {
        let Some(routing_tag) = extract_routing_tag(&packet) else {
            return Ok(());
        };

        if state.established.contains_key(&routing_tag) {
            let event = if let Some(slot) = state.established.get_mut(&routing_tag) {
                slot.session.set_peer_addr(source);
                slot.last_activity = received_at;
                slot.session.open_inbound(packet)?
            } else {
                return Ok(());
            };
            Self::process_server_session_event_with(shard_id, event_tx, state, routing_tag, event)
                .await?;
            return Ok(());
        }

        if let Some(entry) = state.pending_server.remove(&routing_tag) {
            if let Ok(frame) = decode_handshake_frame(packet.clone()) {
                if frame.kind == HandshakeKind::Finish
                    && verify_handshake_packet_mac1(
                        cookie_generator,
                        &state.identity.public,
                        &packet,
                    )?
                {
                    let session = entry.handshake.complete(packet, state.psk)?;
                    if let Some(remote_static) = session.remote_static() {
                        if state.acl.authorize(&remote_static).is_none() {
                            debug!("rejecting unauthorized client on shard {}", shard_id);
                            return Ok(());
                        }
                    } else {
                        return Ok(());
                    }
                    state.established.insert(
                        routing_tag,
                        SessionSlot {
                            session,
                            last_activity: received_at,
                            last_keepalive: Instant::now(),
                        },
                    );
                    return Ok(());
                }
            }
            Self::emit_udp(event_tx, shard_id, source, entry.response.clone());
            state.pending_server.insert(routing_tag, entry);
            return Ok(());
        }

        let Ok(frame) = decode_handshake_frame(packet.clone()) else {
            return Ok(());
        };
        if frame.kind != HandshakeKind::Init {
            return Ok(());
        }
        if !verify_handshake_packet_mac1(cookie_generator, &state.identity.public, &packet)? {
            debug!("dropping init with invalid MAC1 from {source}");
            return Ok(());
        }
        if Self::source_is_under_load(&mut state.rate_buckets, source, received_at) {
            let now = SystemTime::now();
            let current_cookie = cookie_generator.issue_cookie(source, &routing_tag, now)?;
            let previous_cookie = now
                .checked_sub(cookie_generator.rotation_period())
                .and_then(|when| cookie_generator.issue_cookie(source, &routing_tag, when).ok());
            let valid_cookie = verify_handshake_packet_mac2(cookie_generator, &current_cookie, &packet)?
                || previous_cookie
                    .as_ref()
                    .map(|cookie| verify_handshake_packet_mac2(cookie_generator, cookie, &packet))
                    .transpose()?
                    .unwrap_or(false);
            if !valid_cookie {
                let reply = issue_cookie_reply(
                    cookie_generator,
                    &state.identity.public,
                    source,
                    routing_tag,
                    now,
                )?;
                Self::emit_udp(event_tx, shard_id, source, reply);
                return Ok(());
            }
        }

        let (pending, response) = PendingServerHandshake::from_init(
            &state.identity,
            &state.psk,
            source,
            routing_tag,
            frame.payload.as_ref(),
        )?;
        Self::emit_udp(event_tx, shard_id, source, response.clone());
        state.pending_server.insert(
            routing_tag,
            PendingServerEntry {
                handshake: pending,
                response,
                created_at: received_at,
            },
        );
        Ok(())
    }

    async fn process_server_session_event_with(
        shard_id: usize,
        event_tx: &mpsc::Sender<ShardEvent>,
        state: &mut ServerShardState,
        routing_tag: RoutingTag,
        event: SessionEvent,
    ) -> Result<()> {
        match event {
            SessionEvent::Control(frame) => match frame {
                ControlFrame::BootstrapInit { requested_ip: _ } => {
                    let Some(slot) = state.established.get_mut(&routing_tag) else {
                        return Ok(());
                    };
                    let Some(remote_static) = slot.session.remote_static() else {
                        return Ok(());
                    };
                    let Some(client) = state.acl.authorize(&remote_static) else {
                        return Ok(());
                    };
                    slot.session.assign_ip(client.inner_ip);
                    state.peer_routes.insert(client.inner_ip, routing_tag);
                    Self::emit_route(
                        event_tx,
                        shard_id,
                        RouteUpdate::Install {
                            destination: client.inner_ip,
                            shard_id,
                        },
                    );
                    let reply = slot.session.send_bootstrap_resp(client.inner_ip)?;
                    Self::emit_udp(event_tx, shard_id, slot.session.peer_addr(), reply);
                    info!("assigned {} to ACL client {}", client.inner_ip, client.name);
                }
                ControlFrame::Keepalive => {
                    if let Some(slot) = state.established.get_mut(&routing_tag) {
                        let ack = slot.session.send_keepalive_ack()?;
                        Self::emit_udp(event_tx, shard_id, slot.session.peer_addr(), ack);
                    }
                }
                ControlFrame::Close { .. } => {
                    Self::remove_server_session(event_tx, shard_id, state, routing_tag);
                }
                ControlFrame::KeepaliveAck
                | ControlFrame::RekeyInit { .. }
                | ControlFrame::RekeyResp { .. }
                | ControlFrame::PmtudProbe { .. }
                | ControlFrame::PmtudAck { .. }
                | ControlFrame::BootstrapResp { .. } => {}
            },
            SessionEvent::Data(payload) => {
                if let Some(slot) = state.established.get(&routing_tag) {
                    if let Some(assigned_ip) = slot.session.assigned_ip() {
                        if let Some(source_ip) = parse_ipv4_source(&payload) {
                            if source_ip != assigned_ip {
                                debug!(
                                    "dropping spoofed payload from {source_ip}; expected {assigned_ip}"
                                );
                                return Ok(());
                            }
                        }
                    }
                }
                Self::emit_tun(event_tx, shard_id, payload);
            }
            SessionEvent::None
            | SessionEvent::Established
            | SessionEvent::RouteInstall(_)
            | SessionEvent::RouteRemove(_) => {}
        }
        Ok(())
    }

    async fn handle_client_udp_with(
        shard_id: usize,
        _num_shards: usize,
        event_tx: &mpsc::Sender<ShardEvent>,
        state: &mut ClientShardState,
        source: SocketAddr,
        packet: Bytes,
        received_at: Instant,
    ) -> Result<()> {
        if let Ok(frame) = decode_handshake_frame(packet.clone()) {
            if frame.kind == HandshakeKind::CookieReply {
                if let Some(pending) = state.pending_client.take() {
                    let cookie = decode_cookie_reply(packet)?;
                    let (next_pending, next_init) = pending.restart_with_cookie(cookie)?;
                    state.pending_client = Some(next_pending);
                    Self::emit_udp(event_tx, shard_id, state.config.server_addr, next_init);
                }
                return Ok(());
            }

            if frame.kind == HandshakeKind::Resp {
                if let Some(pending) = state.pending_client.take() {
                    let (mut session, finish) = pending.into_established(packet)?;
                    session.set_peer_addr(source);
                    Self::emit_udp(event_tx, shard_id, state.config.server_addr, finish);
                    state.established = Some(SessionSlot {
                        session,
                        last_activity: received_at,
                        last_keepalive: Instant::now(),
                    });
                    state.bootstrap_pending = true;
                }
                return Ok(());
            }
        }

        let Some(slot) = state.established.as_mut() else {
            return Ok(());
        };
        slot.session.set_peer_addr(source);
        slot.last_activity = received_at;
        match slot.session.open_inbound(packet)? {
            SessionEvent::Control(frame) => match frame {
                ControlFrame::BootstrapResp { assigned_ip } => {
                    slot.session.assign_ip(assigned_ip);
                    info!("client assigned tunnel IP {assigned_ip}");
                }
                ControlFrame::Keepalive => {
                    let ack = slot.session.send_keepalive_ack()?;
                    Self::emit_udp(event_tx, shard_id, state.config.server_addr, ack);
                }
                ControlFrame::Close { .. } => {
                    state.established = None;
                    state.bootstrap_pending = false;
                }
                ControlFrame::KeepaliveAck
                | ControlFrame::RekeyInit { .. }
                | ControlFrame::RekeyResp { .. }
                | ControlFrame::PmtudProbe { .. }
                | ControlFrame::PmtudAck { .. }
                | ControlFrame::BootstrapInit { .. } => {}
            },
            SessionEvent::Data(payload) => {
                Self::emit_tun(event_tx, shard_id, payload);
            }
            SessionEvent::None
            | SessionEvent::Established
            | SessionEvent::RouteInstall(_)
            | SessionEvent::RouteRemove(_) => {}
        }
        Ok(())
    }

    fn remove_server_session(
        event_tx: &mpsc::Sender<ShardEvent>,
        shard_id: usize,
        state: &mut ServerShardState,
        routing_tag: RoutingTag,
    ) {
        if let Some(slot) = state.established.remove(&routing_tag) {
            if let Some(assigned_ip) = slot.session.assigned_ip() {
                state.peer_routes.remove(&assigned_ip);
                Self::emit_route(event_tx, shard_id, RouteUpdate::Remove {
                    destination: assigned_ip,
                });
            }
        }
    }

    fn source_is_under_load(rate_buckets: &mut HashMap<SocketAddr, SourceRateState>, source: SocketAddr, now: Instant) -> bool {
        let entry = rate_buckets.entry(source).or_insert(SourceRateState {
            window_started_at: now,
            count: 0,
        });
        if now.duration_since(entry.window_started_at) >= RATE_WINDOW {
            entry.window_started_at = now;
            entry.count = 0;
        }
        entry.count = entry.count.saturating_add(1);
        entry.count > RATE_THRESHOLD
    }

    fn emit_udp(event_tx: &mpsc::Sender<ShardEvent>, shard_id: usize, target: SocketAddr, packet: Bytes) {
        match event_tx.try_send(ShardEvent::Udp(UdpOutbound { target, packet })) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("dropping UDP outbound packet from shard {shard_id}");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!("UDP event channel closed for shard {shard_id}");
            }
        }
    }

    fn emit_tun(event_tx: &mpsc::Sender<ShardEvent>, shard_id: usize, packet: Bytes) {
        match event_tx.try_send(ShardEvent::Tun(TunWrite { packet })) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("dropping TUN write event from shard {shard_id}");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!("TUN event channel closed for shard {shard_id}");
            }
        }
    }

    fn emit_route(event_tx: &mpsc::Sender<ShardEvent>, shard_id: usize, route: RouteUpdate) {
        match event_tx.try_send(ShardEvent::Route(route)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("dropping route event from shard {shard_id}");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!("route event channel closed for shard {shard_id}");
            }
        }
    }
}
