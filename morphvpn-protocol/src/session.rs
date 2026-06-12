use crate::cookie::{Cookie, StatelessCookieGenerator};
use crate::cookie::{compute_mac1, compute_mac2};
use crate::crypto::{
    decrypt_data, derive_epoch_keys, encrypt_data, open_transport_packet, random_padding_len,
    seal_transport_packet, EpochKeys, SessionRole,
};
use crate::handshake::{
    Established as HandshakeEstablished, InitiatorCreated, ResponderCreated, Seed, StaticIdentity,
    WaitFinish, WaitResp,
};
use crate::replay::ReplayWindow2048;
use crate::wire::{
    decode_handshake_frame, encode_handshake_frame, ControlFrame, HandshakeFrame, HandshakeKind,
    ProtectedHeader, RoutingTag, TransportKind, MAC_LEN,
};
use anyhow::{anyhow, Result};
use bytes::Bytes;
use rand::{rngs::OsRng, RngCore};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::SystemTime;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionTag(pub RoutingTag);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionEvent {
    Established,
    Data(Bytes),
    Control(ControlFrame),
    RouteInstall(Ipv4Addr),
    RouteRemove(Ipv4Addr),
    None,
}

#[derive(Debug)]
pub struct PendingClientHandshake {
    local_identity: StaticIdentity,
    psk: Seed,
    server_public_key: Seed,
    requested_ip: Ipv4Addr,
    routing_tag: RoutingTag,
    wait_resp: WaitResp,
}

#[derive(Debug)]
pub struct PendingServerHandshake {
    wait_finish: WaitFinish,
    routing_tag: RoutingTag,
    peer_addr: SocketAddr,
}

#[derive(Debug)]
pub struct EstablishedSession {
    _role: SessionRole,
    routing_tag: RoutingTag,
    peer_addr: SocketAddr,
    _psk: Seed,
    _handshake_hash: Bytes,
    remote_static: Option<Seed>,
    control: HandshakeEstablished,
    tx_epoch: EpochKeys,
    rx_epoch: EpochKeys,
    control_tx_nonce: u64,
    control_replay: ReplayWindow2048,
    data_tx_nonce: u64,
    data_replay: ReplayWindow2048,
    assigned_ip: Option<Ipv4Addr>,
    requested_ip: Option<Ipv4Addr>,
}

impl PendingClientHandshake {
    pub fn new(
        local_identity: StaticIdentity,
        psk: Seed,
        server_public_key: Seed,
        requested_ip: Ipv4Addr,
        routing_tag: RoutingTag,
    ) -> Result<(Self, Bytes)> {
        Self::with_cookie(local_identity, psk, server_public_key, requested_ip, routing_tag, None)
    }

    pub fn restart_with_cookie(self, cookie: Cookie) -> Result<(Self, Bytes)> {
        Self::with_cookie(
            self.local_identity,
            self.psk,
            self.server_public_key,
            self.requested_ip,
            self.routing_tag,
            Some(cookie),
        )
    }

    pub fn routing_tag(&self) -> RoutingTag {
        self.routing_tag
    }

    pub fn into_established(self, raw_packet: Bytes) -> Result<(EstablishedSession, Bytes)> {
        let frame = decode_handshake_frame(raw_packet)?;
        if frame.kind != HandshakeKind::Resp {
            return Err(anyhow!("expected handshake response frame"));
        }

        let send_finish = self.wait_resp.read_resp(&frame.payload)?;
        let (control, finish_payload) = send_finish.send_finish(b"finish")?;
        let finish_frame = build_handshake_frame(
            self.routing_tag,
            HandshakeKind::Finish,
            finish_payload,
            None,
            Some(self.server_public_key),
        )?;
        let session = EstablishedSession::new(
            SessionRole::Client,
            self.routing_tag,
            SocketAddr::from(([0, 0, 0, 0], 0)),
            self.psk,
            control,
            Some(self.requested_ip),
        )?;
        Ok((session, encode_handshake_frame(&finish_frame)))
    }

    fn with_cookie(
        local_identity: StaticIdentity,
        psk: Seed,
        server_public_key: Seed,
        requested_ip: Ipv4Addr,
        routing_tag: RoutingTag,
        cookie: Option<Cookie>,
    ) -> Result<(Self, Bytes)> {
        let initiator = InitiatorCreated::new(&local_identity, &psk, Some(server_public_key))?;
        let (wait_resp, init_payload) = initiator.send_init(b"init")?;
        let init_frame = build_handshake_frame(
            routing_tag,
            HandshakeKind::Init,
            init_payload,
            cookie,
            Some(server_public_key),
        )?;
        Ok((
            Self {
                local_identity,
                psk,
                server_public_key,
                requested_ip,
                routing_tag,
                wait_resp,
            },
            encode_handshake_frame(&init_frame),
        ))
    }
}

impl PendingServerHandshake {
    pub fn from_init(
        identity: &StaticIdentity,
        psk: &Seed,
        source: SocketAddr,
        routing_tag: RoutingTag,
        init_payload: &[u8],
    ) -> Result<(Self, Bytes)> {
        let responder = ResponderCreated::new(identity, psk)?;
        let send_resp = responder.read_init(init_payload)?;
        let (wait_finish, resp_payload) = send_resp.send_resp(b"resp")?;
        let response = build_handshake_frame(
            routing_tag,
            HandshakeKind::Resp,
            resp_payload,
            None,
            Some(identity.public),
        )?;
        Ok((
            Self {
                wait_finish,
                routing_tag,
                peer_addr: source,
            },
            encode_handshake_frame(&response),
        ))
    }

    pub fn complete(self, finish_packet: Bytes, psk: Seed) -> Result<EstablishedSession> {
        let frame = decode_handshake_frame(finish_packet)?;
        if frame.kind != HandshakeKind::Finish {
            return Err(anyhow!("expected handshake finish frame"));
        }
        let control = self.wait_finish.read_finish(&frame.payload)?;
        EstablishedSession::new(
            SessionRole::Server,
            self.routing_tag,
            self.peer_addr,
            psk,
            control,
            None,
        )
    }
}

impl EstablishedSession {
    pub fn new(
        role: SessionRole,
        routing_tag: RoutingTag,
        peer_addr: SocketAddr,
        psk: Seed,
        control: HandshakeEstablished,
        requested_ip: Option<Ipv4Addr>,
    ) -> Result<Self> {
        let (tx_epoch, rx_epoch) =
            derive_epoch_keys(role, 0, &psk, control.handshake_hash.as_ref())?;
        Ok(Self {
            _role: role,
            routing_tag,
            peer_addr,
            _psk: psk,
            _handshake_hash: control.handshake_hash.clone(),
            remote_static: control.remote_static,
            control,
            tx_epoch,
            rx_epoch,
            control_tx_nonce: 0,
            control_replay: ReplayWindow2048::default(),
            data_tx_nonce: 0,
            data_replay: ReplayWindow2048::default(),
            assigned_ip: None,
            requested_ip,
        })
    }

    pub fn routing_tag(&self) -> RoutingTag {
        self.routing_tag
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    pub fn set_peer_addr(&mut self, peer_addr: SocketAddr) {
        self.peer_addr = peer_addr;
    }

    pub fn remote_static(&self) -> Option<Seed> {
        self.remote_static
    }

    pub fn assigned_ip(&self) -> Option<Ipv4Addr> {
        self.assigned_ip
    }

    pub fn requested_ip(&self) -> Option<Ipv4Addr> {
        self.requested_ip
    }

    pub fn assign_ip(&mut self, ip: Ipv4Addr) {
        self.assigned_ip = Some(ip);
    }

    pub fn current_routing_tag(&self) -> RoutingTag {
        self.routing_tag
    }

    pub fn send_bootstrap_init(&mut self, requested_ip: Ipv4Addr) -> Result<Bytes> {
        self.send_control(ControlFrame::BootstrapInit { requested_ip }, 8)
    }

    pub fn send_bootstrap_resp(&mut self, assigned_ip: Ipv4Addr) -> Result<Bytes> {
        self.send_control(ControlFrame::BootstrapResp { assigned_ip }, 8)
    }

    pub fn send_keepalive(&mut self) -> Result<Bytes> {
        self.send_control(ControlFrame::Keepalive, 8)
    }

    pub fn send_keepalive_ack(&mut self) -> Result<Bytes> {
        self.send_control(ControlFrame::KeepaliveAck, 8)
    }

    pub fn send_close(&mut self, reason: u8) -> Result<Bytes> {
        self.send_control(ControlFrame::Close { reason }, 8)
    }

    pub fn send_data(&mut self, payload: Bytes, padding_len: usize) -> Result<Bytes> {
        let packet_no = self.data_tx_nonce;
        self.data_tx_nonce = self.data_tx_nonce.wrapping_add(1);
        let ciphertext = encrypt_data(&self.tx_epoch, packet_no, payload.as_ref())?;
        let header = ProtectedHeader {
            version: 1,
            transport_kind: TransportKind::Data,
            flags: 0,
            epoch: self.tx_epoch.epoch,
            packet_no,
            body_len: ciphertext.len() as u16,
            pad_len: padding_len as u16,
            probe_id: 0,
            probe_size: 0,
        };
        seal_transport_packet(self.routing_tag, &self.tx_epoch, &header, ciphertext, padding_len)
    }

    pub fn open_inbound(&mut self, packet: Bytes) -> Result<SessionEvent> {
        let opened = open_transport_packet(packet, &self.rx_epoch)?;
        match opened.header.transport_kind {
            TransportKind::Control => self.open_control(opened.header.packet_no, opened.body),
            TransportKind::Data => self.open_data(opened.header.packet_no, opened.body),
        }
    }

    pub fn advance_rekey(&mut self) -> Result<Option<Bytes>> {
        if self.data_tx_nonce < (u64::MAX - 4_096) {
            return Ok(None);
        }

        let close = self.send_close(1)?;
        Ok(Some(close))
    }

    fn open_control(&mut self, nonce: u64, body: Bytes) -> Result<SessionEvent> {
        if !self.control_replay.observe(nonce) {
            return Ok(SessionEvent::None);
        }
        let plaintext = self.control.decrypt_control(nonce, body.as_ref())?;
        let frame = ControlFrame::decode(plaintext)?;
        Ok(SessionEvent::Control(frame))
    }

    fn open_data(&mut self, packet_no: u64, body: Bytes) -> Result<SessionEvent> {
        let plaintext = decrypt_data(&self.rx_epoch, packet_no, body.as_ref())?;
        if !self.data_replay.observe(packet_no) {
            return Ok(SessionEvent::None);
        }
        Ok(SessionEvent::Data(plaintext))
    }

    fn send_control(&mut self, frame: ControlFrame, padding_len: usize) -> Result<Bytes> {
        let nonce = self.control_tx_nonce;
        self.control_tx_nonce = self.control_tx_nonce.wrapping_add(1);
        let plaintext = frame.encode();
        let ciphertext = self.control.encrypt_control(nonce, plaintext.as_ref())?;
        let header = ProtectedHeader {
            version: 1,
            transport_kind: TransportKind::Control,
            flags: 0,
            epoch: self.tx_epoch.epoch,
            packet_no: nonce,
            body_len: ciphertext.len() as u16,
            pad_len: padding_len as u16,
            probe_id: 0,
            probe_size: 0,
        };
        seal_transport_packet(self.routing_tag, &self.tx_epoch, &header, ciphertext, padding_len)
    }
}

pub fn verify_handshake_packet_mac1(
    generator: &StatelessCookieGenerator,
    responder_public_key: &[u8; 32],
    packet: &Bytes,
) -> Result<bool> {
    let frame = decode_handshake_frame(packet.clone())?;
    let mac_bytes_len = MAC_LEN + usize::from(frame.mac2.is_some()) * MAC_LEN;
    generator.verify_mac1(
        responder_public_key,
        &packet[..packet.len() - mac_bytes_len],
        &frame.mac1,
    )
}

pub fn verify_handshake_packet_mac2(
    generator: &StatelessCookieGenerator,
    cookie: &Cookie,
    packet: &Bytes,
) -> Result<bool> {
    let frame = decode_handshake_frame(packet.clone())?;
    let Some(mac2) = frame.mac2 else {
        return Ok(false);
    };
    generator.verify_mac2(cookie, &packet[..packet.len() - MAC_LEN], &mac2)
}

pub fn issue_cookie_reply(
    generator: &StatelessCookieGenerator,
    responder_public_key: &[u8; 32],
    source: SocketAddr,
    routing_tag: RoutingTag,
    now: SystemTime,
) -> Result<Bytes> {
    let cookie = generator.issue_cookie(source, &routing_tag, now)?;
    let frame = build_handshake_frame(
        routing_tag,
        HandshakeKind::CookieReply,
        Bytes::copy_from_slice(&cookie),
        None,
        Some(*responder_public_key),
    )?;
    Ok(encode_handshake_frame(&frame))
}

pub fn decode_cookie_reply(packet: Bytes) -> Result<Cookie> {
    let frame = decode_handshake_frame(packet)?;
    if frame.kind != HandshakeKind::CookieReply {
        return Err(anyhow!("expected cookie reply frame"));
    }
    if frame.payload.len() != MAC_LEN {
        return Err(anyhow!("cookie reply payload length mismatch"));
    }

    let mut cookie = [0u8; MAC_LEN];
    cookie.copy_from_slice(frame.payload.as_ref());
    Ok(cookie)
}

pub fn generate_routing_tag_for_shard<F>(mut shard_of: F, shard_id: usize) -> RoutingTag
where
    F: FnMut(&RoutingTag) -> usize,
{
    loop {
        let mut tag = [0u8; crate::wire::ROUTING_TAG_LEN];
        OsRng.fill_bytes(&mut tag);
        if shard_of(&tag) == shard_id {
            return tag;
        }
    }
}

fn random_outer_nonce() -> crate::wire::OuterNonce {
    crate::crypto::generate_outer_nonce()
}

fn random_padding() -> Bytes {
    let padding_len = random_padding_len(8..=32);
    let mut out = vec![0u8; padding_len];
    if padding_len > 0 {
        OsRng.fill_bytes(&mut out);
    }
    Bytes::from(out)
}

fn build_handshake_frame(
    routing_tag: RoutingTag,
    kind: HandshakeKind,
    payload: Bytes,
    mac2_cookie: Option<Cookie>,
    responder_public_key: Option<Seed>,
) -> Result<HandshakeFrame> {
    let padding = random_padding();
    let outer_nonce = random_outer_nonce();
    let mac2 = if mac2_cookie.is_some() {
        Some([0u8; MAC_LEN])
    } else {
        None
    };
    let mut frame = HandshakeFrame {
        routing_tag,
        outer_nonce,
        kind,
        payload,
        padding,
        mac1: [0u8; MAC_LEN],
        mac2,
    };

    if let Some(public_key) = responder_public_key {
        let without_macs = encode_handshake_without_macs(&frame);
        frame.mac1 = compute_mac1(&public_key, &without_macs)?;
        if let Some(cookie) = mac2_cookie {
            let mut with_mac1 = without_macs;
            with_mac1.extend_from_slice(&frame.mac1);
            frame.mac2 = Some(compute_mac2(&cookie, &with_mac1)?);
        }
    }

    Ok(frame)
}

fn encode_handshake_without_macs(frame: &HandshakeFrame) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        crate::wire::ROUTING_TAG_LEN
            + crate::wire::OUTER_NONCE_LEN
            + 1
            + 2
            + frame.payload.len()
            + frame.padding.len(),
    );
    out.extend_from_slice(&frame.routing_tag);
    out.extend_from_slice(&frame.outer_nonce);
    out.push(frame.kind as u8);
    out.extend_from_slice(&(frame.payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&frame.payload);
    out.extend_from_slice(&frame.padding);
    out
}
