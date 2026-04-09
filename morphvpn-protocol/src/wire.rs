use anyhow::{anyhow, Result};
use bytes::{BufMut, Bytes, BytesMut};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use std::net::Ipv4Addr;

pub type RoutingTag = [u8; 12];
pub type OuterNonce = [u8; 24];
pub type Mac = [u8; 16];
pub type MaskKey = [u8; 32];

pub const ROUTING_TAG_LEN: usize = 12;
pub const OUTER_NONCE_LEN: usize = 24;
pub const MAC_LEN: usize = 16;
pub const PROTECTED_HEADER_LEN: usize = 24;
pub const DATA_NONCE_LEN: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeKind {
    Init = 1,
    Resp = 2,
    Finish = 3,
    CookieReply = 4,
}

impl HandshakeKind {
    fn parse(byte: u8) -> Result<Self> {
        match byte {
            1 => Ok(Self::Init),
            2 => Ok(Self::Resp),
            3 => Ok(Self::Finish),
            4 => Ok(Self::CookieReply),
            _ => Err(anyhow!("unknown handshake kind {byte}")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TransportKind {
    Control = 1,
    Data = 2,
}

impl TransportKind {
    fn parse(byte: u8) -> Result<Self> {
        match byte {
            1 => Ok(Self::Control),
            2 => Ok(Self::Data),
            _ => Err(anyhow!("unknown transport kind {byte}")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedHeader {
    pub version: u8,
    pub transport_kind: TransportKind,
    pub flags: u8,
    pub epoch: u32,
    pub packet_no: u64,
    pub body_len: u16,
    pub pad_len: u16,
    pub probe_id: u16,
    pub probe_size: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeFrame {
    pub routing_tag: RoutingTag,
    pub outer_nonce: OuterNonce,
    pub kind: HandshakeKind,
    pub payload: Bytes,
    pub padding: Bytes,
    pub mac1: Mac,
    pub mac2: Option<Mac>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CookieReplyFrame {
    pub routing_tag: RoutingTag,
    pub outer_nonce: OuterNonce,
    pub payload: Bytes,
    pub mac1: Mac,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportEnvelope {
    pub routing_tag: RoutingTag,
    pub outer_nonce: OuterNonce,
    pub masked_header: Bytes,
    pub body: Bytes,
    pub padding: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlFrame {
    BootstrapInit { requested_ip: Ipv4Addr },
    BootstrapResp { assigned_ip: Ipv4Addr },
    RekeyInit { epoch: u32, public_key: [u8; 32] },
    RekeyResp { epoch: u32, public_key: [u8; 32] },
    Keepalive,
    KeepaliveAck,
    PmtudProbe { probe_id: u16, target_size: u16 },
    PmtudAck { probe_id: u16, confirmed_size: u16 },
    Close { reason: u8 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataFrame {
    pub payload: Bytes,
}

impl ProtectedHeader {
    pub fn encode(&self) -> Bytes {
        let mut out = BytesMut::with_capacity(PROTECTED_HEADER_LEN);
        out.put_u8(self.version);
        out.put_u8(self.transport_kind as u8);
        out.put_u8(self.flags);
        out.put_u8(0);
        out.put_u32(self.epoch);
        out.put_u64(self.packet_no);
        out.put_u16(self.body_len);
        out.put_u16(self.pad_len);
        out.put_u16(self.probe_id);
        out.put_u16(self.probe_size);
        out.freeze()
    }

    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() != PROTECTED_HEADER_LEN {
            return Err(anyhow!(
                "protected header must be {PROTECTED_HEADER_LEN} bytes, got {}",
                raw.len()
            ));
        }

        Ok(Self {
            version: raw[0],
            transport_kind: TransportKind::parse(raw[1])?,
            flags: raw[2],
            epoch: u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]),
            packet_no: u64::from_be_bytes([
                raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
            ]),
            body_len: u16::from_be_bytes([raw[16], raw[17]]),
            pad_len: u16::from_be_bytes([raw[18], raw[19]]),
            probe_id: u16::from_be_bytes([raw[20], raw[21]]),
            probe_size: u16::from_be_bytes([raw[22], raw[23]]),
        })
    }
}

impl ControlFrame {
    pub fn encode(&self) -> Bytes {
        let mut out = BytesMut::with_capacity(43);
        match self {
            Self::BootstrapInit { requested_ip } => {
                out.put_u8(0x01);
                out.extend_from_slice(&requested_ip.octets());
            }
            Self::BootstrapResp { assigned_ip } => {
                out.put_u8(0x02);
                out.extend_from_slice(&assigned_ip.octets());
            }
            Self::RekeyInit { epoch, public_key } => {
                out.put_u8(0x03);
                out.put_u32(*epoch);
                out.extend_from_slice(public_key);
            }
            Self::RekeyResp { epoch, public_key } => {
                out.put_u8(0x04);
                out.put_u32(*epoch);
                out.extend_from_slice(public_key);
            }
            Self::Keepalive => {
                out.put_u8(0x05);
            }
            Self::KeepaliveAck => {
                out.put_u8(0x06);
            }
            Self::PmtudProbe {
                probe_id,
                target_size,
            } => {
                out.put_u8(0x07);
                out.put_u16(*probe_id);
                out.put_u16(*target_size);
            }
            Self::PmtudAck {
                probe_id,
                confirmed_size,
            } => {
                out.put_u8(0x08);
                out.put_u16(*probe_id);
                out.put_u16(*confirmed_size);
            }
            Self::Close { reason } => {
                out.put_u8(0x09);
                out.put_u8(*reason);
            }
        }
        out.freeze()
    }

    pub fn decode(raw: Bytes) -> Result<Self> {
        let kind = *raw
            .first()
            .ok_or_else(|| anyhow!("empty control frame"))?;
        match kind {
            0x01 if raw.len() == 5 => Ok(Self::BootstrapInit {
                requested_ip: decode_ipv4(&raw[1..5])?,
            }),
            0x02 if raw.len() == 5 => Ok(Self::BootstrapResp {
                assigned_ip: decode_ipv4(&raw[1..5])?,
            }),
            0x03 if raw.len() == 37 => Ok(Self::RekeyInit {
                epoch: decode_u32(&raw[1..5])?,
                public_key: decode_seed(&raw[5..37])?,
            }),
            0x04 if raw.len() == 37 => Ok(Self::RekeyResp {
                epoch: decode_u32(&raw[1..5])?,
                public_key: decode_seed(&raw[5..37])?,
            }),
            0x05 if raw.len() == 1 => Ok(Self::Keepalive),
            0x06 if raw.len() == 1 => Ok(Self::KeepaliveAck),
            0x07 if raw.len() == 5 => Ok(Self::PmtudProbe {
                probe_id: decode_u16(&raw[1..3])?,
                target_size: decode_u16(&raw[3..5])?,
            }),
            0x08 if raw.len() == 5 => Ok(Self::PmtudAck {
                probe_id: decode_u16(&raw[1..3])?,
                confirmed_size: decode_u16(&raw[3..5])?,
            }),
            0x09 if raw.len() == 2 => Ok(Self::Close { reason: raw[1] }),
            _ => Err(anyhow!("unknown or malformed control frame kind {kind:#x}")),
        }
    }
}

impl DataFrame {
    pub fn encode(&self) -> Bytes {
        self.payload.clone()
    }

    pub fn decode(raw: Bytes) -> Self {
        Self { payload: raw }
    }
}

pub fn apply_header_mask(
    mask_key: &MaskKey,
    outer_nonce: &OuterNonce,
    header: &mut [u8],
) -> Result<()> {
    let nonce = &outer_nonce[..12];
    let mut cipher = ChaCha20::new_from_slices(mask_key, nonce)
        .map_err(|_| anyhow!("invalid ChaCha20 key or nonce length"))?;
    cipher.apply_keystream(header);
    Ok(())
}

pub fn encode_handshake_frame(frame: &HandshakeFrame) -> Bytes {
    let mut out = BytesMut::with_capacity(
        ROUTING_TAG_LEN
            + OUTER_NONCE_LEN
            + 1
            + 2
            + frame.payload.len()
            + frame.padding.len()
            + MAC_LEN
            + usize::from(frame.mac2.is_some()) * MAC_LEN,
    );

    out.extend_from_slice(&frame.routing_tag);
    out.extend_from_slice(&frame.outer_nonce);
    out.put_u8(frame.kind as u8);
    out.put_u16(frame.payload.len() as u16);
    out.extend_from_slice(&frame.payload);
    out.extend_from_slice(&frame.padding);
    out.extend_from_slice(&frame.mac1);
    if let Some(mac2) = frame.mac2 {
        out.extend_from_slice(&mac2);
    }
    out.freeze()
}

pub fn decode_handshake_frame(raw: Bytes) -> Result<HandshakeFrame> {
    let min_len = ROUTING_TAG_LEN + OUTER_NONCE_LEN + 1 + 2 + MAC_LEN;
    if raw.len() < min_len {
        return Err(anyhow!("handshake frame too short: {}", raw.len()));
    }

    let mut routing_tag = [0u8; ROUTING_TAG_LEN];
    routing_tag.copy_from_slice(&raw[..ROUTING_TAG_LEN]);

    let mut outer_nonce = [0u8; OUTER_NONCE_LEN];
    outer_nonce.copy_from_slice(&raw[ROUTING_TAG_LEN..ROUTING_TAG_LEN + OUTER_NONCE_LEN]);

    let kind = HandshakeKind::parse(raw[ROUTING_TAG_LEN + OUTER_NONCE_LEN])?;
    let payload_len_offset = ROUTING_TAG_LEN + OUTER_NONCE_LEN + 1;
    let payload_len =
        u16::from_be_bytes([raw[payload_len_offset], raw[payload_len_offset + 1]]) as usize;
    let payload_offset = payload_len_offset + 2;
    let payload_end = payload_offset + payload_len;
    if payload_end + MAC_LEN > raw.len() {
        return Err(anyhow!("handshake payload overruns frame"));
    }

    let has_mac2 = (raw.len() - payload_end) >= MAC_LEN * 2;
    let mac1_offset = raw.len() - MAC_LEN - if has_mac2 { MAC_LEN } else { 0 };
    let padding = raw.slice(payload_end..mac1_offset);
    let payload = raw.slice(payload_offset..payload_end);

    let mut mac1 = [0u8; MAC_LEN];
    mac1.copy_from_slice(&raw[mac1_offset..mac1_offset + MAC_LEN]);

    let mac2 = if has_mac2 {
        let mut out = [0u8; MAC_LEN];
        out.copy_from_slice(&raw[mac1_offset + MAC_LEN..mac1_offset + (2 * MAC_LEN)]);
        Some(out)
    } else {
        None
    };

    Ok(HandshakeFrame {
        routing_tag,
        outer_nonce,
        kind,
        payload,
        padding,
        mac1,
        mac2,
    })
}

pub fn encode_transport_envelope(
    routing_tag: RoutingTag,
    outer_nonce: OuterNonce,
    header: &ProtectedHeader,
    mask_key: &MaskKey,
    body: Bytes,
    padding: Bytes,
) -> Result<Bytes> {
    let mut masked_header = header.encode().to_vec();
    apply_header_mask(mask_key, &outer_nonce, &mut masked_header)?;

    let mut out = BytesMut::with_capacity(
        ROUTING_TAG_LEN + OUTER_NONCE_LEN + masked_header.len() + body.len() + padding.len(),
    );
    out.extend_from_slice(&routing_tag);
    out.extend_from_slice(&outer_nonce);
    out.extend_from_slice(&masked_header);
    out.extend_from_slice(&body);
    out.extend_from_slice(&padding);
    Ok(out.freeze())
}

pub fn decode_transport_envelope(
    raw: Bytes,
    mask_key: &MaskKey,
) -> Result<(ProtectedHeader, TransportEnvelope)> {
    let min_len = ROUTING_TAG_LEN + OUTER_NONCE_LEN + PROTECTED_HEADER_LEN;
    if raw.len() < min_len {
        return Err(anyhow!("transport envelope too short: {}", raw.len()));
    }

    let mut routing_tag = [0u8; ROUTING_TAG_LEN];
    routing_tag.copy_from_slice(&raw[..ROUTING_TAG_LEN]);

    let mut outer_nonce = [0u8; OUTER_NONCE_LEN];
    outer_nonce.copy_from_slice(&raw[ROUTING_TAG_LEN..ROUTING_TAG_LEN + OUTER_NONCE_LEN]);

    let header_offset = ROUTING_TAG_LEN + OUTER_NONCE_LEN;
    let header_end = header_offset + PROTECTED_HEADER_LEN;
    let mut header_bytes = raw[header_offset..header_end].to_vec();
    apply_header_mask(mask_key, &outer_nonce, &mut header_bytes)?;
    let header = ProtectedHeader::decode(&header_bytes)?;

    let body_start = header_end;
    let body_end = body_start + header.body_len as usize;
    let padding_end = body_end + header.pad_len as usize;
    if padding_end > raw.len() {
        return Err(anyhow!("transport body or padding overruns envelope"));
    }

    Ok((
        header,
        TransportEnvelope {
            routing_tag,
            outer_nonce,
            masked_header: raw.slice(header_offset..header_end),
            body: raw.slice(body_start..body_end),
            padding: raw.slice(body_end..padding_end),
        },
    ))
}

fn decode_u16(raw: &[u8]) -> Result<u16> {
    if raw.len() != 2 {
        return Err(anyhow!("expected 2 bytes, got {}", raw.len()));
    }
    Ok(u16::from_be_bytes([raw[0], raw[1]]))
}

fn decode_u32(raw: &[u8]) -> Result<u32> {
    if raw.len() != 4 {
        return Err(anyhow!("expected 4 bytes, got {}", raw.len()));
    }
    Ok(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn decode_ipv4(raw: &[u8]) -> Result<Ipv4Addr> {
    if raw.len() != 4 {
        return Err(anyhow!("expected IPv4 length 4, got {}", raw.len()));
    }
    Ok(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))
}

fn decode_seed(raw: &[u8]) -> Result<[u8; 32]> {
    if raw.len() != 32 {
        return Err(anyhow!("expected 32-byte key, got {}", raw.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_mask_is_reversible() {
        let key = [0x11; 32];
        let nonce = [0x22; 24];
        let mut first = ProtectedHeader {
            version: 1,
            transport_kind: TransportKind::Data,
            flags: 0xA5,
            epoch: 7,
            packet_no: 99,
            body_len: 64,
            pad_len: 13,
            probe_id: 4,
            probe_size: 1200,
        }
        .encode()
        .to_vec();

        apply_header_mask(&key, &nonce, &mut first).unwrap();
        apply_header_mask(&key, &nonce, &mut first).unwrap();

        let decoded = ProtectedHeader::decode(&first).unwrap();
        assert_eq!(decoded.packet_no, 99);
        assert_eq!(decoded.pad_len, 13);
    }

    #[test]
    fn handshake_frame_roundtrip() {
        let frame = HandshakeFrame {
            routing_tag: [0xAA; ROUTING_TAG_LEN],
            outer_nonce: [0xBB; OUTER_NONCE_LEN],
            kind: HandshakeKind::Init,
            payload: Bytes::from_static(b"payload"),
            padding: Bytes::from_static(b"random-padding"),
            mac1: [0xCC; MAC_LEN],
            mac2: Some([0xDD; MAC_LEN]),
        };

        let encoded = encode_handshake_frame(&frame);
        let decoded = decode_handshake_frame(encoded).unwrap();
        assert_eq!(decoded.kind, HandshakeKind::Init);
        assert_eq!(decoded.payload, Bytes::from_static(b"payload"));
        assert_eq!(decoded.padding, Bytes::from_static(b"random-padding"));
        assert_eq!(decoded.mac2, Some([0xDD; MAC_LEN]));
    }

    #[test]
    fn transport_envelope_roundtrip() {
        let key = [0x33; 32];
        let header = ProtectedHeader {
            version: 1,
            transport_kind: TransportKind::Control,
            flags: 0x11,
            epoch: 10,
            packet_no: 1234,
            body_len: 5,
            pad_len: 7,
            probe_id: 9,
            probe_size: 1300,
        };

        let encoded = encode_transport_envelope(
            [0x44; ROUTING_TAG_LEN],
            [0x55; OUTER_NONCE_LEN],
            &header,
            &key,
            Bytes::from_static(b"hello"),
            Bytes::from_static(b"padding"),
        )
        .unwrap();

        let (decoded_header, decoded) = decode_transport_envelope(encoded, &key).unwrap();
        assert_eq!(decoded_header, header);
        assert_eq!(decoded.body, Bytes::from_static(b"hello"));
        assert_eq!(decoded.padding, Bytes::from_static(b"padding"));
    }

    #[test]
    fn control_frame_roundtrip() {
        let frame = ControlFrame::BootstrapResp {
            assigned_ip: Ipv4Addr::new(10, 8, 0, 5),
        };
        let decoded = ControlFrame::decode(frame.encode()).unwrap();
        assert_eq!(decoded, frame);
    }
}
