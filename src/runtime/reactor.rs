use anyhow::{anyhow, Context, Result};
use bytes::{Bytes, BytesMut};
use morphvpn_protocol::wire::{RoutingTag, ROUTING_TAG_LEN};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, warn};

const UDP_BUFFER_CAPACITY: usize = 65_535;
const TUN_BUFFER_CAPACITY: usize = 65_535;

#[derive(Clone, Debug)]
pub struct UdpIngress {
    pub source: SocketAddr,
    pub packet: Bytes,
    pub received_at: Instant,
}

#[derive(Clone, Debug)]
pub struct TunIngress {
    pub packet: Bytes,
    pub received_at: Instant,
}

#[derive(Clone, Debug)]
pub enum ShardInbound {
    Udp(UdpIngress),
    Tun(TunIngress),
}

#[derive(Clone, Debug)]
pub struct UdpOutbound {
    pub target: SocketAddr,
    pub packet: Bytes,
}

#[derive(Clone, Debug)]
pub struct TunWrite {
    pub packet: Bytes,
}

#[derive(Clone, Debug)]
pub enum RouteUpdate {
    Install { destination: Ipv4Addr, shard_id: usize },
    Remove { destination: Ipv4Addr },
}

#[derive(Clone, Debug)]
pub enum ShardEvent {
    Udp(UdpOutbound),
    Tun(TunWrite),
    Route(RouteUpdate),
}

#[derive(Clone, Debug)]
pub enum TunCommand {
    Write(TunWrite),
    Route(RouteUpdate),
}

pub struct UdpReactor {
    socket: Arc<UdpSocket>,
    shard_senders: Vec<mpsc::Sender<ShardInbound>>,
}

pub struct UdpTxAggregator {
    socket: Arc<UdpSocket>,
    rx: mpsc::Receiver<UdpOutbound>,
}

pub struct TunWorker {
    device: tun::AsyncDevice,
    shard_senders: Vec<mpsc::Sender<ShardInbound>>,
    rx: mpsc::Receiver<TunCommand>,
    default_shard: usize,
}

impl UdpReactor {
    pub fn new(socket: Arc<UdpSocket>, shard_senders: Vec<mpsc::Sender<ShardInbound>>) -> Self {
        Self {
            socket,
            shard_senders,
        }
    }

    pub async fn run(self) -> Result<()> {
        let mut buffer = vec![0u8; UDP_BUFFER_CAPACITY];
        loop {
            let (len, source) = self
                .socket
                .recv_from(&mut buffer)
                .await
                .context("failed to receive UDP datagram")?;
            if len < ROUTING_TAG_LEN {
                debug!("dropping short UDP datagram from {source}");
                continue;
            }

            let mut bytes = BytesMut::with_capacity(len);
            bytes.extend_from_slice(&buffer[..len]);
            let packet = bytes.freeze();
            let Some(routing_tag) = extract_routing_tag(&packet) else {
                continue;
            };
            let shard_id = shard_for_tag(&routing_tag, self.shard_senders.len());
            let message = ShardInbound::Udp(UdpIngress {
                source,
                packet,
                received_at: Instant::now(),
            });

            if let Some(sender) = self.shard_senders.get(shard_id) {
                match sender.try_send(message) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        warn!("dropping UDP datagram for saturated shard {shard_id}");
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        return Err(anyhow!("shard {shard_id} channel closed"));
                    }
                }
            }
        }
    }
}

impl UdpTxAggregator {
    pub fn new(socket: Arc<UdpSocket>, rx: mpsc::Receiver<UdpOutbound>) -> Self {
        Self { socket, rx }
    }

    pub async fn run(mut self) -> Result<()> {
        while let Some(outbound) = self.rx.recv().await {
            self.socket
                .send_to(&outbound.packet, outbound.target)
                .await
                .with_context(|| format!("failed to send UDP datagram to {}", outbound.target))?;
        }
        Ok(())
    }
}

impl TunWorker {
    pub fn new(
        device: tun::AsyncDevice,
        shard_senders: Vec<mpsc::Sender<ShardInbound>>,
        rx: mpsc::Receiver<TunCommand>,
        default_shard: usize,
    ) -> Self {
        Self {
            device,
            shard_senders,
            rx,
            default_shard,
        }
    }

    pub async fn run(self) -> Result<()> {
        let (mut reader, mut writer) = tokio::io::split(self.device);
        let mut rx = self.rx;
        let mut route_map: HashMap<Ipv4Addr, usize> = HashMap::new();
        let mut buffer = vec![0u8; TUN_BUFFER_CAPACITY];

        loop {
            tokio::select! {
                result = reader.read(&mut buffer) => {
                    let len = result.context("failed to read TUN device")?;
                    if len == 0 {
                        continue;
                    }

                    let mut bytes = BytesMut::with_capacity(len);
                    bytes.extend_from_slice(&buffer[..len]);
                    let packet = bytes.freeze();
                    let shard_id = match parse_ipv4_destination(&packet) {
                        Some(destination) => route_map.get(&destination).copied().unwrap_or(self.default_shard),
                        None => self.default_shard,
                    };
                    let message = ShardInbound::Tun(TunIngress {
                        packet,
                        received_at: Instant::now(),
                    });

                    if let Some(sender) = self.shard_senders.get(shard_id) {
                        match sender.try_send(message) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                warn!("dropping TUN packet for saturated shard {shard_id}");
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                return Err(anyhow!("shard {shard_id} channel closed"));
                            }
                        }
                    }
                }
                command = rx.recv() => {
                    let Some(command) = command else {
                        return Ok(());
                    };
                    match command {
                        TunCommand::Write(write) => {
                            writer
                                .write_all(&write.packet)
                                .await
                                .context("failed to write packet to TUN device")?;
                        }
                        TunCommand::Route(RouteUpdate::Install { destination, shard_id }) => {
                            route_map.insert(destination, shard_id);
                        }
                        TunCommand::Route(RouteUpdate::Remove { destination }) => {
                            route_map.remove(&destination);
                        }
                    }
                }
            }
        }
    }
}

pub fn create_tun(name: &str, mtu: i32) -> Result<tun::AsyncDevice> {
    let mut config = tun::Configuration::default();
    config.name(name).mtu(mtu).up();
    tun::create_as_async(&config)
        .with_context(|| format!("failed to create TUN interface '{name}'"))
}

pub fn extract_routing_tag(packet: &[u8]) -> Option<RoutingTag> {
    if packet.len() < ROUTING_TAG_LEN {
        return None;
    }
    let mut tag = [0u8; ROUTING_TAG_LEN];
    tag.copy_from_slice(&packet[..ROUTING_TAG_LEN]);
    Some(tag)
}

pub fn shard_for_tag(tag: &RoutingTag, num_shards: usize) -> usize {
    let shards = num_shards.max(1);
    let mut acc = 0u64;
    for byte in tag {
        acc = acc.wrapping_mul(16777619).wrapping_add(u64::from(*byte));
    }
    (acc % shards as u64) as usize
}

pub fn parse_ipv4_destination(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 || (packet[0] >> 4) != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
}

pub fn parse_ipv4_source(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 || (packet[0] >> 4) != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ))
}
