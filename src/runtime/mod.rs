pub mod reactor;
pub mod shard;

use crate::acl::AccessControlList;
use anyhow::{anyhow, Context, Result};
use morphvpn_protocol::handshake::{Seed, StaticIdentity};
use reactor::{create_tun, ShardEvent, TunCommand, UdpOutbound};
use shard::{ClientShardConfig, ServerShardConfig, ShardModeConfig, ShardWorker};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::info;

const SHARD_CHANNEL_CAPACITY: usize = 1024;
const EVENT_CHANNEL_CAPACITY: usize = 2048;
const UDP_TX_CHANNEL_CAPACITY: usize = 2048;
const TUN_COMMAND_CHANNEL_CAPACITY: usize = 2048;
const DEFAULT_TUN_MTU: i32 = 1104;

struct RuntimePlumbing {
    socket: Arc<UdpSocket>,
    tun: tun::AsyncDevice,
    shard_senders: Vec<mpsc::Sender<reactor::ShardInbound>>,
    event_rx: mpsc::Receiver<ShardEvent>,
    udp_tx: mpsc::Sender<UdpOutbound>,
    udp_rx: mpsc::Receiver<UdpOutbound>,
    tun_tx: mpsc::Sender<TunCommand>,
    tun_rx: mpsc::Receiver<TunCommand>,
    default_shard: usize,
}

#[derive(Clone)]
pub struct ServerRuntimeConfig {
    pub bind: SocketAddr,
    pub tun_name: String,
    pub psk: Seed,
    pub identity: StaticIdentity,
    pub acl: AccessControlList,
    pub num_shards: usize,
}

#[derive(Clone)]
pub struct ClientRuntimeConfig {
    pub server_addr: SocketAddr,
    pub tun_name: String,
    pub psk: Seed,
    pub identity: StaticIdentity,
    pub server_public_key: Seed,
    pub requested_ip: Ipv4Addr,
}

pub async fn run_server(config: ServerRuntimeConfig) -> Result<()> {
    let num_shards = config.num_shards.max(1);
    let socket = Arc::new(
        UdpSocket::bind(config.bind)
            .await
            .with_context(|| format!("failed to bind UDP socket on {}", config.bind))?,
    );
    let tun = create_tun(&config.tun_name, DEFAULT_TUN_MTU)?;
    info!(
        "server runtime ready: bind={}, tun={}, shards={}",
        config.bind, config.tun_name, num_shards
    );

    let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let (udp_tx, udp_rx) = mpsc::channel(UDP_TX_CHANNEL_CAPACITY);
    let (tun_tx, tun_rx) = mpsc::channel(TUN_COMMAND_CHANNEL_CAPACITY);
    let mut shard_senders = Vec::with_capacity(num_shards);
    let mut joins = JoinSet::new();

    for shard_id in 0..num_shards {
        let (inbound_tx, inbound_rx) = mpsc::channel(SHARD_CHANNEL_CAPACITY);
        shard_senders.push(inbound_tx);
        let worker = ShardWorker::new(
            shard_id,
            num_shards,
            inbound_rx,
            event_tx.clone(),
            ShardModeConfig::Server(ServerShardConfig {
                identity: config.identity.clone(),
                psk: config.psk,
                acl: config.acl.clone(),
            }),
        )?;
        joins.spawn(async move { worker.run().await });
    }

    spawn_runtime_plumbing(
        &mut joins,
        RuntimePlumbing {
            socket,
            tun,
            shard_senders,
            event_rx,
            udp_tx,
            udp_rx,
            tun_tx,
            tun_rx,
            default_shard: 0,
        },
    );

    drive_join_set(joins).await
}

pub async fn run_client(config: ClientRuntimeConfig) -> Result<()> {
    let socket = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .context("failed to bind client UDP socket")?,
    );
    let tun = create_tun(&config.tun_name, DEFAULT_TUN_MTU)?;
    info!(
        "client runtime ready: server={}, tun={}",
        config.server_addr, config.tun_name
    );

    let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let (udp_tx, udp_rx) = mpsc::channel(UDP_TX_CHANNEL_CAPACITY);
    let (tun_tx, tun_rx) = mpsc::channel(TUN_COMMAND_CHANNEL_CAPACITY);
    let (inbound_tx, inbound_rx) = mpsc::channel(SHARD_CHANNEL_CAPACITY);
    let shard_senders = vec![inbound_tx];
    let mut joins = JoinSet::new();

    let worker = ShardWorker::new(
        0,
        1,
        inbound_rx,
        event_tx.clone(),
        ShardModeConfig::Client(ClientShardConfig {
            identity: config.identity,
            psk: config.psk,
            server_addr: config.server_addr,
            server_public_key: config.server_public_key,
            requested_ip: config.requested_ip,
        }),
    )?;
    joins.spawn(async move { worker.run().await });

    spawn_runtime_plumbing(
        &mut joins,
        RuntimePlumbing {
            socket,
            tun,
            shard_senders,
            event_rx,
            udp_tx,
            udp_rx,
            tun_tx,
            tun_rx,
            default_shard: 0,
        },
    );

    drive_join_set(joins).await
}

fn spawn_runtime_plumbing(joins: &mut JoinSet<Result<()>>, plumbing: RuntimePlumbing) {
    let RuntimePlumbing {
        socket,
        tun,
        shard_senders,
        event_rx,
        udp_tx,
        udp_rx,
        tun_tx,
        tun_rx,
        default_shard,
    } = plumbing;

    let reactor_socket = Arc::clone(&socket);
    let tx_socket = Arc::clone(&socket);
    let reactor_senders = shard_senders.clone();
    let tun_senders = shard_senders;

    joins.spawn(async move {
        reactor::UdpReactor::new(reactor_socket, reactor_senders)
            .run()
            .await
    });
    joins.spawn(async move {
        reactor::UdpTxAggregator::new(tx_socket, udp_rx)
            .run()
            .await
    });
    joins.spawn(async move {
        reactor::TunWorker::new(tun, tun_senders, tun_rx, default_shard)
            .run()
            .await
    });
    joins.spawn(async move { route_shard_events(event_rx, udp_tx, tun_tx).await });
}

async fn route_shard_events(
    mut event_rx: mpsc::Receiver<ShardEvent>,
    udp_tx: mpsc::Sender<UdpOutbound>,
    tun_tx: mpsc::Sender<TunCommand>,
) -> Result<()> {
    while let Some(event) = event_rx.recv().await {
        match event {
            ShardEvent::Udp(outbound) => {
                udp_tx
                    .send(outbound)
                    .await
                    .map_err(|_| anyhow!("UDP aggregator channel closed"))?;
            }
            ShardEvent::Tun(write) => {
                tun_tx
                    .send(TunCommand::Write(write))
                    .await
                    .map_err(|_| anyhow!("TUN worker channel closed"))?;
            }
            ShardEvent::Route(route) => {
                tun_tx
                    .send(TunCommand::Route(route))
                    .await
                    .map_err(|_| anyhow!("TUN worker channel closed"))?;
            }
        }
    }
    Ok(())
}

async fn drive_join_set(mut joins: JoinSet<Result<()>>) -> Result<()> {
    while let Some(joined) = joins.join_next().await {
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return Err(err),
            Err(err) => return Err(anyhow!("runtime task failed to join: {err}")),
        }
    }
    Ok(())
}
