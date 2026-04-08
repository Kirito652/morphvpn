use crate::crypto::RoutingTag;
use crate::state_machine::{
    parse_ipv4_destination, ProcessResult, Session, SessionConfig, SessionStatus, BASE_PLPMTU,
    TUN_OVERHEAD_BYTES,
};
use crate::stealth::peek_routing_tag;
use crate::sys_net::{self, NetConfig};
use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

const UDP_BUF_SIZE: usize = 65_535;
const TICK_INTERVAL: Duration = Duration::from_secs(1);
const TUN_RECREATE_BACKOFF: Duration = Duration::from_secs(1);

pub async fn run_client(
    config: SessionConfig,
    server_addr: SocketAddr,
    tun_name: &str,
    net_config: Option<NetConfig>,
) -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.context("UDP bind")?;
    socket.connect(server_addr).await.context("UDP connect")?;

    let now = Instant::now();
    let (mut session, hello) = Session::new_client(config, server_addr, now)?;
    socket
        .send(&hello)
        .await
        .context("send initial handshake")?;

    let mut applied_mtu = initial_tun_mtu();
    loop {
        if let Some(cfg) = net_config.as_ref() {
            if let Err(err) = sys_net::reapply_client_tun(cfg) {
                warn!("failed to reapply client TUN network state: {err}");
            }
        }

        let tun = match create_tun(tun_name, applied_mtu as i32) {
            Ok(tun) => tun,
            Err(err) => {
                warn!("failed to create client TUN '{tun_name}': {err}");
                tokio::time::sleep(TUN_RECREATE_BACKOFF).await;
                continue;
            }
        };
        match run_client_with_tun(&mut session, &socket, tun, tun_name, &mut applied_mtu).await {
            Ok(()) => return Ok(()),
            Err(loop_err) if loop_err.is_tun() => {
                warn!(
                    "client TUN failed, recreating interface: {}",
                    loop_err.error
                );
                tokio::time::sleep(TUN_RECREATE_BACKOFF).await;
            }
            Err(loop_err) => return Err(loop_err.error),
        }
    }
}

pub async fn run_server(
    config: SessionConfig,
    bind_addr: SocketAddr,
    tun_name: &str,
    net_config: Option<NetConfig>,
) -> Result<()> {
    let socket = UdpSocket::bind(bind_addr)
        .await
        .context("UDP bind server")?;
    info!("server listening on {bind_addr}");

    let mut sessions: HashMap<RoutingTag, Session> = HashMap::new();
    let mut routes: HashMap<Ipv4Addr, RoutingTag> = HashMap::new();
    let mut applied_mtu = initial_tun_mtu();

    loop {
        if let Some(cfg) = net_config.as_ref() {
            if let Err(err) = sys_net::reapply_server_tun(cfg) {
                warn!("failed to reapply server TUN network state: {err}");
            }
        }

        let tun = match create_tun(tun_name, applied_mtu as i32) {
            Ok(tun) => tun,
            Err(err) => {
                warn!("failed to create server TUN '{tun_name}': {err}");
                tokio::time::sleep(TUN_RECREATE_BACKOFF).await;
                continue;
            }
        };
        match run_server_with_tun(
            &config,
            &socket,
            tun,
            tun_name,
            &mut sessions,
            &mut routes,
            &mut applied_mtu,
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(loop_err) if loop_err.is_tun() => {
                warn!(
                    "server TUN failed, recreating interface: {}",
                    loop_err.error
                );
                tokio::time::sleep(TUN_RECREATE_BACKOFF).await;
            }
            Err(loop_err) => return Err(loop_err.error),
        }
    }
}

async fn run_client_with_tun(
    session: &mut Session,
    socket: &UdpSocket,
    tun: tun::AsyncDevice,
    tun_name: &str,
    applied_mtu: &mut u32,
) -> Result<(), LoopError> {
    use tokio::io::AsyncReadExt;

    let (mut tun_reader, mut tun_writer) = tokio::io::split(tun);
    let mut tun_buf = vec![0u8; UDP_BUF_SIZE];
    let mut udp_buf = vec![0u8; UDP_BUF_SIZE];
    let mut tick = tokio::time::interval(TICK_INTERVAL);

    loop {
        tokio::select! {
            _ = tick.tick() => {
                let result = session.on_tick(Instant::now()).map_err(LoopError::fatal)?;
                flush_result(socket, None, &mut tun_writer, result).await?;
                maybe_apply_client_mtu(session, tun_name, applied_mtu).await.map_err(LoopError::fatal)?;
                if session.status() == SessionStatus::Closed {
                    return Err(LoopError::fatal(anyhow!("client session closed")));
                }
            }
            n = tun_reader.read(&mut tun_buf) => {
                let n = n.map_err(|err| LoopError::tun(anyhow!("TUN read failed: {err}")))?;
                if n == 0 {
                    continue;
                }
                if let Some(packet) = session.on_tun_packet(&tun_buf[..n], Instant::now()).map_err(LoopError::fatal)? {
                    socket.send(&packet).await.map_err(|err| LoopError::fatal(anyhow!("UDP send failed: {err}")))?;
                }
            }
            n = socket.recv(&mut udp_buf) => {
                let n = n.map_err(|err| LoopError::fatal(anyhow!("UDP recv failed: {err}")))?;
                if n == 0 {
                    continue;
                }
                let result = session
                    .process_datagram(&udp_buf[..n], socket.peer_addr().map_err(|err| LoopError::fatal(anyhow!("peer addr failed: {err}")) )?, Instant::now())
                    .map_err(LoopError::fatal)?;
                flush_result(socket, None, &mut tun_writer, result).await?;
                maybe_apply_client_mtu(session, tun_name, applied_mtu).await.map_err(LoopError::fatal)?;
            }
        }
    }
}

async fn run_server_with_tun(
    config: &SessionConfig,
    socket: &UdpSocket,
    tun: tun::AsyncDevice,
    tun_name: &str,
    sessions: &mut HashMap<RoutingTag, Session>,
    routes: &mut HashMap<Ipv4Addr, RoutingTag>,
    applied_mtu: &mut u32,
) -> Result<(), LoopError> {
    use tokio::io::AsyncReadExt;

    let (mut tun_reader, mut tun_writer) = tokio::io::split(tun);
    let mut tun_buf = vec![0u8; UDP_BUF_SIZE];
    let mut udp_buf = vec![0u8; UDP_BUF_SIZE];
    let mut tick = tokio::time::interval(TICK_INTERVAL);

    loop {
        tokio::select! {
            _ = tick.tick() => {
                let now = Instant::now();
                let tags: Vec<RoutingTag> = sessions.keys().copied().collect();
                for tag in tags {
                    let Some(session) = sessions.get_mut(&tag) else { continue; };
                    let peer = session.peer_addr();
                    let assigned_ip = session.assigned_tun_ip();
                    let result = session.on_tick(now).map_err(LoopError::fatal)?;
                    flush_result(socket, Some(peer), &mut tun_writer, result).await?;
                    if session.status() == SessionStatus::Established {
                        if let Some(ip) = assigned_ip {
                            routes.insert(ip, tag);
                        }
                    }
                }
                reap_closed_sessions(sessions, routes);
                maybe_apply_server_mtu(sessions, tun_name, applied_mtu).await.map_err(LoopError::fatal)?;
            }
            result = socket.recv_from(&mut udp_buf) => {
                let (n, src) = result.map_err(|err| LoopError::fatal(anyhow!("UDP recv_from failed: {err}")))?;
                if n == 0 {
                    continue;
                }

                let tag = match peek_routing_tag(&udp_buf[..n]) {
                    Ok(tag) => tag,
                    Err(_) => continue,
                };

                if !sessions.contains_key(&tag) {
                    match Session::new_server_from_client_init(config.clone(), src, &udp_buf[..n], Instant::now()) {
                        Ok((session, reply)) => {
                            socket
                                .send_to(&reply, src)
                                .await
                                .map_err(|err| LoopError::fatal(anyhow!("send handshake reply failed: {err}")))?;
                            if let Some(ip) = session.assigned_tun_ip() {
                                routes.insert(ip, tag);
                            }
                            sessions.insert(tag, session);
                        }
                        Err(_) => {
                            continue;
                        }
                    }
                    continue;
                }

                let (peer, assigned_ip, result) = {
                    let session = sessions.get_mut(&tag).expect("session exists");
                    let result = session
                        .process_datagram(&udp_buf[..n], src, Instant::now())
                        .map_err(LoopError::fatal)?;
                    (session.peer_addr(), session.assigned_tun_ip(), result)
                };
                flush_result(socket, Some(peer), &mut tun_writer, result).await?;
                if let Some(ip) = assigned_ip {
                    routes.insert(ip, tag);
                }
                reap_closed_sessions(sessions, routes);
                maybe_apply_server_mtu(sessions, tun_name, applied_mtu).await.map_err(LoopError::fatal)?;
            }
            n = tun_reader.read(&mut tun_buf) => {
                let n = n.map_err(|err| LoopError::tun(anyhow!("server TUN read failed: {err}")))?;
                if n == 0 {
                    continue;
                }

                let Some(dst_ip) = parse_ipv4_destination(&tun_buf[..n]) else {
                    continue;
                };
                let Some(tag) = routes.get(&dst_ip).copied() else {
                    debug!("no route for inner destination {dst_ip}");
                    continue;
                };
                let Some(session) = sessions.get_mut(&tag) else {
                    continue;
                };
                if let Some(packet) = session.on_tun_packet(&tun_buf[..n], Instant::now()).map_err(LoopError::fatal)? {
                    socket
                        .send_to(&packet, session.peer_addr())
                        .await
                        .map_err(|err| LoopError::fatal(anyhow!("UDP send_to failed: {err}")))?;
                }
            }
        }
    }
}

async fn flush_result<W>(
    socket: &UdpSocket,
    peer: Option<SocketAddr>,
    tun_writer: &mut W,
    result: ProcessResult,
) -> Result<(), LoopError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    for packet in result.outbound {
        if let Some(peer) = peer {
            socket
                .send_to(&packet, peer)
                .await
                .map_err(|err| LoopError::fatal(anyhow!("send_to outbound failed: {err}")))?;
        } else {
            socket
                .send(&packet)
                .await
                .map_err(|err| LoopError::fatal(anyhow!("send outbound failed: {err}")))?;
        }
    }

    for payload in result.tun_payloads {
        tun_writer
            .write_all(&payload)
            .await
            .map_err(|err| LoopError::tun(anyhow!("TUN write failed: {err}")))?;
    }

    Ok(())
}

fn reap_closed_sessions(
    sessions: &mut HashMap<RoutingTag, Session>,
    routes: &mut HashMap<Ipv4Addr, RoutingTag>,
) {
    let dead: Vec<RoutingTag> = sessions
        .iter()
        .filter_map(|(tag, session)| {
            if session.status() == SessionStatus::Closed {
                Some(*tag)
            } else {
                None
            }
        })
        .collect();
    for tag in dead {
        sessions.remove(&tag);
        routes.retain(|_, mapped| *mapped != tag);
    }
}

async fn maybe_apply_client_mtu(
    session: &Session,
    tun_name: &str,
    applied_mtu: &mut u32,
) -> Result<()> {
    let desired = session.desired_tun_mtu();
    if desired != *applied_mtu {
        sys_net::update_tun_mtu(tun_name, desired).await?;
        *applied_mtu = desired;
    }
    Ok(())
}

async fn maybe_apply_server_mtu(
    sessions: &HashMap<RoutingTag, Session>,
    tun_name: &str,
    applied_mtu: &mut u32,
) -> Result<()> {
    let desired = sessions
        .values()
        .filter(|session| session.status() == SessionStatus::Established)
        .map(|session| session.desired_tun_mtu())
        .min()
        .unwrap_or_else(initial_tun_mtu);
    if desired != *applied_mtu {
        sys_net::update_tun_mtu(tun_name, desired).await?;
        *applied_mtu = desired;
    }
    Ok(())
}

fn create_tun(name: &str, mtu: i32) -> Result<tun::AsyncDevice> {
    let mut config = tun::Configuration::default();
    config.name(name).mtu(mtu).up();
    let dev = tun::create_as_async(&config)
        .with_context(|| format!("failed to create TUN interface '{name}'"))?;
    info!("TUN interface '{name}' ready with MTU {mtu}");
    Ok(dev)
}

fn initial_tun_mtu() -> u32 {
    BASE_PLPMTU.saturating_sub(TUN_OVERHEAD_BYTES) as u32
}

struct LoopError {
    error: anyhow::Error,
    tun_failed: bool,
}

impl LoopError {
    fn fatal(error: anyhow::Error) -> Self {
        Self {
            error,
            tun_failed: false,
        }
    }

    fn tun(error: anyhow::Error) -> Self {
        Self {
            error,
            tun_failed: true,
        }
    }

    fn is_tun(&self) -> bool {
        self.tun_failed
    }
}
