use anyhow::Result;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Clone, Debug, Serialize)]
pub struct HealthStatus {
    pub status: String,
    pub uptime_secs: u64,
    pub connections: u32,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub version: String,
    pub total_peers: usize,
    pub established_peers: usize,
    pub peers: Vec<crate::peer::PeerSnapshot>,
}

pub struct HealthServer {
    listener: TcpListener,
    start_time: Instant,
    connections: Arc<std::sync::atomic::AtomicU32>,
}

impl HealthServer {
    pub async fn bind(addr: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            listener,
            start_time: Instant::now(),
            connections: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    pub fn increment_connections(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement_connections(&self) {
        self.connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub async fn run(
        self,
        metrics: crate::metrics::MetricsHandle,
        peer_manager: Arc<tokio::sync::RwLock<crate::peer::PeerManager>>,
    ) -> Result<()> {
        loop {
            let (mut stream, _) = self.listener.accept().await?;
            self.increment_connections();

            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf).await;

            let udp_snap = metrics.udp.snapshot();
            let tun_snap = metrics.tun.snapshot();
            let peers = peer_manager.read().await;
            let peer_snapshots = peers.snapshots();
            let total_peers = peers.count();
            let established_peers = peers.count_established();
            drop(peers);

            let status = HealthStatus {
                status: "ok".into(),
                uptime_secs: self.start_time.elapsed().as_secs(),
                connections: self.connections.load(Ordering::Relaxed),
                rx_packets: udp_snap.rx_packets + tun_snap.rx_packets,
                tx_packets: udp_snap.tx_packets + tun_snap.tx_packets,
                version: env!("CARGO_PKG_VERSION").into(),
                total_peers,
                established_peers,
                peers: peer_snapshots,
            };

            self.decrement_connections();
            let json = serde_json::to_string(&status)?;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                json.len(),
                json
            );
            stream.write_all(response.as_bytes()).await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn health_server_bind_and_request() {
        let server = HealthServer::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = server.local_addr().unwrap();

        let metrics = crate::metrics::MetricsHandle::new();
        let peer_manager = Arc::new(tokio::sync::RwLock::new(crate::peer::PeerManager::new()));

        tokio::spawn(async move {
            server.run(metrics, peer_manager).await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();

        let mut response = vec![0u8; 4096];
        let n = stream.read(&mut response).await.unwrap();
        let response_str = String::from_utf8_lossy(&response[..n]);

        assert!(response_str.contains("200 OK"));
        assert!(response_str.contains("\"status\":\"ok\""));
        assert!(response_str.contains("\"total_peers\""));
    }
}
