use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Instant;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerState {
    Connecting,
    Handshaking,
    Established,
    Dead,
}

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub state: PeerState,
    pub assigned_ip: Option<Ipv4Addr>,
    pub connected_at: Instant,
    pub last_activity: Instant,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

impl PeerInfo {
    pub fn new(addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            addr,
            state: PeerState::Connecting,
            assigned_ip: None,
            connected_at: now,
            last_activity: now,
            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,
        }
    }

    pub fn record_rx(&mut self, bytes: u64) {
        self.rx_bytes += bytes;
        self.rx_packets += 1;
        self.last_activity = Instant::now();
    }

    pub fn record_tx(&mut self, bytes: u64) {
        self.tx_bytes += bytes;
        self.tx_packets += 1;
        self.last_activity = Instant::now();
    }

    pub fn uptime_secs(&self) -> u64 {
        self.connected_at.elapsed().as_secs()
    }

    pub fn idle_secs(&self) -> u64 {
        self.last_activity.elapsed().as_secs()
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct PeerSnapshot {
    pub addr: String,
    pub state: String,
    pub assigned_ip: Option<String>,
    pub uptime_secs: u64,
    pub idle_secs: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

impl From<&PeerInfo> for PeerSnapshot {
    fn from(peer: &PeerInfo) -> Self {
        Self {
            addr: peer.addr.to_string(),
            state: format!("{:?}", peer.state),
            assigned_ip: peer.assigned_ip.map(|ip| ip.to_string()),
            uptime_secs: peer.uptime_secs(),
            idle_secs: peer.idle_secs(),
            rx_bytes: peer.rx_bytes,
            tx_bytes: peer.tx_bytes,
            rx_packets: peer.rx_packets,
            tx_packets: peer.tx_packets,
        }
    }
}

pub struct PeerManager {
    peers: HashMap<SocketAddr, PeerInfo>,
}

impl PeerManager {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    pub fn add_peer(&mut self, addr: SocketAddr) {
        self.peers.insert(addr, PeerInfo::new(addr));
    }

    pub fn remove_peer(&mut self, addr: &SocketAddr) -> Option<PeerInfo> {
        self.peers.remove(addr)
    }

    pub fn get_peer(&self, addr: &SocketAddr) -> Option<&PeerInfo> {
        self.peers.get(addr)
    }

    pub fn get_peer_mut(&mut self, addr: &SocketAddr) -> Option<&mut PeerInfo> {
        self.peers.get_mut(addr)
    }

    pub fn set_state(&mut self, addr: &SocketAddr, state: PeerState) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.state = state;
            peer.last_activity = Instant::now();
        }
    }

    pub fn set_assigned_ip(&mut self, addr: &SocketAddr, ip: Ipv4Addr) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.assigned_ip = Some(ip);
        }
    }

    pub fn count(&self) -> usize {
        self.peers.len()
    }

    pub fn count_established(&self) -> usize {
        self.peers
            .values()
            .filter(|p| p.state == PeerState::Established)
            .count()
    }

    pub fn snapshots(&self) -> Vec<PeerSnapshot> {
        self.peers.values().map(PeerSnapshot::from).collect()
    }

    pub fn remove_dead_peers(&mut self, timeout: std::time::Duration) -> Vec<PeerInfo> {
        let now = Instant::now();
        let dead: Vec<SocketAddr> = self
            .peers
            .iter()
            .filter(|(_, peer)| {
                peer.state == PeerState::Established
                    && now.duration_since(peer.last_activity) > timeout
            })
            .map(|(addr, _)| *addr)
            .collect();
        dead.into_iter()
            .filter_map(|addr| self.peers.remove(&addr))
            .collect()
    }
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_get_peer() {
        let mut pm = PeerManager::new();
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        pm.add_peer(addr);
        assert_eq!(pm.count(), 1);
        assert!(pm.get_peer(&addr).is_some());
    }

    #[test]
    fn remove_peer() {
        let mut pm = PeerManager::new();
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        pm.add_peer(addr);
        pm.remove_peer(&addr);
        assert_eq!(pm.count(), 0);
    }

    #[test]
    fn set_state_transitions() {
        let mut pm = PeerManager::new();
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        pm.add_peer(addr);
        pm.set_state(&addr, PeerState::Handshaking);
        assert_eq!(pm.get_peer(&addr).unwrap().state, PeerState::Handshaking);
        pm.set_state(&addr, PeerState::Established);
        assert_eq!(pm.get_peer(&addr).unwrap().state, PeerState::Established);
    }

    #[test]
    fn count_established() {
        let mut pm = PeerManager::new();
        let a1: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let a2: SocketAddr = "127.0.0.1:5001".parse().unwrap();
        pm.add_peer(a1);
        pm.add_peer(a2);
        pm.set_state(&a1, PeerState::Established);
        assert_eq!(pm.count_established(), 1);
    }

    #[test]
    fn record_traffic() {
        let mut pm = PeerManager::new();
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        pm.add_peer(addr);
        pm.set_state(&addr, PeerState::Established);
        let peer = pm.get_peer_mut(&addr).unwrap();
        peer.record_rx(100);
        peer.record_tx(200);
        assert_eq!(peer.rx_bytes, 100);
        assert_eq!(peer.tx_bytes, 200);
    }

    #[test]
    fn snapshot_conversion() {
        let mut pm = PeerManager::new();
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        pm.add_peer(addr);
        pm.set_state(&addr, PeerState::Established);
        pm.set_assigned_ip(&addr, "10.8.0.5".parse().unwrap());
        let snapshots = pm.snapshots();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].state, "Established");
    }
}