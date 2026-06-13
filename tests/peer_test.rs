use morphvpn::peer::{PeerManager, PeerState};
use std::net::SocketAddr;

#[test]
fn peer_manager_lifecycle() {
    let mut pm = PeerManager::new();
    let addr: SocketAddr = "192.168.1.100:4000".parse().unwrap();

    pm.add_peer(addr);
    assert_eq!(pm.count(), 1);
    assert_eq!(pm.get_peer(&addr).unwrap().state, PeerState::Connecting);

    pm.set_state(&addr, PeerState::Handshaking);
    pm.set_state(&addr, PeerState::Established);
    pm.set_assigned_ip(&addr, "10.8.0.10".parse().unwrap());
    assert_eq!(pm.count_established(), 1);

    let snapshots = pm.snapshots();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].assigned_ip.as_deref(), Some("10.8.0.10"));

    pm.remove_peer(&addr);
    assert_eq!(pm.count(), 0);
}