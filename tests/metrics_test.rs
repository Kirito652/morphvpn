use morphvpn::metrics::{MetricsHandle, PacketCounter};

#[test]
fn counter_records_rx() {
    let c = PacketCounter::default();
    c.record_rx(100);
    c.record_rx(200);
    let snap = c.snapshot();
    assert_eq!(snap.rx_packets, 2);
    assert_eq!(snap.rx_bytes, 300);
}

#[test]
fn counter_records_tx() {
    let c = PacketCounter::default();
    c.record_tx(500);
    let snap = c.snapshot();
    assert_eq!(snap.tx_packets, 1);
    assert_eq!(snap.tx_bytes, 500);
}

#[test]
fn counter_records_errors() {
    let c = PacketCounter::default();
    c.record_rx_error();
    c.record_tx_error();
    c.record_tx_error();
    let snap = c.snapshot();
    assert_eq!(snap.rx_errors, 1);
    assert_eq!(snap.tx_errors, 2);
}

#[test]
fn snapshot_delta() {
    let c = PacketCounter::default();
    c.record_rx(100);
    c.record_rx(200);
    let before = c.snapshot();
    c.record_rx(50);
    let after = c.snapshot();
    let delta = after.delta(&before);
    assert_eq!(delta.rx_packets, 1);
    assert_eq!(delta.rx_bytes, 50);
}

#[test]
fn metrics_handle_has_separate_counters() {
    let h = MetricsHandle::new();
    h.udp.record_rx(100);
    h.tun.record_tx(200);
    assert_eq!(h.udp.snapshot().rx_bytes, 100);
    assert_eq!(h.tun.snapshot().tx_bytes, 200);
    assert_eq!(h.udp.snapshot().tx_bytes, 0);
}
