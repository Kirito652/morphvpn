use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Default)]
pub struct PacketCounter {
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_errors: AtomicU64,
    pub tx_errors: AtomicU64,
}

impl PacketCounter {
    pub fn record_rx(&self, bytes: u64) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_tx(&self, bytes: u64) {
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_rx_error(&self) {
        self.rx_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tx_error(&self) {
        self.tx_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_errors: self.rx_errors.load(Ordering::Relaxed),
            tx_errors: self.tx_errors.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MetricsSnapshot {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

impl MetricsSnapshot {
    pub fn delta(&self, prev: &MetricsSnapshot) -> MetricsSnapshot {
        MetricsSnapshot {
            rx_packets: self.rx_packets.saturating_sub(prev.rx_packets),
            tx_packets: self.tx_packets.saturating_sub(prev.tx_packets),
            rx_bytes: self.rx_bytes.saturating_sub(prev.rx_bytes),
            tx_bytes: self.tx_bytes.saturating_sub(prev.tx_bytes),
            rx_errors: self.rx_errors.saturating_sub(prev.rx_errors),
            tx_errors: self.tx_errors.saturating_sub(prev.tx_errors),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MetricsHandle {
    pub udp: Arc<PacketCounter>,
    pub tun: Arc<PacketCounter>,
}

impl Default for MetricsHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsHandle {
    pub fn new() -> Self {
        Self {
            udp: Arc::new(PacketCounter::default()),
            tun: Arc::new(PacketCounter::default()),
        }
    }

    pub fn log_periodic(&self, interval: Duration, running: Arc<std::sync::atomic::AtomicBool>) {
        let udp = self.udp.clone();
        let tun = self.tun.clone();
        tokio::spawn(async move {
            let mut prev_udp = udp.snapshot();
            let mut prev_tun = tun.snapshot();
            let mut tick = tokio::time::interval(interval);
            tick.tick().await;
            while running.load(Ordering::Relaxed) {
                tick.tick().await;
                let cur_udp = udp.snapshot();
                let cur_tun = tun.snapshot();
                let d_udp = cur_udp.delta(&prev_udp);
                let d_tun = cur_tun.delta(&prev_tun);
                tracing::info!(
                    "metrics: udp rx={}pkts/{}B tx={}pkts/{}B err={}/{} | tun rx={}pkts/{}B tx={}pkts/{}B err={}/{}",
                    d_udp.rx_packets, d_udp.rx_bytes, d_udp.tx_packets, d_udp.tx_bytes,
                    d_udp.rx_errors, d_udp.tx_errors,
                    d_tun.rx_packets, d_tun.rx_bytes, d_tun.tx_packets, d_tun.tx_bytes,
                    d_tun.rx_errors, d_tun.tx_errors,
                );
                prev_udp = cur_udp;
                prev_tun = cur_tun;
            }
        });
    }
}
