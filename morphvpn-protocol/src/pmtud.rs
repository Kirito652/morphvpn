use std::time::{Duration, Instant};

const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const MIN_PROBE_SIZE: u16 = 576;

#[derive(Clone, Debug)]
pub struct PmtudState {
    current_mtu: u16,
    probe_id: u16,
    pending_probe: Option<PendingProbe>,
    confirmed_mtu: u16,
}

#[derive(Clone, Debug)]
struct PendingProbe {
    probe_id: u16,
    probe_size: u16,
    sent_at: Instant,
}

impl PmtudState {
    pub fn new(initial_mtu: u16) -> Self {
        Self {
            current_mtu: initial_mtu,
            probe_id: 0,
            pending_probe: None,
            confirmed_mtu: initial_mtu,
        }
    }

    pub fn current_mtu(&self) -> u16 {
        self.confirmed_mtu
    }

    pub fn should_probe(&self) -> bool {
        self.pending_probe.is_none()
    }

    pub fn create_probe(&mut self) -> (u16, u16) {
        self.probe_id = self.probe_id.wrapping_add(1);
        let probe_size = self.current_mtu;
        self.pending_probe = Some(PendingProbe {
            probe_id: self.probe_id,
            probe_size,
            sent_at: Instant::now(),
        });
        (self.probe_id, probe_size)
    }

    pub fn handle_ack(&mut self, probe_id: u16, confirmed_size: u16) -> bool {
        if let Some(ref pending) = self.pending_probe {
            if pending.probe_id == probe_id {
                self.pending_probe = None;
                self.confirmed_mtu = confirmed_size;
                return true;
            }
        }
        false
    }

    pub fn check_timeout(&mut self) -> bool {
        if let Some(ref pending) = self.pending_probe {
            if pending.sent_at.elapsed() > PROBE_TIMEOUT {
                self.pending_probe = None;
                self.current_mtu = (self.current_mtu.saturating_sub(100)).max(MIN_PROBE_SIZE);
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_state_uses_initial_mtu() {
        let state = PmtudState::new(1400);
        assert_eq!(state.current_mtu(), 1400);
        assert!(state.should_probe());
    }

    #[test]
    fn create_probe_returns_id_and_size() {
        let mut state = PmtudState::new(1400);
        let (id, size) = state.create_probe();
        assert_eq!(id, 1);
        assert_eq!(size, 1400);
        assert!(!state.should_probe());
    }

    #[test]
    fn handle_ack_updates_mtu() {
        let mut state = PmtudState::new(1400);
        let (id, _) = state.create_probe();
        assert!(state.handle_ack(id, 1200));
        assert_eq!(state.current_mtu(), 1200);
        assert!(state.should_probe());
    }

    #[test]
    fn handle_ack_rejects_wrong_id() {
        let mut state = PmtudState::new(1400);
        let (id, _) = state.create_probe();
        assert!(!state.handle_ack(id + 1, 1200));
        assert_eq!(state.current_mtu(), 1400);
    }

    #[test]
    fn probe_id_wraps_around() {
        let mut state = PmtudState::new(1400);
        state.probe_id = u16::MAX;
        let (id, _) = state.create_probe();
        assert_eq!(id, 0);
    }
}
