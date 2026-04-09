pub const REPLAY_WINDOW_BITS: u64 = 2_048;
const REPLAY_WORD_BITS: u64 = 64;
const REPLAY_WORDS: usize = 32;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReplayWindow2048 {
    pub highest_seq: Option<u64>,
    pub words: [u64; REPLAY_WORDS],
}

impl ReplayWindow2048 {
    pub fn would_accept(&self, seq: u64) -> bool {
        let Some(highest) = self.highest_seq else {
            return true;
        };

        if seq > highest {
            return true;
        }

        let distance = highest - seq;
        if distance >= REPLAY_WINDOW_BITS {
            return false;
        }

        let word_index = (distance / REPLAY_WORD_BITS) as usize;
        let bit_index = (distance % REPLAY_WORD_BITS) as u32;
        (self.words[word_index] & (1u64 << bit_index)) == 0
    }

    pub fn observe(&mut self, seq: u64) -> bool {
        if !self.would_accept(seq) {
            return false;
        }

        let Some(highest) = self.highest_seq else {
            self.highest_seq = Some(seq);
            self.words = [0u64; REPLAY_WORDS];
            self.words[0] = 1;
            return true;
        };

        if seq > highest {
            self.advance(seq - highest);
            self.highest_seq = Some(seq);
            self.words[0] |= 1;
            return true;
        }

        let distance = highest - seq;
        let word_index = (distance / REPLAY_WORD_BITS) as usize;
        let bit_index = (distance % REPLAY_WORD_BITS) as u32;
        self.words[word_index] |= 1u64 << bit_index;
        true
    }

    pub fn left_edge(&self) -> Option<u64> {
        let highest = self.highest_seq?;
        let span = self.max_seen_offset()? as u64;
        Some(highest.saturating_sub(span))
    }

    fn advance(&mut self, shift: u64) {
        if shift >= REPLAY_WINDOW_BITS {
            self.words = [0u64; REPLAY_WORDS];
            return;
        }

        let word_shift = (shift / REPLAY_WORD_BITS) as usize;
        let bit_shift = (shift % REPLAY_WORD_BITS) as u32;
        let mut next = [0u64; REPLAY_WORDS];

        let mut dst = REPLAY_WORDS;
        while dst > 0 {
            dst -= 1;
            if dst < word_shift {
                continue;
            }

            let src = dst - word_shift;
            let mut value = self.words[src] << bit_shift;
            if bit_shift != 0 && src > 0 {
                value |= self.words[src - 1] >> (REPLAY_WORD_BITS as u32 - bit_shift);
            }
            next[dst] = value;
        }

        self.words = next;
    }

    fn max_seen_offset(&self) -> Option<u16> {
        let mut index = REPLAY_WORDS;
        while index > 0 {
            index -= 1;
            let word = self.words[index];
            if word == 0 {
                continue;
            }

            let highest_bit = 63u16 - word.reverse_bits().trailing_zeros() as u16;
            return Some((index as u16 * 64) + highest_bit);
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_reordered_packets_within_window() {
        let mut replay = ReplayWindow2048::default();
        assert!(replay.observe(1));
        assert!(replay.observe(3));
        assert!(replay.observe(2));
        assert_eq!(replay.highest_seq, Some(3));
        assert_eq!(replay.left_edge(), Some(1));
    }

    #[test]
    fn rejects_duplicates() {
        let mut replay = ReplayWindow2048::default();
        assert!(replay.observe(2));
        assert!(!replay.observe(2));
    }

    #[test]
    fn rejects_packets_outside_window_after_large_gap() {
        let mut replay = ReplayWindow2048::default();
        assert!(replay.observe(1));
        assert!(replay.observe(150));
        assert!(!replay.observe(1));
        assert!(replay.observe(149));
    }

    #[test]
    fn shifts_full_window_by_words() {
        let mut replay = ReplayWindow2048::default();
        assert!(replay.observe(100));
        assert!(replay.observe(164));
        assert!(replay.observe(228));
        assert!(!replay.observe(100));
        assert!(replay.observe(227));
    }

    #[test]
    fn clears_window_when_gap_exceeds_2048_bits() {
        let mut replay = ReplayWindow2048::default();
        assert!(replay.observe(10));
        assert!(replay.observe(2_200));
        assert_eq!(replay.left_edge(), Some(2_200));
        assert!(!replay.observe(10));
    }
}
