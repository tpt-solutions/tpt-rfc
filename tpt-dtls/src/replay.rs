// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Anti-replay protection for received DTLS records (RFC 9147 §4.4).
//!
//! Each epoch maintains a sliding window of recently-seen sequence numbers.
//! A record whose sequence is older than the bottom of the window, or whose
//! sequence has already been accepted within the window, is a replay and is
//! rejected. The recommended minimum window is 32; this implementation
//! defaults to 64 and supports any window size that is a multiple of 64.

use crate::error::Result;
use subtle::ConstantTimeEq;

/// Constant-time comparison of two byte slices (used for cookie and MAC
/// checks). Returns `true` iff the slices are equal in length and content.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// A sliding-window replay checker.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    /// Number of sequence numbers tracked.
    window: usize,
    /// Sequence number mapped to bit 0 of `words[0]`.
    base: u64,
    /// Bitmask of accepted sequence numbers within `[base, base+window)`.
    words: Vec<u64>,
}

impl ReplayWindow {
    /// Create a replay window tracking `window` sequence numbers (rounded up
    /// to a multiple of 64). The DTLS-recommended minimum is 32.
    pub fn new(window: usize) -> Self {
        let window = window.max(64).next_multiple_of(64);
        let nwords = window / 64;
        Self {
            window,
            base: 0,
            words: vec![0u64; nwords],
        }
    }

    /// The configured window size.
    pub fn window_size(&self) -> usize {
        self.window
    }

    /// Check `seq`. Returns `Ok(true)` if the record is new and accepted
    /// (updating state), `Ok(false)` if it is a replay, or an error if `seq`
    /// would overflow the 48-bit DTLS sequence space.
    pub fn check(&mut self, seq: u64) -> Result<bool> {
        if seq > 0xFF_FFFF_FFFF_FFFF {
            return Err(crate::error::DtlsError::SequenceOverflow(0));
        }

        // Older than the bottom of the window → replay.
        if seq < self.base {
            return Ok(false);
        }

        let top = self.base + self.window as u64;
        if seq >= top {
            // Beyond the top: slide the window forward so `seq` becomes the
            // new highest (top - 1). `new_base = seq + 1 - window`, so the
            // shift amount is `new_base - base` (capped at the window width
            // so we never shift past all history).
            let new_base = seq + 1 - self.window as u64;
            let shift = (new_base - self.base).min(self.window as u64) as usize;
            self.window_slide(shift);
            self.base = new_base;
        }

        let bit = (seq - self.base) as usize;
        let word = bit / 64;
        let mask = 1u64 << (bit % 64);
        if self.words[word] & mask != 0 {
            return Ok(false); // already seen within window → replay
        }
        self.words[word] |= mask;
        Ok(true)
    }

    /// Slide the bitmask forward (window base increases) by `n` bit
    /// positions. Because a sequence `seq` maps to bit `seq - base`, sliding
    /// the window forward requires shifting the bitmap **right** by `n`,
    /// dropping the lowest `n` sequence numbers that fall out of the window.
    fn window_slide(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        let word_shift = n / 64;
        let bit_shift = n % 64;
        let len = self.words.len();
        if word_shift >= len {
            for w in self.words.iter_mut() {
                *w = 0;
            }
            return;
        }
        if bit_shift == 0 {
            for i in 0..len - word_shift {
                self.words[i] = self.words[i + word_shift];
            }
        } else {
            for i in 0..len - word_shift - 1 {
                let low = self.words[i + word_shift] >> bit_shift;
                let high = self.words[i + word_shift + 1] << (64 - bit_shift);
                self.words[i] = low | high;
            }
            let last = len - word_shift - 1;
            self.words[last] = self.words[len - 1] >> bit_shift;
        }
        for w in self.words.iter_mut().skip(len - word_shift) {
            *w = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_in_order_and_rejects_replay() {
        let mut w = ReplayWindow::new(64);
        assert!(w.check(0).unwrap());
        assert!(w.check(1).unwrap());
        assert!(w.check(2).unwrap());
        // Replay of 1 is rejected.
        assert!(!w.check(1).unwrap());
        // Out-of-window (older than base after sliding) rejected.
        assert!(w.check(3).unwrap());
        assert!(!w.check(0).unwrap()); // 0 < base now
    }

    #[test]
    fn out_of_order_within_window_accepted_once() {
        let mut w = ReplayWindow::new(64);
        assert!(w.check(10).unwrap());
        assert!(w.check(5).unwrap());
        assert!(!w.check(5).unwrap());
        assert!(w.check(6).unwrap());
        assert!(!w.check(10).unwrap());
    }

    #[test]
    fn large_leap_slides_window() {
        let mut w = ReplayWindow::new(64);
        assert!(w.check(1000).unwrap());
        // 1000-63 is below the window bottom now.
        assert!(!w.check(900).unwrap());
        assert!(w.check(1063).unwrap());
        assert!(!w.check(1000).unwrap());
    }
}
