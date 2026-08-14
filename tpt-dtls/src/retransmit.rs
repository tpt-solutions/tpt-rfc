// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! DTLS retransmission timer (RFC 9147 §5.2).
//!
//! DTLS is message-driven: a peer retransmits the *entire flight* it last
//! sent if no acceptable response arrives within a timeout. The timeout
//! starts at a base value and doubles on each retransmission (exponential
//! backoff), up to a cap and a maximum number of retries, after which the
//! handshake is abandoned.

use std::time::Duration;

/// What a timer tick decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetransmitEvent {
    /// No timeout elapsed; nothing to do.
    None,
    /// The timeout elapsed; the current flight should be retransmitted.
    Retransmit,
    /// Retries exhausted; the handshake should be aborted.
    Abort,
}

/// The DTLS retransmission timer.
#[derive(Debug, Clone)]
pub struct RetransmitTimer {
    base: Duration,
    max: Duration,
    current: Duration,
    elapsed: Duration,
    retries: u32,
    max_retries: u32,
    armed: bool,
}

impl RetransmitTimer {
    /// Create a timer with the given base timeout, cap, and maximum retries.
    pub fn new(base: Duration, max: Duration, max_retries: u32) -> Self {
        Self {
            base,
            max,
            current: base,
            elapsed: Duration::ZERO,
            retries: 0,
            max_retries,
            armed: false,
        }
    }

    /// Whether the timer is currently armed (awaiting a response).
    pub fn is_armed(&self) -> bool {
        self.armed
    }

    /// Arm (or re-arm) the timer at the base timeout. Called when a flight is
    /// transmitted and when progress is made.
    pub fn arm(&mut self) {
        self.current = self.base;
        self.elapsed = Duration::ZERO;
        self.retries = 0;
        self.armed = true;
    }

    /// Disarm the timer (e.g. after the handshake completes or a valid
    /// response is received).
    pub fn disarm(&mut self) {
        self.armed = false;
        self.elapsed = Duration::ZERO;
        self.retries = 0;
    }

    /// Advance the timer by `dt`. Returns the action the caller should take.
    pub fn tick(&mut self, dt: Duration) -> RetransmitEvent {
        if !self.armed {
            return RetransmitEvent::None;
        }
        self.elapsed += dt;
        if self.elapsed < self.current {
            return RetransmitEvent::None;
        }
        self.elapsed = Duration::ZERO;
        self.retries += 1;
        if self.retries > self.max_retries {
            self.armed = false;
            return RetransmitEvent::Abort;
        }
        self.current = (self.current * 2).min(self.max);
        RetransmitEvent::Retransmit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backs_off_and_aborts() {
        let mut t = RetransmitTimer::new(Duration::from_millis(10), Duration::from_millis(80), 3);
        t.arm();
        assert_eq!(t.tick(Duration::from_millis(5)), RetransmitEvent::None);
        assert_eq!(t.tick(Duration::from_millis(5)), RetransmitEvent::Retransmit); // 10ms, retry 1
        assert_eq!(t.tick(Duration::from_millis(20)), RetransmitEvent::Retransmit); // 20ms, retry 2
        assert_eq!(t.tick(Duration::from_millis(40)), RetransmitEvent::Retransmit); // 40ms, retry 3
        assert_eq!(t.tick(Duration::from_millis(80)), RetransmitEvent::Abort); // retries>3
        assert!(!t.is_armed());
    }

    #[test]
    fn progress_rearms() {
        let mut t = RetransmitTimer::new(Duration::from_millis(10), Duration::from_millis(80), 3);
        t.arm();
        assert_eq!(t.tick(Duration::from_millis(10)), RetransmitEvent::Retransmit);
        t.arm(); // progress
        assert_eq!(t.tick(Duration::from_millis(5)), RetransmitEvent::None);
        assert_eq!(t.tick(Duration::from_millis(5)), RetransmitEvent::Retransmit);
    }
}
