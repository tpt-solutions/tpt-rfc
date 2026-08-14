//! RTCP transmission-interval scheduler (RFC 3550 §6.2 / §6.3.1).
//!
//! Computes the bandwidth-aware RTCP reporting interval so that the aggregate
//! RTCP traffic of a session stays within the RTCP bandwidth budget (5% of the
//! session bandwidth by default), with senders granted 25% of that budget and
//! receivers 75% (RFC 3550 §6.2). Also implements the *reverse* and *forward*
//! reconsideration rules (§6.3.4 / §6.3.5) used when members join/leave or
//! after a packet is sent.

/// Default RTCP bandwidth as a fraction of the total session bandwidth (RFC
/// 3550 §6.2).
pub const DEFAULT_RTCP_FRACTION: f64 = 0.05;

/// Default minimum RTCP interval (seconds). Used as the base for the initial
/// transmission (`Tmin/2`) and as the floor in reconsideration.
pub const DEFAULT_MIN_INTERVAL: f64 = 5.0;

/// Default estimate of the average RTCP packet size in octets (RFC 3550
/// Appendix A.7).
pub const DEFAULT_AVG_RTCP_SIZE: f64 = 128.0;

/// Computes and tracks RTCP transmission timing for one participant.
#[derive(Debug, Clone)]
pub struct RtcpScheduler {
    /// Total session bandwidth in octets (bytes) per second.
    session_bandwidth: f64,
    /// Fraction of session bandwidth allocated to RTCP.
    rtcp_fraction: f64,
    /// Current number of members (sources) in the session.
    members: usize,
    /// Current number of senders (sources sending RTP) in the session.
    senders: usize,
    /// Whether this participant has sent RTP data since the last 2*Tmin.
    we_sent: bool,
    /// Whether this is the very first RTCP transmission.
    initial: bool,
    /// Estimated average RTCP packet size (octets).
    avg_rtcp_size: f64,
    /// Minimum interval (seconds) — base for the initial timer and the floor.
    min_interval: f64,
    /// Randomization factor applied to the computed interval (RFC 3550 §6.3.1
    /// specifies 0.5..1.5). Defaults to `1.0` for deterministic behavior;
    /// production callers should set a value in `[0.5, 1.5)`.
    random_factor: f64,
}

impl RtcpScheduler {
    /// Create a scheduler for a session with the given total bandwidth
    /// (octets/second). Uses the default RTCP fraction (5%) and a 1-member,
    /// 0-sender, not-yet-sent, initial state.
    pub fn new(session_bandwidth: f64) -> RtcpScheduler {
        RtcpScheduler {
            session_bandwidth,
            rtcp_fraction: DEFAULT_RTCP_FRACTION,
            members: 1,
            senders: 0,
            we_sent: false,
            initial: true,
            avg_rtcp_size: DEFAULT_AVG_RTCP_SIZE,
            min_interval: DEFAULT_MIN_INTERVAL,
            random_factor: 1.0,
        }
    }

    /// Total RTCP bandwidth available (octets/second).
    pub fn rtcp_bandwidth(&self) -> f64 {
        self.session_bandwidth * self.rtcp_fraction
    }

    /// Set the number of members (sources) currently in the session.
    pub fn set_members(&mut self, members: usize) -> &mut Self {
        self.members = members.max(1);
        self
    }

    /// Set the number of senders currently in the session.
    pub fn set_senders(&mut self, senders: usize) -> &mut Self {
        self.senders = senders;
        self
    }

    /// Set whether this participant has sent RTP data since the last 2*Tmin.
    pub fn set_we_sent(&mut self, we_sent: bool) -> &mut Self {
        self.we_sent = we_sent;
        self
    }

    /// Set the estimated average RTCP packet size in octets.
    pub fn set_avg_rtcp_size(&mut self, avg: f64) -> &mut Self {
        self.avg_rtcp_size = avg.max(1.0);
        self
    }

    /// Set the minimum interval (seconds) used for the initial timer.
    pub fn set_min_interval(&mut self, min: f64) -> &mut Self {
        self.min_interval = min.max(0.0);
        self
    }

    /// Set the randomization factor. Should be in `[0.5, 1.5)` per RFC 3550
    /// §6.3.1; defaults to `1.0`.
    pub fn set_random_factor(&mut self, factor: f64) -> &mut Self {
        self.random_factor = factor;
        self
    }

    /// Clear the initial-transmission state (call after the first RTCP packet
    /// is sent).
    pub fn mark_sent(&mut self) {
        self.initial = false;
    }

    /// Compute the RTCP transmission interval (seconds), applying the
    /// bandwidth weighting and the configured randomization factor. Does not
    /// mutate scheduler state.
    pub fn interval(&self) -> f64 {
        let mut bw = self.rtcp_bandwidth();
        let mut n = self.members;
        if self.senders > 0 && self.we_sent {
            bw *= 0.25;
            n = self.senders;
        } else {
            bw *= 0.75;
        }
        let t = if self.initial {
            self.min_interval / 2.0
        } else {
            (n as f64) * self.avg_rtcp_size / bw
        };
        t * self.random_factor
    }

    /// Time at which the next RTCP packet should be sent, given the current
    /// time `now` (seconds).
    pub fn next_time(&self, now: f64) -> f64 {
        now + self.interval()
    }

    /// Forward reconsideration (RFC 3550 §6.3.5): after sending at `now`,
    /// recompute the next transmission time and return it. Clears the initial
    /// flag.
    pub fn forward_reconsideration(&mut self, now: f64) -> f64 {
        self.initial = false;
        now + self.interval()
    }

    /// Reverse reconsideration (RFC 3550 §6.3.4): when the membership count
    /// drops (e.g. a BYE is received), shorten the pending `tn` proportionally
    /// to the reduction in members. `tc` is the current time, `tn` the
    /// previously scheduled next-transmission time, and `new_members` the
    /// reduced membership estimate.
    pub fn reverse_reconsideration(&self, tc: f64, tn: f64, new_members: usize) -> f64 {
        let new_members = new_members.max(1) as f64;
        let old = self.members.max(1) as f64;
        if new_members >= old {
            return tn;
        }
        let t = tn - tc;
        if t <= 0.0 {
            return tn;
        }
        tc + (new_members / old) * t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_interval_is_half_min() {
        let s = RtcpScheduler::new(8000.0);
        // initial -> Tmin/2 = 2.5, factor 1.0
        assert!((s.interval() - 2.5).abs() < 1e-9);
    }

    #[test]
    fn receiver_interval_scales_with_members() {
        let mut s = RtcpScheduler::new(8000.0);
        s.set_members(10).mark_sent();
        // t = 10 * 128 / (0.75 * 400) = 1280 / 300 = 4.2666...
        let want = 10.0 * 128.0 / (0.75 * 400.0);
        assert!((s.interval() - want).abs() < 1e-9);
    }

    #[test]
    fn sender_interval_uses_sender_share() {
        let mut s = RtcpScheduler::new(8000.0);
        s.set_members(10).set_senders(2).set_we_sent(true).mark_sent();
        // t = 2 * 128 / (0.25 * 400) = 256 / 100 = 2.56
        let want = 2.0 * 128.0 / (0.25 * 400.0);
        assert!((s.interval() - want).abs() < 1e-9);
    }

    #[test]
    fn reverse_reconsideration_shortens() {
        let mut s = RtcpScheduler::new(8000.0);
        s.set_members(10); // 10 members before the drop
        // scheduled tn = 10.0 at tc = 0; drops to 5 members
        let new_tn = s.reverse_reconsideration(0.0, 10.0, 5);
        // tn' = 0 + (5/10)*10 = 5.0
        assert!((new_tn - 5.0).abs() < 1e-9);
    }

    #[test]
    fn forward_reconsideration_clears_initial() {
        let mut s = RtcpScheduler::new(8000.0);
        assert!(s.initial);
        let tn = s.forward_reconsideration(0.0);
        assert!(!s.initial);
        // after init cleared, interval = 1*128/(0.75*400) = 0.4266...
        assert!((tn - 0.4266666).abs() < 1e-6);
    }
}
