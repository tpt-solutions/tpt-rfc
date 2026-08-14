//! Receiver-side RTP statistics and RTCP Reception Report generation.
//!
//! This implements the sequence-number validity/wraparound tracking,
//! interarrival-jitter estimate, and lost-packet accounting described in
//! RFC 3550 Appendix A (§A.1, §A.3, §A.8), turning them into
//! [`ReceptionReport`] blocks ready to be placed inside an RR (or SR).
//!
//! The public entry point is [`SessionStatistics`], which tracks one
//! [`ReceiverStats`] per SSRC and can produce a report for each.

use crate::rtcp::{ReceptionReport, RtcpPacket};

/// Modulus of the 16-bit RTP sequence number space.
const RTP_SEQ_MOD: u32 = 1 << 16;
/// Maximum number of packets a sequence number may drop out before the source
/// is considered to have restarted (RFC 3550 §A.1).
const MAX_DROPOUT: u32 = 3000;
/// Maximum distance a packet may be misordered without being treated as a
/// restart (RFC 3550 §A.1).
const MAX_MISORDER: u32 = 100;

/// Per-SSRC receiver statistics for one RTP stream.
#[derive(Debug, Clone)]
pub struct ReceiverStats {
    ssrc: u32,
    clock_rate: u32,
    init: bool,
    base_seq: u32,
    prev_seq: u16,
    cycles: u32,
    max_seq_ext: u32,
    received: u32,
    /// Running interarrival-jitter estimate (integer, RFC 3550 §A.8).
    jitter: i64,
    prev_transit: i64,
    has_prev_transit: bool,
    last_expected: u32,
    last_lost: i64,
    /// Middle 32 bits of the NTP timestamp of the last SR received from this
    /// source (LSR field), and the delay since (DLSR). Zero if none received.
    last_sr: u32,
    delay_since_last_sr: u32,
}

impl ReceiverStats {
    /// Create a fresh statistics tracker for `ssrc`. `clock_rate` is the media
    /// clock rate (Hz) and is used only to interpret arrival times supplied to
    /// [`ReceiverStats::update`].
    pub fn new(ssrc: u32, clock_rate: u32) -> ReceiverStats {
        ReceiverStats {
            ssrc,
            clock_rate,
            init: false,
            base_seq: 0,
            prev_seq: 0,
            cycles: 0,
            max_seq_ext: 0,
            received: 0,
            jitter: 0,
            prev_transit: 0,
            has_prev_transit: false,
            last_expected: 0,
            last_lost: 0,
            last_sr: 0,
            delay_since_last_sr: 0,
        }
    }

    /// The SSRC this tracker observes.
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// The media clock rate this tracker was configured with.
    pub fn clock_rate(&self) -> u32 {
        self.clock_rate
    }

    /// Record reception of one RTP packet.
    ///
    /// `arrival` is the reception time expressed in the **same units as
    /// `rtp_timestamp`** (i.e. already scaled by `clock_rate`). Supplying raw
    /// wall-clock nanoseconds will produce meaningless jitter.
    pub fn update(&mut self, seq: u16, rtp_timestamp: u32, arrival: u32) {
        self.update_seq(seq);
        self.update_jitter(rtp_timestamp, arrival);
    }

    fn update_seq(&mut self, seq: u16) {
        if !self.init {
            self.init = true;
            self.base_seq = seq as u32;
            self.prev_seq = seq;
            self.max_seq_ext = seq as u32;
            self.received = 1;
            return;
        }
        let udelta = seq.wrapping_sub(self.prev_seq) as u32;
        if udelta == 0 {
            // Exact duplicate of the most recent packet: do not count it and
            // do not advance the high-water mark.
            return;
        }
        if udelta < MAX_DROPOUT {
            // Valid forward advance (a small forward distance, or a wrap since a
            // wrap produces a small forward distance on the circle).
            if (seq as u32) < (self.prev_seq as u32) {
                self.cycles += RTP_SEQ_MOD;
            }
            self.max_seq_ext = self.cycles + seq as u32;
            self.received += 1;
            self.prev_seq = seq;
        } else if udelta <= RTP_SEQ_MOD - MAX_MISORDER {
            // Late or misordered packet: already accounted for in lost; do not
            // advance the high-water mark or double-count.
        } else {
            // Far out of order / implausible: ignore (do not count).
        }
    }

    fn update_jitter(&mut self, rtp_timestamp: u32, arrival: u32) {
        let transit = arrival as i64 - rtp_timestamp as i64;
        if self.has_prev_transit {
            let d = (transit - self.prev_transit).abs();
            self.jitter += (d - self.jitter) / 16;
        }
        self.prev_transit = transit;
        self.has_prev_transit = true;
    }

    /// Extended highest sequence number received (RFC 3550 §A.1), combining the
    /// cycle count with the most recent low 16 bits.
    pub fn extended_sequence(&self) -> u32 {
        self.max_seq_ext
    }

    /// Total number of packets received (excluding duplicates/late).
    pub fn received(&self) -> u32 {
        self.received
    }

    /// Number of packets expected = (extended highest − first + 1).
    pub fn expected(&self) -> u32 {
        if !self.init {
            return 0;
        }
        self.max_seq_ext - self.base_seq + 1
    }

    /// Cumulative number of packets lost = expected − received.
    pub fn cumulative_lost(&self) -> i64 {
        let expected = self.expected() as i64;
        expected - self.received as i64
    }

    /// Current interarrival-jitter estimate (RFC 3550 §A.8), as a `u32`.
    pub fn jitter(&self) -> u32 {
        self.jitter.max(0) as u32
    }

    /// Record that an RTCP Sender Report carrying `ntp_mid` (the middle 32
    /// bits of the sender's NTP timestamp) was received from this source, and
    /// that `dlsr` (in 1/65536 s) has elapsed since. Feeds the LSR/DLSR fields.
    pub fn note_sender_report(&mut self, ntp_mid: u32, dlsr: u32) {
        self.last_sr = ntp_mid;
        self.delay_since_last_sr = dlsr;
    }

    /// Fraction of packets lost since the previous call to this method, scaled
    /// by 256 (an 8-bit fixed-point value, RFC 3550 §6.4.1). Calling this
    /// snapshots the cumulative counters so successive calls report *interval*
    /// loss rather than cumulative loss.
    pub fn fraction_lost(&mut self) -> u8 {
        let expected = self.expected();
        let lost = self.cumulative_lost();
        let exp_interval = expected.saturating_sub(self.last_expected);
        let lost_interval = (lost - self.last_lost).max(0) as u64;
        let fraction = lost_interval
            .checked_mul(256)
            .and_then(|v| v.checked_div(exp_interval as u64))
            .unwrap_or(0)
            .min(255) as u8;
        self.last_expected = expected;
        self.last_lost = lost;
        fraction
    }

    /// Build a [`ReceptionReport`] for this source. The `last_sr`/`dlsr` fields
    /// reflect any SR previously reported via [`ReceiverStats::note_sender_report`].
    pub fn build_reception_report(&mut self) -> ReceptionReport {
        let cumulative = self.cumulative_lost().clamp(0, 0x00FF_FFFF) as u32;
        ReceptionReport {
            ssrc: self.ssrc,
            fraction_lost: self.fraction_lost(),
            cumulative_lost: cumulative,
            extended_seq: self.extended_sequence(),
            interarrival_jitter: self.jitter(),
            last_sr: self.last_sr,
            delay_since_last_sr: self.delay_since_last_sr,
        }
    }
}

/// Aggregate receiver statistics across multiple SSRCs.
#[derive(Debug, Clone, Default)]
pub struct SessionStatistics {
    sources: std::collections::HashMap<u32, ReceiverStats>,
    clock_rate: u32,
}

impl SessionStatistics {
    /// Create an aggregator using `clock_rate` for jitter computations on any
    /// source added implicitly via [`SessionStatistics::update_packet`].
    pub fn new(clock_rate: u32) -> SessionStatistics {
        SessionStatistics {
            sources: std::collections::HashMap::new(),
            clock_rate,
        }
    }

    /// Update statistics for the given source on packet receipt. Unknown
    /// sources are created on first sight.
    pub fn update_packet(&mut self, ssrc: u32, seq: u16, rtp_timestamp: u32, arrival: u32) {
        let rate = self.clock_rate;
        let e = self.sources.entry(ssrc).or_insert_with(|| ReceiverStats::new(ssrc, rate));
        e.update(seq, rtp_timestamp, arrival);
    }

    /// Borrow a source's statistics, if tracked.
    pub fn source(&self, ssrc: u32) -> Option<&ReceiverStats> {
        self.sources.get(&ssrc)
    }

    /// Mutably borrow a source's statistics, if tracked.
    pub fn source_mut(&mut self, ssrc: u32) -> Option<&mut ReceiverStats> {
        self.sources.get_mut(&ssrc)
    }

    /// Number of distinct sources tracked.
    pub fn len(&self) -> usize {
        self.sources.len()
    }

    /// Whether any sources are tracked.
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Produce a Receiver Report (RR) packet covering every tracked source.
    pub fn receiver_report(&mut self, reporter_ssrc: u32) -> RtcpPacket {
        let reports: Vec<ReceptionReport> =
            self.sources.values_mut().map(|s| s.build_reception_report()).collect();
        RtcpPacket::Rr(crate::rtcp::ReceiverReport {
            ssrc: reporter_ssrc,
            reports,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_tracking_with_gap() {
        let mut s = ReceiverStats::new(1, 8000);
        for seq in [0u16, 1, 2, 5] {
            s.update(seq, seq as u32 * 160, seq as u32 * 160);
        }
        assert_eq!(s.expected(), 6);
        assert_eq!(s.received(), 4);
        assert_eq!(s.cumulative_lost(), 2);
        assert_eq!(s.extended_sequence(), 5);
    }

    #[test]
    fn duplicate_ignored() {
        let mut s = ReceiverStats::new(1, 8000);
        for seq in [10u16, 11, 11, 12] {
            s.update(seq, seq as u32, seq as u32);
        }
        // 10,11,12 accepted; duplicate 11 ignored
        assert_eq!(s.received(), 3);
        assert_eq!(s.expected(), 3);
        assert_eq!(s.cumulative_lost(), 0);
    }

    #[test]
    fn sequence_wraparound() {
        let mut s = ReceiverStats::new(1, 8000);
        for seq in [65534u16, 65535, 0] {
            s.update(seq, seq as u32, seq as u32);
        }
        // base=65534, extended_max=65536 -> expected=3, received=3, lost=0
        assert_eq!(s.expected(), 3);
        assert_eq!(s.cumulative_lost(), 0);
        assert_eq!(s.extended_sequence(), 65536);
    }

    #[test]
    fn jitter_estimate() {
        // arrival and rtp_ts in the same units (clock_rate == 1 for clarity)
        let mut s = ReceiverStats::new(1, 1);
        // p1: arrival 0, ts 0 -> transit 0, jitter 0
        s.update(0, 0, 0);
        // p2: arrival 160, ts 80 -> transit 80, d=80, jitter += 80/16 = 5
        s.update(1, 80, 160);
        // p3: arrival 320, ts 160 -> transit 160, d=|160-80|=80, jitter += (80-5)/16 = 4 -> 9
        s.update(2, 160, 320);
        assert_eq!(s.jitter(), 9);
    }

    #[test]
    fn fraction_lost_interval() {
        let mut s = ReceiverStats::new(1, 8000);
        for seq in [0u16, 1, 2, 5] {
            s.update(seq, seq as u32, seq as u32);
        }
        // First report: 2 lost out of 6 expected -> fraction = (2<<8)/6 = 512/6 = 85
        assert_eq!(u32::from(s.fraction_lost()), (2u32 << 8) / 6);
        // No new packets: interval loss 0
        assert_eq!(s.fraction_lost(), 0);
    }

    #[test]
    fn session_aggregator() {
        let mut sess = SessionStatistics::new(8000);
        sess.update_packet(1, 0, 0, 0);
        sess.update_packet(1, 1, 160, 160);
        sess.update_packet(2, 100, 0, 0);
        assert_eq!(sess.len(), 2);
        let rr = sess.receiver_report(0xABCD);
        if let RtcpPacket::Rr(rr) = rr {
            assert_eq!(rr.ssrc, 0xABCD);
            assert_eq!(rr.reports.len(), 2);
        } else {
            panic!("expected RR");
        }
    }
}
