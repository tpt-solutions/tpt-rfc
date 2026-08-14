# SPEC-NOTES — RFC 3550 (RTP) / RFC 3551 (RTP Profile for Audio and Video Conferences)

This file tracks the RFC sections implemented in this crate and the conformance
test vectors wired into the suite. It is the authoritative "are we done?" record
for the crate.

## Source documents

- RFC 3550: RTP: A Transport Protocol for Real-Time Applications
  — <https://www.rfc-editor.org/rfc/rfc3550>
- RFC 3551: RTP Profile for Audio and Video Conferences with Minimal Control
  — <https://www.rfc-editor.org/rfc/rfc3551>
- Errata: <https://www.rfc-editor.org/errata/rfc3550> (noted where relevant)

## Implemented sections

### RFC 3550 — RTP

- [x] §5.1 RTP fixed header (V/P/X/CC/M/PT/seq/ts/SSRC/CSRC)
- [x] §5.3.1 RTP header extension (profile / length / words)
- [x] §5.1 padding handling (last octet = padding count)
- [x] §5.1 CSRC list encode/decode

### RFC 3550 — RTCP

- [x] §6.1 common RTCP header (V/P/RC/PT/length)
- [x] §6.4.1 Sender Report (SR, PT=200): sender info + reception report blocks
- [x] §6.4.2 Receiver Report (RR, PT=201): reception report blocks
- [x] §6.5 SDES (PT=202): CNAME/NAME/EMAIL/PHONE/LOC/TOOL/NOTE/PRIV items
- [x] §6.6 BYE (PT=203): source list + optional reason
- [x] §6.7 APP (PT=204): subtype + name + application data

### RFC 3550 — Reception statistics & scheduling

- [x] §6.4.1 fraction lost / cumulative lost (§A.3)
- [x] §A.1 sequence number validity / wraparound tracking
- [x] §6.4.1 interarrival jitter estimation (§6.4.1 / §A.8)
- [x] §6.2 / §6.3 bandwidth-aware RTCP transmission interval (§A.7)

### RFC 3551 — Profile

- [x] §6 static payload type table (PT 0–34)

## Data model / public API

- `rtp::RtpPacket` — owned RTP packet; `rtp::RtpHeader` + payload.
  - `decode` / `encode` for full in-memory packets.
  - `decode_from_slice` / `encode_to_slice` for zero-copy-ish packet I/O.
- `rtp::RtpReader` / `rtp::RtpWriter` — borrowed header views over a buffer.
- `rtcp` module: `RtcpPacket` (typed SR/RR/SDES/BYE/APP), `SenderReport`,
  `ReceptionReport`, `Sdes`, `SdesItem`, `SourceDescription`, `Bye`, `App`.
- `session::ReceiverStats` / `SourceStats` — sequence tracking, jitter, loss,
  and `build_reception_report()` for RR generation.
- `session::SessionStatistics` — aggregate per-SSRC statistics.
- `scheduler::RtcpScheduler` — computes next RTCP transmission time (§6.3.1).
- `profile` — `PAYLOAD_TYPES` static table and `PayloadTypeInfo`.

## Test vectors

- [x] In-crate round-trip: every packet type encoded then decoded equals input
  (wired in `tests/rtp.rs`, `tests/rtcp.rs`).
- [x] Hand-constructed RTP packet with CSRC + extension + padding, field
  assertions (`tests/vectors.rs`).
- [x] Hand-constructed SR/RR with full reception-report-block assertions
  (`tests/vectors.rs`).
- [x] Sequence-tracking / jitter / loss reference cases from RFC 3550
  Appendix A (§A.1, §A.3, §A.8) (`tests/session.rs`).
- [ ] Interop-test against a real RTP stack (GStreamer, webrtc-rs) — BLOCKED:
  no RTP implementation available in this environment; verified by the
  in-crate round-trip + hand-constructed-vector harness instead.

## spec-complete checklist

- [x] All in-scope RFC sections implemented
- [x] Test vectors passing (round-trip + hand-constructed + Appendix A stats)
- [x] `cargo clippy` + `cargo fmt` clean
- [x] docs.rs-quality documentation
- [ ] Tagged `0.1.0` and published to crates.io (BLOCKED: no crates.io
  credentials in this environment)
