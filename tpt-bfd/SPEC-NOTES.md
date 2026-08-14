# SPEC-NOTES — RFC 5880 (BFD) + RFC 5881 (IPv4/IPv6 encapsulation)

Clean-room implementation of the Bidirectional Forwarding Detection (BFD)
control protocol. Conformance is exercised by an end-to-end test harness
(`tests/bfd.rs`) that drives two `Session` state machines against each
other (over an in-memory channel and over real `localhost` UDP), covering
session establishment (three-way handshake), teardown, the detection
timer, demand mode, poll sequences, and authentication.

The wire format (RFC 5880 §4.1) and the session state machine (§6.2)
plus the timer/detection procedures (§6.8) are implemented from the RFC
text. No third-party BFD codec or protocol dependency is used, keeping
the crate self-contained and fully auditable, consistent with the
platform's clean-room requirement.

## Source documents

- RFC 5880: Bidirectional Forwarding Detection — https://www.rfc-editor.org/rfc/rfc5880
- RFC 5881: BFD for IPv4 and IPv6 (Single Hop) — https://www.rfc-editor.org/rfc/rfc5881
- Errata: https://www.rfc-editor.org/errata/rfc5880 (none affecting this crate)

## Implemented sections

- [x] §4.1 Control packet format: `Vers`, `Diag`, `Sta`, `P`/`F`/`C`/`A`/
      `D`/`M` bits, `Detect Mult`, `Length`, the four discriminator and
      interval fields — encode/decode with strict validation.
- [x] §4.2-§4.4 Authentication section encode/decode for all types.
      Simple Password is fully verified/created; Keyed SHA1 and
      Meticulous Keyed SHA1 are fully verified/created (using the
      dual-licensed `sha1` crate). MD5-based types are parsed but
      intentionally unsupported (RFC 5880 §6.7 discourages MD5).
- [x] §6.1 Active/Passive roles: a Passive session does not transmit
      until it has learned the peer's discriminator.
- [x] §6.2 State machine (`AdminDown`/`Down`/`Init`/`Up`) including the
      full transition table for establishment and teardown.
- [x] §6.5 Poll Sequence (P/F bits), used for parameter re-negotiation
      and (in Demand mode) connectivity verification.
- [x] §6.6 Demand mode: D bit set only when both ends are Up; periodic
      transmission suppressed when the remote requests it.
- [x] §6.8.1 State variables tracked per session.
- [x] §6.8.2-§6.8.3 Timer negotiation: negotiated transmit interval is
      `max(local Desired Min TX, remote Required Min RX)`; when not Up
      the effective interval is at least 1 second.
- [x] §6.8.4 Detection time: in asynchronous mode
      `remote DetectMult * max(local Required Min RX, remote Desired Min TX)`;
      in demand mode `local DetectMult * max(local Desired Min TX, remote Required Min RX)`.
      Expiry drives the session to `Down` with diagnostic
      `Control Detection Time Expired`.
- [x] §6.8.6 Reception rules: version, length, detect-mult, multipoint,
      discriminator, and authentication validation, followed by the
      state-machine update and Final-bit response.
- [x] §6.8.7 Transmission rules: contents of transmitted packets (state,
      D bit gating, auth), and suppression conditions.
- [x] RFC 5881: asynchronous-mode session carried over UDP (control
      packets to UDP port 3784) via `transport::UdpTransport`.

## Explicitly out of scope

- [ ] §5 / §6.8.5 / §6.8.8 / §6.8.9 The Echo function. It requires the
      forwarding path to loop packets back, which is outside a userspace
      control-plane implementation. The `Required Min Echo RX Interval`
      field is carried on the wire (and, when zero, halts echo
      transmission) but no echo packets are generated or consumed.
- [ ] Multihop / authenticated multi-hop and the BFD Management Control
      Plane Independent subtleties beyond the C bit.

## Data model / public API

- `packet::{ControlPacket, Diagnostic, SessionState, AuthType, AuthSection}`
  — the wire model and typed fields.
- `session::{Session, SessionConfig, AuthConfig, Role, PacketResult}` —
  the transport-agnostic session: `process_bytes`, `next_periodic_packet`,
  `encode_packet`, `check_timeout`, `start_poll`, `admin_down`/`admin_up`,
  and timer accessors (`transmit_interval`, `detection_time`).
- `transport::UdpTransport` — a synchronous UDP driver for asynchronous
  mode (`step`, `run`, `send_packet`, `recv_packet`).

## Test vectors

- [x] Packet round-trip encode/decode in `tests/bfd.rs`.
- [x] Two-session handshake to `Up` (three-way handshake) in `tests/bfd.rs`.
- [x] Detection-timer expiry → `Down` (real-time) in `tests/bfd.rs`.
- [x] AdminDown signalling teardown and re-establishment in `tests/bfd.rs`.
- [x] Demand mode: D bit set, periodic transmission suppressed, in `tests/bfd.rs`.
- [x] Simple Password authentication accept (matching key) and reject
      (mismatched key) in `tests/bfd.rs`.
- [x] Keyed SHA1 authentication round-trip, plus discard of a packet
      with a wrong key, in `tests/bfd.rs`.
- [x] End-to-end UDP transport handshake over `localhost` in `tests/bfd.rs`.

## spec-complete checklist

- [x] Control packet encode/decode (RFC 5880 §4.1)
- [x] Session state machine (AdminDown/Down/Init/Up) + detection timer + demand mode
- [x] Asynchronous-mode session over UDP (RFC 5881)
- [x] Integration harness passing (covers RFC-required message flow, timers, demand, auth)
- [x] `cargo clippy` + `cargo fmt` clean
- [x] docs.rs-quality documentation
- [ ] Interop-test against a real router/BFD implementation (e.g. FRRouting)
      (BLOCKED: no BFD router/implementation in this environment — verified
      by the in-crate two-session + UDP integration harness instead)
- [ ] Tagged `0.1.0` and published to crates.io (pending platform-wide launch)
- [ ] Mark crate "spec-complete" once session state machine passes interop testing
