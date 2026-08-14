# tpt-bfd

Clean-room, dual-licensed implementation of the **Bidirectional Forwarding
Detection (BFD)** control protocol — [RFC 5880](https://www.rfc-editor.org/rfc/rfc5880)
with the IPv4/IPv6 UDP encapsulation of
[RFC 5881](https://www.rfc-editor.org/rfc/rfc5881).

BFD provides low-overhead, sub-second liveness detection between two
forwarding engines. This crate implements the BFD control-protocol state
machine, timers, demand mode, poll sequences, and authentication, plus a
dependency-free UDP transport for asynchronous mode. It is part of the
TPT Solutions RFC platform: every crate is MIT OR Apache-2.0 and written
clean-room from the specification (no copying from other BFD
implementations).

## Features

- Full BFD control-packet encode/decode (RFC 5880 §4.1).
- Session state machine `AdminDown` / `Down` / `Init` / `Up` with the
  three-way handshake for establishment and teardown (§6.2).
- Negotiated transmit interval and detection-time calculation
  (§6.8.2–§6.8.4) and a detection timer that drives the session `Down`
  on packet loss.
- Demand mode (D bit) in both directions (§6.6), including suppression
  of periodic transmission when the remote requests it.
- Poll Sequence (P/F bits) for parameter re-negotiation (§6.5).
- Authentication: Simple Password, plus Keyed SHA1 / Meticulous Keyed
  SHA1 (§6.7). MD5 is intentionally omitted (RFC 5880 §6.7 discourages
  it); the Echo function is out of scope for a userspace control-plane
  implementation.
- Asynchronous-mode session over UDP via [`UdpTransport`].

## Example

```rust,no_run
use tpt_bfd::session::{Session, SessionConfig, Role};
use tpt_bfd::packet::SessionState;

let cfg = SessionConfig {
    local_discriminator: 1,
    desired_min_tx_interval: 1_000_000,
    required_min_rx_interval: 1_000_000,
    detect_mult: 3,
    demand_mode: false,
    control_plane_independent: false,
    role: Role::Active,
    auth: None,
};
let mut a = Session::new(cfg).unwrap();
let _first = a.next_periodic_packet();
assert_eq!(a.state(), SessionState::Down);
```

A complete two-peer handshake over UDP can be found in `tests/bfd.rs`.

## License

Licensed under either of

- Apache License, Version 2.0
- MIT license

at your option.
