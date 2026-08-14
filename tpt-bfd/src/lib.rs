//! # tpt-bfd
//!
//! A clean-room, dual-licensed implementation of the Bidirectional
//! Forwarding Detection (BFD) control protocol, specified in
//! [RFC 5880](https://www.rfc-editor.org/rfc/rfc5880) (protocol) and
//! [RFC 5881](https://www.rfc-editor.org/rfc/rfc5881) (IPv4/IPv6 UDP
//! encapsulation).
//!
//! BFD provides low-overhead, sub-second liveness detection between two
//! forwarding engines. A single [`session::Session`] models one
//! endpoint's view of a session; callers feed it packets
//! ([`session::Session::process_bytes`],
//! [`session::Session::next_periodic_packet`],
//! [`session::Session::encode_packet`]) and place the resulting bytes on
//! the wire. [`transport::UdpTransport`] provides a ready-made,
//! dependency-free UDP driver for asynchronous mode.
//!
//! ## Supported features
//!
//! - Full BFD control-packet encode/decode (RFC 5880 §4.1).
//! - Session state machine (`AdminDown`/`Down`/`Init`/`Up`) including
//!   the three-way handshake for establishment and teardown (§6.2).
//! - Negotiated transmit interval and detection-time calculation
//!   (§6.8.2-§6.8.4).
//! - Detection timer driving the session to `Down` on packet loss.
//! - Demand mode (D bit) in both directions (§6.6), including
//!   suppression of periodic transmission when the remote requests it.
//! - Poll Sequence (P/F bits) for parameter re-negotiation (§6.5).
//! - Authentication: Simple Password, plus Keyed SHA1 / Meticulous
//!   Keyed SHA1 (§6.7).
//! - Asynchronous-mode session over UDP (RFC 5881), via
//!   [`transport::UdpTransport`].
//!
//! The Echo function (§5, §6.8.5/§6.8.8/§6.8.9) is intentionally not
//! implemented: it requires the forwarding path to loop packets back,
//! which is outside a userspace control-plane implementation. MD5-based
//! authentication is intentionally omitted (RFC 5880 §6.7 strongly
//! discourages it).
//!
//! ## Example
//!
//! ```no_run
//! use tpt_bfd::session::{Session, SessionConfig, Role};
//! use tpt_bfd::packet::{ControlPacket, SessionState};
//!
//! let cfg = SessionConfig {
//!     local_discriminator: 1,
//!     desired_min_tx_interval: 1_000_000,
//!     required_min_rx_interval: 1_000_000,
//!     detect_mult: 3,
//!     demand_mode: false,
//!     control_plane_independent: false,
//!     role: Role::Active,
//!     auth: None,
//! };
//! let mut a = Session::new(cfg).unwrap();
//! let _first: Option<ControlPacket> = a.next_periodic_packet();
//! assert_eq!(a.state(), SessionState::Down);
//! ```
#![warn(missing_docs)]

pub mod error;
pub mod packet;
pub mod session;
pub mod transport;

pub use error::BfdError;
pub use packet::{
    AuthSection, AuthType, ControlPacket, Diagnostic, SessionState,
};
pub use session::{AuthConfig, PacketResult, Role, Session, SessionConfig};
pub use transport::UdpTransport;
