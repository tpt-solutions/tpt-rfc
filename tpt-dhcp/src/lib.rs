// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # tpt-dhcp
//!
//! A clean-room, dual-licensed implementation of **DHCP** — the Dynamic Host
//! Configuration Protocol of [RFC 2131](https://www.rfc-editor.org/rfc/rfc2131),
//! using the BOOTP message format and the DHCP options encoding of
//! [RFC 2132](https://www.rfc-editor.org/rfc/rfc2132).
//!
//! This crate provides both a **client** and a **server** finite-state machine
//! with a pluggable lease backend, so callers can bring their own address
//! store. The only other production-grade Rust DHCP server
//! ([dhcproto](https://crates.io/crates/dhcproto), MIT) is a wire-codec library
//! with no bundled client or server, which is why this crate exists within the
//! dual MIT/Apache-2.0 TPT Solutions platform.
//!
//! ## Architecture
//!
//! - [`message::DhcpMessage`] — the BOOTP/DHCP message with clean-room
//!   encode/decode and typed option accessors.
//! - [`options`] — the [`options::DhcpOption`] and [`options::MessageType`]
//!   types.
//! - [`lease::LeaseStore`] — pluggable lease backend trait. Implement it (or use
//!   [`memory::MemoryLeaseStore`]) to control address allocation.
//! - [`client::Client`] — the RFC 2131 client FSM:
//!   `INIT → SELECTING → REQUESTING → BOUND → RENEWING/REBINDING`.
//! - [`server::Server`] — the RFC 2131 server FSM; `process` is
//!   transport-agnostic and `run` provides a UDP listener.
//!
//! ## Example
//!
//! ```
//! use tpt_dhcp::client::Client;
//! use tpt_dhcp::memory::PoolConfig;
//! use tpt_dhcp::server::Server;
//!
//! let config = PoolConfig::default();
//! let mut server = Server::new(config.clone());
//! let mut client = Client::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
//!
//! // Client broadcasts a DISCOVER.
//! let discover = client.start_discover();
//! // Server replies with an OFFER (encoded bytes round-trip through the wire).
//! let offer = tpt_dhcp::message::DhcpMessage::from_bytes(
//!     &server.process_bytes(&discover.to_bytes()).unwrap().unwrap(),
//! )
//! .unwrap();
//! // Client replies with a REQUEST.
//! let request = client.receive_offer(&offer).unwrap();
//! let ack = tpt_dhcp::message::DhcpMessage::from_bytes(
//!     &server.process_bytes(&request.to_bytes()).unwrap().unwrap(),
//! )
//! .unwrap();
//! client.receive_ack(&ack).unwrap();
//!
//! assert_eq!(client.state(), tpt_dhcp::client::ClientState::Bound);
//! let lease = client.lease().unwrap();
//! assert_eq!(lease.server_id, config.server_ip);
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod client;
pub mod error;
pub mod lease;
pub mod memory;
pub mod message;
pub mod options;
pub mod server;

pub use client::{Client, ClientLease, ClientState};
pub use error::{DecodeError, DhcpError, LeaseError};
pub use lease::{AcquireRequest, Lease, LeaseStore};
pub use message::{DhcpMessage, MessageOp};
pub use options::{DhcpOption, MessageType};
