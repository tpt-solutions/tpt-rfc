// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # tpt-dhcpv6
//!
//! A clean-room, dual-licensed implementation of **DHCPv6** — the Dynamic Host
//! Configuration Protocol for IPv6 of
//! [RFC 8415](https://www.rfc-editor.org/rfc/rfc8415), using the message and
//! option encoding of RFC 8415 §7 and §21, the DUID formats of §11, and the IA
//! containers of §21.4–§21.6 and §21.21–§21.22.
//!
//! This crate provides both a **client** and a **server** finite-state machine
//! with a pluggable lease backend, so callers can bring their own address/prefix
//! store. The only other production-grade Rust DHCPv6 implementations are client
//! libraries or coupled to larger frameworks; this crate fills the gap with a
//! self-contained, fully auditable, MIT/Apache-2.0 implementation.
//!
//! ## Architecture
//!
//! - [`message::Dhcpv6Message`] — the DHCPv6 message with clean-room
//!   encode/decode and typed option accessors.
//! - [`options`] — the [`options::Dhcpv6Option`], [`options::MessageType`],
//!   [`options::Duid`], and IA types.
//! - [`lease::LeaseStore`] — pluggable lease backend trait. Implement it (or use
//!   [`memory::MemoryLeaseStore`]) to control address/prefix allocation.
//! - [`client::Client`] — the RFC 8415 client FSM:
//!   `INIT → SELECTING → REQUESTING → BOUND → RENEWING/REBINDING`.
//! - [`server::Server`] — the RFC 8415 server FSM; `process` is
//!   transport-agnostic and `run` provides a UDP listener.
//!
//! ## Example
//!
//! ```
//! use tpt_dhcpv6::client::Client;
//! use tpt_dhcpv6::memory::PoolConfig;
//! use tpt_dhcpv6::options::Duid;
//! use tpt_dhcpv6::server::Server;
//!
//! let config = PoolConfig::default();
//! let mut server = Server::new(config.clone());
//! let mut client = Client::new(Duid::from_ethernet_ll(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]));
//!
//! // Client multicasts a SOLICIT.
//! let solicit = client.start_solicit();
//! // Server replies with an ADVERTISE (encoded bytes round-trip through the wire).
//! let advertise = tpt_dhcpv6::message::Dhcpv6Message::from_bytes(
//!     &server.process_bytes(&solicit.to_bytes()).unwrap().unwrap(),
//! )
//! .unwrap();
//! // Client replies with a REQUEST.
//! let request = client.receive_advertise(&advertise).unwrap();
//! let reply = tpt_dhcpv6::message::Dhcpv6Message::from_bytes(
//!     &server.process_bytes(&request.to_bytes()).unwrap().unwrap(),
//! )
//! .unwrap();
//! client.receive_reply(&reply).unwrap();
//!
//! assert_eq!(client.state(), tpt_dhcpv6::client::ClientState::Bound);
//! let lease = client.lease().unwrap();
//! assert_eq!(lease.addresses.len(), 1);
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
pub use error::{DecodeError, Dhcpv6Error, LeaseError};
pub use lease::{AcquireRequest, IaAddressLease, IaLease, IaPrefixLease, LeaseStore};
pub use message::Dhcpv6Message;
pub use options::{Dhcpv6Option, Duid, IaKind, IaNa, MessageType};
pub use server::Server;
