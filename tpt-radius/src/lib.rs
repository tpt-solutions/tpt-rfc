// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # tpt-radius
//!
//! A clean-room, dual-licensed implementation of **RADIUS** — the Remote
//! Authentication Dial In User Service of
//! [RFC 2865](https://www.rfc-editor.org/rfc/rfc2865) — together with
//! accounting ([RFC 2866](https://www.rfc-editor.org/rfc/rfc2866)),
//! `Message-Authenticator` ([RFC 3579](https://www.rfc-editor.org/rfc/rfc3579)),
//! and the `EAP-Message` passthrough used by EAP-based authentication.
//!
//! The only full-featured Rust RADIUS server ([FreeRADIUS bindings aside]) is
//! either AGPL-licensed or pulls in C — this crate closes the dual
//! MIT/Apache-2.0 gap with a from-spec, fully auditable implementation.
//!
//! ## Shared-secret cryptography
//!
//! RADIUS authenticates the server's replies with a shared secret: the
//! **response authenticator** is `MD5(Code | Identifier | Length |
//! RequestAuthenticator | Attributes | Secret)` (RFC 2865 §3), and PAP
//! passwords are hidden by XORing with a chain of `MD5(Secret |
//! PreviousBlock)` (§5.2). Accounting requests are themselves signed the same
//! way with a zeroed authenticator field (RFC 2866 §3). All of this is
//! implemented here on top of the dual-licensed `md-5` / `hmac` primitives.
//!
//! ## Example
//!
//! ```
//! use std::sync::Arc;
//! use tpt_radius::memory::MemoryBackend;
//! use tpt_radius::server::Server;
//! use tpt_radius::Client;
//!
//! let backend = Arc::new(MemoryBackend::new());
//! backend.add_user("alice", "s3cret");
//! let server = Server::new(Arc::clone(&backend), "secret").unwrap();
//!
//! let mut client = Client::new("secret");
//! let request = client.access_request("alice", "s3cret").unwrap();
//! let reply = server.process(&request).unwrap().unwrap();
//! assert!(client.verify_response(&request, &reply));
//! ```
//!
//! ## Architecture
//!
//! - [`packet::Packet`] — wire encode/decode, attribute access, and the
//!   shared-secret hiding/verification primitives.
//! - [`attribute`] — the [`attribute::Attribute`] AVP container and the
//!   `AttributeType` registry from RFC 2865 §5.44.
//! - [`client::Client`] — request construction, reply verification, and a
//!   blocking UDP transport.
//! - [`server::Server`] — request processing behind a pluggable
//!   [`server::AuthBackend`]; `run` provides a UDP listener.
//! - [`memory::MemoryBackend`] — reference in-memory backend for tests/examples.
//! - [`accounting`] — `Acct-Status-Type` constants.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod accounting;
pub mod attribute;
pub mod client;
pub mod crypto;
pub mod error;
pub mod memory;
pub mod packet;
pub mod server;

pub use accounting::AcctStatusType;
pub use attribute::{Attribute, AttributeType};
pub use client::Client;
pub use error::{DecodeError, RadiusError};
pub use packet::{Packet, PacketCode};
pub use server::{AuthBackend, AuthDecision, AuthRequest, Server};
