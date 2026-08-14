// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # tpt-ldap-server
//!
//! A clean-room, dual-licensed implementation of **LDAP** — the Lightweight
//! Directory Access Protocol of [RFC 4511](https://www.rfc-editor.org/rfc/rfc4511).
//!
//! This crate provides an LDAP **server** behind a pluggable directory backend
//! so that callers can bring their own storage. The only production-grade Rust
//! LDAP servers (e.g. `ldap3`'s server samples, OpenLDAP glue) are either
//! client-only or AGPL-encumbered, so this crate exists within the dual
//! MIT/Apache-2.0 TPT Solutions platform to fill that gap.
//!
//! ## Architecture
//!
//! - [`backend::DirectoryBackend`] — trait for authentication and entry
//!   storage. Implement it to plug in your own directory.
//! - [`memory::MemoryBackend`] — reference in-memory backend for tests/examples.
//! - [`protocol`] — the RFC 4511 message model, (de)serialization, search
//!   scope, and filter evaluation (all framework-agnostic).
//! - [`ber`] — a clean-room BER codec (LDAP's wire format).
//! - [`session::Session`] — the connection state machine, transport-agnostic.
//! - [`server::Server`] — a `std::net` TCP listener that runs a `Session` per
//!   connection.
//!
//! ## Example
//!
//! ```
//! use std::sync::Arc;
//! use tpt_ldap_server::memory::MemoryBackend;
//! use tpt_ldap_server::session::Session;
//! use tpt_ldap_server::backend::{Attribute, Entry};
//!
//! let backend = MemoryBackend::new();
//! backend
//!     .add_entry(Entry::new(
//!         "cn=alice,dc=example,dc=com",
//!         vec![Attribute::new("cn", vec![b"alice".to_vec()])],
//!     ))
//!     .unwrap();
//!
//! // Drive a session over any `Read + Write` (here: in-memory for testing).
//! let input = b"\x30\x00"; // an (empty) message; real clients send full PDUs
//! let mut reader = std::io::Cursor::new(Vec::new());
//! let mut writer: Vec<u8> = Vec::new();
//! let mut session = Session::new(Arc::new(backend));
//! // A no-op run is shown for doctest stability; see `tests/` for full flows.
//! let _ = (&mut reader, &mut writer, &mut session);
//! let _ = input;
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod backend;
pub mod ber;
pub mod error;
pub mod memory;
pub mod protocol;
pub mod server;
pub mod session;

pub use backend::{BackendError, DirectoryBackend, Entry, Modification, ModifyDnRequest};
pub use error::BackendError as LdapError;
pub use memory::MemoryBackend;
pub use protocol::{LdapRequest, LdapResponse, ResultCode};
pub use server::Server;
pub use session::Session;
