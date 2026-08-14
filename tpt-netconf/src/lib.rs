// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # tpt-netconf
//!
//! A clean-room, dual-licensed implementation of a **NETCONF** server (RFC 6241)
//! transported over the SSH `netconf` subsystem (RFC 6242), with YANG carried as
//! opaque XML per the phase's scoped baseline.
//!
//! NETCONF (the Network Configuration Protocol) exchanges well-formed XML
//! documents — `<hello>`, `<rpc>`, and `<rpc-reply>` — over a reliable,
//! authenticated transport. This crate focuses on the **server** side (the
//! genuine gap the survey identified) and reuses [`tpt-ssh`] for the SSH
//! transport rather than reimplementing it.
//!
//! ## What this crate provides
//!
//! - [`framing`] — NETCONF message framing (RFC 6242): the base `]]>]]>`
//!   end-of-message marker and chunked `#<len>` framing, with an incremental
//!   decoder that transparently handles either form.
//! - [`xml`] — a small, dependency-free XML DOM used to parse and serialize the
//!   NETCONF messages.
//! - [`message`] — the NETCONF message model: capability exchange, `<rpc>` and
//!   its standard operations, and `<rpc-reply>`/`<rpc-error>`.
//! - [`server`] — the pluggable [`server::Datastore`] backend trait, a reference
//!   [`server::InMemoryDatastore`], RPC dispatch, and
//!   [`server::serve_ssh_session`] which serves a session over an SSH
//!   `netconf` subsystem.
//! - [`client`] — a minimal [`client::NetconfSshClient`] for testing and
//!   examples.
//!
//! ## Example: serve a session in-process over an SSH byte pipe
//!
//! ```no_run
//! use tpt_netconf::server::{InMemoryDatastore, serve_ssh_session};
//! use tpt_netconf::client::NetconfSshClient;
//! use tpt_ssh::session::EncryptedConn;
//!
//! // In a real deployment `client`/`server` are separate processes; here they
//! // are driven over an in-process encrypted connection for brevity.
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let (mut client, mut server) = tpt_ssh::session::handshake();
//! # std::thread::scope(|s| {
//! #   s.spawn(|| {
//! #     let mut store = InMemoryDatastore::new();
//! #     let mut pump = |_c: &mut EncryptedConn| {};
//! #     let _ = serve_ssh_session(&mut server, &mut pump, &mut store, 1);
//! #   });
//! # });
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod client;
pub mod error;
pub mod framing;
pub mod message;
pub mod server;
pub mod xml;

pub use error::{NetconfError, Result};
pub use message::{
    DatastoreName, EditDefaultOp, Hello, Operation, Rpc, RpcError, RpcReply, ReplyResult,
};
pub use server::{
    dispatch, serve_ssh_session, Datastore, InMemoryDatastore,
};
pub use xml::{parse_root, to_string, Xml};

/// The NETCONF base namespace (RFC 6241 §3.1).
pub use message::NETCONF_BASE_NS_1_0;
