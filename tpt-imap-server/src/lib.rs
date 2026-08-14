// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # tpt-imap-server
//!
//! A clean-room, dual-licensed (MIT OR Apache-2.0) implementation of an
//! **IMAP4rev2** server ([RFC 9051](https://www.rfc-editor.org/rfc/rfc9051)),
//! built to close the licensing gap identified in the TPT Solutions RFC
//! survey: the only production-grade Rust IMAP *server* (Stalwart) is
//! AGPL-3.0, leaving the MIT/Apache crowd with no server option at all.
//!
//! The crate is protocol-only: it owns the IMAP state machine, parsing, and
//! response generation, but delegates actual message storage to a pluggable
//! [`MailboxStore`] trait. A ready-to-use in-memory implementation,
//! [`InMemoryStore`], ships for tests, examples, and as a template.
//!
//! ## Quick start
//!
//! ```no_run
//! use tpt_imap_server::{Server, InMemoryStore};
//!
//! let store = InMemoryStore::new().with_user("alice", "secret");
//! // Bind and serve (blocking):
//! // Server::new(store).serve("127.0.0.1:143").unwrap();
//! let _ = Server::new(store);
//! ```
//!
//! ## Implemented scope
//!
//! - States: Not Authenticated → Authenticated → Selected → Logout.
//! - Core: `CAPABILITY`, `LOGIN`, `AUTHENTICATE` (PLAIN, LOGIN), `LOGOUT`,
//!   `NOOP`, `ID`, `NAMESPACE`.
//! - Mailbox management: `CREATE`, `DELETE`, `RENAME`, `LIST`, `LSUB`,
//!   `SUBSCRIBE`, `UNSUBSCRIBE`, `STATUS`, `APPEND`.
//! - Messages: `SELECT`/`EXAMINE`, `FETCH` (+ `UID FETCH`), `STORE`
//!   (+ `UID STORE`), `COPY` (+ `UID COPY`), `SEARCH` (+ `UID SEARCH`),
//!   `EXPUNGE`, `UID EXPUNGE`, `CLOSE`, `CHECK`, `IDLE`.
//!
//! See `SPEC-NOTES.md` for the section-by-section conformance status.

pub mod command;
pub mod error;
pub mod memory;
pub mod proto;
pub mod server;
pub mod session;
pub mod store;
pub mod types;

pub use error::{ImapError, Result as ImapResult};
pub use memory::InMemoryStore;
pub use server::Server;
pub use session::{Session, CAPABILITIES};
pub use store::MailboxStore;
pub use types::{
    AppendMessage, Flag, FlagOp, ListEntry, MailboxStatus, MessageSnapshot, SystemFlag,
};
