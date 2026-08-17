// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # tpt-pop3
//!
//! A clean-room, dual-licensed implementation of **POP3** — the Post Office
//! Protocol, Version 3 of [RFC 1939](https://www.rfc-editor.org/rfc/rfc1939).
//!
//! This crate provides a POP3 **server** behind a pluggable mailbox backend so
//! that callers can bring their own storage, *and* a clean-room POP3
//! **client** ([`client`]) for talking to any RFC 1939 server. The only
//! production-grade Rust POP3 server ([Stalwart](https://github.com/stalwartlabs))
//! is AGPL-3.0, which is why this crate exists within the dual MIT/Apache-2.0
//! TPT Solutions platform.
//!
//! ## Architecture
//!
//! - [`backend::MailboxBackend`] — trait for credential checking and message
//!   storage. Implement it to plug in your own mailbox.
//! - [`memory::MemoryBackend`] — reference in-memory backend for tests/examples.
//! - [`session::Session`] — the RFC 1939 state machine, transport-agnostic.
//! - [`server::Server`] — a `std::net` TCP listener that runs a `Session` per
//!   connection.
//! - [`client`] — a clean-room POP3 **client** (RFC 1939) over any
//!   `BufRead + Write`, with a [`client::TcpClient`] convenience wrapper.
//!
//! ## Example
//!
//! ```
//! use std::sync::Arc;
//! use tpt_pop3::memory::MemoryBackend;
//! use tpt_pop3::session::Session;
//!
//! let backend = MemoryBackend::new();
//! backend.add_user("alice", "secret", vec![
//!     b"From: bob@example.com\r\nSubject: hi\r\n\r\nHello!\r\n".to_vec(),
//! ]);
//!
//! // Drive a session over any `BufRead + Write` (here: in-memory for testing).
//! let input = b"USER alice\r\nPASS secret\r\nSTAT\r\nQUIT\r\n";
//! let mut reader = std::io::Cursor::new(input.to_vec());
//! let mut writer: Vec<u8> = Vec::new();
//! let mut session = Session::new(Arc::new(backend));
//! session.run(&mut reader, &mut writer).unwrap();
//! let out = String::from_utf8(writer).unwrap();
//! assert!(out.starts_with("+OK POP3 server ready"));
//! assert!(out.contains("\r\n+OK 1 46\r\n"));
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod backend;
pub mod client;
pub mod error;
pub mod memory;
pub mod server;
pub mod session;

pub use backend::{BackendError, MailboxBackend, MailboxMessage};
pub use client::{Client, Entry, Error as ClientError, Stat, TcpClient};
pub use memory::MemoryBackend;
pub use server::Server;
pub use session::Session;
