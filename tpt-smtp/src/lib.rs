// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # tpt-smtp
//!
//! A clean-room, dual-licensed implementation of **SMTP** — the Simple Mail
//! Transfer Protocol of [RFC 5321](https://www.rfc-editor.org/rfc/rfc5321) —
//! together with an **Internet Message Format / MIME** ([RFC 5322](https://www.rfc-editor.org/rfc/rfc5322)
//! + MIME RFC 2045/2046/2047) parsing and building library.
//!
//! This crate exists within the dual MIT/Apache-2.0 TPT Solutions platform to
//! close the gap identified in the RFC survey: the only confirmed MIT-chain
//! Rust SMTP crates are thin/fragmented clients (`lettre`, `mail-send`),
//! and there is no cohesive, dual-licensed server. `tpt-smtp` provides **both**
//! a client and a server behind pluggable backends.
//!
//! ## Architecture
//!
//! - [`message`] — RFC 5322 message parsing, address parsing, MIME decoding
//!   (multipart, base64, quoted-printable), RFC 2047 encoded-word handling, and
//!   a [`message::MessageBuilder`] for generating messages.
//! - [`backend::MailDelivery`] — trait for message delivery; implement it to
//!   plug in your own store/relay. [`memory::MemoryBackend`] is a reference
//!   in-memory implementation.
//! - [`session::Session`] — the RFC 5321 server state machine,
//!   transport-agnostic (driven over any `BufRead + Write`).
//! - [`server::Server`] — a `std::net` TCP listener running a `Session` per
//!   connection.
//! - [`client::Client`] — an RFC 5321 submission client, also
//!   transport-agnostic.
//! - [`reply`] / [`codec`] — low-level reply and command-line parsing.
//!
//! ## Example: server with an in-memory backend
//!
//! ```
//! use std::sync::Arc;
//! use tpt_smtp::memory::MemoryBackend;
//! use tpt_smtp::session::{Session, Extensions};
//! use std::io::Cursor;
//!
//! let backend = Arc::new(MemoryBackend::new());
//! let backend: Arc<dyn tpt_smtp::backend::MailDelivery> = backend;
//! let mut session = Session::new(backend);
//! session.set_extensions(Extensions { size: true, ..Default::default() });
//!
//! let input = "EHLO client\r\nMAIL FROM:<alice@example.com>\r\nQUIT\r\n";
//! let mut reader = Cursor::new(input.as_bytes().to_vec());
//! let mut writer: Vec<u8> = Vec::new();
//! session.run(&mut reader, &mut writer).unwrap();
//! let out = String::from_utf8(writer).unwrap();
//! assert!(out.starts_with("220 "));
//! assert!(out.contains("\r\n250 "));
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod backend;
pub mod client;
pub mod codec;
pub mod error;
pub mod memory;
pub mod message;
pub mod reply;
pub mod server;
pub mod session;

pub use backend::{DeliveryError, Envelope, MailDelivery};
pub use client::Client;
pub use error::SmtpError;
pub use memory::MemoryBackend;
pub use message::{Address, Header, Message, MessageBuilder};
pub use reply::Reply;
pub use server::Server;
pub use session::{Extensions, Session};
