// SPDX-License-Identifier: MIT OR Apache-2.0
//! # tpt-sip
//!
//! A clean-room, dual-licensed implementation of the Session Initiation
//! Protocol — [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) — as
//! found in the TPT Solutions RFC platform. It is written from the
//! specification only (no copying from other SIP stacks) and covers the
//! layers needed to build user agents and proxies:
//!
//! - **Message codec** ([`message`]): parse and serialise SIP requests
//!   and responses, including header folding, compact forms, and
//!   `Content-Length`-bounded bodies.
//! - **URIs** ([`uri`]): `sip:` / `sips:` URI parsing and rendering
//!   (§19.1) with userinfo, parameters, and header components.
//! - **Headers** ([`headers`]): typed `Via`, `From`/`To`, `Contact`, and
//!   `CSeq` plus generic parameter parsing.
//! - **Transaction layer** ([`transaction`]): the four state machines of
//!   §17 — client/server × INVITE/non-INVITE — with retransmission and
//!   all the standard timers (A, B, D/E/F, G/H/I, J/K/M), transport
//!   agnostic and timer-driven.
//! - **Dialogs** ([`dialog`]): dialog creation and tracking from
//!   §12 (early/confirmed, route set, remote target).
//! - **Methods** ([`methods`]): ergonomic builders for REGISTER, INVITE,
//!   ACK, BYE, CANCEL, and OPTIONS.
//! - **SDP** ([`sdp`]): a minimal offer/answer body parser/serialiser
//!   (RFC 8866) for `application/sdp` integration points.
//! - **Transport** ([`transport`]): a `Transport` trait plus a
//!   dependency-free UDP driver.
//!
//! ## Example: building and parsing an INVITE
//!
//! ```rust
//! use tpt_sip::methods::{invite, named};
//! use tpt_sip::uri::Uri;
//! use tpt_sip::message::Message;
//!
//! let from = named(Uri::parse("sip:alice@example.com").unwrap());
//! let contact = named(Uri::parse("sip:alice@192.0.2.10:5060").unwrap());
//! let req_uri = Uri::parse("sip:bob@example.com").unwrap();
//! let invite = invite(req_uri, from, contact).build();
//!
//! let bytes = invite.to_bytes();
//! let parsed = Message::parse(&bytes).unwrap();
//! assert_eq!(parsed.method().unwrap().to_string(), "INVITE");
//! ```
//!
//! ## Driving a transaction
//!
//! ```rust
//! use tpt_sip::transaction::{Transaction, TransportReliability, TxEvent};
//! use tpt_sip::methods::{invite, named};
//! use tpt_sip::uri::Uri;
//!
//! let from = named(Uri::parse("sip:alice@example.com").unwrap());
//! let contact = named(Uri::parse("sip:alice@192.0.2.10:5060").unwrap());
//! let uri = Uri::parse("sip:bob@example.com").unwrap();
//! let (mut tx, actions) = Transaction::client_invite(
//!     &invite(uri, from, contact).build(),
//!     false,
//! ).unwrap();
//! // `actions` contains the initial Transmit + timer starts; feed
//! // responses back via `tx.on_event(TxEvent::Response(..))`.
//! assert!(!actions.is_empty());
//! ```
#![warn(missing_docs)]

pub mod dialog;
pub mod error;
pub mod headers;
pub mod message;
pub mod method;
pub mod methods;
pub mod sdp;
pub mod transaction;
pub mod transport;
pub mod uri;

pub use dialog::{Dialog, DialogState};
pub use error::{Result, SipError};
pub use headers::{CSeq, NameAddr, ViaEntry};
pub use message::{Header, Message, RequestLine, StartLine, StatusLine};
pub use method::Method;
pub use uri::{Param, Scheme, Uri};
