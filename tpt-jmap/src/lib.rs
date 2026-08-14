// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # tpt-jmap
//!
//! A clean-room, dual-licensed implementation of the **server side** of
//! [JMAP](https://jmap.io) — the JSON Meta Application Protocol — covering
//! [RFC 8620](https://www.rfc-editor.org/rfc/rfc8620) (core) and
//! [RFC 8621](https://www.rfc-editor.org/rfc/rfc8621) (Mail).
//!
//! The crate intentionally leaves the HTTP transport to the caller. The
//! [`Dispatcher`] owns a [`MailStore`] backend and turns a parsed `Request`
//! JSON value into a `Response`, so it can be wired behind any HTTP server.
//!
//! ```
//! use tpt_jmap::{Session, Dispatcher, MemoryMailStore};
//!
//! let store = MemoryMailStore::new();
//! let session = Session::default_for("account1");
//! let dispatcher = Dispatcher::with_session(store, session);
//!
//! let request = serde_json::json!({
//!     "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
//!     "methodCalls": [
//!         ["Mailbox/get", { "accountId": "account1" }, "a1"]
//!     ]
//! });
//! let response = dispatcher.dispatch(request).unwrap();
//! assert_eq!(response.method_responses[0].name, "Mailbox/get");
//! ```
//!
//! All cryptographic and ASN.1 concerns are out of scope for this protocol
//! layer; the crate only depends on `serde`/`serde_json` (dual-licensed) for
//! JSON handling.

pub mod dispatcher;
pub mod error;
pub mod mail;
pub mod reference;
pub mod session;
pub mod types;

pub use dispatcher::Dispatcher;
pub use error::{MethodError, RequestError};
pub use mail::store::{MailStore, MemoryMailStore};
pub use mail::{Email, EmailAddress, EmailHeader, EmailSubmission, Mailbox, MailboxRights, Thread};
pub use session::{Account, Capability, CoreCapability, MailCapability, Session};
pub use types::{Id, Invocation, Request, Response};

/// JMAP capability URNs (re-exported for convenience).
pub mod capability {
    pub use crate::types::capability::*;
}
