// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # tpt-sieve
//!
//! A clean-room, dual-licensed ([`MIT OR Apache-2.0`](../LICENSE-MIT)) implementation
//! of the **Sieve** mail filtering language defined in
//! [RFC 5228](https://www.rfc-editor.org/rfc/rfc5228).
//!
//! Sieve is a domain-specific language for filtering email messages at delivery
//! time. This crate provides two independent pieces that compose cleanly:
//!
//! 1. A **parser** ([`parse`]) that turns Sieve source text into an AST
//!    ([`Script`]) following the RFC 5228 grammar (commands, tests, actions,
//!    and the `if`/`elsif`/`else` control structures).
//! 2. An **evaluation engine** ([`evaluate`]) that runs a parsed
//!    [`Script`] against a [`MessageContext`] supplied by the caller.
//!
//! The engine never reads a message directly; it only asks the caller's
//! [`MessageContext`] for header values, envelope values, and message size.
//! That keeps the crate composable with mail stores such as `tpt-smtp` or
//! `tpt-imap-server`: hand the engine a message wrapper that implements
//! [`MessageContext`] and collect the resulting [`ActionSet`].
//!
//! ## Supported features (RFC 5228 base)
//!
//! - Tests: `allof`, `anyof`, `not`, `exists`, `true`, `false`, `size`,
//!   `header`, `address`, `envelope`.
//! - Actions: `keep`, `discard`, `redirect`, `fileinto`, `stop`.
//! - Control: `if` / `elsif` / `else`, `require`.
//! - Match types: `:is`, `:contains`, `:matches` (with `*`/`?` wildcards).
//! - Comparators: `i;ascii-casemap` (default) and `i;octet`.
//! - Address parts: `:all` (default), `:localpart`, `:domainpart`.
//! - Size quantifiers: `K`, `M`, `G` (e.g. `:over 100K`).
//! - Capability enforcement for `require "fileinto"` and `require "envelope"`.
//!
//! ## Example
//!
//! ```rust
//! use tpt_sieve::{parse, evaluate, InMemoryMessage};
//!
//! let script = r#"
//!     require ["fileinto"];
//!     if header :contains "Subject" "make money" {
//!         discard;
//!     } elsif address :is :domain "From" "example.com" {
//!         fileinto "INBOX.example";
//!     } else {
//!         keep;
//!     }
//! "#;
//!
//! let msg = InMemoryMessage::new(1024)
//!     .add_header("Subject", "you can make money fast")
//!     .add_header("From", "Someone <someone@example.com>");
//!
//! let actions = evaluate(&parse(script).unwrap(), &msg).unwrap();
//! let final_actions = actions.finalize();
//! assert!(matches!(final_actions, tpt_sieve::FinalActions::Discard));
//! ```
#![warn(missing_docs)]

pub mod actions;
pub mod ast;
pub mod context;
pub mod error;
pub mod evaluator;
pub mod lexer;
pub mod parser;

pub use actions::{ActionSet, DeliverActions, FinalActions};
pub use ast::{
    Action, AddressPart, AddressTest, Command, Comparator, EnvelopeTest, HeaderTest, IfCommand,
    MatchType, Script, Test,
};
pub use context::{InMemoryMessage, MessageContext};
pub use error::{SieveError, SieveResult};
pub use evaluator::evaluate;
pub use parser::parse;

/// Parse Sieve source text and run it against the given message context,
/// returning the [`ActionSet`] accumulated during evaluation.
///
/// This is a convenience wrapper around [`parse`] followed by [`evaluate`].
///
/// # Errors
///
/// Returns a [`SieveError`] if the script fails to lex, parse, or evaluate
/// (for example, when an extension is used without a matching `require`).
pub fn run<C: MessageContext>(input: &str, ctx: &C) -> SieveResult<ActionSet> {
    let script = parse(input)?;
    evaluate(&script, ctx)
}
