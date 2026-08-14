// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Abstract syntax tree for a parsed Sieve script (RFC 5228).
//!
//! The [`Script`] is the root of the tree. It contains the top-level
//! [`Command`] list and the set of capabilities declared via `require`.

use std::collections::HashSet;

/// A complete parsed Sieve script.
#[derive(Debug, Clone, Default)]
pub struct Script {
    /// Top-level commands in execution order.
    pub commands: Vec<Command>,
    /// Capabilities declared with `require` (case preserved as written).
    pub capabilities: HashSet<String>,
}

/// A top-level or block-level command.
#[derive(Debug, Clone)]
pub enum Command {
    /// A `require` capability declaration (must precede other commands).
    Require(Vec<String>),
    /// An `if` / `elsif` / `else` control structure.
    If(IfCommand),
    /// A leaf action command (`keep`, `discard`, `redirect`, `fileinto`, `stop`).
    Action(Action),
}

/// An `if` control structure with optional `elsif` branches and an `else`
/// block.
#[derive(Debug, Clone)]
pub struct IfCommand {
    /// The `if` condition.
    pub test: Test,
    /// Commands executed when the `if` test matches.
    pub block: Vec<Command>,
    /// Ordered `elsif` branches: `(test, block)`.
    pub elsif: Vec<(Test, Vec<Command>)>,
    /// Optional `else` block.
    pub else_block: Option<Vec<Command>>,
}

/// An action command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// `keep` — explicit keep in the user's main mailbox.
    Keep,
    /// `discard` — silently discard the message (cancels the implicit keep).
    Discard,
    /// `stop` — stop executing the script immediately.
    Stop,
    /// `redirect <address>` — forward the message to an address.
    Redirect(String),
    /// `fileinto <folder>` — deliver into a named folder.
    FileInto(String),
}

/// A Sieve test (used as a condition).
#[derive(Debug, Clone)]
pub enum Test {
    /// `allof` — true when every sub-test is true.
    AllOf(Vec<Test>),
    /// `anyof` — true when at least one sub-test is true.
    AnyOf(Vec<Test>),
    /// `not` — logical negation of a single sub-test.
    Not(Box<Test>),
    /// `exists` — true when every named header is present.
    Exists(Vec<String>),
    /// `true` — always true.
    True,
    /// `false` — always false.
    False,
    /// `size :over/:under <amount>` — compare the message size.
    Size {
        /// `true` for `:over`, `false` for `:under`.
        over: bool,
        /// Threshold in octets (quantifiers already applied).
        amount: u64,
    },
    /// `header` test.
    Header(HeaderTest),
    /// `address` test.
    Address(AddressTest),
    /// `envelope` test.
    Envelope(EnvelopeTest),
}

/// Comparator used when comparing strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparator {
    /// `i;ascii-casemap` (default) — case-insensitive ASCII comparison.
    AsciiCasemap,
    /// `i;octet` — exact byte-for-byte comparison.
    Octet,
}

/// Match type for string comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchType {
    /// `:is` — exact equality.
    Is,
    /// `:contains` — substring.
    Contains,
    /// `:matches` — wildcard (`*`/`?`) match.
    Matches,
}

/// Which part of an address is compared by an `address` test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressPart {
    /// `:all` (default) — the full `localpart@domain`.
    All,
    /// `:localpart` — only the local part.
    LocalPart,
    /// `:domainpart` — only the domain.
    DomainPart,
}

/// A `header` test with optional comparator/match-type and two string lists.
#[derive(Debug, Clone)]
pub struct HeaderTest {
    /// Comparator in effect.
    pub comparator: Comparator,
    /// Match type in effect.
    pub match_type: MatchType,
    /// Header field names to inspect.
    pub names: Vec<String>,
    /// Keys to compare against.
    pub keys: Vec<String>,
}

/// An `address` test.
#[derive(Debug, Clone)]
pub struct AddressTest {
    /// Address part being compared.
    pub address_part: AddressPart,
    /// Comparator in effect.
    pub comparator: Comparator,
    /// Match type in effect.
    pub match_type: MatchType,
    /// Header field names whose addresses are inspected.
    pub headers: Vec<String>,
    /// Keys to compare against.
    pub keys: Vec<String>,
}

/// An `envelope` test.
#[derive(Debug, Clone)]
pub struct EnvelopeTest {
    /// Comparator in effect.
    pub comparator: Comparator,
    /// Match type in effect.
    pub match_type: MatchType,
    /// Envelope part names to inspect (e.g. `from`, `to`).
    pub parts: Vec<String>,
    /// Keys to compare against.
    pub keys: Vec<String>,
}
