// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pluggable message context for Sieve evaluation.
//!
//! The evaluation engine never inspects a message directly. Instead it asks the
//! caller-supplied [`MessageContext`] for header values, envelope values, and
//! the message size. This keeps `tpt-sieve` decoupled from any particular mail
//! store, so it composes with `tpt-smtp`, `tpt-imap-server`, or a custom
//! backend.

use std::collections::HashMap;

/// A view of a mail message that a Sieve script is evaluated against.
///
/// Implementors expose the header fields, envelope information, and the total
/// size of the message. Header names and envelope parts are matched
/// case-insensitively by the engine.
pub trait MessageContext {
    /// Return every value of the named header field.
    ///
    /// Header names are matched case-insensitively. A header that appears
    /// multiple times (for example `Received`) yields multiple entries, in
    /// order.
    fn header_values(&self, name: &str) -> Vec<String>;

    /// Return the envelope values for the named envelope part.
    ///
    /// Recognized parts include `"from"`, `"to"`, `"auth"`, and `"org"`,
    /// though any part name may be supplied. Matching is case-insensitive.
    fn envelope_values(&self, part: &str) -> Vec<String>;

    /// Total size of the message in octets.
    fn size(&self) -> usize;
}

/// A simple in-memory [`MessageContext`] backed by `HashMap`s, useful for
/// examples and tests.
///
/// Header and envelope keys are stored lower-cased, so lookups are
/// case-insensitive.
#[derive(Debug, Clone, Default)]
pub struct InMemoryMessage {
    headers: HashMap<String, Vec<String>>,
    envelope: HashMap<String, Vec<String>>,
    size: usize,
}

impl InMemoryMessage {
    /// Create a message of the given size in octets with no headers or
    /// envelope values.
    pub fn new(size: usize) -> Self {
        InMemoryMessage {
            headers: HashMap::new(),
            envelope: HashMap::new(),
            size,
        }
    }

    /// Set the message size (builder-style).
    pub fn with_size(mut self, size: usize) -> Self {
        self.size = size;
        self
    }

    /// Add a header field (builder-style). Repeated calls with the same name
    /// append additional values, mirroring repeated header lines.
    pub fn add_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .entry(name.into().to_ascii_lowercase())
            .or_default()
            .push(value.into());
        self
    }

    /// Add an envelope value (builder-style).
    pub fn add_envelope(mut self, part: impl Into<String>, value: impl Into<String>) -> Self {
        self.envelope
            .entry(part.into().to_ascii_lowercase())
            .or_default()
            .push(value.into());
        self
    }
}

impl MessageContext for InMemoryMessage {
    fn header_values(&self, name: &str) -> Vec<String> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default()
    }

    fn envelope_values(&self, part: &str) -> Vec<String> {
        self.envelope
            .get(&part.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default()
    }

    fn size(&self) -> usize {
        self.size
    }
}
