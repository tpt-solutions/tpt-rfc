// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Error types for `tpt-sieve`.

/// A specialized [`Result`] type for Sieve operations.
pub type SieveResult<T> = Result<T, SieveError>;

/// Errors produced while lexing, parsing, or evaluating a Sieve script.
#[derive(Debug, thiserror::Error)]
pub enum SieveError {
    /// A lexer error. The first field is the character offset into the source
    /// where the error was detected.
    #[error("lex error at offset {0}: {1}")]
    Lex(usize, String),

    /// A parser error. The first field is the token index where the error was
    /// detected.
    #[error("parse error at token {0}: {1}")]
    Parse(usize, String),

    /// An action or test was used that requires a capability (declared via
    /// `require`) that the script did not declare.
    #[error("missing required capability `{0}` (add a `require` for it)")]
    MissingCapability(String),

    /// An evaluation-time error that is not attributable to a specific parse
    /// position (for example, an unsupported comparator).
    #[error("evaluation error: {0}")]
    Eval(String),
}
