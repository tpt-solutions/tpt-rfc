// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Error types for the `tpt-doh` crate.

use thiserror::Error;

/// Errors originating from the DNS wire codec.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DnsError {
    #[error("DNS message is truncated")]
    Truncated,
    #[error("malformed domain name label")]
    BadLabel,
    #[error("domain name exceeds maximum length")]
    NameTooLong,
}

/// Errors returned by the DoH client.
#[derive(Debug, Error)]
pub enum Error {
    #[error("DNS codec error: {0}")]
    Dns(#[from] DnsError),

    #[error("HTTP client error: {0}")]
    Http(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("DoH server returned HTTP status {status}")]
    HttpStatus { status: u16 },

    #[error("malformed DoH response: {0}")]
    InvalidResponse(String),

    #[error("base64 decoding error: {0}")]
    Base64(String),

    #[error("cache error: {0}")]
    Cache(String),
}

impl From<Box<dyn std::error::Error + Send + Sync>> for Error {
    fn from(e: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Error::Http(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
