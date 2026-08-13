// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # tpt-ssh
//!
//! A clean-room, dual-licensed implementation of the SSH protocol suite
//! (RFC 4251-4254). It implements the **transport layer** (on-the-wire data
//! types, version exchange, binary packet framing, the `curve25519-sha256`
//! key exchange of RFC 8732, and the `chacha20-poly1305@openssh.com`
//! authenticated-encryption cipher), the **user authentication protocol**
//! (RFC 4252: `none`/`password`/`publickey`), and the **connection protocol**
//! (RFC 4254: session channels and the `exec` request with window flow
//! control and `exit-status`).
//!
//! All cryptographic primitives are reused from dual-licensed crates rather
//! than reimplemented.

pub mod auth;
pub mod cipher;
pub mod connection;
pub mod host_key;
pub mod kex;
pub mod session;
pub mod transport;
pub mod version;
pub mod wire;

/// Errors produced across the SSH transport modules.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Wire encoding/decoding failure (RFC 4251 §5).
    #[error("wire error: {0}")]
    Wire(#[from] wire::WireError),
    /// Transport framing failure (RFC 4253 §6).
    #[error("transport error: {0}")]
    Transport(#[from] transport::TransportError),
    /// Protocol version exchange failure (RFC 4253 §4.2).
    #[error("version error: {0}")]
    Version(#[from] version::VersionError),
    /// Key-exchange failure.
    #[error("kex error: {0}")]
    Kex(String),
    /// Cipher failure.
    #[error("cipher error: {0}")]
    Cipher(String),
    /// Host-key (Ed25519) failure.
    #[error("host key error: {0}")]
    HostKey(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Timing-safe equality of two byte slices.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
