// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stateless DTLS cookie exchange (RFC 9147 §4.2.3 / §5.2).
//!
//! To avoid amplification/DoS, a DTLS server does not allocate state for a
//! client until it has proved reachability. It does this with a
//! HelloRetryRequest carrying a *stateless cookie*: an HMAC over the client's
//! stable parameters (its source address and `ClientHello.random`), keyed by
//! a server secret. The client echoes the cookie; the server recomputes the
//! HMAC and compares — no per-client state required before the second
//! ClientHello.

use crate::crypto::HashAlg;
use crate::error::Result;

/// Generates and verifies stateless DTLS cookies.
#[derive(Debug, Clone)]
pub struct CookieMaker {
    secret: [u8; 32],
}

impl CookieMaker {
    /// Create a cookie maker with a 32-byte server secret.
    pub fn new(secret: [u8; 32]) -> Self {
        Self { secret }
    }

    /// Compute the cookie for `client_address` and `client_random`.
    pub fn generate(&self, client_address: &[u8], client_random: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(client_address.len() + client_random.len());
        data.extend_from_slice(client_address);
        data.extend_from_slice(client_random);
        HashAlg::Sha256.hmac(&self.secret, &data)
    }

    /// Verify that `cookie` matches the expected value for the given client
    /// parameters.
    pub fn verify(&self, client_address: &[u8], client_random: &[u8], cookie: &[u8]) -> bool {
        let expected = self.generate(client_address, client_random);
        crate::replay::ct_eq(&expected, cookie)
    }

    /// Generate a cookie from a parsed [`crate::handshake::ClientHello`].
    pub fn from_hello(
        &self,
        client_address: &[u8],
        hello: &crate::handshake::ClientHello,
    ) -> Vec<u8> {
        self.generate(client_address, &hello.random)
    }
}

/// Convenience: verify a cookie against a parsed ClientHello.
pub fn verify_hello(
    maker: &CookieMaker,
    client_address: &[u8],
    hello: &crate::handshake::ClientHello,
    cookie: &[u8],
) -> Result<bool> {
    Ok(maker.verify(client_address, &hello.random, cookie))
}
