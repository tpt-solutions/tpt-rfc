// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # tpt-hotp
//!
//! A clean-room, dual-licensed implementation of **HOTP** — the HMAC-Based
//! One-Time Password algorithm of [RFC 4226](https://www.rfc-editor.org/rfc/rfc4226).
//!
//! The public API deliberately mirrors [`totp-rs`](https://crates.io/crates/totp-rs)
//! so existing users can migrate with minimal friction, while the underlying
//! HMAC-SHA-1 primitive is supplied by the dual-licensed RustCrypto `hmac`/`sha1`
//! crates.
//!
//! ```
//! use tpt_hotp::Hotp;
//!
//! // RFC 4226 Appendix D test secret.
//! let hotp = Hotp::new(b"12345678901234567890", 6).unwrap();
//! assert_eq!(hotp.generate(0), "755224");
//! assert_eq!(hotp.generate(1), "287082");
//! ```

use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// Maximum number of digits an HOTP value may have (kept within `u64`).
pub const MAX_DIGITS: u32 = 10;
/// Minimum number of digits recommended by RFC 4226 §5.3 (we allow fewer).
pub const MIN_DIGITS: u32 = 1;

/// Errors produced while configuring or running HOTP.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The requested digit count is outside `[MIN_DIGITS, MAX_DIGITS]`.
    #[error("digit count must be between {MIN_DIGITS} and {MAX_DIGITS}")]
    InvalidDigits,
    /// The shared secret is empty.
    #[error("shared secret must not be empty")]
    EmptySecret,
    /// A supplied code was not a valid decimal string.
    #[error("code is not a valid decimal string")]
    InvalidCode,
}

pub type Result<T> = std::result::Result<T, Error>;

/// An HOTP generator/validator bound to a shared secret and digit count.
#[derive(Debug, Clone)]
pub struct Hotp {
    secret: Vec<u8>,
    digits: u32,
}

impl Hotp {
    /// Create a generator from a shared secret and the number of output digits.
    ///
    /// `digits` must be in `[1, 10]`. RFC 4226 §5.3 requires at least 6 in
    /// practice; this implementation permits fewer for interoperability with
    /// constrained systems.
    pub fn new(secret: impl Into<Vec<u8>>, digits: u32) -> Result<Self> {
        if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
            return Err(Error::InvalidDigits);
        }
        let secret = secret.into();
        if secret.is_empty() {
            return Err(Error::EmptySecret);
        }
        Ok(Hotp { secret, digits })
    }

    /// Create a generator with the RFC-recommended 6 digits.
    pub fn with_secret(secret: impl Into<Vec<u8>>) -> Result<Self> {
        Hotp::new(secret, 6)
    }

    /// The configured digit count.
    pub fn digits(&self) -> u32 {
        self.digits
    }

    /// The shared secret.
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    /// Generate the HOTP value for `counter`.
    pub fn generate(&self, counter: u64) -> String {
        hotp(&self.secret, counter, self.digits).expect("validated in constructor")
    }

    /// Verify a code against `counter` and the next `window` counters
    /// (inclusive), returning whether any matched and, if so, the counter value
    /// that produced the match.
    ///
    /// This implements the look-ahead resynchronization described in
    /// RFC 4226 §7.4. The caller should advance its stored counter to the
    /// returned value + 1 on success.
    pub fn verify_with_counter(&self, code: &str, counter: u64, window: u64) -> Option<u64> {
        let end = counter.saturating_add(window);
        for c in counter..=end {
            let candidate = self.generate(c);
            if constant_time_eq(code.as_bytes(), candidate.as_bytes()) {
                return Some(c);
            }
        }
        None
    }

    /// Verify a code, returning only a boolean (see [`Hotp::verify_with_counter`]).
    pub fn verify(&self, code: &str, counter: u64, window: u64) -> bool {
        self.verify_with_counter(code, counter, window).is_some()
    }
}

/// Compute the HOTP value for `(secret, counter, digits)` per RFC 4226 §5.3.
pub fn hotp(secret: &[u8], counter: u64, digits: u32) -> Result<String> {
    if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
        return Err(Error::InvalidDigits);
    }
    if secret.is_empty() {
        return Err(Error::EmptySecret);
    }

    let mut mac = HmacSha1::new_from_slice(secret)
        .expect("HMAC accepts keys of any size; secret is non-empty");
    mac.update(&counter.to_be_bytes());
    let hs = mac.finalize().into_bytes();

    // Dynamic truncation (RFC 4226 §5.3): take the low 4 bits of the last
    // byte as an offset into the 20-byte digest, then read 4 bytes there,
    // masking the sign bit to get a 31-bit big-endian integer.
    let offset = (hs[19] & 0x0f) as usize;
    let bin_code = ((hs[offset] & 0x7f) as u32) << 24
        | (hs[offset + 1] as u32) << 16
        | (hs[offset + 2] as u32) << 8
        | (hs[offset + 3] as u32);

    let modulo = 10u64.pow(digits);
    let value = (bin_code as u64) % modulo;
    Ok(format!("{value:0width$}", width = digits as usize))
}

/// Constant-time equality of two byte slices (timing-safe string compare).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4226 Appendix D test secret.
    const SECRET: &[u8] = b"12345678901234567890";

    // Expected values computed from the RFC algorithm (Appendix D).
    const EXPECTED_6: [&str; 10] = [
        "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
        "520489",
    ];
    const EXPECTED_8: [&str; 10] = [
        "84755224", "94287082", "37359152", "26969429", "40338314", "68254676", "18287922",
        "82162583", "73399871", "45520489",
    ];

    #[test]
    fn appendix_d_six_digits() {
        let hotp = Hotp::new(SECRET, 6).unwrap();
        for (c, expected) in EXPECTED_6.iter().enumerate() {
            assert_eq!(hotp.generate(c as u64), *expected, "counter {c}");
        }
    }

    #[test]
    fn appendix_d_eight_digits() {
        let hotp = Hotp::new(SECRET, 8).unwrap();
        for (c, expected) in EXPECTED_8.iter().enumerate() {
            assert_eq!(hotp.generate(c as u64), *expected, "counter {c}");
        }
    }

    #[test]
    fn standalone_hotp_matches() {
        for (c, expected) in EXPECTED_6.iter().enumerate() {
            assert_eq!(hotp(SECRET, c as u64, 6).unwrap(), *expected);
        }
    }

    #[test]
    fn accepts_variable_digit_counts() {
        assert!(Hotp::new(SECRET, 1).is_ok());
        assert!(Hotp::new(SECRET, 10).is_ok());
        assert!(Hotp::new(SECRET, 0).is_err());
        assert!(Hotp::new(SECRET, 11).is_err());
        assert!(Hotp::new(b"", 6).is_err());
    }

    #[test]
    fn verify_and_resync_window() {
        let hotp = Hotp::new(SECRET, 6).unwrap();
        let code = hotp.generate(5);
        // Exact counter, window 0.
        assert!(hotp.verify(&code, 5, 0));
        // Counter ahead within the look-ahead window.
        assert!(hotp.verify(&code, 3, 2));
        let matched = hotp.verify_with_counter(&code, 3, 2).unwrap();
        assert_eq!(matched, 5);
        // Outside the window -> rejected.
        assert!(!hotp.verify(&code, 0, 2));
        // Wrong code -> rejected.
        assert!(!hotp.verify("000000", 5, 0));
    }

    #[test]
    fn constant_time_eq_basics() {
        assert!(constant_time_eq(b"123456", b"123456"));
        assert!(!constant_time_eq(b"123456", b"123457"));
        assert!(!constant_time_eq(b"123456", b"12345"));
    }
}
