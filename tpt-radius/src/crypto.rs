// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Small MD5 / HMAC-MD5 helpers used by the RADIUS shared-secret cryptography.
//!
//! RADIUS (RFC 2865/2866) and its extensions build their authentication on top
//! of MD5, so we lean on the dual-licensed RustCrypto `md-5` and `hmac` crates
//! rather than reimplementing the primitives.

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};

type HmacMd5 = Hmac<Md5>;

/// Compute `MD5(data)` and return the 16-octet digest.
pub(crate) fn md5(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(data);
    finalize_16(hasher.finalize())
}

/// Compute `MD5(a || b)` and return the 16-octet digest.
pub(crate) fn md5_concat(a: &[u8], b: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(a);
    hasher.update(b);
    finalize_16(hasher.finalize())
}

/// Compute `HMAC-MD5(key, data)` and return the 16-octet tag.
pub(crate) fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = HmacMd5::new_from_slice(key).expect("HMAC-MD5 accepts keys of any length");
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag);
    out
}

/// Convert a 16-byte digest into a fixed-size array.
fn finalize_16(out: impl AsRef<[u8]>) -> [u8; 16] {
    let bytes = out.as_ref();
    let mut arr = [0u8; 16];
    arr.copy_from_slice(bytes);
    arr
}
