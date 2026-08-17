// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The TLS 1.3 (EC)DHE key schedule, reused verbatim by DTLS 1.3.
//!
//! DTLS 1.3 shares TLS 1.3's key derivation (RFC 8446 §7.1) exactly; only the
//! record/transport layer differs. This module implements HKDF-Extract,
//! HKDF-Expand-Label, Derive-Secret, traffic-key/IV derivation, and the
//! Finished verify-data, building on the dual-licensed `hmac`/`sha2`
//! primitives. (HKDF itself is the ~10-line construction from RFC 5869, so it
//! is implemented directly rather than pulling in a heavier dependency.)

use crate::crypto::HashAlg;

const TLS13_PREFIX: &[u8] = b"tls13 ";

/// HKDF-Extract(`salt`, `ikm`) = HMAC-Hash(salt, ikm), with a
/// zero-filled salt when `salt` is `None` (RFC 5869 §2.2).
fn hkdf_extract(alg: HashAlg, salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8> {
    let zero = vec![0u8; alg.output_len()];
    let salt = salt.unwrap_or(&zero);
    alg.hmac(salt, ikm)
}

/// HKDF-Expand(`prk`, `info`, `len`) = the first `len` bytes of the iterated
/// HMAC output (RFC 5869 §2.3).
fn hkdf_expand(alg: HashAlg, prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hlen = alg.output_len();
    let blocks = len.div_ceil(hlen);
    let mut out = Vec::with_capacity(blocks * hlen);
    let mut t = Vec::new();
    for i in 1..=blocks as u8 {
        let mut input = t.clone();
        input.extend_from_slice(info);
        input.push(i);
        t = alg.hmac(prk, &input);
        out.extend_from_slice(&t);
    }
    out.truncate(len);
    out
}

/// The TLS 1.3 key schedule for one connection.
#[derive(Debug, Clone, Copy)]
pub struct KeySchedule {
    /// Hash algorithm in use (SHA-256 or SHA-384).
    pub hash: HashAlg,
}

impl KeySchedule {
    /// Create a key schedule for `hash`.
    pub fn new(hash: HashAlg) -> Self {
        Self { hash }
    }

    /// HKDF-Extract with an explicit salt.
    pub fn extract(&self, salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8> {
        hkdf_extract(self.hash, salt, ikm)
    }

    /// HKDF-Expand-Label (`secret`, `label`, `context`, `length`) as defined
    /// in RFC 8446 §7.1:
    ///
    /// ```text
    /// HkdfLabel.length    = length                     (uint16, big-endian)
    /// HkdfLabel.label     = "tls13 " + label
    /// HkdfLabel.context   = context
    /// info                = HkdfLabel.length
    ///                       || HkdfLabel.label
    ///                       || HkdfLabel.context
    /// return HKDF-Expand(secret, info, length)
    /// ```
    pub fn expand_label(
        &self,
        secret: &[u8],
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Vec<u8> {
        let mut info = Vec::with_capacity(2 + TLS13_PREFIX.len() + label.len() + context.len());
        info.extend_from_slice(&(length as u16).to_be_bytes());
        info.extend_from_slice(TLS13_PREFIX);
        info.extend_from_slice(label.as_bytes());
        info.extend_from_slice(context);
        hkdf_expand(self.hash, secret, &info, length)
    }

    /// Derive-Secret(`secret`, `label`, `transcript_hash`) =
    /// HKDF-Expand-Label(secret, label, transcript_hash, Hash.length)
    /// (RFC 8446 §7.1).
    pub fn derive_secret(&self, secret: &[u8], label: &str, transcript_hash: &[u8]) -> Vec<u8> {
        self.expand_label(secret, label, transcript_hash, self.hash.output_len())
    }

    /// Derive the AEAD write key and IV from a traffic secret (RFC 8446 §7.3).
    pub fn derive_traffic_keys(
        &self,
        traffic_secret: &[u8],
        key_len: usize,
        iv_len: usize,
    ) -> (Vec<u8>, Vec<u8>) {
        let key = self.expand_label(traffic_secret, "key", &[], key_len);
        let iv = self.expand_label(traffic_secret, "iv", &[], iv_len);
        (key, iv)
    }

    /// Derive the `finished_key` used to compute Finished.verify_data
    /// (RFC 8446 §4.4.4).
    pub fn derive_finished_key(&self, base_secret: &[u8]) -> Vec<u8> {
        self.expand_label(base_secret, "finished", &[], self.hash.output_len())
    }

    /// Finished.verify_data = HMAC(finished_key, Transcript-Hash)
    /// (RFC 8446 §4.4.4). Returns `Hash.length` bytes.
    pub fn finished_verify_data(&self, finished_key: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
        self.hash.hmac(finished_key, transcript_hash)
    }
}

/// The per-direction traffic keys derived for one epoch.
#[derive(Debug, Clone)]
pub struct TrafficKeys {
    /// AEAD write key.
    pub key: Vec<u8>,
    /// AEAD write IV (12 bytes).
    pub iv: Vec<u8>,
    /// The traffic secret they were derived from (needed to derive the
    /// Finished key for the same direction).
    pub traffic_secret: Vec<u8>,
}

impl TrafficKeys {
    /// Derive traffic keys for `suite` from `traffic_secret`.
    pub fn from_secret(
        ks: &KeySchedule,
        suite: crate::crypto::CipherSuite,
        traffic_secret: &[u8],
    ) -> Self {
        let (key, iv) = ks.derive_traffic_keys(traffic_secret, suite.key_len(), suite.iv_len());
        Self {
            key,
            iv,
            traffic_secret: traffic_secret.to_vec(),
        }
    }

    /// The `finished_key` for this direction's traffic secret.
    pub fn finished_key(&self, ks: &KeySchedule) -> Vec<u8> {
        ks.derive_finished_key(&self.traffic_secret)
    }
}
