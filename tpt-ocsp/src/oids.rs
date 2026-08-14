// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Object identifiers used by RFC 6960 (OCSP) and related PKIX structures.
//!
//! All values are taken from the IANA/ITU registries referenced by the RFCs.

use const_oid::ObjectIdentifier;

pub(crate) const SHA1: &str = "1.3.14.3.2.26";
pub(crate) const SHA256: &str = "2.16.840.1.101.3.4.2.1";
pub(crate) const SHA384: &str = "2.16.840.1.101.3.4.2.2";
pub(crate) const SHA512: &str = "2.16.840.1.101.3.4.2.3";

/// `id-pkix-ocsp` (RFC 6960).
pub(crate) const OCSP: &str = "1.3.6.1.5.5.7.48.1";
/// `id-pkix-ocsp-basic` — the only `responseType` defined in RFC 6960.
pub(crate) const OCSP_BASIC: &str = "1.3.6.1.5.5.7.48.1.1";
/// `id-pkix-ocsp-nonce` — the standard OCSP nonce request/response extension.
pub(crate) const OCSP_NONCE: &str = "1.3.6.1.5.5.7.48.1.2";

/// `sha256WithRSAEncryption` (RFC 4055 / RFC 8017).
pub(crate) const SHA256_RSA: &str = "1.2.840.113549.1.1.11";
pub(crate) const SHA384_RSA: &str = "1.2.840.113549.1.1.12";
pub(crate) const SHA512_RSA: &str = "1.2.840.113549.1.1.13";

/// `ecdsaWithSHA256` / `ecdsaWithSHA384` / `ecdsaWithSHA512` (RFC 5758 / RFC 3279).
pub(crate) const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
pub(crate) const ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
pub(crate) const ECDSA_SHA512: &str = "1.2.840.10045.4.3.4";

/// `rsaEncryption` (RFC 8017).
pub(crate) const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
/// `id-ecPublicKey` (RFC 5480).
pub(crate) const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
/// `id-Ed25519` (RFC 8410 / RFC 8419).
pub(crate) const ED25519: &str = "1.3.101.112";
pub(crate) const P256: &str = "1.2.840.10045.3.1.7";
pub(crate) const P384: &str = "1.3.132.0.34";

#[inline]
pub(crate) fn oid(s: &str) -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(s)
}
