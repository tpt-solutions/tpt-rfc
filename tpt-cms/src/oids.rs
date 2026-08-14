//! Object identifiers used by RFC 5652 (CMS) and its companion algorithm specs.
//!
//! All values are taken from the IANA/ITU/NIST registries referenced by the
//! relevant RFCs (5652, 5280, 3565, 5753, 8418, 4055, 8410, 3279, 4055).

use const_oid::ObjectIdentifier;

/// `id-data` — opaque (uninterpreted) encapsulated content (RFC 5652 §4).
pub(crate) const ID_DATA: &str = "1.2.840.113549.1.7.1";
/// `id-signedData` (RFC 5652 §5).
pub(crate) const ID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
/// `id-envelopedData` (RFC 5652 §6).
pub(crate) const ID_ENVELOPED_DATA: &str = "1.2.840.113549.1.7.3";
/// `id-digestedData` (RFC 5652 §7).
pub(crate) const ID_DIGESTED_DATA: &str = "1.2.840.113549.1.7.5";
/// `id-encryptedData` (RFC 5652 §8).
pub(crate) const ID_ENCRYPTED_DATA: &str = "1.2.840.113549.1.7.6";

/// CMS signed-attribute OIDs (RFC 5652 §11).
pub(crate) const CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
pub(crate) const MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
pub(crate) const SIGNING_TIME: &str = "1.2.840.113549.1.9.5";

/// Digest algorithm OIDs (NIST hashAlgs arc).
pub(crate) const SHA256: &str = "2.16.840.1.101.3.4.2.1";
pub(crate) const SHA384: &str = "2.16.840.1.101.3.4.2.2";
pub(crate) const SHA512: &str = "2.16.840.1.101.3.4.2.3";

/// AES content-encryption (CBC) OIDs (NIST aes arc).
pub(crate) const AES128_CBC: &str = "2.16.840.1.101.3.4.1.2";
pub(crate) const AES192_CBC: &str = "2.16.840.1.101.3.4.1.22";
pub(crate) const AES256_CBC: &str = "2.16.840.1.101.3.4.1.42";

/// AES key-wrap OIDs (NIST aes arc).
pub(crate) const AES128_WRAP: &str = "2.16.840.1.101.3.4.1.5";
pub(crate) const AES192_WRAP: &str = "2.16.840.1.101.3.4.1.25";
pub(crate) const AES256_WRAP: &str = "2.16.840.1.101.3.4.1.45";

/// RSA key-transport OIDs.
pub(crate) const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1"; // PKCS#1 v1.5
pub(crate) const RSAES_OAEP: &str = "1.2.840.113549.1.1.7";

/// RSASSA-PKCS1-v1_5 with SHA-2 (RFC 4055).
pub(crate) const SHA256_RSA: &str = "1.2.840.113549.1.1.11";
pub(crate) const SHA384_RSA: &str = "1.2.840.113549.1.1.12";
pub(crate) const SHA512_RSA: &str = "1.2.840.113549.1.1.13";

/// ECDSA with SHA-2 (RFC 3279 / 5758).
pub(crate) const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
pub(crate) const ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
pub(crate) const ECDSA_SHA512: &str = "1.2.840.10045.4.3.4";

/// Ed25519 (RFC 8410 / 8419).
pub(crate) const ED25519: &str = "1.3.101.112";

/// `id-ecPublicKey` (RFC 5480).
pub(crate) const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";

/// `id-ce-subjectKeyIdentifier` (RFC 5280 §4.2.1.2).
pub(crate) const SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";

/// NIST P-curve OIDs (ansi-X962 / certicom).
pub(crate) const P256: &str = "1.2.840.10045.3.1.7";
pub(crate) const P384: &str = "1.3.132.0.34";

/// ECDH single-pass standard DH with SHA-2 KDF (RFC 5753 / secg-scheme 11).
/// Parameters are the key-wrap `AlgorithmIdentifier`.
pub(crate) const DH_SINGLE_PASS_STD_SHA256: &str = "1.3.132.1.11.1";
pub(crate) const DH_SINGLE_PASS_STD_SHA384: &str = "1.3.132.1.11.2";
pub(crate) const DH_SINGLE_PASS_STD_SHA512: &str = "1.3.132.1.11.3";

#[inline]
pub(crate) fn oid(s: &str) -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(s)
}
