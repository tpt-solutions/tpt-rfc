//! Object identifiers used by RFC 3161 and the CMS wrapper (RFC 5652).
//!
//! All values are taken from the IANA/ITU registries referenced by the RFCs.

use const_oid::ObjectIdentifier;

pub(crate) const SHA256: &str = "2.16.840.1.101.3.4.2.1";
pub(crate) const SHA384: &str = "2.16.840.1.101.3.4.2.2";
pub(crate) const SHA512: &str = "2.16.840.1.101.3.4.2.3";

/// `id-ct-TSTInfo` — the `eContentType` of a time-stamp token (RFC 3161 §2.4.3).
pub(crate) const ID_CT_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";

/// `id-signedData` (RFC 5652).
pub(crate) const ID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";

/// `sha256WithRSAEncryption` (RFC 4055 / RFC 8017).
pub(crate) const SHA256_RSA: &str = "1.2.840.113549.1.1.11";
pub(crate) const SHA384_RSA: &str = "1.2.840.113549.1.1.12";
pub(crate) const SHA512_RSA: &str = "1.2.840.113549.1.1.13";

/// `ecdsaWithSHA256` / `ecdsaWithSHA384` (RFC 5758 / RFC 3279).
pub(crate) const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
pub(crate) const ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";

/// `id-Ed25519` (RFC 8410 / RFC 8419).
pub(crate) const ED25519: &str = "1.3.101.112";

/// CMS signed-attribute OIDs (RFC 5652 §11).
pub(crate) const CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
pub(crate) const MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
pub(crate) const SIGNING_TIME: &str = "1.2.840.113549.1.9.5";

/// `rsaEncryption` (for `SubjectPublicKeyInfo` key OID, RFC 8017).
pub(crate) const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
/// `id-ecPublicKey` (RFC 5480).
pub(crate) const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
pub(crate) const P256: &str = "1.2.840.10045.3.1.7";
pub(crate) const P384: &str = "1.3.132.0.34";

#[inline]
pub(crate) fn oid(s: &str) -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(s)
}
