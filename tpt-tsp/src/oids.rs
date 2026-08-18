//! Object identifiers used by RFC 3161 (TSP) and its companion specs.
//!
//! All values are taken from the IANA/ITU/NIST registries referenced by the
//! relevant RFCs (3161, 5652, 5280, 4055, 8410, 3279).

use const_oid::ObjectIdentifier;

// --- RFC 3161 content / token types --------------------------------------

/// `id-ct-TSTInfo` — the encapsulated content type of a `TimeStampToken`
/// (RFC 3161 §2.4.2). Value: `1.2.840.113549.1.9.16.1.4`.
pub const ID_CT_TSTINFO: &str = "1.2.840.113549.1.9.16.1.4";

/// `id-aa-timeStampAuthority` — optional `ESSCertID`/`SigningCertificate`
/// signed attribute identifying the TSA cert (RFC 3161 §2.4.3.2, RFC 2634/5035).
pub const ID_AA_TIME_STAMP_AUTHORITY: &str = "1.2.840.113549.1.9.16.2.12";

// --- CMS content-info / signed-data OIDs (RFC 5652) ----------------------

/// `id-signedData` — the `TimeStampToken` is a CMS `SignedData` (RFC 3161 §2.4.2).
pub const ID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";

/// CMS signed-attribute OIDs (RFC 5652 §11).
pub const CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
pub const MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
pub const SIGNING_TIME: &str = "1.2.840.113549.1.9.5";

// --- PKIStatus / response status -----------------------------------------

/// `id-aa-signingCertificate` (ESSCertID, SHA-1) signed attribute.
pub const ID_AA_SIGNING_CERTIFICATE: &str = "1.2.840.113549.1.9.16.2.12";

// --- Digest algorithm OIDs (NIST hashAlgs arc) ---------------------------

pub const SHA1: &str = "1.3.14.3.2.26";
pub const SHA256: &str = "2.16.840.1.101.3.4.2.1";
pub const SHA384: &str = "2.16.840.1.101.3.4.2.2";
pub const SHA512: &str = "2.16.840.1.101.3.4.2.3";

// --- Signature algorithm OIDs (RFC 4055 / 3279 / 8410) ------------------

pub const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
pub const SHA256_RSA: &str = "1.2.840.113549.1.1.11";
pub const SHA384_RSA: &str = "1.2.840.113549.1.1.12";
pub const SHA512_RSA: &str = "1.2.840.113549.1.1.13";
pub const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
pub const ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
pub const ECDSA_SHA512: &str = "1.2.840.10045.4.3.4";
pub const ED25519: &str = "1.3.101.112";

/// `id-ecPublicKey` (RFC 5480).
pub const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";

/// NIST P-curve OIDs.
pub const P256: &str = "1.2.840.10045.3.1.7";
pub const P384: &str = "1.3.132.0.34";

/// `id-ce-subjectKeyIdentifier` (RFC 5280 §4.2.1.2).
pub const SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";

#[inline]
pub(crate) fn oid(s: &str) -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(s)
}
