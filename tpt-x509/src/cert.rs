//! Certificate parsing and extension-extraction helpers.

use der::{Decode, Encode, Length};
use x509_cert::{
    ext::{
        pkix::{
            BasicConstraints, CertificatePolicies, ExtendedKeyUsage, KeyUsage, NameConstraints,
            SubjectAltName,
        },
        Extensions,
    },
    name::Name,
    Certificate, SubjectPublicKeyInfo,
};

/// Re-export of the parsed X.509 certificate type.
pub use x509_cert::Certificate as Cert;

/// Decode a single DER-encoded certificate.
pub fn parse_der(der: &[u8]) -> Result<Certificate, der::Error> {
    Certificate::from_der(der)
}

/// Decode a PEM-encoded certificate (e.g. `-----BEGIN CERTIFICATE-----`).
///
/// Only the "CERTIFICATE" label is accepted.
pub fn parse_pem(pem: &[u8]) -> Result<Certificate, der::Error> {
    let der = pem_to_der(pem).ok_or_else(pem_error)?;
    Certificate::from_der(&der)
}

/// Extract the raw DER of a certificate's `tbsCertificate` (the signed blob).
pub fn tbs_der(cert: &Certificate) -> Result<Vec<u8>, der::Error> {
    cert.tbs_certificate().to_der()
}

/// Canonical DER bytes of a certificate's `subject` `Name`.
pub fn subject_der(cert: &Certificate) -> Result<Vec<u8>, der::Error> {
    cert.tbs_certificate().subject().to_der()
}

/// Canonical DER bytes of a certificate's `issuer` `Name`.
pub fn issuer_der(cert: &Certificate) -> Result<Vec<u8>, der::Error> {
    cert.tbs_certificate().issuer().to_der()
}

/// Returns `true` if the certificate is self-issued (subject == issuer).
pub fn is_self_issued(cert: &Certificate) -> bool {
    subject_der(cert)
        .ok()
        .zip(issuer_der(cert).ok())
        .map(|(s, i)| s == i)
        .unwrap_or(false)
}

/// Returns `true` if the certificate is self-signed (self-issued and its
/// signature verifies against its own public key).
pub fn is_self_signed(cert: &Certificate) -> bool {
    if !is_self_issued(cert) {
        return false;
    }
    crate::verify::verify_signature(cert, cert.tbs_certificate().subject_public_key_info()).is_ok()
}

/// Extract the `BasicConstraints` extension, if present.
pub fn basic_constraints(cert: &Certificate) -> Option<BasicConstraints> {
    cert.tbs_certificate()
        .get_extension::<BasicConstraints>()
        .ok()
        .flatten()
        .map(|(_, bc)| bc)
}

/// Extract the `KeyUsage` extension, if present.
pub fn key_usage(cert: &Certificate) -> Option<KeyUsage> {
    cert.tbs_certificate()
        .get_extension::<KeyUsage>()
        .ok()
        .flatten()
        .map(|(_, ku)| ku)
}

/// Extract the `ExtendedKeyUsage` extension, if present.
pub fn extended_key_usage(cert: &Certificate) -> Option<ExtendedKeyUsage> {
    cert.tbs_certificate()
        .get_extension::<ExtendedKeyUsage>()
        .ok()
        .flatten()
        .map(|(_, eku)| eku)
}

/// Extract the `NameConstraints` extension, if present.
pub fn name_constraints(cert: &Certificate) -> Option<NameConstraints> {
    cert.tbs_certificate()
        .get_extension::<NameConstraints>()
        .ok()
        .flatten()
        .map(|(_, nc)| nc)
}

/// Extract the `SubjectAltName` extension, if present.
pub fn subject_alt_name(cert: &Certificate) -> Option<SubjectAltName> {
    cert.tbs_certificate()
        .get_extension::<SubjectAltName>()
        .ok()
        .flatten()
        .map(|(_, san)| san)
}

/// Extract the `CertificatePolicies` extension, if present.
pub fn certificate_policies(cert: &Certificate) -> Option<CertificatePolicies> {
    cert.tbs_certificate()
        .get_extension::<CertificatePolicies>()
        .ok()
        .flatten()
        .map(|(_, cp)| cp)
}

/// A trust anchor: the name and public key against which the top of a
/// certification path is validated, plus any name constraints the anchor
/// imposes on subordinate certificates.
#[derive(Clone, Debug)]
pub struct TrustAnchor {
    /// The anchor's subject `Name` (used to match the top certificate's issuer).
    pub name: Name,
    /// The anchor's public key.
    pub spki: SubjectPublicKeyInfo,
    /// The anchor's certificate, if this anchor was built from a (self-signed)
    /// root certificate. When present, it is prepended to validated paths so
    /// the returned path runs from the trust anchor down to the end entity.
    pub cert: Option<Certificate>,
    /// Permitted subtrees (RFC 5280 §4.2.1.10), if the anchor constrains them.
    pub permitted_subtrees: Option<Vec<crate::constraints::GeneralSubtreeLike>>,
    /// Excluded subtrees, if the anchor constrains them.
    pub excluded_subtrees: Option<Vec<crate::constraints::GeneralSubtreeLike>>,
    /// The anchor's `pathLenConstraint`, if present.
    pub path_len: Option<u8>,
}

impl TrustAnchor {
    /// Build a trust anchor from a self-signed (or otherwise trusted) root
    /// certificate. The root's basic constraints (if any) supply the path
    /// length, and its name constraints (if any) are applied to the path.
    pub fn from_cert(cert: &Certificate) -> Result<Self, crate::ValidationError> {
        let nc = name_constraints(cert);
        let (permitted, excluded) = match nc {
            Some(nc) => (
                nc.permitted_subtrees.map(|s| {
                    s.into_iter()
                        .map(crate::constraints::GeneralSubtreeLike::from)
                        .collect()
                }),
                nc.excluded_subtrees.map(|s| {
                    s.into_iter()
                        .map(crate::constraints::GeneralSubtreeLike::from)
                        .collect()
                }),
            ),
            None => (None, None),
        };
        Ok(Self {
            name: cert.tbs_certificate().subject().clone(),
            spki: cert.tbs_certificate().subject_public_key_info().clone(),
            cert: Some(cert.clone()),
            permitted_subtrees: permitted,
            excluded_subtrees: excluded,
            path_len: basic_constraints(cert).and_then(|bc| bc.path_len_constraint),
        })
    }
}

/// Convenience accessor for the raw extensions sequence, if present.
pub fn extensions(cert: &Certificate) -> Option<&Extensions> {
    cert.tbs_certificate().extensions()
}

// --- PEM decoding (minimal, dependency-free) ---------------------------------

const PEM_BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
const PEM_END: &[u8] = b"-----END CERTIFICATE-----";

fn pem_to_der(pem: &[u8]) -> Option<Vec<u8>> {
    let mut in_body = false;
    let mut b64 = Vec::new();
    for line in pem.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.starts_with(PEM_BEGIN) {
            in_body = true;
            continue;
        }
        if line.starts_with(PEM_END) {
            break;
        }
        if in_body {
            b64.extend_from_slice(line);
        }
    }
    if !in_body {
        return None;
    }
    Some(base64_decode(&b64))
}

fn pem_error() -> der::Error {
    der::Error::new(der::ErrorKind::Failed, Length::ZERO)
}

fn base64_decode(b64: &[u8]) -> Vec<u8> {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(b64.len() / 4 * 3);
    let mut buf = 0u32;
    let mut bits = 0u8;
    for &c in b64 {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = match TABLE.iter().position(|&t| t == c) {
            Some(v) => v,
            None => return Vec::new(),
        };
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    out
}
