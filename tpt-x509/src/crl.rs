//! CRL parsing and revocation checking (RFC 5280 §6.3).

use der::{Decode, Encode, Length};
use x509_cert::{crl::CertificateList, Certificate};

use crate::{
    cert::{subject_der, TrustAnchor},
    error::ValidationError,
    verify::verify_signature_raw,
};

/// Parse a DER-encoded CRL.
pub fn parse_der(der: &[u8]) -> Result<CertificateList, der::Error> {
    CertificateList::from_der(der)
}

/// Parse a PEM-encoded CRL (`-----BEGIN X509 CRL-----`).
pub fn parse_pem(pem: &[u8]) -> Result<CertificateList, der::Error> {
    let der = pem_to_der(pem)
        .ok_or_else(|| der::Error::new(der::ErrorKind::Failed, Length::ZERO))?;
    CertificateList::from_der(&der)
}

/// Check whether `cert` has been revoked according to any supplied CRL whose
/// issuer is a CA in `path` (or the trust anchor).
///
/// Returns `None` if no relevant CRL was supplied (treated as "no information"),
/// or `Some(ValidationError)` describing the failure.
pub fn check_revocation(
    cert: &Certificate,
    crls: &[CertificateList],
    path: &[Certificate],
    anchor: &TrustAnchor,
) -> Option<ValidationError> {
    let serial = cert.tbs_certificate().serial_number().as_bytes().to_vec();
    let mut saw_crl_for_issuer = false;

    for crl in crls {
        let crl_issuer = match crl.tbs_cert_list.issuer.to_der() {
            Ok(d) => d,
            Err(_) => continue,
        };

        // Locate the signing key: a CA in the path or the trust anchor.
        let spki = path
            .iter()
            .find(|c| subject_der(c).ok().as_deref() == Some(crl_issuer.as_slice()))
            .map(|c| c.tbs_certificate().subject_public_key_info())
            .or_else(|| {
                if anchor.name.to_der().ok().as_deref() == Some(crl_issuer.as_slice()) {
                    Some(&anchor.spki)
                } else {
                    None
                }
            })?; // `?` here means "this CRL isn't from a CA we know" -> skip it

        saw_crl_for_issuer = true;

        let signed = match crl.tbs_cert_list.to_der() {
            Ok(d) => d,
            Err(e) => return Some(ValidationError::Encoding(e)),
        };
        let sig = crl.signature.raw_bytes();
        if let Err(reason) = verify_signature_raw(&signed, sig, spki, crl.signature_algorithm.oid) {
            return Some(ValidationError::Signature {
                issuer: format!("CRL issuer {crl_issuer:?}"),
                reason,
            });
        }

        if let Some(revoked) = &crl.tbs_cert_list.revoked_certificates {
            for rc in revoked {
                if rc.serial_number.as_bytes() == serial.as_slice() {
                    return Some(ValidationError::Revoked {
                        serial: cert.tbs_certificate().serial_number().to_string(),
                    });
                }
            }
        }
    }

    if saw_crl_for_issuer {
        None
    } else {
        None
    }
}

const PEM_BEGIN: &[u8] = b"-----BEGIN X509 CRL-----";
const PEM_END: &[u8] = b"-----END X509 CRL-----";

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
    base64_decode(&b64)
}

fn base64_decode(b64: &[u8]) -> Option<Vec<u8>> {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(b64.len() / 4 * 3);
    let mut buf = 0u32;
    let mut bits = 0u8;
    for &c in b64 {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = TABLE.iter().position(|&t| t == c)?;
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}
