//! Certificate handling for TSP: locating the TSA signer certificate, verifying
//! its signature, and (optionally) building a chain to a supplied trust anchor.
//!
//! This is intentionally small — full RFC 5280 path validation (policies, name
//! constraints, revocation, …) is the job of `tpt-x509`. Here we only need
//! enough to bind a `SignerInfo` to a certificate and optionally prove it
//! chains to a trust anchor. Patterns mirror `tpt-cms`'s `cert.rs`.

use std::collections::HashSet;

use der::{Decode, Encode};
use x509_cert::Certificate;

use crate::crypto::{public_key_from_spki, sig_alg_hash, verify_signature, PublicKey};
use crate::error::{TspError, Result};
use crate::oids;
use crate::wire;

/// Parse a DER-encoded X.509 certificate.
pub(crate) fn parse_cert(der: &[u8]) -> Result<Certificate> {
    Certificate::from_der(der).map_err(TspError::Asn1)
}

/// DER encoding of a certificate's `issuer` `Name`.
pub(crate) fn cert_issuer_der(cert: &Certificate) -> Vec<u8> {
    cert.tbs_certificate().issuer().to_der().expect("issuer der")
}

/// DER encoding of a certificate's `subject` `Name`.
pub(crate) fn subject_der(cert: &Certificate) -> Vec<u8> {
    cert.tbs_certificate().subject().to_der().expect("subject der")
}

/// Raw value bytes of a certificate's `serialNumber`.
pub(crate) fn cert_serial_bytes(cert: &Certificate) -> Vec<u8> {
    cert.tbs_certificate().serial_number().as_bytes().to_vec()
}

/// DER of the `tbsCertificate` (the signed part).
pub(crate) fn tbs_der(cert: &Certificate) -> Vec<u8> {
    cert.tbs_certificate().to_der().expect("tbs der")
}

/// True when `issuer` == `subject` (self-issued).
pub(crate) fn is_self_signed(cert: &Certificate) -> bool {
    cert_issuer_der(cert) == subject_der(cert)
}

/// Locate the signer certificate within `certs` matching either an
/// `IssuerAndSerialNumber` (by `issuer_der` + `serial` value bytes) or a
/// `subjectKeyIdentifier` (`ski`).
pub(crate) fn find_signer_cert(
    certs: &[Certificate],
    issuer_der: &[u8],
    serial: &[u8],
    ski: Option<&[u8]>,
) -> Option<Certificate> {
    if let Some(ski) = ski {
        return certs
            .iter()
            .find(|c| ski_extension(c).as_deref() == Some(ski))
            .cloned();
    }
    certs
        .iter()
        .find(|c| cert_issuer_der(c) == issuer_der && cert_serial_bytes(c) == serial)
        .cloned()
}

/// Extract the SubjectKeyIdentifier extension value bytes from a cert, if any.
fn ski_extension(cert: &Certificate) -> Option<Vec<u8>> {
    let exts = cert.tbs_certificate().extensions()?;
    for ext in exts.iter() {
        if ext.extn_id.to_string() == oids::SUBJECT_KEY_IDENTIFIER {
            // extn_value is an OCTET STRING whose content is the DER of the
            // SubjectKeyIdentifier (itself an OCTET STRING).
            let outer = der::asn1::OctetString::from_der(ext.extn_value.as_bytes()).ok()?;
            let inner = der::asn1::OctetString::from_der(outer.as_bytes()).ok()?;
            return Some(inner.as_bytes().to_vec());
        }
    }
    None
}

/// Parse the `certificates` `IMPLICIT [0]` set into individual certificates.
pub(crate) fn parse_cert_set(raw: &Option<Vec<u8>>) -> Result<Vec<Certificate>> {
    let mut out = Vec::new();
    let Some(raw) = raw else {
        return Ok(out);
    };
    let elems = wire::parse_set_elements_raw(raw)?;
    for e in elems {
        out.push(parse_cert(&e)?);
    }
    Ok(out)
}

/// Verify `cert`'s signature using the public key of its issuer `issuer_pub`.
pub(crate) fn verify_cert_signature(cert: &Certificate, issuer_pub: &PublicKey) -> Result<()> {
    let alg_oid = cert.signature_algorithm().oid;
    let sig = cert.signature().as_bytes();
    if alg_oid.to_string() == oids::ED25519 {
        verify_signature(&alg_oid, &tbs_der(cert), sig.expect("ed25519 signature"), issuer_pub)
    } else {
        let hash = sig_alg_hash(&alg_oid)?;
        let digest = hash.digest(&tbs_der(cert));
        verify_signature(&alg_oid, &digest, sig.expect("signature"), issuer_pub)
    }
}

/// Build/validate `ee`'s chain to one of `anchors`, using `intermediates`.
pub(crate) fn verify_chain(
    ee: &Certificate,
    intermediates: &[Certificate],
    anchors: &[Certificate],
) -> Result<()> {
    if anchors.is_empty() {
        return Err(TspError::CertChain("no trust anchors supplied".into()));
    }

    let mut current = ee.clone();
    let mut visited: HashSet<(Vec<u8>, Vec<u8>)> = HashSet::new();
    let path_len_limit = 16;

    for _ in 0..path_len_limit {
        let anchor_hit = anchors
            .iter()
            .any(|a| subject_der(a) == subject_der(&current) && is_self_signed(&current));
        if anchor_hit {
            let pk = public_key_from_spki(current.tbs_certificate().subject_public_key_info())?;
            return verify_cert_signature(&current, &pk);
        }

        let issuer = find_issuer(&current, anchors, intermediates)?;
        let pk = public_key_from_spki(issuer.tbs_certificate().subject_public_key_info())?;
        verify_cert_signature(&current, &pk)?;

        let key = (cert_issuer_der(&current), cert_serial_bytes(&current));
        if !visited.insert(key) {
            return Err(TspError::CertChain("certificate chain loop detected".into()));
        }
        current = issuer.clone();
    }
    Err(TspError::CertChain("certificate chain too long".into()))
}

fn find_issuer<'a>(
    cert: &Certificate,
    anchors: &'a [Certificate],
    intermediates: &'a [Certificate],
) -> Result<&'a Certificate> {
    let want = subject_der(cert);
    for a in anchors {
        if subject_der(a) == want {
            return Ok(a);
        }
    }
    for i in intermediates {
        if subject_der(i) == want {
            return Ok(i);
        }
    }
    Err(TspError::CertChain(format!(
        "no issuer certificate found for {}",
        cert_issuer_der(cert)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )))
}
