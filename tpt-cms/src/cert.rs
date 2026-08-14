//! Certificate handling for CMS: locating signer certificates, verifying
//! certificate signatures, and building a certification chain to a trust anchor.
//!
//! This is intentionally small — full RFC 5280 path validation (policies, name
//! constraints, revocation, etc.) is the job of `tpt-x509`. Here we only need
//! enough to (a) bind a `SignerInfo` to a certificate in the `certificates`
//! set and (b) optionally prove that certificate chains to a provided trust
//! anchor.

use std::collections::HashSet;

use spki::SubjectPublicKeyInfo;
use x509_cert::Certificate;

use crate::crypto::{public_key_from_spki, sig_alg_hash, verify_signature, PublicKey};
use crate::error::{CmsError, Result};
use crate::oids;
use crate::wire::{IssuerAndSerialNumber, SignerIdentifier};
use der::asn1::OctetStringRef;

/// Parse a DER-encoded X.509 certificate.
pub(crate) fn parse_cert(der: &[u8]) -> Result<Certificate> {
    Certificate::from_der(der).map_err(CmsError::Decode)
}

/// DER encoding of a certificate's `issuer` `Name`.
pub(crate) fn issuer_der(cert: &Certificate) -> Vec<u8> {
    cert.tbs_certificate().issuer().to_der().expect("issuer der")
}

/// DER encoding of a certificate's `subject` `Name`.
pub(crate) fn subject_der(cert: &Certificate) -> Vec<u8> {
    cert.tbs_certificate().subject().to_der().expect("subject der")
}

/// DER encoding of a certificate's `serialNumber`.
pub(crate) fn serial_der(cert: &Certificate) -> Vec<u8> {
    cert.tbs_certificate()
        .serial_number()
        .as_bytes()
        .to_vec()
}

/// DER of the `tbsCertificate` (the signed part).
pub(crate) fn tbs_der(cert: &Certificate) -> Vec<u8> {
    cert.tbs_certificate().to_der().expect("tbs der")
}

/// True when `issuer` == `subject` (self-issued/self-signed by DN).
pub(crate) fn is_self_signed(cert: &Certificate) -> bool {
    issuer_der(cert) == subject_der(cert)
}

/// Locate the signer certificate within `certs` matching `sid`.
pub(crate) fn find_signer_cert(certs: &[Certificate], sid: &SignerIdentifier) -> Option<Certificate> {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => {
            let want_issuer = ias.issuer.to_der().ok()?;
            let want_serial = ias.serial_number.as_bytes().to_vec();
            certs.iter().find(|c| {
                issuer_der(c) == want_issuer && serial_der(c) == want_serial
            }).cloned()
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => {
            // Compare against the SKI extension if present.
            certs.iter().find(|c| {
                ski_extension(c).map(|s| s == ski.as_bytes()).unwrap_or(false)
            }).cloned()
        }
    }
}

/// Extract the SubjectKeyIdentifier extension value bytes from a cert, if any.
fn ski_extension(cert: &Certificate) -> Option<Vec<u8>> {
    use x509_cert::ext::pkix::SubjectKeyIdentifier;
    use x509_cert::ext::Extensions;
    let exts: &Extensions = cert.tbs_certificate().extensions.as_ref()?;
    for ext in exts.iter() {
        if ext.extn_id.to_string() == oids::SUBJECT_KEY_IDENTIFIER {
            // The extension value is a DER OCTET STRING wrapping the SKI.
            let inner = der::asn1::OctetStringRef::from_der(ext.extn_value).ok()?;
            return Some(inner.as_bytes().to_vec());
        }
    }
    None
}

/// Verify `cert`'s signature using the public key of its issuer `issuer_pub`.
pub(crate) fn verify_cert_signature(cert: &Certificate, issuer_pub: &PublicKey) -> Result<()> {
    let alg_oid = cert.signature_algorithm().oid;
    let sig = cert.signature().as_bytes();
    if alg_oid.to_string() == oids::ED25519 {
        verify_signature(&alg_oid, &tbs_der(cert), sig, issuer_pub)
    } else {
        let hash = sig_alg_hash(&alg_oid)?;
        let digest = hash.digest(&tbs_der(cert));
        verify_signature(&alg_oid, &digest, sig, issuer_pub)
    }
}

/// Build/validate `ee`'s chain to one of `anchors`, optionally using
/// `intermediates`. Returns `Ok(())` when a trusted, signature-valid chain is
/// found.
pub(crate) fn verify_chain(
    ee: &Certificate,
    intermediates: &[Certificate],
    anchors: &[Certificate],
) -> Result<()> {
    if anchors.is_empty() {
        return Err(CmsError::CertChain("no trust anchors supplied".into()));
    }

    let mut current = ee.clone();
    let mut visited: HashSet<(Vec<u8>, Vec<u8>)> = HashSet::new();
    let path_len_limit = 16;

    for _ in 0..path_len_limit {
        let anchor_hit = anchors.iter().any(|a| {
            subject_der(a) == subject_der(&current) && is_self_signed(&current)
        });
        if anchor_hit {
            let pk = public_key_from_spki(current.tbs_certificate().subject_public_key_info())?;
            return verify_cert_signature(&current, &pk);
        }

        let issuer = find_issuer(&current, anchors, intermediates)?;
        let pk = public_key_from_spki(issuer.tbs_certificate().subject_public_key_info())?;
        verify_cert_signature(&current, &pk)?;

        let key = (issuer_der(&current), serial_der(&current));
        if !visited.insert(key) {
            return Err(CmsError::CertChain("certificate chain loop detected".into()));
        }
        current = issuer;
    }
    Err(CmsError::CertChain("certificate chain too long".into()))
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
    Err(CmsError::CertChain(format!(
        "no issuer certificate found for {}",
        issuer_der(cert)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )))
}

/// The subject's `SubjectPublicKeyInfo` as required by signers.
pub(crate) fn subject_public_key_info(cert: &Certificate) -> SubjectPublicKeyInfo {
    cert.tbs_certificate().subject_public_key_info().clone()
}
