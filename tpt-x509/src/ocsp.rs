//! OCSP support (RFC 6960).
//!
//! This crate implements the X.509 *path validation* engine. Revocation
//! checking is provided here via **CRL** (see [`crate::crl`]). Full OCSP
//! client/responder support is intentionally **scoped out** of `tpt-x509` and
//! tracked as its own dual-licensed crate, `tpt-ocsp` (Phase 11 of the
//! platform plan). The rationale: OCSP response *verification* is itself a
//! path-validation problem (the responder certificate must chain to the same
//! trust anchors), so it composes naturally on top of this engine rather than
//! living inside it.
//!
//! What this module *does* provide is a self-contained, dependency-light OCSP
//! **request** builder, which is useful on its own for callers that want to
//! query a responder and verify the response with `tpt-ocsp` later.

use der::Encode;
use sha2::{Digest, Sha256};
use x509_cert::{serial_number::SerialNumber, Certificate};

/// DER encoding of the SHA-256 `AlgorithmIdentifier`
/// (`2.16.840.1.101.3.4.2.1`, parameters `NULL`).
const SHA256_ALG_ID: &[u8] = &[
    0x30, 0x0c, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
];

/// OID of the OCSP nonce extension (`1.3.6.1.5.5.7.48.1.2`).
const NONCE_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];

/// Parameters for building an OCSP request.
#[derive(Clone, Debug)]
pub struct RequestParams {
    /// The issuer certificate (its subject and public key are hashed).
    pub issuer: Certificate,
    /// The serial number of the certificate being queried.
    pub serial: SerialNumber,
    /// An optional nonce for replay protection.
    pub nonce: Option<Vec<u8>>,
}

/// Build a DER-encoded `OCSPRequest` for the given parameters.
///
/// The request contains a single `Request` (one `CertID`) and, when a nonce is
/// supplied, a `requestExtensions` block carrying the OCSP nonce extension.
pub fn build_request(params: &RequestParams) -> Result<Vec<u8>, der::Error> {
    let issuer_name = params.issuer.tbs_certificate().subject().to_der()?;
    let issuer_spki = params
        .issuer
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()?;

    let name_hash = Sha256::digest(&issuer_name);
    let key_hash = Sha256::digest(&issuer_spki);
    let serial = params.serial.to_der()?;

    let cert_id = der_seq(&[
        SHA256_ALG_ID,
        &octet_string(&name_hash),
        &octet_string(&key_hash),
        &serial,
    ]);
    let request = der_seq(&[&cert_id]);
    let request_list = der_seq(&[&request]);

    let tbs_request = if let Some(nonce) = &params.nonce {
        // requestExtensions [2] EXPLICIT Extensions
        let nonce_ext = der_seq(&[NONCE_OID, &der_bool_false(), &octet_string(nonce)]);
        let extensions = der_seq(&[&nonce_ext]);
        let explicit = der_explicit_ctx(2, &extensions);
        der_seq(&[&request_list, &explicit])
    } else {
        der_seq(&[&request_list])
    };

    Ok(der_seq(&[&tbs_request]))
}

fn der_seq(parts: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::new();
    for p in parts {
        content.extend_from_slice(p);
    }
    der_tlv(0x30, &content)
}

fn der_explicit_ctx(tag: u8, content: &[u8]) -> Vec<u8> {
    // [tag] EXPLICIT => context tag 0xA0 + tag, wrapping the DER content.
    der_tlv(0xA0 | tag, content)
}

fn der_bool_false() -> Vec<u8> {
    vec![0x01, 0x01, 0x00]
}

fn octet_string(bytes: &[u8]) -> Vec<u8> {
    der_tlv(0x04, bytes)
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 2);
    out.push(tag);
    if content.len() < 128 {
        out.push(content.len() as u8);
    } else {
        // Multi-byte length (supports up to 2^16-1, ample here).
        let len = content.len();
        let bytes = [(len >> 8) as u8, (len & 0xff) as u8];
        out.push(0x82);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(content);
    out
}
