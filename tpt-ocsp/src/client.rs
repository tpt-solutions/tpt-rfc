//! OCSP client: request construction, response parsing/verification.

use std::time::SystemTime;

use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use sha1::{Digest as _, Sha1};
use spki::SubjectPublicKeyInfoRef;
use x509_cert::Certificate;

use crate::certid::{CertId, CertStatusValue};
use crate::error::{OcspError, OcspResult};
use crate::oids;
use crate::verify::{build_nonce_ext, extract_nonce, verify_signature};
use crate::wire::{
    BasicOcspResponse, CertStatus, CrlReason, OcspRequest, OcspResponse, Request, ResponderId,
    ResponseData, SingleResponse, TbsRequest,
};

/// Options controlling how an OCSP request is built.
#[derive(Clone, Debug, Default)]
pub struct RequestOptions {
    /// Optional nonce bytes included as the `id-pkix-ocsp-nonce` extension.
    ///
    /// A nonce protects against replay attacks; clients should supply
    /// cryptographically random bytes (e.g. 16–32 octets).
    pub nonce: Option<Vec<u8>>,
}

/// A parsed OCSP request, as produced by a client and consumed by a responder.
#[derive(Clone, Debug)]
pub struct DecodedRequest {
    /// The certificate whose status was requested.
    pub cert_id: CertId,
    /// The nonce supplied by the client, if any.
    pub nonce: Option<Vec<u8>>,
}

/// Build a DER-encoded `OCSPRequest` for `cert_id`.
pub fn build_request(cert_id: &CertId, opts: &RequestOptions) -> OcspResult<Vec<u8>> {
    let req_cert = cert_id.to_wire()?;
    let request_extensions = match &opts.nonce {
        Some(nonce) => Some(vec![build_nonce_ext(nonce)]),
        None => None,
    };
    let request = Request {
        req_cert,
        single_request_extensions: None,
    };
    let tbs = TbsRequest {
        version: None,
        requestor_name: None,
        request_list: vec![request],
        request_extensions: request_extensions,
    };
    let req = OcspRequest {
        tbs_request: tbs,
        optional_signature: None,
    };
    Ok(req.to_der()?)
}

/// Parse a DER-encoded `OCSPRequest` into its certificate id and nonce.
pub fn decode_request(der: &[u8]) -> OcspResult<DecodedRequest> {
    let req = OcspRequest::from_der(der)?;
    let first = req
        .tbs_request
        .request_list
        .first()
        .ok_or(OcspError::EmptyRequest)?;
    let cert_id = CertId::from_wire(&first.req_cert)?;
    let nonce = extract_nonce(&req.tbs_request.request_extensions);
    Ok(DecodedRequest { cert_id, nonce })
}

/// A verified OCSP response for a single certificate.
#[derive(Clone, Debug)]
pub struct VerifiedResponse {
    /// The status of the requested certificate.
    pub status: CertStatusValue,
    /// The `thisUpdate` time of the response.
    pub this_update: SystemTime,
    /// The `nextUpdate` time, if provided by the responder.
    pub next_update: Option<SystemTime>,
    /// The nonce returned by the responder, if any.
    pub nonce: Option<Vec<u8>>,
}

/// OCSP client configuration for verifying responses.
///
/// A client is configured with one or more trust anchors (typically the
/// issuing CA certificate) and verifies that the responder's signature chains
/// to one of them, that the nonce matches the original request, and that the
/// returned status corresponds to the requested certificate.
#[derive(Clone, Debug, Default)]
pub struct OcspClient {
    trust_anchors: Vec<Vec<u8>>,
    require_nonce: bool,
}

impl OcspClient {
    /// Create a client with no trust anchors.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a DER-encoded trust-anchor certificate (e.g. the issuer CA).
    pub fn add_trust_anchor(&mut self, cert_der: &[u8]) {
        self.trust_anchors.push(cert_der.to_vec());
    }

    /// Require that responses carry a nonce matching the request (default
    /// `false`).
    pub fn set_require_nonce(&mut self, require: bool) {
        self.require_nonce = require;
    }

    /// Verify an `OCSPResponse` (DER) for `expected`, optionally checking that
    /// the response nonce matches `expected_nonce`.
    pub fn verify_response(
        &self,
        response_der: &[u8],
        expected: &CertId,
        expected_nonce: Option<&[u8]>,
    ) -> OcspResult<VerifiedResponse> {
        let resp = OcspResponse::from_der(response_der)?;
        let status = resp.response_status as u8;
        if status != 0 {
            return Err(OcspError::ResponseStatus(status));
        }
        let rb = resp.response_bytes.ok_or(OcspError::MissingResponseBytes)?;
        let resp_type = ObjectIdentifier::from_der(rb.response_type.as_bytes())
            .map_err(OcspError::from)?;
        if resp_type != oids::oid(oids::OCSP_BASIC) {
            return Err(OcspError::WrongResponseType);
        }

        let basic_der = rb.response.as_bytes();
        let basic = BasicOcspResponse::from_der(basic_der)?;
        let tbs = basic.tbs_response_data.as_bytes();
        let sig_oid = ObjectIdentifier::from_der(basic.signature_algorithm.oid.as_bytes())
            .map_err(OcspError::from)?;
        let sig_bytes = basic
            .signature
            .as_bytes()
            .map_err(|e| OcspError::Crypto(e.to_string()))?;

        let rd = ResponseData::from_der(tbs)?;

        // Verify the responder signature against a matching trust anchor.
        verify_responder(&self.trust_anchors, &rd.responder_id, &sig_oid, tbs, sig_bytes)?;

        // Find the single response for the requested certificate.
        let mut found: Option<&crate::wire::SingleResponse> = None;
        for single in &rd.responses {
            if CertId::from_wire(&single.cert_id)? == *expected {
                found = Some(single);
                break;
            }
        }
        let single = found.ok_or(OcspError::CertIdNotFound)?;

        // Nonce check.
        let resp_nonce = extract_nonce(&rd.response_extensions);
        match (expected_nonce, &resp_nonce) {
            (Some(exp), Some(got)) if exp == got.as_slice() => {}
            (Some(_), _) => {
                return Err(if self.require_nonce && resp_nonce.is_none() {
                    OcspError::NonceRequired
                } else {
                    OcspError::NonceMismatch
                });
            }
            (None, _) => {}
        }

        // Map the cert status.
        let status = match &single.cert_status {
            CertStatus::Good(_) => CertStatusValue::Good,
            CertStatus::Unknown(_) => CertStatusValue::Unknown,
            CertStatus::Revoked(rev) => {
                let revocation_time = SystemTime::from(rev.revocation_time);
                let reason = rev.revocation_reason.map(|r| r.code());
                CertStatusValue::Revoked {
                    revocation_time,
                    reason,
                }
            }
        };

        let this_update = SystemTime::from(single.this_update);
        let next_update = single.next_update.map(SystemTime::from);

        Ok(VerifiedResponse {
            status,
            this_update,
            next_update,
            nonce: resp_nonce,
        })
    }
}

fn responder_matches(rid: &ResponderId, cert: &Certificate) -> OcspResult<bool> {
    match rid {
        ResponderId::ByName(name) => {
            let subject_der = cert
                .tbs_certificate()
                .subject()
                .to_der()
                .map_err(|e| OcspError::Crypto(e.to_string()))?;
            let name_der = name
                .to_der()
                .map_err(|e| OcspError::Crypto(e.to_string()))?;
            Ok(subject_der == name_der)
        }
        ResponderId::ByKey(keyhash) => {
            let spki = cert.tbs_certificate().subject_public_key_info();
            let val = spki
                .subject_public_key
                .as_bytes()
                .ok_or_else(|| OcspError::Crypto("anchor has no public key".into()))?;
            let h = Sha1::digest(val).to_vec();
            Ok(h == keyhash.as_bytes())
        }
    }
}

fn verify_responder(
    anchors: &[Vec<u8>],
    rid: &ResponderId,
    sig_oid: &ObjectIdentifier,
    tbs: &[u8],
    sig: &[u8],
) -> OcspResult<()> {
    let mut any_match = false;
    let mut last_err = None;
    for anchor in anchors {
        let cert = match Certificate::from_der(anchor) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if !responder_matches(rid, &cert)? {
            continue;
        }
        any_match = true;
        let spki = cert.tbs_certificate().subject_public_key_info();
        let spki_ref = SubjectPublicKeyInfoRef::try_from(spki)
            .map_err(|e| OcspError::Crypto(e.to_string()))?;
        match verify_signature(spki_ref, sig_oid, tbs, sig) {
            Ok(()) => return Ok(()),
            Err(e) => last_err = Some(e),
        }
    }
    if any_match {
        Err(last_err.unwrap_or(OcspError::Signature("no anchor verified".into())))
    } else {
        Err(OcspError::ResponderUntrusted)
    }
}
