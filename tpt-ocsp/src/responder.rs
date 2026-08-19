//! Minimal RFC 6960 OCSP responder.
//!
//! Given a parsed `OCSPRequest`, it looks up the requested certificate's status
//! via a pluggable [`CertStatusProvider`], builds the `SingleResponse` and
//! `ResponseData`, and signs it into a `BasicOCSPResponse` `OCSPResponse`. This
//! is the part of RFC 6960 that is missing under a clean dual license (most
//! crates only cover the client side).

use std::time::{Duration, SystemTime};

use der::{
    asn1::{AnyRef, BitStringRef, GeneralizedTime, Null, OctetString},
    Decode, Encode,
};
use sha1::{Digest as _, Sha1};
use spki::AlgorithmIdentifierRef;
use x509_cert::Certificate;

use crate::certid::CertId;
use crate::client::DecodedRequest;
use crate::error::{OcspError, OcspResult};
use crate::hash::HashAlgorithm;
use crate::oids;
use crate::signer::SigningKey;
use crate::verify::null_params;
use crate::wire::{
    BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus, ResponderId, ResponseBytes,
    ResponseData, RevokedInfo, SingleResponse,
};

/// The status a [`CertStatusProvider`] returns for a requested certificate.
#[derive(Clone, Debug)]
pub enum ProvidedStatus {
    /// The certificate is good (not revoked).
    Good,
    /// The certificate has been revoked.
    Revoked {
        /// Time at which the certificate was revoked.
        revocation_time: SystemTime,
        /// Optional X.509 `CRLReason` code.
        reason: Option<u8>,
    },
    /// The responder does not know about this certificate.
    Unknown,
}

/// Trait implemented by the authority that owns the revocation information.
///
/// The responder calls [`CertStatusProvider::status`] for each requested
/// certificate; implementations typically consult a certificate store, CRL, or
/// in-memory map.
pub trait CertStatusProvider {
    /// Return the status for `cert_id`.
    fn status(&self, cert_id: &CertId) -> OcspResult<ProvidedStatus>;
}

/// How the responder identifies itself in the `ResponseData.responderID` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponderIdKind {
    /// `byName` — the responder's subject `Name` (common for issuer-operated
    /// responders).
    ByName,
    /// `byKey` — a SHA-1 key hash of the responder's public key.
    ByKey,
}

/// A minimal OCSP responder.
pub struct OcspResponder {
    cert_der: Vec<u8>,
    signer: SigningKey,
    hash: HashAlgorithm,
    responder_id: ResponderIdKind,
}

impl OcspResponder {
    /// Build a responder from a DER-encoded responder certificate, the matching
    /// private `signer`, the signature `hash` algorithm, and the
    /// `responder_id` identification mode.
    pub fn new(
        cert_der: &[u8],
        signer: SigningKey,
        hash: HashAlgorithm,
        responder_id: ResponderIdKind,
    ) -> OcspResult<Self> {
        Certificate::from_der(cert_der)
            .map_err(|e| OcspError::Crypto(format!("invalid responder cert: {e}")))?;
        Ok(Self {
            cert_der: cert_der.to_vec(),
            signer,
            hash,
            responder_id,
        })
    }

    /// Produce a DER `OCSPResponse` for a DER `OCSPRequest`.
    pub fn respond(
        &self,
        provider: &dyn CertStatusProvider,
        request_der: &[u8],
    ) -> OcspResult<Vec<u8>> {
        let req = crate::client::decode_request(request_der)?;
        self.respond_decoded(provider, &req)
    }

    /// Produce a DER `OCSPResponse` for an already-decoded request.
    pub fn respond_decoded(
        &self,
        provider: &dyn CertStatusProvider,
        req: &DecodedRequest,
    ) -> OcspResult<Vec<u8>> {
        let status = provider.status(&req.cert_id)?;

        let now = SystemTime::now();
        let produced_at =
            GeneralizedTime::try_from(now).map_err(|e| OcspError::Crypto(e.to_string()))?;
        let this_update = produced_at;
        let next_update = GeneralizedTime::try_from(now + Duration::from_secs(3600))
            .map_err(|e| OcspError::Crypto(e.to_string()))?;

        let cid_wire = req.cert_id.to_wire()?;
        let cert_status = match &status {
            ProvidedStatus::Good => CertStatus::Good(Null),
            ProvidedStatus::Unknown => CertStatus::Unknown(Null),
            ProvidedStatus::Revoked {
                revocation_time,
                reason,
            } => {
                let rt = GeneralizedTime::try_from(*revocation_time)
                    .map_err(|e| OcspError::Crypto(e.to_string()))?;
                let rev_reason = reason.map(crate::wire::CrlReason::from_code).flatten();
                CertStatus::Revoked(RevokedInfo {
                    revocation_time: rt,
                    revocation_reason: rev_reason,
                })
            }
        };

        let single = SingleResponse {
            cert_id: cid_wire,
            cert_status,
            this_update,
            next_update: Some(next_update),
            single_extensions: None,
        };

        let cert = Certificate::from_der(&self.cert_der)
            .map_err(|e| OcspError::Crypto(e.to_string()))?;
        let responder_id = match self.responder_id {
            ResponderIdKind::ByName => {
                ResponderId::ByName(cert.tbs_certificate().subject().clone())
            }
            ResponderIdKind::ByKey => {
                let spki = cert.tbs_certificate().subject_public_key_info();
                let val = spki
                    .subject_public_key
                    .as_bytes()
                    .ok_or_else(|| OcspError::Crypto("responder has no public key".into()))?;
                let h = Sha1::digest(val).to_vec();
                ResponderId::ByKey(OctetString::new(h).map_err(OcspError::from)?)
            }
        };

        let response_extensions = req.nonce.as_ref().map(|n| vec![crate::verify::build_nonce_ext(n)]);

        let rd = ResponseData {
            version: None,
            responder_id,
            produced_at,
            responses: vec![single],
            response_extensions,
        };
        let tbs_der = rd.to_der().map_err(OcspError::from)?;

        let (sig_oid, signature) = self.signer.sign_response(self.hash, &tbs_der)?;

        // RSASSA-PKCS1-v1_5 signature algorithms require a NULL parameter;
        // ECDSA and Ed25519 must omit it.
        let sig_alg_params = if sig_oid == oids::oid(oids::SHA256_RSA)
            || sig_oid == oids::oid(oids::SHA384_RSA)
            || sig_oid == oids::oid(oids::SHA512_RSA)
        {
            null_params()
        } else {
            None
        };

        let basic = BasicOcspResponse {
            tbs_response_data: AnyRef::from_der(&tbs_der).map_err(OcspError::from)?,
            signature_algorithm: AlgorithmIdentifierRef {
                oid: sig_oid,
                parameters: sig_alg_params,
            },
            signature: BitStringRef::new(0, &signature).map_err(OcspError::from)?,
            certs: Some(vec![cert]),
        };
        let basic_der = basic.to_der().map_err(OcspError::from)?;

        let resp_bytes = ResponseBytes {
            response_type: oids::oid(oids::OCSP_BASIC),
            response: OctetString::new(basic_der).map_err(OcspError::from)?,
        };
        let ocsp_resp = OcspResponse {
            response_status: OcspResponseStatus::Success,
            response_bytes: Some(resp_bytes),
        };
        Ok(ocsp_resp.to_der().map_err(OcspError::from)?)
    }
}
