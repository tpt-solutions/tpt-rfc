//! OCSP `CertID` construction and representation.

use std::time::SystemTime;

use der::{
    asn1::{OctetString, Uint},
    Decode,
};

use x509_cert::Certificate;

use crate::error::{OcspError, OcspResult};
use crate::hash::HashAlgorithm;
use crate::wire::CertIdWire;

/// The status returned for a certificate in an OCSP response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertStatusValue {
    /// The certificate is not revoked (`good`).
    Good,
    /// The certificate has been revoked (`revoked`), with the revocation time
    /// and optional reason code.
    Revoked {
        /// Time at which the certificate was revoked.
        revocation_time: SystemTime,
        /// X.509 `CRLReason` code, if supplied by the responder.
        reason: Option<u8>,
    },
    /// The responder does not know about the certificate (`unknown`).
    Unknown,
}

/// An OCSP `CertID` — the key used to request and match the status of a
/// certificate.
///
/// A `CertID` binds three pieces of information: the hash algorithm, the hash
/// of the issuer's distinguished name, the hash of the issuer's public key, and
/// the certificate's serial number. Two `CertID` values are equal only when all
/// four components match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertId {
    /// Hash algorithm used for the issuer name/key hashes.
    pub hash_algorithm: HashAlgorithm,
    /// Hash of the issuer's `Name` (DER-encoded).
    pub issuer_name_hash: Vec<u8>,
    /// Hash of the issuer's `SubjectPublicKeyInfo` (BIT STRING value).
    pub issuer_key_hash: Vec<u8>,
    /// The certificate's serial number (DER `INTEGER` content bytes).
    pub serial_number: Vec<u8>,
}

impl CertId {
    /// Construct a `CertID` directly from the raw material.
    ///
    /// * `issuer_name_der` — DER encoding of the issuer's `Name`.
    /// * `issuer_spki_value` — the BIT STRING *value* (without tag/length) of
    ///   the issuer's `SubjectPublicKeyInfo`.
    /// * `serial` — the DER `INTEGER` content bytes of the certificate serial
    ///   number.
    pub fn new(
        hash: HashAlgorithm,
        issuer_name_der: &[u8],
        issuer_spki_value: &[u8],
        serial: &[u8],
    ) -> Self {
        let name_hash = hash.digest(issuer_name_der);
        let key_hash = hash.digest(issuer_spki_value);
        CertId {
            hash_algorithm: hash,
            issuer_name_hash: name_hash,
            issuer_key_hash: key_hash,
            serial_number: serial.to_vec(),
        }
    }

    /// Construct a `CertID` for `serial` issued by the CA in `issuer_cert_der`.
    pub fn from_issuer_and_serial(
        hash: HashAlgorithm,
        issuer_cert_der: &[u8],
        serial: &[u8],
    ) -> OcspResult<Self> {
        let cert = Certificate::from_der(issuer_cert_der)
            .map_err(|e| OcspError::Crypto(format!("invalid issuer cert: {e}")))?;
        let tbs = cert.tbs_certificate();
        let issuer_name_der = tbs
            .issuer()
            .to_der()
            .map_err(|e| OcspError::Crypto(e.to_string()))?;
        let spki = tbs.subject_public_key_info();
        let spki_value = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| OcspError::Crypto("issuer has no public key".into()))?;
        Ok(CertId::new(hash, &issuer_name_der, spki_value, serial))
    }

    pub(crate) fn to_wire(&self) -> OcspResult<CertIdWire<'static>> {
        Ok(CertIdWire {
            hash_algorithm: self.hash_algorithm.algorithm_id(),
            issuer_name_hash: OctetString::new(self.issuer_name_hash.clone())
                .map_err(OcspError::from)?,
            issuer_key_hash: OctetString::new(self.issuer_key_hash.clone())
                .map_err(OcspError::from)?,
            serial_number: Uint::new(&self.serial_number).map_err(OcspError::from)?,
        })
    }

    pub(crate) fn from_wire(w: &CertIdWire) -> OcspResult<Self> {
        let hash = HashAlgorithm::from_oid(&w.hash_algorithm.oid)?;
        Ok(CertId {
            hash_algorithm: hash,
            issuer_name_hash: w.issuer_name_hash.as_bytes().to_vec(),
            issuer_key_hash: w.issuer_key_hash.as_bytes().to_vec(),
            serial_number: w.serial_number.as_bytes().to_vec(),
        })
    }
}
