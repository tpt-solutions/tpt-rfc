//! Client-side request building for RFC 3161 (and a thin response decoder).

use const_oid::ObjectIdentifier;
use der::asn1::{OctetStringRef, UintRef};
use spki::AlgorithmIdentifierRef;

use crate::error::{Result, TspError};
use crate::hash::HashAlgorithm;
use crate::oids;
use crate::signer::uint_be;
use crate::wire::{MessageImprint, TimeStampReq};

/// Builder for a DER-encoded `TimeStampReq`.
///
/// ```ignore
/// let req = TimeStampReqBuilder::new(HashAlgorithm::Sha256, b"data")
///     .nonce(1234)
///     .cert_req(true)
///     .build()?;
/// ```
pub struct TimeStampReqBuilder {
    hash: HashAlgorithm,
    data: Vec<u8>,
    policy: Option<ObjectIdentifier>,
    nonce: Option<u64>,
    cert_req: bool,
}

impl TimeStampReqBuilder {
    /// Start a request requesting a timestamp over `data` (hashed with `hash`).
    pub fn new(hash: HashAlgorithm, data: &[u8]) -> Self {
        TimeStampReqBuilder {
            hash,
            data: data.to_vec(),
            policy: None,
            nonce: None,
            cert_req: false,
        }
    }

    /// Request a specific TSA policy OID.
    pub fn policy(mut self, policy: ObjectIdentifier) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Include a `nonce` for replay protection / later cross-checking.
    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Request that the TSA return its signer certificate in the response.
    pub fn cert_req(mut self, cert_req: bool) -> Self {
        self.cert_req = cert_req;
        self
    }

    /// Build the DER-encoded `TimeStampReq`.
    pub fn build(&self) -> Result<Vec<u8>> {
        let hashed = self.hash.digest(&self.data);
        let hash_oid = self.hash.oid();
        let version = uint_be(1);

        let req = TimeStampReq {
            version: UintRef::new(&version).map_err(der_err)?,
            message_imprint: MessageImprint {
                hash_algorithm: AlgorithmIdentifierRef {
                    oid: (&hash_oid).into(),
                    parameters: None,
                },
                hashed_message: OctetStringRef::new(&hashed).map_err(der_err)?,
            },
            req_policy: self.policy.as_ref().map(|p| p.into()),
            nonce: self
                .nonce
                .map(|n| {
                    let b = uint_be(n);
                    UintRef::new(&b).map_err(der_err)
                })
                .transpose()?,
            cert_req: if self.cert_req {
                Some(true)
            } else {
                None
            },
            extensions: None,
        };
        req.to_der().map_err(der_err)
    }
}

fn der_err(e: der::Error) -> TspError {
    TspError::Der(e)
}
