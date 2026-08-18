//! RFC 3161 `TimeStampReq` — client-side request generation and parsing.
//!
//! ```text
//! TimeStampReq ::= SEQUENCE  {
//!    version                      INTEGER  { v1(1) },
//!    messageImprint               MessageImprint,
//!    reqPolicy            [0]     OBJECT IDENTIFIER            OPTIONAL,
//!    nonce                [1]     INTEGER                      OPTIONAL,
//!    certReq              [2]     BOOLEAN                      OPTIONAL,
//!    extensions           [3]     IMPLICIT Extensions          OPTIONAL  }
//!
//! MessageImprint ::= SEQUENCE  {
//!    hashAlgorithm                AlgorithmIdentifier,
//!    hashedMessage                OCTET STRING  }
//! ```

use const_oid::ObjectIdentifier;
use der::{Decode, Encode, Tag, Tagged};

use crate::crypto::HashAlgorithm;
use crate::error::{TspError, Result};
use crate::wire;

/// The `MessageImprint` of a `TimeStampReq` / `TSTInfo`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageImprint {
    /// The hash algorithm applied to the message.
    pub hash_algorithm: HashAlgorithm,
    /// The hash output (the `hashedMessage` OCTET STRING).
    pub hashed_message: Vec<u8>,
}

impl MessageImprint {
    pub(crate) fn to_der(&self) -> Vec<u8> {
        wire::sequence(&[
            wire::algorithm_identifier(&self.hash_algorithm.oid(), None),
            wire::octet_string(&self.hashed_message),
        ])
    }

    pub(crate) fn from_der(der_bytes: &[u8]) -> Result<MessageImprint> {
        let seq = der::Any::from_der(der_bytes).map_err(TspError::Asn1)?;
        wire::ensure_tag(seq.tag(), Tag::Sequence)?;
        let mut c = wire::Cursor::new(seq.value());
        let alg = wire::algid_of(&c.take()?)?;
        let hash_algorithm = HashAlgorithm::from_oid(&alg.oid)?;
        let hm = wire::octet_value(&c.take()?)?;
        Ok(MessageImprint {
            hash_algorithm,
            hashed_message: hm,
        })
    }
}

/// A builder for an RFC 3161 `TimeStampReq`.
#[derive(Clone, Debug)]
pub struct TimestampRequest {
    hash: HashAlgorithm,
    message: Vec<u8>,
    policy: Option<ObjectIdentifier>,
    nonce: Option<u64>,
    cert_req: bool,
}

impl TimestampRequest {
    /// Start a request by hashing `message` with `hash` (the `messageImprint`).
    pub fn new(hash: HashAlgorithm, message: &[u8]) -> Self {
        TimestampRequest {
            hash,
            message: hash.digest(message),
            policy: None,
            nonce: None,
            cert_req: true,
        }
    }

    /// Set the requested TSA policy OID (`reqPolicy`, `[0]` IMPLICIT).
    pub fn with_policy(mut self, policy: ObjectIdentifier) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Set the request nonce (`[1]` IMPLICIT INTEGER).
    pub fn with_nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Request that the TSA include its signing certificate (`certReq`, default true).
    pub fn with_cert_req(mut self, cert_req: bool) -> Self {
        self.cert_req = cert_req;
        self
    }

    /// Return the message imprint's hash algorithm.
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        self.hash
    }

    /// Return the already-computed `hashedMessage` bytes.
    pub fn hashed_message(&self) -> &[u8] {
        &self.message
    }

    /// Return the request nonce, if set.
    pub fn nonce(&self) -> Option<u64> {
        self.nonce
    }

    /// Return the requested policy OID, if set.
    pub fn policy(&self) -> Option<&ObjectIdentifier> {
        self.policy.as_ref()
    }

    /// Whether the request asks the TSA to include its certificate.
    pub fn cert_req(&self) -> bool {
        self.cert_req
    }

    /// Build the `MessageImprint` for this request.
    pub fn message_imprint(&self) -> MessageImprint {
        MessageImprint {
            hash_algorithm: self.hash,
            hashed_message: self.message.clone(),
        }
    }

    /// Encode the `TimeStampReq` to DER.
    pub fn to_der(&self) -> Vec<u8> {
        let imprint = self.message_imprint().to_der();
        let mut parts = vec![
            wire::integer_u64(1), // version v1(1)
            imprint,
        ];
        if let Some(p) = &self.policy {
            parts.push(wire::ctx(0, &wire::oid_der(p)));
        }
        if let Some(n) = self.nonce {
            parts.push(wire::ctx(1, &wire::integer_u64(n)));
        }
        // certReq [2] IMPLICIT BOOLEAN (DEFAULT FALSE). Emit only when true.
        if self.cert_req {
            parts.push(wire::ctx(2, &wire::tlv(0x01, &[0xFF])));
        }
        wire::sequence(&parts)
    }
}

/// Parse a `TimeStampReq` from DER.
pub fn parse_timestamp_req(der: &[u8]) -> Result<TimestampRequest> {
    let seq = der::Any::from_der(der).map_err(TspError::Asn1)?;
    wire::ensure_tag(seq.tag(), Tag::Sequence)?;
    let mut c = wire::Cursor::new(seq.value());

    let _version = c.take()?; // INTEGER (v1)
    let imprint = MessageImprint::from_der(&c.take()?.to_der().map_err(TspError::Asn1)?)?;

    let mut policy = None;
    let mut nonce = None;
    let mut cert_req = false;

    while !c.at_end() {
        let peek = c.peek_tag().unwrap();
        match peek {
            t if t == wire::ctx_tag(0) => {
                let v = c.take()?;
                policy = Some(oid_of_der(v.value())?);
            }
            t if t == wire::ctx_tag(1) => {
                let v = c.take()?;
                let int = der::asn1::UintRef::from_der(v.value()).map_err(TspError::Asn1)?;
                let bytes = int.as_bytes();
                let mut n: u64 = 0;
                for b in bytes {
                    n = (n << 8) | (*b as u64);
                }
                nonce = Some(n);
            }
            t if t == wire::ctx_tag(2) => {
                let v = c.take()?;
                cert_req = v.value() == [0xFF];
            }
            t if t == wire::ctx_tag(3) => {
                c.take()?; // extensions — ignored
            }
            _ => break,
        }
    }

    Ok(TimestampRequest {
        hash: imprint.hash_algorithm,
        message: imprint.hashed_message,
        policy,
        nonce,
        cert_req,
    })
}

fn oid_of_der(der: &[u8]) -> Result<ObjectIdentifier> {
    ObjectIdentifier::from_der(der).map_err(TspError::Asn1)
}
