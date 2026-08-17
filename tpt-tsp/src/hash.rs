//! Hash algorithm mapping (RFC 3161 message imprint / CMS digest algorithm).

use const_oid::ObjectIdentifier;
use sha2::{Digest, Sha256, Sha384, Sha512};
use spki::AlgorithmIdentifierRef;

use crate::error::{Result, TspError};
use crate::oids;

/// Hash algorithms supported for RFC 3161 message imprints and CMS digests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    /// The OID identifying this hash algorithm.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            HashAlgorithm::Sha256 => oids::oid(oids::SHA256),
            HashAlgorithm::Sha384 => oids::oid(oids::SHA384),
            HashAlgorithm::Sha512 => oids::oid(oids::SHA512),
        }
    }

    /// AlgorithmIdentifier with no parameters (the form used by RFC 3161/CMS).
    pub fn algorithm_id(&self) -> AlgorithmIdentifierRef<'static> {
        AlgorithmIdentifierRef {
            oid: self.oid(),
            parameters: None,
        }
    }

    /// Parse a hash algorithm from its OID.
    pub fn from_oid(oid: &ObjectIdentifier) -> Result<Self> {
        match oid {
            o if *o == oids::oid(oids::SHA256) => Ok(HashAlgorithm::Sha256),
            o if *o == oids::oid(oids::SHA384) => Ok(HashAlgorithm::Sha384),
            o if *o == oids::oid(oids::SHA512) => Ok(HashAlgorithm::Sha512),
            other => Err(TspError::UnsupportedHash(other.to_string())),
        }
    }

    /// The digest size in bytes.
    pub fn output_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }

    /// Hash `data` with this algorithm.
    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
            HashAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
            HashAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}
