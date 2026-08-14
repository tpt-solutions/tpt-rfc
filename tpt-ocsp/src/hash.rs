// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hash algorithm mapping (RFC 6960 CertID / signature digest algorithm).

use const_oid::ObjectIdentifier;
use der::asn1::ObjectIdentifierRef;
use sha1::{Digest as _, Sha1};
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use spki::AlgorithmIdentifierRef;

use crate::error::{OcspError, OcspResult};
use crate::oids;

/// Hash algorithms supported for RFC 6960 issuer-name/issuer-key hashes and
/// signature digests.
///
/// SHA-1 is retained because it is still the default `HashAlgorithm` used by a
/// large number of deployed OCSP responders for `CertID` construction, even
/// though SHA-256 is preferred for new deployments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-1.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl HashAlgorithm {
    /// The OID identifying this hash algorithm.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            HashAlgorithm::Sha1 => oids::oid(oids::SHA1),
            HashAlgorithm::Sha256 => oids::oid(oids::SHA256),
            HashAlgorithm::Sha384 => oids::oid(oids::SHA384),
            HashAlgorithm::Sha512 => oids::oid(oids::SHA512),
        }
    }

    /// AlgorithmIdentifier with a `NULL` parameter (the form used by RFC 6960
    /// for `CertID.hashAlgorithm`).
    pub fn algorithm_id(&self) -> AlgorithmIdentifierRef<'static> {
        AlgorithmIdentifierRef {
            oid: self.oid(),
            parameters: Some(crate::verify::null_params()),
        }
    }

    /// Parse a hash algorithm from its OID.
    pub fn from_oid(oid: &ObjectIdentifier) -> OcspResult<Self> {
        match oid {
            o if *o == oids::oid(oids::SHA1) => Ok(HashAlgorithm::Sha1),
            o if *o == oids::oid(oids::SHA256) => Ok(HashAlgorithm::Sha256),
            o if *o == oids::oid(oids::SHA384) => Ok(HashAlgorithm::Sha384),
            o if *o == oids::oid(oids::SHA512) => Ok(HashAlgorithm::Sha512),
            other => Err(OcspError::UnsupportedHash(other.to_string())),
        }
    }

    /// The digest size in bytes.
    pub fn output_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha1 => 20,
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }

    /// Hash `data` with this algorithm.
    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlgorithm::Sha1 => Sha1::digest(data).to_vec(),
            HashAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
            HashAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
            HashAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}
