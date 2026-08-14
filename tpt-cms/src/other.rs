//! RFC 5652 `DigestedData` and `EncryptedData` content types.
//!
//! `DigestedData` is a message digest of content (useful for content integrity
//! without a signature); `EncryptedData` is symmetric content encryption where the
//! content-encryption key is distributed out of band (no key transport or key
//! agreement is used).

use const_oid::ObjectIdentifier;
use der::{
    asn1::{AnyRef, ObjectIdentifierRef, OctetStringRef, UintRef},
    Sequence,
};

use crate::crypto::{ContentEncryption, HashAlgorithm};
use crate::error::{CmsError, Result};
use crate::oids;
use crate::wire::{self, ContentInfo, EncapsulatedContentInfo};

/// Build a `DigestedData` `ContentInfo` (DER) digesting `content` with `hash`.
pub fn build_digested_data(content: &[u8], hash: HashAlgorithm) -> Result<Vec<u8>> {
    let digest = hash.digest(content);
    let eci = wire::sequence(&[
        wire::oid_der(&oids::oid(oids::ID_DATA)),
        wire::ctx(0, &wire::octet_string(content)),
    ]);
    let dd = wire::sequence(&[
        wire::integer_u64(0),
        wire::algorithm_identifier(&hash.oid(), None),
        eci,
        wire::octet_string(&digest),
    ]);
    Ok(wire::sequence(&[
        wire::oid_der(&oids::oid(oids::ID_DIGESTED_DATA)),
        wire::ctx(0, &dd),
    ]))
}

/// Verify a `DigestedData` `ContentInfo` (DER), returning the encapsulated content.
pub fn verify_digested_data(der: &[u8]) -> Result<Vec<u8>> {
    let ci = ContentInfo::from_der(der)?;
    if ci.content_type.to_string() != oids::ID_DIGESTED_DATA {
        return Err(CmsError::UnexpectedContentType {
            expected: oids::ID_DIGESTED_DATA.into(),
            got: ci.content_type.to_string(),
        });
    }
    let dd = ci.content_as::<DigestedData>()?;
    let content = dd.encap_content_info.content_bytes()?;
    let hash = HashAlgorithm::from_oid(&dd.digest_algorithm.oid.to_owned())?;
    let computed = hash.digest(&content);
    if computed != dd.digest.as_bytes() {
        return Err(CmsError::MessageDigestMismatch);
    }
    Ok(content)
}

/// Build an `EncryptedData` `ContentInfo` (DER) encrypting `content` with `key`.
///
/// The content-encryption key `key` is shared out of band; `EncryptedData` uses
/// no recipient information.
pub fn build_encrypted_data(
    content: &[u8],
    content_enc: ContentEncryption,
    key: &[u8],
) -> Result<Vec<u8>> {
    use rand_core::{OsRng, RngCore};
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    let encrypted = content_enc.encrypt(key, &iv, content)?;
    let iv_param = wire::octet_string(&iv);
    let eci = wire::sequence(&[
        wire::oid_der(&content_enc.oid()),
        wire::algorithm_identifier(&content_enc.oid(), Some(&iv_param)),
        wire::ctx(0, &wire::octet_string(&encrypted)),
    ]);
    let ed = wire::sequence(&[wire::integer_u64(0), eci]);
    Ok(wire::sequence(&[
        wire::oid_der(&oids::oid(oids::ID_ENCRYPTED_DATA)),
        wire::ctx(0, &ed),
    ]))
}

/// Decrypt an `EncryptedData` `ContentInfo` (DER) with the out-of-band `key`.
pub fn decrypt_encrypted_data(der: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let ci = ContentInfo::from_der(der)?;
    if ci.content_type.to_string() != oids::ID_ENCRYPTED_DATA {
        return Err(CmsError::UnexpectedContentType {
            expected: oids::ID_ENCRYPTED_DATA.into(),
            got: ci.content_type.to_string(),
        });
    }
    let ed = ci.content_as::<EncryptedDataWrapper>()?;
    let eci = &ed.encrypted_content_info;
    let ct: ObjectIdentifier = (*eci.e_content_type).clone();
    let content_enc = ContentEncryption::from_oid(&ct)?;
    let iv = {
        let params = eci
            .content_enc_alg
            .parameters
            .as_ref()
            .ok_or_else(|| CmsError::Crypto("missing IV".into()))?;
        OctetStringRef::from_der(params.value)?.as_bytes().to_vec()
    };
    let encrypted = eci
        .encrypted_content
        .as_ref()
        .ok_or(CmsError::MissingContent)?;
    let encrypted = OctetStringRef::from_der(encrypted.value)?.as_bytes().to_vec();
    content_enc.decrypt(key, &iv, &encrypted)
}

// ---------------------------------------------------------------------------
// DER structures
// ---------------------------------------------------------------------------

#[derive(Clone, Sequence)]
struct DigestedData<'a> {
    version: UintRef<'a>,
    digest_algorithm: ObjectIdentifierRef<'a>,
    encap_content_info: EncapsulatedContentInfo<'a>,
    digest: OctetStringRef<'a>,
}

#[derive(Clone, Sequence)]
struct EncryptedDataWrapper<'a> {
    version: UintRef<'a>,
    encrypted_content_info: EncryptedContentInfoFull<'a>,
    #[asn1(context_specific = "1", constructed, optional)]
    unprotected_attrs: Option<AnyRef<'a>>,
}

#[derive(Clone, Sequence)]
struct EncryptedContentInfoFull<'a> {
    e_content_type: ObjectIdentifierRef<'a>,
    content_enc_alg: ObjectIdentifierRef<'a>,
    #[asn1(context_specific = "0", constructed, optional)]
    encrypted_content: Option<AnyRef<'a>>,
}
