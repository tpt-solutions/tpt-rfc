//! RFC 5652 `DigestedData` and `EncryptedData` content types.
//!
//! `DigestedData` is a message digest of content (useful for content integrity
//! without a signature); `EncryptedData` is symmetric content encryption where the
//! content-encryption key is distributed out of band (no key transport or key
//! agreement is used).

use const_oid::ObjectIdentifier;
use der::asn1::{AnyRef, OctetStringRef};
use der::Tag;

use crate::crypto::{ContentEncryption, HashAlgorithm};
use crate::error::{CmsError, Result};
use crate::oids;
use crate::wire;

/// Build a `DigestedData` `ContentInfo` (DER) digesting `content` with `hash`.
pub fn build_digested_data(content: &[u8], hash: HashAlgorithm) -> Result<Vec<u8>> {
    let digest = hash.digest(content);
    let eci = wire::sequence(&[
        wire::oid_der(&oids::oid(oids::ID_DATA)),
        wire::implicit_octet_string(0, content),
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
    let (ct, content_der) = decode_content_info(der)?;
    if ct.to_string() != oids::ID_DIGESTED_DATA {
        return Err(CmsError::UnexpectedContentType {
            expected: oids::ID_DIGESTED_DATA.into(),
            got: ct.to_string(),
        });
    }
    let seq = AnyRef::from_der(&content_der).map_err(CmsError::Asn1)?;
    wire::ensure_tag(seq.tag(), Tag::Sequence)?;
    let mut c = wire::Cursor::new(seq.value());
    let _version = c.take()?;
    let digest_alg = wire::algid_of(&c.take()?)?.oid.to_owned();
    let hash = HashAlgorithm::from_oid(&digest_alg)?;
    let encap = c.take()?;
    let content = parse_encap_content(&encap)?;
    let digest = wire::octet_value(&c.take()?)?;
    let computed = hash.digest(&content);
    if computed != digest {
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
        wire::implicit_octet_string(0, &encrypted),
    ]);
    let ed = wire::sequence(&[wire::integer_u64(0), eci]);
    Ok(wire::sequence(&[
        wire::oid_der(&oids::oid(oids::ID_ENCRYPTED_DATA)),
        wire::ctx(0, &ed),
    ]))
}

/// Decrypt an `EncryptedData` `ContentInfo` (DER) with the out-of-band `key`.
pub fn decrypt_encrypted_data(der: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let (ct, content_der) = decode_content_info(der)?;
    if ct.to_string() != oids::ID_ENCRYPTED_DATA {
        return Err(CmsError::UnexpectedContentType {
            expected: oids::ID_ENCRYPTED_DATA.into(),
            got: ct.to_string(),
        });
    }
    let seq = AnyRef::from_der(&content_der).map_err(CmsError::Asn1)?;
    wire::ensure_tag(seq.tag(), Tag::Sequence)?;
    let mut c = wire::Cursor::new(seq.value());
    let _version = c.take()?;
    let eci = c.take()?;
    wire::ensure_tag(eci.tag(), Tag::Sequence)?;
    let mut ec = wire::Cursor::new(eci.value());
    let e_content_type = wire::oid_of(&ec.take()?)?.to_owned();
    let alg_any = ec.take()?;
    let algid = wire::algid_of(&alg_any)?;
    let iv = wire::octet_value_param(algid.parameters.as_ref(), "IV")?;
    let content_enc = ContentEncryption::from_oid(&e_content_type)?;
    let encrypted = if ec.at_end() {
        return Err(CmsError::MissingContent);
    } else {
        let e = ec.take()?;
        wire::ensure_tag(e.tag(), wire::ctx_tag_prim(0))?;
        wire::octet_value(&AnyRef::from_der(e.value()).map_err(CmsError::Asn1)?)?
    };
    content_enc.decrypt(key, &iv, &encrypted)
}

// ---------------------------------------------------------------------------
// Shared decode helpers
// ---------------------------------------------------------------------------

fn decode_content_info(der: &[u8]) -> Result<(ObjectIdentifier, Vec<u8>)> {
    let seq = AnyRef::from_der(der).map_err(CmsError::Asn1)?;
    wire::ensure_tag(seq.tag(), Tag::Sequence)?;
    let mut c = wire::Cursor::new(seq.value());
    let ct = wire::oid_of(&c.take()?)?;
    let content = if c.at_end() {
        Vec::new()
    } else {
        let inner = c.take()?;
        wire::ensure_tag(inner.tag(), wire::ctx_tag(0))?;
        inner.value().to_vec()
    };
    Ok((ct, content))
}

/// Parse `EncapsulatedContentInfo` ::= SEQUENCE { eContentType, eContent [0] IMPLICIT OCTET STRING }.
fn parse_encap_content(encap: &AnyRef) -> Result<Vec<u8>> {
    wire::ensure_tag(encap.tag(), Tag::Sequence)?;
    let mut ec = wire::Cursor::new(encap.value());
    let _e_content_type = wire::oid_of(&ec.take()?)?;
    if ec.at_end() {
        Ok(Vec::new())
    } else {
        let e = ec.take()?;
        wire::ensure_tag(e.tag(), wire::ctx_tag_prim(0))?;
        Ok(e.value().to_vec())
    }
}
