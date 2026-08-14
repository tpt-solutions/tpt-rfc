//! RFC 5652 `SignedData`: signing, verification, certificate bundling, and
//! multiple-signer support.

use const_oid::ObjectIdentifier;
use der::asn1::{Any, GeneralizedTime, OctetString, OctetStringRef};
use der::{Decode, Encode, Tag, Tagged};
use x509_cert::Certificate;

use crate::cert::{find_signer_cert, parse_cert, verify_chain};
use crate::crypto::{public_key_from_spki, verify_signature, HashAlgorithm, SigningKey};
use crate::error::{CmsError, Result};
use crate::oids;
use crate::wire;

/// A signer entry for building `SignedData`: its signing key and certificate.
pub struct CmsSigner {
    pub key: SigningKey,
    pub cert: Certificate,
}

impl CmsSigner {
    pub fn new(key: SigningKey, cert: Certificate) -> Self {
        CmsSigner { key, cert }
    }
}

/// Build a `ContentInfo` wrapping a `SignedData` over `content`.
///
/// The content is encapsulated as `id-data` by default; `content_type` selects
/// the `eContentType`. All signer certificates (and any `extra_certs`) are
/// bundled into the `certificates` set.
pub fn build_signed_data(
    content_type: &ObjectIdentifier,
    content: &[u8],
    signers: &[CmsSigner],
    extra_certs: &[Certificate],
) -> Result<Vec<u8>> {
    if signers.is_empty() {
        return Err(CmsError::Crypto("at least one signer is required".into()));
    }

    let encapsulated = wire::sequence(&[
        wire::oid_der(content_type),
        wire::implicit_octet_string(0, content),
    ]);

    let mut digest_algs: Vec<Vec<u8>> = Vec::new();
    let mut signer_infos: Vec<Vec<u8>> = Vec::new();

    for s in signers {
        let (hash, digest_oid_str) = match &s.key {
            SigningKey::EcdsaP256(_) => (HashAlgorithm::Sha256, oids::SHA256),
            SigningKey::EcdsaP384(_) => (HashAlgorithm::Sha384, oids::SHA384),
            SigningKey::Rsa(_) => (HashAlgorithm::Sha256, oids::SHA256),
            SigningKey::Ed25519(_) => (HashAlgorithm::Sha512, oids::SHA512),
        };
        let digest_oid = oids::oid(digest_oid_str);

        // Signed attributes: contentType, messageDigest, signingTime (sorted by DER).
        let content_digest = hash.digest(content);
        let ct_attr = wire::attribute(&oids::oid(oids::CONTENT_TYPE), &wire::oid_der(content_type));
        let md_attr = wire::attribute(
            &oids::oid(oids::MESSAGE_DIGEST),
            &wire::octet_string(&content_digest),
        );
        let st_attr = {
            let now = der::DateTime::try_from(std::time::SystemTime::now())
                .map_err(|e| CmsError::Crypto(e.to_string()))?;
            let gt = GeneralizedTime::from(now).to_der()?;
            wire::attribute(&oids::oid(oids::SIGNING_TIME), &gt)
        };
        let mut attrs = vec![ct_attr, md_attr, st_attr];
        attrs.sort();
        let signed_attrs_content: Vec<u8> = attrs.concat();

        // The signature is computed over the DER encoding of the SET OF
        // SignedAttributes (which includes the SET tag), per RFC 5652 §5.4.
        let signed_attrs_set = wire::signed_attrs_tlv(&signed_attrs_content);
        let message: Vec<u8> = if let SigningKey::Ed25519(_) = &s.key {
            signed_attrs_set.clone()
        } else {
            hash.digest(&signed_attrs_set)
        };

        let (sig_oid, signature) = s.key.sign(hash, &message)?;

        // SignerIdentifier = IssuerAndSerialNumber from the signer certificate.
        let issuer = s
            .cert
            .tbs_certificate()
            .issuer()
            .to_der()
            .map_err(CmsError::Asn1)?;
        let serial = s.cert.tbs_certificate().serial_number().as_bytes().to_vec();
        let sid = wire::sequence(&[issuer, wire::integer_be(&serial)]);

        let signer_info = wire::sequence(&[
            wire::integer_u64(1), // SignerInfo version 1 for IssuerAndSerialNumber
            sid,
            wire::algorithm_identifier(&digest_oid, None),
            wire::ctx(0, &signed_attrs_content),
            wire::algorithm_identifier(&sig_oid, None),
            wire::octet_string(&signature),
        ]);
        signer_infos.push(signer_info);

        let alg = wire::algorithm_identifier(&digest_oid, None);
        if !digest_algs.contains(&alg) {
            digest_algs.push(alg);
        }
    }

    // Certificate set (IMPLICIT [0] SET OF Certificate).
    let mut cert_der_list: Vec<Vec<u8>> = signers
        .iter()
        .map(|s| s.cert.to_der().expect("cert der"))
        .collect();
    cert_der_list.extend(extra_certs.iter().map(|c| c.to_der().expect("cert der")));
    cert_der_list.sort();
    let certs_set_content: Vec<u8> = cert_der_list.concat();

    let signed_data = wire::sequence(&[
        wire::integer_u64(3), // SignedData version 3 (certificates present)
        wire::set_of(&digest_algs),
        encapsulated,
        wire::ctx(0, &certs_set_content),
        wire::set_of(&signer_infos),
    ]);

    let content_info = wire::sequence(&[
        wire::oid_der(&oids::oid(oids::ID_SIGNED_DATA)),
        wire::ctx(0, &signed_data),
    ]);
    Ok(content_info)
}

/// Result of verifying a `SignedData`.
#[derive(Debug, Clone)]
pub struct VerifiedSignedData {
    pub content_type: ObjectIdentifier,
    pub content: Vec<u8>,
    /// Number of signers that verified successfully.
    pub signer_count: usize,
}

/// Verify a `SignedData` `ContentInfo` (DER). If `anchors` is non-empty, the
/// signer certificate of each accepted signer must additionally chain to one of
/// the anchors. Returns the encapsulated content of the first valid signer.
pub fn verify_signed_data(der: &[u8], anchors: &[Certificate]) -> Result<VerifiedSignedData> {
    let (ct, content_der) = decode_content_info(der)?;
    if ct.to_string() != oids::ID_SIGNED_DATA {
        return Err(CmsError::UnexpectedContentType {
            expected: oids::ID_SIGNED_DATA.into(),
            got: ct.to_string(),
        });
    }
    let sd = parse_signed_data(&content_der)?;
    let certs = parse_cert_set(&sd.certificates)?;

    let mut verified = 0usize;
    for si in &sd.signer_infos {
        let Some(cert) = find_signer_cert(
            &certs,
            &si.sid_issuer,
            &si.sid_serial,
            si.sid_ski.as_deref(),
        ) else {
            return Err(CmsError::SignerCertNotFound);
        };

        let hash = HashAlgorithm::from_oid(&si.digest_alg)?;
        let content_digest = hash.digest(&sd.e_content);

        let (message, signed_attrs_present) = if let Some(sa) = &si.signed_attrs {
            let attrs = parse_attributes(sa)?;
            let mut got_ct = false;
            let mut got_md = false;
            for (oid, val) in &attrs {
                if oid == oids::CONTENT_TYPE {
                    let ct_val = ObjectIdentifier::from_der(val.as_slice()).map_err(CmsError::Asn1)?;
                    if ct_val.to_string() != sd.e_content_type.to_string() {
                        return Err(CmsError::ContentTypeMismatch);
                    }
                    got_ct = true;
                } else if oid == oids::MESSAGE_DIGEST {
                    let md = OctetString::from_der(val.as_slice()).map_err(CmsError::Asn1)?;
                    if md.as_bytes() != content_digest {
                        return Err(CmsError::MessageDigestMismatch);
                    }
                    got_md = true;
                }
            }
            if !got_ct || !got_md {
                return Err(CmsError::Crypto(
                    "signed attributes missing content-type or message-digest".into(),
                ));
            }
            (hash.digest(&wire::signed_attrs_tlv(sa)), true)
        } else {
            (content_digest.clone(), false)
        };

        // For Ed25519 the signature is over the data itself (no pre-hash).
        let is_ed25519 = si.sig_alg.to_string() == oids::ED25519;
        let message: Vec<u8> = if is_ed25519 {
            if signed_attrs_present {
                wire::signed_attrs_tlv(si.signed_attrs.as_ref().unwrap())
            } else {
                sd.e_content.clone()
            }
        } else {
            message
        };

        let pk = public_key_from_spki(cert.tbs_certificate().subject_public_key_info())?;
        verify_signature(&si.sig_alg, &message, &si.signature, &pk)?;

        if !anchors.is_empty() {
            verify_chain(&cert, &certs, anchors)?;
        }
        verified += 1;
    }

    if verified == 0 {
        return Err(CmsError::Signature("no signers could be verified".into()));
    }

    Ok(VerifiedSignedData {
        content_type: sd.e_content_type,
        content: sd.e_content,
        signer_count: verified,
    })
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// `ContentInfo` — `{ contentType, content [0] EXPLICIT ANY }` (RFC 5652 §3).
fn decode_content_info(der: &[u8]) -> Result<(ObjectIdentifier, Vec<u8>)> {
    let seq = Any::from_der(der).map_err(CmsError::Asn1)?;
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

struct ParsedSignedData {
    e_content_type: ObjectIdentifier,
    e_content: Vec<u8>,
    certificates: Option<Vec<u8>>,
    signer_infos: Vec<ParsedSignerInfo>,
}

struct ParsedSignerInfo {
    sid_issuer: Vec<u8>,
    sid_serial: Vec<u8>,
    sid_ski: Option<Vec<u8>>,
    digest_alg: ObjectIdentifier,
    signed_attrs: Option<Vec<u8>>,
    sig_alg: ObjectIdentifier,
    signature: Vec<u8>,
}

fn parse_signed_data(content_der: &[u8]) -> Result<ParsedSignedData> {
    let seq = Any::from_der(content_der).map_err(CmsError::Asn1)?;
    wire::ensure_tag(seq.tag(), Tag::Sequence)?;
    let mut c = wire::Cursor::new(seq.value());

    let _version = c.take()?; // INTEGER
    let _digest_algs = c.take()?; // SET OF AlgorithmIdentifier

    let encap = c.take()?;
    wire::ensure_tag(encap.tag(), Tag::Sequence)?;
    let mut ec = wire::Cursor::new(encap.value());
    let e_content_type = wire::oid_of(&ec.take()?)?;
    let e_content = if ec.at_end() {
        Vec::new()
    } else {
        let e = ec.take()?;
        wire::ensure_tag(e.tag(), wire::ctx_tag_prim(0))?; // [0] IMPLICIT OCTET STRING
        e.value().to_vec()
    };

    let certificates = if !c.at_end() && c.peek_tag() == Some(wire::ctx_tag(0)) {
        Some(c.take()?.value().to_vec())
    } else {
        None
    };
    // crls [1] IMPLICIT SET OF Certificate (optional, ignored here).
    if !c.at_end() && c.peek_tag() == Some(wire::ctx_tag(1)) {
        c.take()?;
    }

    let si_raw = wire::take_set_of_raw(&mut c)?;
    let mut signer_infos = Vec::with_capacity(si_raw.len());
    for d in &si_raw {
        signer_infos.push(parse_signer_info(d)?);
    }

    Ok(ParsedSignedData {
        e_content_type,
        e_content,
        certificates,
        signer_infos,
    })
}

fn parse_signer_info(der: &[u8]) -> Result<ParsedSignerInfo> {
    let seq = Any::from_der(der).map_err(CmsError::Asn1)?;
    wire::ensure_tag(seq.tag(), Tag::Sequence)?;
    let mut c = wire::Cursor::new(seq.value());

    let _version = c.take()?;
    let sid = c.take()?;

    let (sid_issuer, sid_serial, sid_ski) = if sid.tag() == Tag::Sequence {
        let mut ias = wire::Cursor::new(sid.value());
        let issuer = ias.take()?;
        let serial = ias.take()?;
        (
            issuer.to_der().map_err(CmsError::Asn1)?.to_vec(),
            wire::integer_value(&serial)?,
            None,
        )
    } else if sid.tag() == wire::ctx_tag_prim(0) {
        (Vec::new(), Vec::new(), Some(sid.value().to_vec()))
    } else {
        return Err(wire::unexpected_tag(sid.tag(), Tag::Sequence));
    };

    let digest_alg = wire::algid_of(&c.take()?)?.oid.to_owned();

    let signed_attrs = if !c.at_end() && c.peek_tag() == Some(wire::ctx_tag(0)) {
        Some(c.take()?.value().to_vec())
    } else {
        None
    };

    let sig_alg = wire::algid_of(&c.take()?)?.oid.to_owned();
    let signature = wire::octet_value(&c.take()?)?;

    Ok(ParsedSignerInfo {
        sid_issuer,
        sid_serial,
        sid_ski,
        digest_alg,
        signed_attrs,
        sig_alg,
        signature,
    })
}

/// Parse the `certificates` `IMPLICIT [0]` set into individual certificates.
fn parse_cert_set(raw: &Option<Vec<u8>>) -> Result<Vec<Certificate>> {
    let mut out = Vec::new();
    let Some(raw) = raw else {
        return Ok(out);
    };
    let elems = wire::parse_set_elements_raw(raw)?;
    for e in elems {
        out.push(parse_cert(e)?);
    }
    Ok(out)
}

/// Parse a SET OF `SignedAttribute` into `(attrType OID string, first value DER)`.
fn parse_attributes(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let elems = wire::parse_set_elements_raw(data)?;
    let mut out = Vec::new();
    for e in elems {
        let mut c = wire::Cursor::new(e);
        let atype = c.take()?;
        let oid = wire::oid_of(&atype)?.to_string();
        let av = c.take()?;
        wire::ensure_tag(av.tag(), Tag::Set)?;
        let mut ac = wire::Cursor::new(av.value());
        let first = ac.take()?;
        out.push((oid, first.to_der().map_err(CmsError::Asn1)?.to_vec()));
    }
    Ok(out)
}
