//! RFC 5652 `SignedData`: signing, verification, certificate bundling, and
//! multiple-signer support.

use const_oid::ObjectIdentifier;
use der::asn1::{GeneralizedTime, OctetStringRef};
use x509_cert::Certificate;

use crate::cert::{find_signer_cert, parse_cert, verify_chain};
use crate::crypto::{public_key_from_spki, HashAlgorithm, SigningKey, verify_signature};
use crate::error::{CmsError, Result};
use crate::oids;
use crate::wire::{
    self, Attribute, ContentInfo, IssuerAndSerialNumber, RawContent, SignedData, SignerInfos,
};

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

    let e_content_der = wire::octet_string(content);
    let encapsulated = wire::sequence(&[
        wire::oid_der(content_type),
        wire::ctx(0, &e_content_der),
    ]);

    let mut digest_algs: Vec<Vec<u8>> = Vec::new();
    let mut signer_infos: Vec<Vec<u8>> = Vec::new();

    for s in signers {
        let (hash, digest_oid) = match &s.key {
            SigningKey::EcdsaP256(_) => (HashAlgorithm::Sha256, oids::SHA256),
            SigningKey::EcdsaP384(_) => (HashAlgorithm::Sha384, oids::SHA384),
            SigningKey::Rsa(_) => (HashAlgorithm::Sha256, oids::SHA256),
            SigningKey::Ed25519(_) => (HashAlgorithm::Sha512, oids::SHA512),
        };
        let digest_oid = oids::oid(digest_oid);

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

        // The signature is computed over the DER-encoded SET OF SignedAttributes.
        let signed_attrs_set = wire::signed_attrs_tlv(&signed_attrs_content);
        let message: Vec<u8> = if let SigningKey::Ed25519(_) = &s.key {
            signed_attrs_set.clone()
        } else {
            hash.digest(&signed_attrs_set)
        };

        let (sig_oid, signature) = s.key.sign(hash, &message)?;

        // SignerIdentifier = IssuerAndSerialNumber from the signer certificate.
        let issuer = s.cert.tbs_certificate().issuer().to_der()?;
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
    let mut cert_der_list: Vec<Vec<u8>> = signers.iter().map(|s| s.cert.to_der().unwrap()).collect();
    cert_der_list.extend(extra_certs.iter().map(|c| c.to_der().unwrap()));
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
    let ci = ContentInfo::from_der(der)?;
    if ci.content_type.to_string() != oids::ID_SIGNED_DATA {
        return Err(CmsError::UnexpectedContentType {
            expected: oids::ID_SIGNED_DATA.into(),
            got: ci.content_type.to_string(),
        });
    }
    let sd = ci.content_as::<SignedData>()?;
    let certs = parse_cert_set(&sd.certificates)?;

    let content = sd.encap_content_info.content_bytes()?;
    let e_content_type = sd.encap_content_info.e_content_type.to_string();

    let mut verified = 0usize;
    for si in &sd.signer_infos.0 {
        let Some(cert) = find_signer_cert(&certs, &si.sid) else {
            return Err(CmsError::SignerCertNotFound);
        };

        let hash = HashAlgorithm::from_oid(&si.digest_algorithm.oid.to_owned())?;
        let content_digest = hash.digest(&content);

        let (mut base, signed_attrs_present) = if let Some(sa) = &si.signed_attrs {
            let attrs = wire::decode_set_elements::<Attribute>(&sa.0)?;
            let mut got_ct = false;
            let mut got_md = false;
            for a in &attrs {
                match a.attr_type.to_string().as_str() {
                    oids::CONTENT_TYPE => {
                        let v = a
                            .attr_values
                            .get(0)
                            .ok_or(CmsError::Crypto("empty content-type value".into()))?;
                        let ct = ObjectIdentifier::from_der(v.as_bytes())
                            .map_err(|e| CmsError::Crypto(e.to_string()))?;
                        if ct.to_string() != e_content_type {
                            return Err(CmsError::ContentTypeMismatch);
                        }
                        got_ct = true;
                    }
                    oids::MESSAGE_DIGEST => {
                        let v = a
                            .attr_values
                            .get(0)
                            .ok_or(CmsError::Crypto("empty message-digest value".into()))?;
                        let md = OctetStringRef::from_der(v.as_bytes())?.as_bytes().to_vec();
                        if md != content_digest {
                            return Err(CmsError::MessageDigestMismatch);
                        }
                        got_md = true;
                    }
                    _ => {}
                }
            }
            if !got_ct || !got_md {
                return Err(CmsError::Crypto(
                    "signed attributes missing content-type or message-digest".into(),
                ));
            }
            (hash.digest(&wire::signed_attrs_tlv(&sa.0)), true)
        } else {
            (content_digest.clone(), false)
        };

        // For Ed25519 the signature is over the DER SET (or the content) itself.
        let is_ed25519 = si.signature_algorithm.oid.to_string() == oids::ED25519;
        let message: Vec<u8> = if is_ed25519 {
            if signed_attrs_present {
                wire::signed_attrs_tlv(&si.signed_attrs.as_ref().unwrap().0)
            } else {
                content.clone()
            }
        } else {
            base
        };

        let pk = public_key_from_spki(cert.tbs_certificate().subject_public_key_info())?;
        verify_signature(&si.signature_algorithm.oid.to_owned(), &message, si.signature.as_bytes(), &pk)?;

        if !anchors.is_empty() {
            verify_chain(&cert, &certs, anchors)?;
        }
        verified += 1;
    }

    if verified == 0 {
        return Err(CmsError::Signature("no signers could be verified".into()));
    }

    Ok(VerifiedSignedData {
        content_type: sd.encap_content_info.e_content_type.to_owned(),
        content,
        signer_count: verified,
    })
}

/// Parse the `certificates` `IMPLICIT [0]` set into individual certificates.
fn parse_cert_set(raw: &Option<RawContent>) -> Result<Vec<Certificate>> {
    let mut out = Vec::new();
    let Some(raw) = raw else {
        return Ok(out);
    };
    let mut rest = raw.0.as_slice();
    while !rest.is_empty() {
        let any = der::asn1::AnyRef::from_der(rest)?;
        let consumed = any.as_bytes().len();
        let cert = parse_cert(any.as_bytes())?;
        out.push(cert);
        rest = &rest[consumed..];
    }
    Ok(out)
}

