//! RFC 5652 `EnvelopedData`: key transport (RSA) and key agreement (ECDH)
//! recipient information, with AES-CBC content encryption and AES key wrap.

use const_oid::ObjectIdentifier;
use der::asn1::Any;
use der::{Decode, Encode, Tag, Tagged};
use x509_cert::Certificate;

use crate::cert::{cert_issuer_der, cert_serial_bytes};
use crate::crypto::{
    aes_key_unwrap, aes_key_wrap, cms_ecdh_kdf, public_key_from_spki, ContentEncryption,
    HashAlgorithm, KeyWrap, PublicKey,
};
use crate::error::{CmsError, Result};
use crate::oids;
use crate::wire;

use p256::SecretKey as P256Secret;
use p384::SecretKey as P384Secret;
use rand_core::OsRng;
use rand_core::RngCore;
use rsa::pkcs1v15::Pkcs1v15Encrypt;
use rsa::Oaep;
use rsa::RsaPrivateKey;
use sha2_010::Sha256 as Sha256010;

// ---------------------------------------------------------------------------
// Public build/decrypt API
// ---------------------------------------------------------------------------

/// A recipient for `EnvelopedData` construction.
pub enum RecipientSpec {
    /// RSA key transport. `oaep` selects RSAES-OAEP (true) over PKCS#1 v1.5 (false).
    KeyTransRsa { cert: Certificate, oaep: bool },
    /// ECDH key agreement (ephemeral-static). The curve and KDF hash are taken
    /// from the recipient certificate's public key; `wrap` selects the AES key
    /// wrap used to protect the content-encryption key.
    KeyAgreeEcdh { cert: Certificate, wrap: KeyWrap },
}

/// A private key that can open `EnvelopedData`, paired with its certificate so
/// the matching `RecipientInfo` can be located by issuer/serial.
pub enum RecipientPrivateKey {
    Rsa(RsaPrivateKey, Certificate),
    EcdhP256(P256Secret, Certificate),
    EcdhP384(P384Secret, Certificate),
}

/// Build an `EnvelopedData` `ContentInfo` (DER) encrypting `content`.
pub fn build_enveloped_data(
    content: &[u8],
    content_enc: ContentEncryption,
    recipients: &[RecipientSpec],
) -> Result<Vec<u8>> {
    if recipients.is_empty() {
        return Err(CmsError::Crypto(
            "at least one recipient is required".into(),
        ));
    }
    // RSA key transport and ECDH key agreement both use the rand_core 0.6
    // `OsRng`: ECDH ephemeral keys are derived by feeding random bytes from it
    // into `SecretKey::from_slice` (avoiding a second rand_core version pull-in).
    let mut rng = OsRng;

    let cek = random_bytes(&mut rng, content_enc.key_size());
    let iv = random_bytes(&mut rng, content_enc.iv_size());
    let encrypted = content_enc.encrypt(&cek, &iv, content)?;

    let iv_param = wire::octet_string(&iv);
    let encrypted_content_info = wire::sequence(&[
        wire::oid_der(&content_enc.oid()),
        wire::algorithm_identifier(&content_enc.oid(), Some(&iv_param)),
        wire::implicit_octet_string(0, &encrypted),
    ]);

    let mut recipient_infos: Vec<Vec<u8>> = Vec::new();
    let mut uses_keyagree = false;
    for r in recipients {
        match r {
            RecipientSpec::KeyTransRsa { cert, oaep } => {
                let der = build_key_trans(&mut rng, cert, &cek, *oaep)?;
                recipient_infos.push(wire::ctx(0, &der));
            }
            RecipientSpec::KeyAgreeEcdh { cert, wrap } => {
                uses_keyagree = true;
                let der = build_key_agree(&mut rng, cert, &cek, *wrap)?;
                recipient_infos.push(wire::ctx(1, &der));
            }
        }
    }

    let version = if uses_keyagree { 3 } else { 0 };
    let enveloped = wire::sequence(&[
        wire::integer_u64(version),
        wire::set_of(&recipient_infos),
        encrypted_content_info,
    ]);

    Ok(wire::sequence(&[
        wire::oid_der(&oids::oid(oids::ID_ENVELOPED_DATA)),
        wire::ctx(0, &enveloped),
    ]))
}

/// Open an `EnvelopedData` `ContentInfo` (DER) using one of `recipients`.
pub fn open_enveloped_data(der: &[u8], recipients: &[RecipientPrivateKey]) -> Result<Vec<u8>> {
    let (ct, content_der) = decode_content_info(der)?;
    if ct.to_string() != oids::ID_ENVELOPED_DATA {
        return Err(CmsError::UnexpectedContentType {
            expected: oids::ID_ENVELOPED_DATA.into(),
            got: ct.to_string(),
        });
    }
    let ed = parse_enveloped_data(&content_der)?;
    let content_enc = ContentEncryption::from_oid(&ed.e_content_type)?;
    let encrypted = &ed.encrypted_content;

    let mut last_err = None;
    for ri in &ed.recipient_infos {
        match ri {
            ParsedRecipientInfo::KeyTrans(kt) => {
                for rec in recipients {
                    let RecipientPrivateKey::Rsa(key, cert) = rec else {
                        continue;
                    };
                    if !rid_matches(&kt.rid_issuer, &kt.rid_serial, cert) {
                        continue;
                    }
                    match open_key_trans(key, kt) {
                        Ok(cek) => return content_enc.decrypt(&cek, &ed.iv, encrypted),
                        Err(e) => last_err = Some(e),
                    }
                }
            }
            ParsedRecipientInfo::KeyAgree(ka) => {
                for rec in recipients {
                    match rec {
                        RecipientPrivateKey::EcdhP256(key, cert) => {
                            if !rid_matches(&ka.rid_issuer, &ka.rid_serial, cert) {
                                continue;
                            }
                            match open_key_agree_p256(key, ka) {
                                Ok(cek) => return content_enc.decrypt(&cek, &ed.iv, encrypted),
                                Err(e) => last_err = Some(e),
                            }
                        }
                        RecipientPrivateKey::EcdhP384(key, cert) => {
                            if !rid_matches(&ka.rid_issuer, &ka.rid_serial, cert) {
                                continue;
                            }
                            match open_key_agree_p384(key, ka) {
                                Ok(cek) => return content_enc.decrypt(&cek, &ed.iv, encrypted),
                                Err(e) => last_err = Some(e),
                            }
                        }
                        _ => continue,
                    }
                }
            }
        }
    }
    Err(last_err.unwrap_or(CmsError::NoMatchingRecipient))
}

// ---------------------------------------------------------------------------
// Key transport (RSA)
// ---------------------------------------------------------------------------

fn build_key_trans(rng: &mut OsRng, cert: &Certificate, cek: &[u8], oaep: bool) -> Result<Vec<u8>> {
    let spki = cert.tbs_certificate().subject_public_key_info();
    let pk = public_key_from_spki(spki)?;
    let rsa_pub = match pk {
        PublicKey::Rsa(p) => p,
        _ => return Err(CmsError::UnsupportedKey("recipient cert is not RSA".into())),
    };
    let encrypted_key = if oaep {
        rsa_pub
            .encrypt(rng, Oaep::new::<Sha256010>(), cek)
            .map_err(|e| CmsError::Crypto(e.to_string()))?
    } else {
        rsa_pub
            .encrypt(rng, Pkcs1v15Encrypt, cek)
            .map_err(|e| CmsError::Crypto(e.to_string()))?
    };
    let key_enc_oid = oids::oid(if oaep {
        oids::RSAES_OAEP
    } else {
        oids::RSA_ENCRYPTION
    });
    Ok(wire::sequence(&[
        wire::integer_u64(0),
        issuer_serial_der(cert),
        wire::algorithm_identifier(&key_enc_oid, None),
        wire::octet_string(&encrypted_key),
    ]))
}

fn open_key_trans(key: &RsaPrivateKey, kt: &ParsedKeyTrans) -> Result<Vec<u8>> {
    let oid = kt.key_enc_oid.to_string();
    let decrypted = if oid == oids::RSAES_OAEP {
        key.decrypt(Oaep::new::<Sha256010>(), &kt.encrypted_key)
            .map_err(|e| CmsError::Crypto(e.to_string()))?
    } else if oid == oids::RSA_ENCRYPTION {
        key.decrypt(Pkcs1v15Encrypt, &kt.encrypted_key)
            .map_err(|e| CmsError::Crypto(e.to_string()))?
    } else {
        return Err(CmsError::UnsupportedKeyTransport(oid));
    };
    Ok(decrypted)
}

// ---------------------------------------------------------------------------
// Key agreement (ECDH)
// ---------------------------------------------------------------------------

fn build_key_agree(
    rng: &mut OsRng,
    cert: &Certificate,
    cek: &[u8],
    wrap: KeyWrap,
) -> Result<Vec<u8>> {
    let spki = cert.tbs_certificate().subject_public_key_info();
    let pk = public_key_from_spki(spki)?;
    let (curve_oid, recipient_sec1, is_p256) = match pk {
        PublicKey::EcdsaP256(p) => (oids::oid(oids::P256), p.to_sec1_bytes().to_vec(), true),
        PublicKey::EcdsaP384(p) => (oids::oid(oids::P384), p.to_sec1_bytes().to_vec(), false),
        _ => return Err(CmsError::UnsupportedKey("recipient cert is not EC".into())),
    };
    let key_agree_oid = oids::oid(if is_p256 {
        oids::DH_SINGLE_PASS_STD_SHA256
    } else {
        oids::DH_SINGLE_PASS_STD_SHA384
    });
    let key_wrap_alg_der = wrap.algorithm_id();

    // Use a SINGLE ephemeral key for both the shared secret and the published
    // originator public key (so the recipient derives the same `zz`). Random
    // bytes come from the shared `OsRng`; `from_slice` validates the scalar.
    let (zz, eph_sec1) = if is_p256 {
        let mut eph_bytes = [0u8; 32];
        rng.fill_bytes(&mut eph_bytes);
        let eph = P256Secret::from_slice(&eph_bytes)
            .map_err(|e| CmsError::Crypto(e.to_string()))?;
        let recip = p256::PublicKey::from_sec1_bytes(&recipient_sec1)
            .map_err(|e| CmsError::Crypto(e.to_string()))?;
        let zz = p256::ecdh::diffie_hellman(eph.to_nonzero_scalar(), recip.as_affine())
            .raw_secret_bytes()
            .to_vec();
        let pubk = eph.public_key().to_sec1_bytes().to_vec();
        (zz, pubk)
    } else {
        let mut eph_bytes = [0u8; 48];
        rng.fill_bytes(&mut eph_bytes);
        let eph = P384Secret::from_slice(&eph_bytes)
            .map_err(|e| CmsError::Crypto(e.to_string()))?;
        let recip = p384::PublicKey::from_sec1_bytes(&recipient_sec1)
            .map_err(|e| CmsError::Crypto(e.to_string()))?;
        let zz = p384::ecdh::diffie_hellman(eph.to_nonzero_scalar(), recip.as_affine())
            .raw_secret_bytes()
            .to_vec();
        let pubk = eph.public_key().to_sec1_bytes().to_vec();
        (zz, pubk)
    };

    let kek = cms_ecdh_kdf(
        if is_p256 {
            HashAlgorithm::Sha256
        } else {
            HashAlgorithm::Sha384
        },
        &zz,
        &key_wrap_alg_der,
        &[],
        (wrap.key_size() as u32) * 8,
    )?;
    let wrapped_cek = aes_key_wrap(&kek, cek)?;

    let originator_pub = wire::sequence(&[
        wire::algorithm_identifier(
            &oids::oid(oids::EC_PUBLIC_KEY),
            Some(&wire::oid_der(&curve_oid)),
        ),
        wire::bit_string(&eph_sec1),
    ]);
    // originator [0] EXPLICIT { originatorKey [1] EXPLICIT OriginatorPublicKey }
    let originator = wire::ctx(0, &wire::ctx(1, &originator_pub));

    let rek = wire::sequence(&[issuer_serial_der(cert), wire::octet_string(&wrapped_cek)]);
    let recipient_encrypted_keys = wire::sequence(&[rek]);

    Ok(wire::sequence(&[
        wire::integer_u64(3),
        originator,
        wire::algorithm_identifier(&key_agree_oid, Some(&key_wrap_alg_der)),
        recipient_encrypted_keys,
    ]))
}

fn open_key_agree_p256(secret: &P256Secret, ka: &ParsedKeyAgree) -> Result<Vec<u8>> {
    let pubk = p256::PublicKey::from_sec1_bytes(&ka.originator_pub)
        .map_err(|e| CmsError::Crypto(e.to_string()))?;
    let zz = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), pubk.as_affine())
        .raw_secret_bytes()
        .to_vec();
    unwrap_cek(&zz, ka)
}

fn open_key_agree_p384(secret: &P384Secret, ka: &ParsedKeyAgree) -> Result<Vec<u8>> {
    let pubk = p384::PublicKey::from_sec1_bytes(&ka.originator_pub)
        .map_err(|e| CmsError::Crypto(e.to_string()))?;
    let zz = p384::ecdh::diffie_hellman(secret.to_nonzero_scalar(), pubk.as_affine())
        .raw_secret_bytes()
        .to_vec();
    unwrap_cek(&zz, ka)
}

/// Derive the KEK from the ECDH shared secret and unwrap the CEK.
fn unwrap_cek(zz: &[u8], ka: &ParsedKeyAgree) -> Result<Vec<u8>> {
    let wrap = KeyWrap::from_oid(
        &ObjectIdentifier::from_der(&ka.key_wrap_alg_der)
            .map_err(|e| CmsError::Crypto(e.to_string()))?,
    )?;
    let hash = match ka.key_agree_oid.to_string().as_str() {
        oids::DH_SINGLE_PASS_STD_SHA256 => HashAlgorithm::Sha256,
        oids::DH_SINGLE_PASS_STD_SHA384 => HashAlgorithm::Sha384,
        oids::DH_SINGLE_PASS_STD_SHA512 => HashAlgorithm::Sha512,
        other => return Err(CmsError::UnsupportedKeyAgreement(other.into())),
    };
    let kek = cms_ecdh_kdf(
        hash,
        zz,
        &wrap.algorithm_id(),
        &ka.ukm,
        (wrap.key_size() as u32) * 8,
    )?;
    aes_key_unwrap(&kek, &ka.encrypted_key)
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

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

struct ParsedEnvelopedData {
    e_content_type: ObjectIdentifier,
    iv: Vec<u8>,
    encrypted_content: Vec<u8>,
    recipient_infos: Vec<ParsedRecipientInfo>,
}

enum ParsedRecipientInfo {
    KeyTrans(ParsedKeyTrans),
    KeyAgree(ParsedKeyAgree),
}

struct ParsedKeyTrans {
    rid_issuer: Vec<u8>,
    rid_serial: Vec<u8>,
    rid_ski: Option<Vec<u8>>,
    key_enc_oid: ObjectIdentifier,
    encrypted_key: Vec<u8>,
}

struct ParsedKeyAgree {
    originator_pub: Vec<u8>,
    key_agree_oid: ObjectIdentifier,
    key_wrap_alg_der: Vec<u8>,
    ukm: Vec<u8>,
    rid_issuer: Vec<u8>,
    rid_serial: Vec<u8>,
    rid_ski: Option<Vec<u8>>,
    encrypted_key: Vec<u8>,
}

fn parse_enveloped_data(content_der: &[u8]) -> Result<ParsedEnvelopedData> {
    let seq = Any::from_der(content_der).map_err(CmsError::Asn1)?;
    wire::ensure_tag(seq.tag(), Tag::Sequence)?;
    let mut c = wire::Cursor::new(seq.value());

    let _version = c.take()?; // INTEGER
                              // originatorInfo [0] IMPLICIT SET OF (optional, skipped if present).
    if !c.at_end() && c.peek_tag() == Some(wire::ctx_tag(0)) {
        c.take()?;
    }

    let ri_raw = wire::take_set_of_raw(&mut c)?;
    let mut recipient_infos = Vec::with_capacity(ri_raw.len());
    for d in &ri_raw {
        recipient_infos.push(parse_recipient_info(d)?);
    }

    let encap = c.take()?;
    wire::ensure_tag(encap.tag(), Tag::Sequence)?;
    let mut ec = wire::Cursor::new(encap.value());
    let e_content_type = wire::oid_of(&ec.take()?)?;
    let alg_any = ec.take()?;
    let algid = wire::algid_of(&alg_any)?;
    let enc_alg_oid = algid.oid.to_owned();
    let iv = extract_octet_param(algid.parameters.as_ref(), "content-encryption IV")?;

    let encrypted_content = if ec.at_end() {
        Vec::new()
    } else {
        let e = ec.take()?;
        wire::ensure_tag(e.tag(), wire::ctx_tag_prim(0))?; // [0] IMPLICIT OCTET STRING
        e.value().to_vec()
    };

    Ok(ParsedEnvelopedData {
        e_content_type,
        iv,
        encrypted_content,
        recipient_infos,
    })
}

fn parse_recipient_info(der: &[u8]) -> Result<ParsedRecipientInfo> {
    let any = Any::from_der(der).map_err(CmsError::Asn1)?;
    if any.tag() == wire::ctx_tag(0) {
        let inner = Any::from_der(any.value()).map_err(CmsError::Asn1)?;
        wire::ensure_tag(inner.tag(), Tag::Sequence)?;
        Ok(ParsedRecipientInfo::KeyTrans(parse_key_trans(
            inner.value(),
        )?))
    } else if any.tag() == wire::ctx_tag(1) {
        let inner = Any::from_der(any.value()).map_err(CmsError::Asn1)?;
        wire::ensure_tag(inner.tag(), Tag::Sequence)?;
        Ok(ParsedRecipientInfo::KeyAgree(parse_key_agree(
            inner.value(),
        )?))
    } else {
        Err(wire::unexpected_tag(any.tag(), wire::ctx_tag(0)))
    }
}

fn parse_issuer_serial(rid: &Any) -> Result<(Vec<u8>, Vec<u8>, Option<Vec<u8>>)> {
    if rid.tag() == Tag::Sequence {
        let mut ias = wire::Cursor::new(rid.value());
        let issuer = ias.take()?;
        let serial = ias.take()?;
        Ok((
            issuer.to_der().map_err(CmsError::Asn1)?.to_vec(),
            wire::integer_value(&serial)?,
            None,
        ))
    } else if rid.tag() == wire::ctx_tag_prim(0) {
        Ok((Vec::new(), Vec::new(), Some(rid.value().to_vec())))
    } else {
        Err(wire::unexpected_tag(rid.tag(), Tag::Sequence))
    }
}

fn parse_key_trans(body: &[u8]) -> Result<ParsedKeyTrans> {
    let mut c = wire::Cursor::new(body);
    let _version = c.take()?;
    let rid = c.take()?;
    let (rid_issuer, rid_serial, rid_ski) = parse_issuer_serial(&rid)?;
    let key_enc = c.take()?;
    let key_enc_oid = wire::algid_of(&key_enc)?.oid.to_owned();
    let encrypted_key = wire::octet_value(&c.take()?)?;
    Ok(ParsedKeyTrans {
        rid_issuer,
        rid_serial,
        rid_ski,
        key_enc_oid,
        encrypted_key,
    })
}

fn parse_key_agree(body: &[u8]) -> Result<ParsedKeyAgree> {
    let mut c = wire::Cursor::new(body);
    let _version = c.take()?;

    let originator = c.take()?;
    wire::ensure_tag(originator.tag(), wire::ctx_tag(0))?;
    let inner = Any::from_der(originator.value()).map_err(CmsError::Asn1)?; // [1] EXPLICIT
    wire::ensure_tag(inner.tag(), wire::ctx_tag(1))?;
    let opk = Any::from_der(inner.value()).map_err(CmsError::Asn1)?; // OriginatorPublicKey SEQUENCE
    wire::ensure_tag(opk.tag(), Tag::Sequence)?;
    let mut oc = wire::Cursor::new(opk.value());
    let alg_any = oc.take()?;
    let algid = wire::algid_of(&alg_any)?;
    let _curve_oid: ObjectIdentifier = ObjectIdentifier::from_der(
        algid
            .parameters
            .as_ref()
            .ok_or_else(|| CmsError::Crypto("OriginatorPublicKey missing curve".into()))?
            .value(),
    )
    .map_err(CmsError::Asn1)?;
    let pubk_any = oc.take()?;
        let originator_pub = pubk_any.value()[1..].to_vec();

    // ukm [1] EXPLICIT OCTET STRING OPTIONAL
    let (ukm, key_agree_any, rek) = if !c.at_end() && c.peek_tag() == Some(wire::ctx_tag(1)) {
        let u = c.take()?;
        let ukm = wire::octet_value(&Any::from_der(u.value()).map_err(CmsError::Asn1)?)?;
        let ka = c.take()?;
        let rek = c.take()?;
        (ukm, ka, rek)
    } else {
        let ka = c.take()?;
        let rek = c.take()?;
        (Vec::new(), ka, rek)
    };
    let ka_algid = wire::algid_of(&key_agree_any)?;
    let key_agree_oid = ka_algid.oid.to_owned();
    let key_wrap_alg_der = ka_algid
        .parameters
        .as_ref()
        .ok_or_else(|| CmsError::Crypto("key agreement missing key-wrap parameters".into()))?
        .value()
        .to_vec();

    // RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey
    let rek_seq = Any::from_der(rek.value()).map_err(CmsError::Asn1)?;
    wire::ensure_tag(rek_seq.tag(), Tag::Sequence)?;
    let mut rc = wire::Cursor::new(rek_seq.value());
    let rek_elem = rc.take()?;
    let mut rk = wire::Cursor::new(rek_elem.value());
    let rid = rk.take()?;
    let (rid_issuer, rid_serial, rid_ski) = parse_issuer_serial(&rid)?;
    let encrypted_key = wire::octet_value(&rk.take()?)?;

    Ok(ParsedKeyAgree {
        originator_pub,
        key_agree_oid,
        key_wrap_alg_der,
        ukm,
        rid_issuer,
        rid_serial,
        rid_ski,
        encrypted_key,
    })
}

/// Extract the OCTET STRING content of an `AlgorithmIdentifier` parameter.
fn extract_octet_param(param: Option<&der::asn1::Any>, what: &str) -> Result<Vec<u8>> {
    let p = param.ok_or_else(|| CmsError::Crypto(format!("missing {what}")))?;
    Ok(p.value().to_vec())
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

fn random_bytes<R: rand_core::RngCore>(rng: &mut R, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    rng.fill_bytes(&mut b);
    b
}

fn issuer_serial_der(cert: &Certificate) -> Vec<u8> {
    let issuer = cert_issuer_der(cert);
    let serial = cert_serial_bytes(cert);
    wire::sequence(&[issuer, wire::integer_be(&serial)])
}

fn rid_matches(rid_issuer: &[u8], rid_serial: &[u8], cert: &Certificate) -> bool {
    cert_issuer_der(cert) == rid_issuer && cert_serial_bytes(cert) == rid_serial
}
