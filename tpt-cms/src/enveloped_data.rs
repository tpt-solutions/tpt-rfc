//! RFC 5652 `EnvelopedData`: key transport (RSA) and key agreement (ECDH)
//! recipient information, with AES-CBC content encryption and AES key wrap.

use const_oid::ObjectIdentifier;
use der::{
    asn1::{AnyRef, BitStringRef, ObjectIdentifierRef, OctetStringRef, UintRef},
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Length, Sequence, Tag, Writer,
};
use x509_cert::Certificate;

use crate::cert::{cert_issuer_der, cert_serial_bytes};
use crate::crypto::{
    aes_key_unwrap, aes_key_wrap, cms_ecdh_kdf, public_key_from_spki, ContentEncryption, HashAlgorithm,
    KeyWrap, PublicKey,
};
use crate::error::{CmsError, Result};
use crate::oids;
use crate::wire::{self, ContentInfo};

use p256::SecretKey as P256Secret;
use p384::SecretKey as P384Secret;
use rand_core::OsRng;
use rsa::Oaep;
use rsa::pkcs1v15::Pkcs1v15Encrypt;
use rsa::RsaPrivateKey;

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
        return Err(CmsError::Crypto("at least one recipient is required".into()));
    }
    let mut rng = OsRng;

    let cek = random_bytes(&mut rng, content_enc.key_size());
    let iv = random_bytes(&mut rng, content_enc.iv_size());
    let encrypted = content_enc.encrypt(&cek, &iv, content)?;

    let iv_param = wire::octet_string(&iv);
    let encrypted_content_info = wire::sequence(&[
        wire::oid_der(&content_enc.oid()),
        wire::algorithm_identifier(&content_enc.oid(), Some(&iv_param)),
        wire::ctx(0, &wire::octet_string(&encrypted)),
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
    let ci = ContentInfo::from_der(der)?;
    if ci.content_type.to_string() != oids::ID_ENVELOPED_DATA {
        return Err(CmsError::UnexpectedContentType {
            expected: oids::ID_ENVELOPED_DATA.into(),
            got: ci.content_type.to_string(),
        });
    }
    let sd = ci.content_as::<EnvelopedData>()?;
    let eci = &sd.encrypted_content_info;
    let ct: ObjectIdentifier = (*eci.e_content_type).clone();
    let content_enc = ContentEncryption::from_oid(&ct)?;
    let iv = extract_iv(&eci.content_enc_alg)?;
    let encrypted = eci
        .encrypted_content
        .as_ref()
        .ok_or(CmsError::MissingContent)?;
    let encrypted = OctetStringRef::from_der(encrypted.value)?.as_bytes().to_vec();

    let mut last_err = None;
    for ri in &sd.recipient_infos.0 {
        match ri {
            RecipientInfo::KeyTrans(kt) => {
                for rec in recipients {
                    let RecipientPrivateKey::Rsa(key, cert) = rec else { continue };
                    if !rid_matches_cert(&kt.rid, cert) { continue; }
                    match open_key_trans(key, kt) {
                        Ok(cek) => return content_enc.decrypt(&cek, &iv, &encrypted),
                        Err(e) => last_err = Some(e),
                    }
                }
            }
            RecipientInfo::KeyAgree(ka) => {
                for rec in recipients {
                    match rec {
                        RecipientPrivateKey::EcdhP256(key, cert) => {
                            if !rid_matches_cert(&ka.recipient.rid, cert) { continue; }
                            match open_key_agree_p256(key, ka) {
                                Ok(cek) => return content_enc.decrypt(&cek, &iv, &encrypted),
                                Err(e) => last_err = Some(e),
                            }
                        }
                        RecipientPrivateKey::EcdhP384(key, cert) => {
                            if !rid_matches_cert(&ka.recipient.rid, cert) { continue; }
                            match open_key_agree_p384(key, ka) {
                                Ok(cek) => return content_enc.decrypt(&cek, &iv, &encrypted),
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
            .encrypt(rng, Oaep::new::<sha2::Sha256>(), cek)
            .map_err(|e| CmsError::Crypto(e.to_string()))?
    } else {
        rsa_pub
            .encrypt(rng, Pkcs1v15Encrypt, cek)
            .map_err(|e| CmsError::Crypto(e.to_string()))?
    };
    let key_enc_oid = oids::oid(if oaep { oids::RSAES_OAEP } else { oids::RSA_ENCRYPTION });
    let kt = wire::sequence(&[
        wire::integer_u64(0),
        issuer_serial_der(cert),
        wire::algorithm_identifier(&key_enc_oid, None),
        wire::octet_string(&encrypted_key),
    ]);
    Ok(kt)
}

fn open_key_trans(key: &RsaPrivateKey, kt: &KeyTransRecipientInfo) -> Result<Vec<u8>> {
    let oid = kt.key_encryption_algorithm.to_string();
    let decrypted = if oid == oids::RSAES_OAEP {
        key.decrypt(Oaep::new::<sha2::Sha256>(), kt.encrypted_key.as_bytes())
            .map_err(|e| CmsError::Crypto(e.to_string()))?
    } else if oid == oids::RSA_ENCRYPTION {
        key.decrypt(Pkcs1v15Encrypt, kt.encrypted_key.as_bytes())
            .map_err(|e| CmsError::Crypto(e.to_string()))?
    } else {
        return Err(CmsError::UnsupportedKeyTransport(oid));
    };
    Ok(decrypted)
}

// ---------------------------------------------------------------------------
// Key agreement (ECDH)
// ---------------------------------------------------------------------------

fn build_key_agree(rng: &mut OsRng, cert: &Certificate, cek: &[u8], wrap: KeyWrap) -> Result<Vec<u8>> {
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

    let zz = if is_p256 {
        let eph = p256::ecdh::EphemeralSecret::random(rng);
        let recip = p256::PublicKey::from_sec1_bytes(&recipient_sec1)
            .map_err(|e| CmsError::Crypto(e.to_string()))?;
        eph.diffie_hellman(&recip).raw_secret_bytes().to_vec()
    } else {
        let eph = p384::ecdh::EphemeralSecret::random(rng);
        let recip = p384::PublicKey::from_sec1_bytes(&recipient_sec1)
            .map_err(|e| CmsError::Crypto(e.to_string()))?;
        eph.diffie_hellman(&recip).raw_secret_bytes().to_vec()
    };

    let kek = cms_ecdh_kdf(
        if is_p256 { HashAlgorithm::Sha256 } else { HashAlgorithm::Sha384 },
        &zz,
        &key_wrap_alg_der,
        &[],
        (wrap.key_size() as u32) * 8,
    );
    let wrapped_cek = aes_key_wrap(&kek, cek)?;

    let eph_sec1 = if is_p256 {
        p256::ecdh::EphemeralSecret::random(rng)
            .public_key()
            .to_sec1_bytes()
            .to_vec()
    } else {
        p384::ecdh::EphemeralSecret::random(rng)
            .public_key()
            .to_sec1_bytes()
            .to_vec()
    };
    let originator_pub = wire::sequence(&[
        wire::algorithm_identifier(&oids::oid(oids::EC_PUBLIC_KEY), Some(&wire::oid_der(&curve_oid))),
        wire::bit_string(&eph_sec1),
    ]);
    // [0] EXPLICIT { [1] EXPLICIT { OriginatorPublicKey } }
    let originator = wire::ctx(0, &wire::ctx(1, &originator_pub));

    let rek = wire::sequence(&[issuer_serial_der(cert), wire::octet_string(&wrapped_cek)]);
    let recipient_encrypted_keys = wire::sequence(&[rek]);

    let ka = wire::sequence(&[
        wire::integer_u64(3),
        originator,
        wire::algorithm_identifier(&key_agree_oid, Some(&key_wrap_alg_der)),
        recipient_encrypted_keys,
    ]);
    Ok(ka)
}

fn open_key_agree_p256(secret: &P256Secret, ka: &KeyAgreeRecipientInfo) -> Result<Vec<u8>> {
    let inner = AnyRef::from_der(ka.originator.value)?;
    let opk = OriginatorPublicKey::from_der(inner.value)?;
    let eph_sec1 = opk.public_key.as_bytes().to_vec();
    let pubk = p256::PublicKey::from_sec1_bytes(&eph_sec1)
        .map_err(|e| CmsError::Crypto(e.to_string()))?;
    let zz = p256::ecdh::diffie_hellman(secret, &pubk)
        .raw_secret_bytes()
        .to_vec();
    unwrap_cek(&zz, ka)
}

fn open_key_agree_p384(secret: &P384Secret, ka: &KeyAgreeRecipientInfo) -> Result<Vec<u8>> {
    let inner = AnyRef::from_der(ka.originator.value)?;
    let opk = OriginatorPublicKey::from_der(inner.value)?;
    let eph_sec1 = opk.public_key.as_bytes().to_vec();
    let pubk = p384::PublicKey::from_sec1_bytes(&eph_sec1)
        .map_err(|e| CmsError::Crypto(e.to_string()))?;
    let zz = p384::ecdh::diffie_hellman(secret, &pubk)
        .raw_secret_bytes()
        .to_vec();
    unwrap_cek(&zz, ka)
}

/// Derive the KEK from the ECDH shared secret and unwrap the CEK.
fn unwrap_cek(zz: &[u8], ka: &KeyAgreeRecipientInfo) -> Result<Vec<u8>> {
    let param = ka
        .key_encryption_algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| CmsError::Crypto("key agreement missing key-wrap parameters".into()))?;
    let wrap = KeyWrap::from_oid(&ObjectIdentifier::from_der(param.value)?)?;
    let key_agree_oid = ka.key_encryption_algorithm.oid.to_string();
    let hash = match key_agree_oid.as_str() {
        oids::DH_SINGLE_PASS_STD_SHA256 => HashAlgorithm::Sha256,
        oids::DH_SINGLE_PASS_STD_SHA384 => HashAlgorithm::Sha384,
        oids::DH_SINGLE_PASS_STD_SHA512 => HashAlgorithm::Sha512,
        _ => return Err(CmsError::UnsupportedKeyAgreement(key_agree_oid)),
    };
    let ukm = ka
        .ukm
        .as_ref()
        .map(|u| OctetStringRef::from_der(u.value).map(|o| o.as_bytes().to_vec()))
        .transpose()?
        .unwrap_or_default();
    let kek = cms_ecdh_kdf(
        hash,
        zz,
        &wrap.algorithm_id(),
        &ukm,
        (wrap.key_size() as u32) * 8,
    );
    aes_key_unwrap(&kek, &ka.recipient.encrypted_key.as_bytes())
}

// ---------------------------------------------------------------------------
// DER structures (decode + encode)
// ---------------------------------------------------------------------------

/// `RecipientIdentifier` CHOICE: `IssuerAndSerialNumber` or
/// `subjectKeyIdentifier [0] IMPLICIT`.
#[derive(Clone)]
pub(crate) enum RecipientIdentifier<'a> {
    IssuerAndSerialNumber(crate::wire::IssuerAndSerialNumber<'a>),
    SubjectKeyIdentifier(OctetStringRef<'a>),
}

impl<'a> Decode<'a> for RecipientIdentifier<'a> {
    fn decode(d: &mut impl der::Reader<'a>) -> der::Result<Self> {
        let any = AnyRef::decode(d)?;
        match any.tag {
            der::Tag::Sequence => Ok(RecipientIdentifier::IssuerAndSerialNumber(
                crate::wire::IssuerAndSerialNumber::from_der(any.as_bytes())?,
            )),
            tag if tag == der::Tag::context_specific(0) => Ok(
                RecipientIdentifier::SubjectKeyIdentifier(OctetStringRef::from_der(any.value)?),
            ),
            other => Err(der::Error::TagUnexpected {
                expected: Some(der::Tag::Sequence),
                actual: other,
            }),
        }
    }
}

impl<'a> Encode for RecipientIdentifier<'a> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        match self {
            RecipientIdentifier::IssuerAndSerialNumber(i) => i.encoded_len(),
            RecipientIdentifier::SubjectKeyIdentifier(s) => s.encoded_len(),
        }
    }
    fn encode(&self, e: &mut impl Writer) -> der::Result<()> {
        match self {
            RecipientIdentifier::IssuerAndSerialNumber(i) => i.encode(e),
            RecipientIdentifier::SubjectKeyIdentifier(s) => s.encode(e),
        }
    }
}

#[derive(Clone, Sequence)]
struct KeyTransRecipientInfo<'a> {
    version: UintRef<'a>,
    rid: RecipientIdentifier<'a>,
    key_encryption_algorithm: ObjectIdentifierRef<'a>,
    encrypted_key: OctetStringRef<'a>,
}

#[derive(Clone)]
struct OriginatorPublicKey<'a> {
    algorithm: ObjectIdentifierRef<'a>,
    public_key: BitStringRef<'a>,
}

impl<'a> DecodeValue<'a> for OriginatorPublicKey<'a> {
    fn decode_value(d: &mut impl der::Reader<'a>, _len: Length) -> der::Result<Self> {
        let algorithm = ObjectIdentifierRef::decode(d)?;
        let public_key = BitStringRef::decode(d)?;
        Ok(OriginatorPublicKey { algorithm, public_key })
    }
}

impl<'a> EncodeValue for OriginatorPublicKey<'a> {
    fn value_len(&self) -> der::Result<Length> {
        Ok(self.algorithm.encoded_len()? + self.public_key.encoded_len()?)
    }
    fn encode_value(&self, e: &mut impl Writer) -> der::Result<()> {
        self.algorithm.encode(e)?;
        self.public_key.encode(e)
    }
}

impl<'a> FixedTag for OriginatorPublicKey<'a> {
    const TAG: Tag = Tag::Sequence;
}
impl<'a> Sequence<'a> for OriginatorPublicKey<'a> {}

/// `RecipientEncryptedKey` = SEQUENCE { rid, encryptedKey }.
#[derive(Clone, Sequence)]
struct RecipientEncryptedKey<'a> {
    rid: RecipientIdentifier<'a>,
    encrypted_key: OctetStringRef<'a>,
}

#[derive(Clone)]
struct KeyAgreeRecipientInfo<'a> {
    version: UintRef<'a>,
    /// Raw `[0]` content (an `[1]` EXPLICIT OriginatorPublicKey).
    originator: AnyRef<'a>,
    /// Inner OCTET STRING of the `[1] EXPLICIT ukm` (if present).
    ukm: Option<OctetStringRef<'a>>,
    key_encryption_algorithm: ObjectIdentifierRef<'a>,
    recipient: RecipientEncryptedKey<'a>,
}

impl<'a> DecodeValue<'a> for KeyAgreeRecipientInfo<'a> {
    fn decode_value(d: &mut impl der::Reader<'a>, _len: Length) -> der::Result<Self> {
        let version = UintRef::decode(d)?;
        let originator = AnyRef::decode(d)?;
        let (ukm, kea, recipient) = if d.peek_tag()? == der::Tag::context_specific(1) {
            let ukm_any = AnyRef::decode(d)?;
            let ukm = OctetStringRef::from_der(ukm_any.value)?;
            let kea = ObjectIdentifierRef::decode(d)?;
            let recipient = RecipientEncryptedKey::decode(d)?;
            (Some(ukm), kea, recipient)
        } else {
            let kea = ObjectIdentifierRef::decode(d)?;
            let recipient = RecipientEncryptedKey::decode(d)?;
            (None, kea, recipient)
        };
        Ok(KeyAgreeRecipientInfo {
            version,
            originator,
            ukm,
            key_encryption_algorithm: kea,
            recipient,
        })
    }
}

impl<'a> EncodeValue for KeyAgreeRecipientInfo<'a> {
    fn value_len(&self) -> der::Result<Length> {
        let mut len = self.version.encoded_len()? + self.originator.encoded_len()?;
        if let Some(u) = &self.ukm {
            len = (len + u.encoded_len())?;
        }
        len = (len + self.key_encryption_algorithm.encoded_len())?;
        len = (len + self.recipient.encoded_len())?;
        Ok(len)
    }
    fn encode_value(&self, e: &mut impl Writer) -> der::Result<()> {
        self.version.encode(e)?;
        self.originator.encode(e)?;
        if let Some(u) = &self.ukm {
            let der = u.to_der()?;
            e.write(&wire::ctx(1, &der))?;
        }
        self.key_encryption_algorithm.encode(e)?;
        self.recipient.encode(e)
    }
}

impl<'a> FixedTag for KeyAgreeRecipientInfo<'a> {
    const TAG: Tag = Tag::Sequence;
}
impl<'a> Sequence<'a> for KeyAgreeRecipientInfo<'a> {}

#[derive(Clone)]
enum RecipientInfo<'a> {
    KeyTrans(KeyTransRecipientInfo<'a>),
    KeyAgree(KeyAgreeRecipientInfo<'a>),
}

impl<'a> Decode<'a> for RecipientInfo<'a> {
    fn decode(d: &mut impl der::Reader<'a>) -> der::Result<Self> {
        let any = AnyRef::decode(d)?;
        match any.tag {
            tag if tag == der::Tag::context_specific(0) => Ok(RecipientInfo::KeyTrans(
                KeyTransRecipientInfo::from_der(any.value)?,
            )),
            tag if tag == der::Tag::context_specific(1) => Ok(RecipientInfo::KeyAgree(
                KeyAgreeRecipientInfo::from_der(any.value)?,
            )),
            other => Err(der::Error::TagUnexpected {
                expected: Some(der::Tag::context_specific(0)),
                actual: other,
            }),
        }
    }
}

impl<'a> Encode for RecipientInfo<'a> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        match self {
            RecipientInfo::KeyTrans(k) => k.encoded_len(),
            RecipientInfo::KeyAgree(k) => k.encoded_len(),
        }
    }
    fn encode(&self, e: &mut impl Writer) -> der::Result<()> {
        match self {
            RecipientInfo::KeyTrans(k) => k.encode(e),
            RecipientInfo::KeyAgree(k) => k.encode(e),
        }
    }
}

#[derive(Clone, Sequence)]
struct EnvelopedData<'a> {
    version: UintRef<'a>,
    #[asn1(context_specific = "0", constructed, optional)]
    originator_info: Option<AnyRef<'a>>,
    recipient_infos: RecipientInfos<'a>,
    encrypted_content_info: EncryptedContentInfo<'a>,
    #[asn1(context_specific = "1", constructed, optional)]
    unprotected_attrs: Option<AnyRef<'a>>,
}

#[derive(Clone)]
struct RecipientInfos<'a>(pub Vec<RecipientInfo<'a>>);

impl<'a> Decode<'a> for RecipientInfos<'a> {
    fn decode(d: &mut impl der::Reader<'a>) -> der::Result<Self> {
        let any = AnyRef::decode(d)?;
        if any.tag != der::Tag::Set {
            return Err(der::Error::TagUnexpected {
                expected: Some(der::Tag::Set),
                actual: any.tag,
            });
        }
        wire::decode_set_elements(&any.value)
    }
}

impl<'a> Encode for RecipientInfos<'a> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let parts: Vec<Vec<u8>> = self
            .0
            .iter()
            .map(|r| r.to_der())
            .collect::<der::Result<Vec<_>>>()?;
        der::Length::try_from(wire::set_of(&parts).len())
    }
    fn encode(&self, e: &mut impl Writer) -> der::Result<()> {
        let parts: Vec<Vec<u8>> = self
            .0
            .iter()
            .map(|r| r.to_der())
            .collect::<der::Result<Vec<_>>>()?;
        e.write(&wire::set_of(&parts))
    }
}

#[derive(Clone, Sequence)]
struct EncryptedContentInfo<'a> {
    e_content_type: ObjectIdentifierRef<'a>,
    content_enc_alg: ObjectIdentifierRef<'a>,
    #[asn1(context_specific = "0", constructed, optional)]
    encrypted_content: Option<AnyRef<'a>>,
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

fn random_bytes(rng: &mut OsRng, n: usize) -> Vec<u8> {
    use rand_core::RngCore;
    let mut b = vec![0u8; n];
    rng.fill_bytes(&mut b);
    b
}

fn issuer_serial_der(cert: &Certificate) -> Vec<u8> {
    let issuer = cert_issuer_der(cert);
    let serial = cert_serial_bytes(cert);
    wire::sequence(&[issuer, wire::integer_be(&serial)])
}

fn rid_matches_cert(rid: &RecipientIdentifier, cert: &Certificate) -> bool {
    match rid {
        RecipientIdentifier::IssuerAndSerialNumber(ias) => {
            let Some(want_issuer) = ias.issuer.to_der().ok() else {
                return false;
            };
            let want_serial = ias.serial_number.as_bytes().to_vec();
            want_issuer == cert_issuer_der(cert) && want_serial == cert_serial_bytes(cert)
        }
        RecipientIdentifier::SubjectKeyIdentifier(_) => false,
    }
}

fn extract_iv(alg: &ObjectIdentifierRef) -> Result<Vec<u8>> {
    let params = alg
        .parameters
        .as_ref()
        .ok_or_else(|| CmsError::Crypto("content-encryption algorithm missing IV".into()))?;
    Ok(OctetStringRef::from_der(params.value)?.as_bytes().to_vec())
}
