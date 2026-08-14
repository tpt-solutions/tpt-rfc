//! Cryptographic verification of a `TimeStampResp` (client side), including the
//! CMS `SignedData` signature over the signed attributes, attribute
//! consistency (`message-digest`, `content-type`), `TSTInfo` consistency, and
//! optional trust-anchor certificate checking.

use const_oid::{ObjectIdentifier, ObjectIdentifierRef};
use der::{
    asn1::{AnyRef, OctetStringRef, UintRef},
    Decode, Encode,
};
use spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfo};
use x509_cert::Certificate;

use crate::error::{Result, TspError};
use crate::hash::HashAlgorithm;
use crate::oids;
use crate::wire::*;

/// The verified contents of a time-stamp token, returned by
/// [`verify_timestamp_response`].
#[derive(Clone, Debug)]
pub struct VerifiedToken {
    /// The TSA policy under which the token was produced.
    pub policy: ObjectIdentifier,
    /// Hash algorithm used for the message imprint.
    pub hash_algorithm: HashAlgorithm,
    /// The hash of the timestamped data (as it appears in `TSTInfo`).
    pub hashed_message: Vec<u8>,
    /// `serialNumber` of the token.
    pub serial_number: Vec<u8>,
    /// Generation time (`genTime`).
    pub gen_time: der::asn1::GeneralizedTime,
    /// `nonce` (if present in the request and token).
    pub nonce: Option<u64>,
}

impl VerifiedToken {
    /// The `hashedMessage` bytes (the message imprint digest).
    pub fn message_imprint(&self) -> &[u8] {
        &self.hashed_message
    }
}

/// Decode and cryptographically verify a DER-encoded `TimeStampResp`.
///
/// `request_der`, when supplied, is used to cross-check the `messageImprint`
/// and `nonce` against what the caller actually requested. `trust_anchors`,
/// when supplied, requires the signer certificate to be signed by one of the
/// given certificates (e.g. a self-signed TSA root).
pub fn verify_timestamp_response(
    resp_der: &[u8],
    request_der: Option<&[u8]>,
    trust_anchors: Option<&[Certificate]>,
) -> Result<VerifiedToken> {
    let resp = TimeStampResp::from_der(resp_der).map_err(der_err)?;
    let status = resp
        .status
        .status
        .as_bytes()
        .first()
        .copied()
        .unwrap_or(0) as u8;
    if status != 0 {
        let reason = resp
            .status
            .status_string
            .as_ref()
            .map(|s| format!("{:?}", s))
            .unwrap_or_else(|| "TSA did not grant the request".into());
        return Err(TspError::RequestRejected { status, reason });
    }
    let token = resp
        .token
        .ok_or_else(|| TspError::Crypto("granted response without a token".into()))?;

    if token.content_type.to_owned() != oids::oid(oids::ID_SIGNED_DATA) {
        return Err(TspError::ContentTypeMismatch);
    }
    let signed_data = token.content_as::<SignedData>().map_err(der_err)?;

    let signer_info = signed_data
        .signer_infos
        .0
        .first()
        .ok_or_else(|| TspError::Crypto("no signer info".into()))?;

    let digest_alg = HashAlgorithm::from_oid(&signer_info.digest_algorithm.oid)?;
    let e_content = signed_data.encap_content_info.content_bytes().map_err(der_err)?;
    let content_digest = digest_alg.digest(&e_content);

    // --- Signed-attribute consistency + signature over the signed attrs ---
    let signed_attrs = signer_info
        .signed_attrs
        .as_ref()
        .ok_or_else(|| TspError::Crypto("token has no signed attributes".into()))?;
    let attrs_set = signed_attrs_set_tlv(&signed_attrs.0);
    let to_be_signed = digest_alg.digest(&attrs_set);

    // Locate the signer certificate and verify its signature.
    let cert = find_signer_cert(&signed_data, signer_info)
        .ok_or(TspError::SignerCertNotFound)?;
    let spki = &cert.tbs_certificate().subject()_public_key_info();
    verify_signature_raw(
        &to_be_signed,
        signer_info.signature.as_bytes(),
        spki,
        signer_info.signature_algorithm.oid,
    )
    .map_err(TspError::Signature)?;

    // Verify the CMS `message-digest` and `content-type` attributes.
    let mut seen_md = false;
    let attrs = decode_set_elements::<Attribute>(&signed_attrs.0).map_err(der_err)?;
    for attr in &attrs {
        if attr.attr_type.to_owned() == oids::oid(oids::MESSAGE_DIGEST) {
            let got = attr_value_octet(&attr.attr_values).map_err(der_err)?;
            if got != content_digest {
                return Err(TspError::MessageDigestMismatch);
            }
            seen_md = true;
        } else if attr.attr_type.to_owned() == oids::oid(oids::CONTENT_TYPE) {
            let got = attr_value_oid(&attr.attr_values).map_err(der_err)?;
            if got != oids::oid(oids::ID_CT_TST_INFO) {
                return Err(TspError::ContentTypeMismatch);
            }
        }
    }
    if !seen_md {
        return Err(TspError::Crypto("missing message-digest attribute".into()));
    }

    // --- TSTInfo ---
    let tst = TstInfo::from_der(&e_content).map_err(der_err)?;
    let tst_hash = HashAlgorithm::from_oid(&tst.message_imprint.hash_algorithm.oid)?;
    if tst_hash != digest_alg {
        return Err(TspError::Crypto(
            "TSTInfo hash algorithm differs from SignedData digest algorithm".into(),
        ));
    }
    let tst_hashed = tst.message_imprint.hashed_message.as_bytes().to_vec();
    let policy = tst.policy.to_owned();

    // Cross-check against the original request, if supplied.
    if let Some(req_der) = request_der {
        let req = TimeStampReq::from_der(req_der).map_err(der_err)?;
        if req.message_imprint.hash_algorithm.oid != tst.message_imprint.hash_algorithm.oid
            || req.message_imprint.hashed_message.as_bytes() != tst_hashed
        {
            return Err(TspError::MessageImprintMismatch);
        }
        match (req.nonce.as_ref(), tst.nonce.as_ref()) {
            (Some(r), Some(t)) if r.as_bytes() == t.as_bytes() => {}
            (None, None) => {}
            _ => return Err(TspError::NonceMismatch),
        }
    }

    // --- Optional trust-anchor check ---
    if let Some(anchors) = trust_anchors {
        let mut trusted = false;
        for anchor in anchors {
            if name_eq(&cert.tbs_certificate().issuer(), &anchor.tbs_certificate().subject())
                && verify_cert_signature(cert, &anchor.tbs_certificate().subject()_public_key_info()).is_ok()
            {
                trusted = true;
                break;
            }
        }
        if !trusted {
            return Err(TspError::Untrusted(format!(
                "serial={}",
                hex_lower(&cert.tbs_certificate().serial_number().as_bytes())
            )));
        }
    }

    let nonce = tst
        .nonce
        .as_ref()
        .map(|n| uint_to_u64(n.as_bytes()))
        .transpose()?;

    Ok(VerifiedToken {
        policy,
        hash_algorithm: tst_hash,
        hashed_message: tst_hashed,
        serial_number: tst.serial_number.as_bytes().to_vec(),
        gen_time: tst.gen_time,
        nonce,
    })
}

fn find_signer_cert<'a>(sd: &SignedData<'a>, si: &SignerInfo<'a>) -> Option<Certificate> {
    let wanted_serial = si.sid.0.serial_number.as_bytes();
    let wanted_issuer = &si.sid.0.issuer;
    let certs = sd.certificates.as_ref()?;
    let certs = decode_set_elements::<Certificate>(&certs.0).ok()?;
    for c in certs {
        if name_eq(&c.tbs_certificate().issuer(), wanted_issuer)
            && c.tbs_certificate().serial_number().as_bytes() == wanted_serial
        {
            return Some(c);
        }
    }
    None
}

fn attr_value_octet(any: &AnyRef) -> der::Result<Vec<u8>> {
    let set = AnyRef::from_der(any.as_bytes())?;
    let elems = decode_set_elements::<AnyRef>(set.value)?;
    let first = elems.into_iter().next().ok_or_else(missing_attr)?;
    Ok(OctetStringRef::from_der(first.as_bytes())?.as_bytes().to_vec())
}

fn attr_value_oid(any: &AnyRef) -> der::Result<ObjectIdentifier> {
    let set = AnyRef::from_der(any.as_bytes())?;
    let elems = decode_set_elements::<AnyRef>(set.value)?;
    let first = elems.into_iter().next().ok_or_else(missing_attr)?;
    Ok(ObjectIdentifierRef::from_der(first.as_bytes())?.to_owned())
}

fn name_eq(a: &x509_cert::name::Name, b: &x509_cert::name::Name) -> bool {
    a.to_der().ok() == b.to_der().ok()
}

fn uint_to_u64(bytes: &[u8]) -> Result<u64> {
    if bytes.len() > 8 {
        return Err(TspError::Crypto("nonce/serial too large for u64".into()));
    }
    let mut buf = [0u8; 8];
    buf[8 - bytes.len()..].copy_from_slice(bytes);
    Ok(u64::from_be_bytes(buf))
}

fn missing_attr() -> der::Error {
    der::Error::new(der::ErrorKind::Failed)
}

fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn der_err(e: der::Error) -> TspError {
    TspError::Der(e)
}

// ---------------------------------------------------------------------------
// Certificate signature verification (clean-room, dual-licensed RustCrypto).
// ---------------------------------------------------------------------------

fn verify_cert_signature(cert: &Certificate, issuer_spki: &SubjectPublicKeyInfo) -> Result<()> {
    let signed_data = cert
        .tbs_certificate()
        .to_der()
        .map_err(|e| TspError::Crypto(e.to_string()))?;
    let sig = cert.signature().raw_bytes();
    verify_signature_raw(
        &signed_data,
        sig,
        issuer_spki,
        cert.signature_algorithm().oid,
    )
    .map_err(|reason| TspError::Untrusted(reason))
}

fn verify_signature_raw(
    signed_data: &[u8],
    sig: &[u8],
    issuer_spki: &SubjectPublicKeyInfo,
    sig_oid: ObjectIdentifier,
) -> std::result::Result<(), String> {
    use const_oid::ObjectIdentifier as Oid;
    let key_oid = issuer_spki.algorithm.oid;
    match key_oid {
        k if k == Oid::new_unwrap(oids::RSA_ENCRYPTION) => {
            verify_rsa(issuer_spki, sig_oid, signed_data, sig)
        }
        k if k == Oid::new_unwrap(oids::EC_PUBLIC_KEY) => verify_ecdsa(issuer_spki, signed_data, sig),
        k if k == Oid::new_unwrap(oids::ED25519) => verify_ed25519(issuer_spki, signed_data, sig),
        other => Err(format!("unsupported public key algorithm {other}")),
    }
}

fn verify_rsa(
    spki: &SubjectPublicKeyInfo,
    sig_oid: ObjectIdentifier,
    msg: &[u8],
    sig: &[u8],
) -> std::result::Result<(), String> {
    use sha2::{Digest, Sha256, Sha384, Sha512};
    #[derive(der::Sequence)]
    struct RsaPubKeyDer<'a> {
        modulus: UintRef<'a>,
        public_exponent: UintRef<'a>,
    }
    let raw = spki.subject_public_key.raw_bytes();
    let pk = RsaPubKeyDer::from_der(raw).map_err(|e| format!("bad RSA public key: {e}"))?;
    let n = rsa::BigUint::from_bytes_be(pk.modulus.as_bytes());
    let e = rsa::BigUint::from_bytes_be(pk.public_exponent.as_bytes());
    let digest = match sig_oid {
        o if o == Oid::new_unwrap(oids::SHA256_RSA) => Sha256::digest(msg).to_vec(),
        o if o == Oid::new_unwrap(oids::SHA384_RSA) => Sha384::digest(msg).to_vec(),
        o if o == Oid::new_unwrap(oids::SHA512_RSA) => Sha512::digest(msg).to_vec(),
        o => return Err(format!("unsupported RSA signature scheme {o}")),
    };
    let t = digest_info(sig_oid, &digest)?;
    let s = rsa::BigUint::from_bytes_be(sig);
    let m = s.modpow(&e, &n);
    let mut em = m.to_bytes_be();
    let k = (n.bits().div_ceil(8)) as usize;
    while em.len() < k {
        em.insert(0, 0);
    }
    pkcs1_v15_check(&em, &t)
}

fn digest_info(sig_oid: ObjectIdentifier, digest: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let prefix: &[u8] = match sig_oid {
        o if o == Oid::new_unwrap(oids::SHA256_RSA) => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, 0x04, 0x20,
        ],
        o if o == Oid::new_unwrap(oids::SHA384_RSA) => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
            0x00, 0x04, 0x30,
        ],
        o if o == Oid::new_unwrap(oids::SHA512_RSA) => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
            0x00, 0x04, 0x40,
        ],
        o => return Err(format!("unsupported RSA signature scheme {o}")),
    };
    let mut t = prefix.to_vec();
    t.extend_from_slice(digest);
    Ok(t)
}

fn pkcs1_v15_check(em: &[u8], t: &[u8]) -> std::result::Result<(), String> {
    if em.len() < 11 + t.len() {
        return Err("RSA block too short".to_string());
    }
    if em[0] != 0x00 || em[1] != 0x01 {
        return Err("bad RSA signature leading bytes".to_string());
    }
    let mut i = 2;
    while i < em.len() && em[i] == 0xFF {
        i += 1;
    }
    if i - 2 < 8 || em[i] != 0x00 {
        return Err("bad RSA PS padding".to_string());
    }
    if &em[i + 1..] != t {
        return Err("RSA digest mismatch".to_string());
    }
    Ok(())
}

fn verify_ecdsa(
    spki: &SubjectPublicKeyInfo,
    msg: &[u8],
    sig: &[u8],
) -> std::result::Result<(), String> {
    use ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature as P256Sig, VerifyingKey as P256Vk};
    use p384::ecdsa::{Signature as P384Sig, VerifyingKey as P384Vk};

    let raw = spki.subject_public_key.raw_bytes();
    let curve = ec_curve(spki)?;
    match curve {
        Curve::P256 => {
            let vk = P256Vk::from_sec1_bytes(raw).map_err(|e| e.to_string())?;
            let sig = P256Sig::from_slice(sig).map_err(|e| format!("bad ECDSA sig: {e}"))?;
            vk.verify(msg, &sig).map_err(|e| format!("P-256 verification failed: {e}"))
        }
        Curve::P384 => {
            let vk = P384Vk::from_sec1_bytes(raw).map_err(|e| e.to_string())?;
            let sig = P384Sig::from_slice(sig).map_err(|e| format!("bad ECDSA sig: {e}"))?;
            vk.verify(msg, &sig).map_err(|e| format!("P-384 verification failed: {e}"))
        }
    }
}

fn verify_ed25519(
    spki: &SubjectPublicKeyInfo,
    msg: &[u8],
    sig: &[u8],
) -> std::result::Result<(), String> {
    use ed25519_compact::{PublicKey, Signature};
    let raw = spki.subject_public_key.raw_bytes();
    if raw.len() != 32 {
        return Err(format!("Ed25519 public key must be 32 bytes, got {}", raw.len()));
    }
    let pk = PublicKey::from_slice(raw).map_err(|e| format!("bad Ed25519 key: {e:?}"))?;
    let sig = Signature::from_slice(sig).map_err(|e| format!("bad Ed25519 signature: {e:?}"))?;
    pk.verify(msg, &sig)
        .map_err(|e| format!("Ed25519 verification failed: {e:?}"))
}

enum Curve {
    P256,
    P384,
}

fn ec_curve(spki: &SubjectPublicKeyInfo) -> std::result::Result<Curve, String> {
    let params = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| "EC public key missing curve parameters".to_string())?;
    let der = params.to_der().map_err(|e| e.to_string())?;
    let curve_oid = ObjectIdentifierRef::from_der(&der).map_err(|e| e.to_string())?;
    match curve_oid {
        c if c == Oid::new_unwrap(oids::P256) => Ok(Curve::P256),
        c if c == Oid::new_unwrap(oids::P384) => Ok(Curve::P384),
        other => Err(format!("unsupported curve {other}")),
    }
}
