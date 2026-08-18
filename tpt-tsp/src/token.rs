//! RFC 3161 `TSTInfo` and the `TimeStampToken` (a CMS `SignedData`, RFC 3161
//! §2.4.2 / RFC 5652 §5).
//!
//! ```text
//! TSTInfo ::= SEQUENCE  {
//!    version                      INTEGER  { v1(1) },
//!    policy                       TSAPolicyId,
//!    messageImprint               MessageImprint,
//!    serialNumber                 INTEGER,
//!    genTime                      GeneralizedTime,
//!    accuracy             [0]     Accuracy                     OPTIONAL,
//!    ordering             [1]     BOOLEAN                      OPTIONAL,
//!    nonce                [2]     INTEGER                      OPTIONAL,
//!    tsa                  [3]     GeneralName                  OPTIONAL,
//!    extensions           [4]     IMPLICIT Extensions          OPTIONAL  }
//!
//! Accuracy ::= SEQUENCE {
//!    seconds        INTEGER          OPTIONAL,
//!    millis     [0]  INTEGER  (1..999) OPTIONAL,
//!    micros     [1]  INTEGER  (1..999) OPTIONAL  }
//! ```

use const_oid::ObjectIdentifier;
use der::{Decode, Encode, Tag, Tagged};

use crate::cert::{find_signer_cert, parse_cert_set, verify_chain};
use crate::crypto::{public_key_from_spki, verify_signature, HashAlgorithm, SigningKey};
use crate::error::{TspError, Result};
use crate::oids;
use crate::request::MessageImprint;
use crate::wire;
use x509_cert::Certificate;

/// A TSA policy identifier (`TSAPolicyId` = `OBJECT IDENTIFIER`).
pub type TsaPolicyId = ObjectIdentifier;

/// RFC 3161 `TSTInfo`, the signed content of a `TimeStampToken`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TstInfo {
    /// `TSTInfo` version (1).
    pub version: u64,
    /// The TSA policy OID under which the token was produced.
    pub policy: TsaPolicyId,
    /// The `MessageImprint` binding the token to the original data.
    pub message_imprint: MessageImprint,
    /// A unique serial number assigned by the TSA.
    pub serial_number: u64,
    /// The time at which the token was produced (`GeneralizedTime`).
    pub gen_time: der::DateTime,
    /// Optional accuracy in seconds.
    pub accuracy_seconds: Option<u64>,
    /// Whether the TSA guarantees the order of tokens it issues.
    pub ordering: bool,
    /// Optional nonce echoed from the request.
    pub nonce: Option<u64>,
    /// Optional `GeneralName` identifying the TSA.
    pub tsa: Option<Vec<u8>>,
}

impl TstInfo {
    /// Build a `TSTInfo` from request fields (used by the TSA responder).
    pub fn from_request(
        policy: TsaPolicyId,
        imprint: &MessageImprint,
        serial_number: u64,
        gen_time: der::DateTime,
        nonce: Option<u64>,
    ) -> Self {
        TstInfo {
            version: 1,
            policy,
            message_imprint: imprint.clone(),
            serial_number,
            gen_time,
            accuracy_seconds: None,
            ordering: false,
            nonce,
            tsa: None,
        }
    }

    /// Encode `TSTInfo` to DER (with the `id-ct-TSTInfo` eContentType).
    pub fn to_der(&self) -> Vec<u8> {
        let mut parts = vec![
            wire::integer_u64(self.version),
            wire::oid_der(&self.policy),
            self.message_imprint.to_der(),
            wire::integer_u64(self.serial_number),
            wire::generalized_time(self.gen_time),
        ];
        if let Some(s) = self.accuracy_seconds {
            // Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL, ... }
            let acc = wire::sequence(&[wire::integer_u64(s)]);
            parts.push(wire::ctx(0, &acc));
        }
        if self.ordering {
            parts.push(wire::ctx(1, &wire::tlv(0x01, &[0xFF])));
        }
        if let Some(n) = self.nonce {
            parts.push(wire::ctx(2, &wire::integer_u64(n)));
        }
        if let Some(tsa) = &self.tsa {
            parts.push(wire::ctx(3, tsa));
        }
        wire::sequence(&parts)
    }

    /// Parse a `TSTInfo` from DER.
    pub fn from_der(der_bytes: &[u8]) -> Result<TstInfo> {
        let seq = der::Any::from_der(der_bytes).map_err(TspError::Asn1)?;
        wire::ensure_tag(seq.tag(), Tag::Sequence)?;
        let mut c = wire::Cursor::new(seq.value());

        let version = u64_of(&c.take()?)?;
        let policy = wire::oid_of(&c.take()?)?;
        let imprint = MessageImprint::from_der(&c.take()?.to_der().map_err(TspError::Asn1)?)?;
        let serial_number = u64_of(&c.take()?)?;
        let gt_any = c.take()?;
        let gen_time = der::asn1::GeneralizedTime::from_der(gt_any.value())
            .map_err(TspError::Asn1)?
            .to_date_time();

        let mut accuracy_seconds = None;
        let mut ordering = false;
        let mut nonce = None;
        let mut tsa = None;

        while !c.at_end() {
            let peek = c.peek_tag().unwrap();
            match peek {
                t if t == wire::ctx_tag(0) => {
                    let v = c.take()?; // Accuracy SEQUENCE (context-wrapped)
                    let inner = der::Any::from_der(v.value()).map_err(TspError::Asn1)?;
                    let mut ac = wire::Cursor::new(inner.value());
                    accuracy_seconds = Some(u64_of(&ac.take()?)?);
                }
                t if t == wire::ctx_tag(1) => {
                    let v = c.take()?;
                    ordering = v.value() == [0xFF];
                }
                t if t == wire::ctx_tag(2) => {
                    let v = c.take()?;
                    nonce = Some(u64_of_any(&v)?);
                }
                t if t == wire::ctx_tag(3) => {
                    let v = c.take()?;
                    tsa = Some(v.value().to_vec());
                }
                t if t == wire::ctx_tag(4) => {
                    c.take()?; // extensions — ignored
                }
                _ => break,
            }
        }

        Ok(TstInfo {
            version,
            policy,
            message_imprint: imprint,
            serial_number,
            gen_time,
            accuracy_seconds,
            ordering,
            nonce,
            tsa,
        })
    }
}

fn u64_of(any: &der::Any) -> Result<u64> {
    let u = der::asn1::UintRef::from_der(any.value()).map_err(TspError::Asn1)?;
    Ok(u64_from_be(u.as_bytes()))
}

fn u64_of_any(any: &der::Any) -> Result<u64> {
    let u = der::asn1::UintRef::from_der(any.value()).map_err(TspError::Asn1)?;
    Ok(u64_from_be(u.as_bytes()))
}

fn u64_from_be(bytes: &[u8]) -> u64 {
    let mut n: u64 = 0;
    for b in bytes {
        n = (n << 8) | (*b as u64);
    }
    n
}

// ===========================================================================
// TimeStampToken — CMS SignedData over TSTInfo
// ===========================================================================

/// Build a `TimeStampToken` (CMS `SignedData`, RFC 5652 §5) whose encapsulated
/// `eContent` is a DER-encoded `TSTInfo` with `eContentType = id-ct-TSTInfo`.
///
/// This mirrors the `tpt-cms` SignedData construction but fixes the content
/// type and omit the CMS `signingTime` attribute (RFC 3161 §2.4.3: the time is
/// carried by `TSTInfo.genTime`).
pub fn build_timestamp_token(
    tst_info: &TstInfo,
    signer: &SigningKey,
    cert: &Certificate,
) -> Result<Vec<u8>> {
    let content_type = oids::oid(oids::ID_CT_TSTINFO);
    let content = tst_info.to_der();

    // Encapsulated content: SEQUENCE { eContentType, eContent [0] IMPLICIT OCTET STRING }.
    let encapsulated = wire::sequence(&[
        wire::oid_der(&content_type),
        wire::implicit_octet_string(0, &content),
    ]);

    // Map the signing key to its digest.
    let (hash, digest_oid_str) = match signer {
        SigningKey::EcdsaP256(_) => (HashAlgorithm::Sha256, oids::SHA256),
        SigningKey::EcdsaP384(_) => (HashAlgorithm::Sha384, oids::SHA384),
        SigningKey::Rsa(_) => (HashAlgorithm::Sha256, oids::SHA256),
        SigningKey::Ed25519(_) => (HashAlgorithm::Sha512, oids::SHA512),
    };
    let digest_oid = oids::oid(digest_oid_str);

    // Signed attributes (DER-sorted): contentType, messageDigest.
    let content_digest = hash.digest(&content);
    let ct_attr = wire::attribute(&oids::oid(oids::CONTENT_TYPE), &wire::oid_der(&content_type));
    let md_attr = wire::attribute(
        &oids::oid(oids::MESSAGE_DIGEST),
        &wire::octet_string(&content_digest),
    );
    let mut attrs = vec![ct_attr, md_attr];
    attrs.sort();
    let signed_attrs_content: Vec<u8> = attrs.concat();

    let signed_attrs_set = wire::signed_attrs_tlv(&signed_attrs_content);
    let message: Vec<u8> = if let SigningKey::Ed25519(_) = signer {
        signed_attrs_set.clone()
    } else {
        hash.digest(&signed_attrs_set)
    };
    let (sig_oid, signature) = signer.sign(hash, &message)?;

    // SignerIdentifier = IssuerAndSerialNumber.
    let issuer = cert
        .tbs_certificate()
        .issuer()
        .to_der()
        .map_err(TspError::Asn1)?;
    let serial = cert.tbs_certificate().serial_number().as_bytes().to_vec();
    let sid = wire::sequence(&[issuer, wire::integer_be(&serial)]);

    let signer_info = wire::sequence(&[
        wire::integer_u64(1),
        sid,
        wire::algorithm_identifier(&digest_oid, None),
        wire::ctx(0, &signed_attrs_content),
        wire::algorithm_identifier(&sig_oid, None),
        wire::octet_string(&signature),
    ]);

    let certs_set_content = cert.to_der().expect("cert der");

    let signed_data = wire::sequence(&[
        wire::integer_u64(3), // SignedData version 3
        wire::set_of(&[wire::algorithm_identifier(&digest_oid, None)]),
        encapsulated,
        wire::ctx(0, &certs_set_content),
        wire::set_of(&[signer_info]),
    ]);

    let content_info = wire::sequence(&[
        wire::oid_der(&oids::oid(oids::ID_SIGNED_DATA)),
        wire::ctx(0, &signed_data),
    ]);
    Ok(content_info)
}

/// Parse and verify a `TimeStampToken` (CMS `SignedData`) DER, returning the
/// signed `TSTInfo`. If `anchors` is non-empty, the TSA certificate must chain
/// to one of them.
pub fn verify_timestamp_token(token_der: &[u8], anchors: &[Certificate]) -> Result<TstInfo> {
    let (ct, content_der) = decode_content_info(token_der)?;
    if ct.to_string() != oids::ID_SIGNED_DATA {
        return Err(TspError::NotSignedData {
            expected: oids::ID_SIGNED_DATA.into(),
            got: ct.to_string(),
        });
    }
    let sd = parse_signed_data(&content_der)?;
    if sd.e_content_type.to_string() != oids::ID_CT_TSTINFO {
        return Err(TspError::ContentTypeMismatch);
    }
    let certs = parse_cert_set(&sd.certificates)?;

    let Some(si) = sd.signer_infos.into_iter().next() else {
        return Err(TspError::SignerCertNotFound);
    };

    let cert = find_signer_cert(
        &certs,
        &si.sid_issuer,
        &si.sid_serial,
        si.sid_ski.as_deref(),
    )
    .ok_or(TspError::SignerCertNotFound)?;

    let hash = HashAlgorithm::from_oid(&si.digest_alg)?;
    let content_digest = hash.digest(&sd.e_content);

    let (message, signed_attrs_present) = if let Some(sa) = &si.signed_attrs {
        let attrs = parse_attributes(sa)?;
        let mut got_ct = false;
        let mut got_md = false;
        for (oid, val) in &attrs {
            if oid == oids::CONTENT_TYPE {
                let ct_val: ObjectIdentifier = ObjectIdentifier::from_der(val.as_slice()).map_err(TspError::Asn1)?;
                if ct_val.to_string() != sd.e_content_type.to_string() {
                    return Err(TspError::ContentTypeMismatch);
                }
                got_ct = true;
            } else if oid == oids::MESSAGE_DIGEST {
                let md = der::asn1::OctetString::from_der(val.as_slice()).map_err(TspError::Asn1)?;
                if md.as_bytes() != content_digest {
                    return Err(TspError::MessageDigestMismatch);
                }
                got_md = true;
            }
        }
        if !got_ct || !got_md {
            return Err(TspError::Crypto(
                "signed attributes missing content-type or message-digest".into(),
            ));
        }
        (hash.digest(&wire::signed_attrs_tlv(sa)), true)
    } else {
        (content_digest.clone(), false)
    };

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

    TstInfo::from_der(&sd.e_content)
}

// ---------------------------------------------------------------------------
// CMS SignedData decoding (timeStampToken)
// ---------------------------------------------------------------------------

fn decode_content_info(der: &[u8]) -> Result<(ObjectIdentifier, Vec<u8>)> {
    let seq = der::Any::from_der(der).map_err(TspError::Asn1)?;
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
    let seq = der::Any::from_der(content_der).map_err(TspError::Asn1)?;
    wire::ensure_tag(seq.tag(), Tag::Sequence)?;
    let mut c = wire::Cursor::new(seq.value());

    let _version = c.take()?;
    let _digest_algs = c.take()?;

    let encap = c.take()?;
    wire::ensure_tag(encap.tag(), Tag::Sequence)?;
    let mut ec = wire::Cursor::new(encap.value());
    let e_content_type = wire::oid_of(&ec.take()?)?;
    let e_content = if ec.at_end() {
        Vec::new()
    } else {
        let e = ec.take()?;
        wire::ensure_tag(e.tag(), wire::ctx_tag_prim(0))?;
        e.value().to_vec()
    };

    let certificates = if !c.at_end() && c.peek_tag() == Some(wire::ctx_tag(0)) {
        Some(c.take()?.value().to_vec())
    } else {
        None
    };
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
    let seq = der::Any::from_der(der).map_err(TspError::Asn1)?;
    wire::ensure_tag(seq.tag(), Tag::Sequence)?;
    let mut c = wire::Cursor::new(seq.value());

    let _version = c.take()?;
    let sid = c.take()?;

    let (sid_issuer, sid_serial, sid_ski) = if sid.tag() == Tag::Sequence {
        let mut ias = wire::Cursor::new(sid.value());
        let issuer = ias.take()?;
        let serial = ias.take()?;
        (
            issuer.to_der().map_err(TspError::Asn1)?.to_vec(),
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

fn parse_attributes(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let elems = wire::parse_set_elements_raw(data)?;
    let mut out = Vec::new();
    for e in elems {
        let mut c = wire::Cursor::new(&e);
        let atype = c.take()?;
        let oid = wire::oid_of(&atype)?.to_string();
        let av = c.take()?;
        wire::ensure_tag(av.tag(), Tag::Set)?;
        let mut ac = wire::Cursor::new(av.value());
        let first = ac.take()?;
        out.push((oid, first.to_der().map_err(TspError::Asn1)?.to_vec()));
    }
    Ok(out)
}
