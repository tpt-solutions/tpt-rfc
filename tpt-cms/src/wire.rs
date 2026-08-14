//! Low-level ASN.1/DER helpers and wire types for RFC 5652 CMS.
//!
//! Encoding is performed with manual TLV helpers (so the crate stays in full
//! control of DER ordering, sorting of SET OF elements, and the exact
//! `IMPLICIT`/`EXPLICIT` tagging the spec mandates). Decoding reuses the `der`
//! `#[derive(Sequence)]` machinery on borrow-from-input types.

use const_oid::ObjectIdentifier;
use der::{
    asn1::{AnyRef, Name, OctetStringRef, UintRef},
    Sequence,
};
use spki::AlgorithmIdentifierRef;
use x509_cert::name::Name as X509Name;

// ---------------------------------------------------------------------------
// Manual TLV builders
// ---------------------------------------------------------------------------

/// Encode a definite-length TLV with a single-byte tag.
pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&enc_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// Encode the DER length octets for `n` (definite length, short/long form).
pub(crate) fn enc_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        let mut bytes = (n as u128).to_be_bytes().to_vec();
        while bytes.len() > 1 && bytes[0] == 0 {
            bytes.remove(0);
        }
        let mut out = vec![0x80 | (bytes.len() as u8)];
        out.extend_from_slice(&bytes);
        out
    }
}

/// `[n] EXPLICIT` (or IMPLICIT-constructed) context tag: `0xA0 | n`.
pub(crate) fn ctx(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xA0 | n, content)
}

pub(crate) fn integer_be(bytes: &[u8]) -> Vec<u8> {
    // Minimal big-endian encoding with the DER integer sign rule.
    let mut v = bytes.to_vec();
    while v.len() > 1 && v[0] == 0 {
        v.remove(0);
    }
    if let Some(&first) = v.first() {
        if first & 0x80 != 0 {
            v.insert(0, 0x00);
        }
    }
    tlv(0x02, &v)
}

pub(crate) fn integer_u64(v: u64) -> Vec<u8> {
    integer_be(&v.to_be_bytes())
}

pub(crate) fn octet_string(data: &[u8]) -> Vec<u8> {
    tlv(0x04, data)
}

pub(crate) fn oid_der(oid: &ObjectIdentifier) -> Vec<u8> {
    oid.to_der().expect("oid der")
}

/// Build an `AlgorithmIdentifier` SEQUENCE `{ OID, [params] }`.
pub(crate) fn algorithm_identifier(oid: &ObjectIdentifier, params: Option<&[u8]>) -> Vec<u8> {
    let mut parts = vec![oid_der(oid)];
    if let Some(p) = params {
        parts.push(p.to_vec());
    }
    sequence(&parts)
}

pub(crate) fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    let content: Vec<u8> = parts.iter().flatten().cloned().collect();
    tlv(0x30, &content)
}

/// Build a `SET OF` TLV, with elements DER-sorted (canonical order).
pub(crate) fn set_of(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut sorted = parts.to_vec();
    sorted.sort();
    let content: Vec<u8> = sorted.iter().flatten().cloned().collect();
    tlv(0x31, &content)
}

/// Build a CMS `Attribute` SEQUENCE `{ attrType, attrValues SET OF value }`.
pub(crate) fn attribute(attr_oid: &ObjectIdentifier, value: &[u8]) -> Vec<u8> {
    sequence(&[oid_der(attr_oid), tlv(0x31, value)])
}

/// Re-wrap SET content with an explicit `SET` (0x31) tag + length.
pub(crate) fn signed_attrs_tlv(content: &[u8]) -> Vec<u8> {
    tlv(0x31, content)
}

// ---------------------------------------------------------------------------
// Shared DER value wrappers
// ---------------------------------------------------------------------------

/// Raw `IMPLICIT [N]` constructed content: carries just the *content* octets of
/// an `IMPLICIT [N]` field (the context tag is emitted by the caller).
#[derive(Clone)]
pub(crate) struct RawContent(pub Vec<u8>);

impl der::Encode for RawContent {
    fn encoded_len(&self) -> der::Result<der::Length> {
        der::Length::try_from(self.0.len())
    }
    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        encoder.write(&self.0)
    }
}

impl<'a> der::Decode<'a> for RawContent {
    fn decode(decoder: &mut impl der::Reader<'a>) -> der::Result<Self> {
        let any = AnyRef::decode(decoder)?;
        Ok(RawContent(any.value.to_vec()))
    }
}

/// `SET OF AlgorithmIdentifier` (RFC 5652 `DigestAlgorithmIdentifiers`).
#[derive(Clone)]
pub(crate) struct DigestAlgorithmIdentifiers<'a>(pub Vec<AlgorithmIdentifierRef<'a>>);

impl<'a> der::Encode for DigestAlgorithmIdentifiers<'a> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let parts: Vec<Vec<u8>> = self
            .0
            .iter()
            .map(|a| a.to_der())
            .collect::<der::Result<Vec<_>>>()?;
        der::Length::try_from(set_of(&parts).len())
    }
    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        let parts: Vec<Vec<u8>> = self
            .0
            .iter()
            .map(|a| a.to_der())
            .collect::<der::Result<Vec<_>>>()?;
        encoder.write(&set_of(&parts))
    }
}

impl<'a> der::Decode<'a> for DigestAlgorithmIdentifiers<'a> {
    fn decode(decoder: &mut impl der::Reader<'a>) -> der::Result<Self> {
        let any = AnyRef::decode(decoder)?;
        if any.tag != der::Tag::Set {
            return Err(der::Error::TagUnexpected {
                expected: Some(der::Tag::Set),
                actual: any.tag,
            });
        }
        decode_set_elements(&any.value)
    }
}

/// `SET OF SignerInfo` (RFC 5652 `SignerInfos`).
#[derive(Clone)]
pub(crate) struct SignerInfos<'a>(pub Vec<SignerInfo<'a>>);

impl<'a> der::Encode for SignerInfos<'a> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let parts: Vec<Vec<u8>> = self
            .0
            .iter()
            .map(|s| s.to_der())
            .collect::<der::Result<Vec<_>>>()?;
        der::Length::try_from(set_of(&parts).len())
    }
    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        let parts: Vec<Vec<u8>> = self
            .0
            .iter()
            .map(|s| s.to_der())
            .collect::<der::Result<Vec<_>>>()?;
        encoder.write(&set_of(&parts))
    }
}

impl<'a> der::Decode<'a> for SignerInfos<'a> {
    fn decode(decoder: &mut impl der::Reader<'a>) -> der::Result<Self> {
        let any = AnyRef::decode(decoder)?;
        if any.tag != der::Tag::Set {
            return Err(der::Error::TagUnexpected {
                expected: Some(der::Tag::Set),
                actual: any.tag,
            });
        }
        decode_set_elements(&any.value)
    }
}

/// Decode the elements of a `SET`/`SET OF` whose DER is in `data`.
pub(crate) fn decode_set_elements<'a, T: der::Decode<'a>>(data: &'a [u8]) -> der::Result<Vec<T>> {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let any = AnyRef::from_der(rest)?;
        let consumed = any.as_bytes().len();
        out.push(T::from_der(any.as_bytes())?);
        rest = &rest[consumed..];
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Top-level content wrapper + core content types (decode side)
// ---------------------------------------------------------------------------

/// `ContentInfo` — `{ contentType, content [0] EXPLICIT ANY }` (RFC 5652 §3).
#[derive(Clone, Sequence)]
pub(crate) struct ContentInfo<'a> {
    pub content_type: ObjectIdentifierRef<'a>,
    #[asn1(context_specific = "0", constructed)]
    pub content: AnyRef<'a>,
}

impl<'a> ContentInfo<'a> {
    pub fn content_as<T: der::Decode<'a>>(&self) -> der::Result<T> {
        T::from_der(self.content.value)
    }
}

/// `EncapsulatedContentInfo` — `{ eContentType, eContent [0] EXPLICIT OCTET STRING }`.
#[derive(Clone, Sequence)]
pub(crate) struct EncapsulatedContentInfo<'a> {
    pub e_content_type: ObjectIdentifierRef<'a>,
    #[asn1(context_specific = "0", constructed, optional)]
    pub e_content: Option<AnyRef<'a>>,
}

impl<'a> EncapsulatedContentInfo<'a> {
    pub fn content_bytes(&self) -> der::Result<Vec<u8>> {
        match &self.e_content {
            Some(any) => Ok(OctetStringRef::from_der(any.value)?.as_bytes().to_vec()),
            None => Ok(Vec::new()),
        }
    }
}

/// `IssuerAndSerialNumber` (RFC 5652 §10.2.4).
#[derive(Clone, Sequence)]
pub(crate) struct IssuerAndSerialNumber<'a> {
    pub issuer: X509Name,
    pub serial_number: UintRef<'a>,
}

/// `SignerIdentifier` (RFC 5652 §10.2.3): CHOICE of `IssuerAndSerialNumber`
/// (the common, default form) or `subjectKeyIdentifier [0] IMPLICIT`.
#[derive(Clone)]
pub(crate) enum SignerIdentifier<'a> {
    IssuerAndSerialNumber(IssuerAndSerialNumber<'a>),
    SubjectKeyIdentifier(der::asn1::OctetStringRef<'a>),
}

impl<'a> der::Decode<'a> for SignerIdentifier<'a> {
    fn decode(decoder: &mut impl der::Reader<'a>) -> der::Result<Self> {
        let any = AnyRef::decode(decoder)?;
        match any.tag {
            der::Tag::Sequence => Ok(SignerIdentifier::IssuerAndSerialNumber(
                IssuerAndSerialNumber::from_der(any.as_bytes())?,
            )),
            // [0] IMPLICIT subjectKeyIdentifier => context-specific, primitive [0].
            tag if tag == der::Tag::context_specific(0) => Ok(
                SignerIdentifier::SubjectKeyIdentifier(der::asn1::OctetStringRef::from_der(
                    any.value,
                )?),
            ),
            other => Err(der::Error::TagUnexpected {
                expected: Some(der::Tag::Sequence),
                actual: other,
            }),
        }
    }
}

impl<'a> der::Encode for SignerIdentifier<'a> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        match self {
            SignerIdentifier::IssuerAndSerialNumber(i) => i.encoded_len(),
            SignerIdentifier::SubjectKeyIdentifier(s) => s.encoded_len(),
        }
    }
    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        match self {
            SignerIdentifier::IssuerAndSerialNumber(i) => i.encode(encoder),
            SignerIdentifier::SubjectKeyIdentifier(s) => s.encode(encoder),
        }
    }
}

/// `SignerInfo` (RFC 5652 §5.3).
#[derive(Clone, Sequence)]
pub(crate) struct SignerInfo<'a> {
    pub version: UintRef<'a>,
    pub sid: SignerIdentifier<'a>,
    pub digest_algorithm: AlgorithmIdentifierRef<'a>,
    #[asn1(context_specific = "0", constructed, optional)]
    pub signed_attrs: Option<RawContent>,
    pub signature_algorithm: AlgorithmIdentifierRef<'a>,
    pub signature: OctetStringRef<'a>,
}

/// CMS `Attribute` `{ attrType, attrValues SET OF AttributeValue }` (RFC 5652 §11).
#[derive(Clone, Sequence)]
pub(crate) struct Attribute<'a> {
    pub attr_type: ObjectIdentifierRef<'a>,
    pub attr_values: der::asn1::SetOfVec<AnyRef<'a>>,
}

/// `SignedData` (RFC 5652 §5.1).
#[derive(Clone, Sequence)]
pub(crate) struct SignedData<'a> {
    pub version: UintRef<'a>,
    pub digest_algorithms: DigestAlgorithmIdentifiers<'a>,
    pub encap_content_info: EncapsulatedContentInfo<'a>,
    #[asn1(context_specific = "0", constructed, optional)]
    pub certificates: Option<RawContent>,
    #[asn1(context_specific = "1", constructed, optional)]
    pub crls: Option<RawContent>,
    pub signer_infos: SignerInfos<'a>,
}
