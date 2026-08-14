//! ASN.1/DER wire types for RFC 3161 (TSP) and the CMS `SignedData` wrapper
//! (RFC 5652) used to convey the `timeStampToken`.
//!
//! All types borrow from the input buffer (`'a`) so they can be decoded cheaply
//! and then copied out into owned public values by the verification path. The
//! TSA responder builds these same types referencing short-lived scratch
//! buffers and calls `to_der()`.

use const_oid::{ObjectIdentifier, ObjectIdentifierRef};
use der::{
    asn1::{AnyRef, GeneralizedTime, OctetStringRef, UintRef},
    Decode, Encode, Sequence, Tagged,
};
use spki::AlgorithmIdentifierRef;
use x509_cert::name::Name;

/// Raw SET/IMPLICIT content: the inner bytes of an `IMPLICIT [N] constructed`
/// field (used for `signedAttrs` and `certificates`). The context tag itself is
/// emitted by the `der` `#[asn1(context_specific = "N", constructed)]` wrapper;
/// this type only carries the *content* octets.
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
        Ok(RawContent(any.value().to_vec()))
    }
}

/// SET OF `T` helpers (manual, to guarantee DER sorting of the elements).
pub(crate) fn set_tlv(items: &[Vec<u8>]) -> der::Result<Vec<u8>> {
    let mut parts = items.to_vec();
    parts.sort();
    let content_len: usize = parts.iter().map(|p| p.len()).sum();
    let len = der::Length::try_from(content_len)?;
    let mut out = Vec::with_capacity(1 + len.to_der()?.len() + content_len);
    out.push(0x31);
    out.extend_from_slice(&len.to_der()?);
    for p in &parts {
        out.extend_from_slice(p);
    }
    Ok(out)
}

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

/// `DigestAlgorithmIdentifiers` — `SET OF AlgorithmIdentifier` (RFC 5652).
#[derive(Clone)]
pub(crate) struct DigestAlgorithmIdentifiers<'a>(pub Vec<AlgorithmIdentifierRef<'a>>);

impl<'a> der::Encode for DigestAlgorithmIdentifiers<'a> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let parts: Vec<Vec<u8>> = self
            .0
            .iter()
            .map(|a| a.to_der())
            .collect::<der::Result<Vec<_>>>()?;
        der::Length::try_from(set_tlv(&parts)?.len())
    }
    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        let parts: Vec<Vec<u8>> = self
            .0
            .iter()
            .map(|a| a.to_der())
            .collect::<der::Result<Vec<_>>>()?;
        let set = set_tlv(&parts)?;
        encoder.write(&set)
    }
}

impl<'a> der::Decode<'a> for DigestAlgorithmIdentifiers<'a> {
    fn decode(decoder: &mut impl der::Reader<'a>) -> der::Result<Self> {
        let any = AnyRef::decode(decoder)?;
        if any.tag() != der::Tag::Set {
            return Err(der::Error::TagUnexpected {
                expected: Some(der::Tag::Set),
                actual: any.tag(),
            });
        }
        Ok(DigestAlgorithmIdentifiers(decode_set_elements(any.value())?))
    }
}

/// `SignerInfos` — `SET OF SignerInfo` (RFC 5652).
#[derive(Clone)]
pub(crate) struct SignerInfos<'a>(pub Vec<SignerInfo<'a>>);

impl<'a> der::Encode for SignerInfos<'a> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let parts: Vec<Vec<u8>> = self
            .0
            .iter()
            .map(|s| s.to_der())
            .collect::<der::Result<Vec<_>>>()?;
        der::Length::try_from(set_tlv(&parts)?.len())
    }
    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        let parts: Vec<Vec<u8>> = self
            .0
            .iter()
            .map(|s| s.to_der())
            .collect::<der::Result<Vec<_>>>()?;
        let set = set_tlv(&parts)?;
        encoder.write(&set)
    }
}

impl<'a> der::Decode<'a> for SignerInfos<'a> {
    fn decode(decoder: &mut impl der::Reader<'a>) -> der::Result<Self> {
        let any = AnyRef::decode(decoder)?;
        if any.tag() != der::Tag::Set {
            return Err(der::Error::TagUnexpected {
                expected: Some(der::Tag::Set),
                actual: any.tag(),
            });
        }
        Ok(SignerInfos(decode_set_elements(any.value())?))
    }
}

/// `MessageImprint` (RFC 3161 §2.4.1).
#[derive(Clone, Sequence)]
pub(crate) struct MessageImprint<'a> {
    pub hash_algorithm: AlgorithmIdentifierRef<'a>,
    pub hashed_message: OctetStringRef<'a>,
}

/// `TimeStampReq` (RFC 3161 §2.4.1).
#[derive(Clone, Sequence)]
pub(crate) struct TimeStampReq<'a> {
    pub version: UintRef<'a>,
    pub message_imprint: MessageImprint<'a>,
    #[asn1(optional)]
    pub req_policy: Option<ObjectIdentifierRef<'a>>,
    #[asn1(optional)]
    pub nonce: Option<UintRef<'a>>,
    #[asn1(optional)]
    pub cert_req: Option<bool>,
    #[asn1(context_specific = "0", constructed, optional)]
    pub extensions: Option<AnyRef<'a>>,
}

impl<'a> TimeStampReq<'a> {
    pub fn cert_req_bool(&self) -> bool {
        self.cert_req.unwrap_or(false)
    }
}

/// `PKIStatusInfo` (RFC 3161 §2.4.2).
#[derive(Clone, Sequence)]
pub(crate) struct PkiStatusInfo<'a> {
    pub status: UintRef<'a>,
    #[asn1(optional)]
    pub status_string: Option<der::asn1::AnyRef<'a>>,
    #[asn1(optional)]
    pub fail_info: Option<der::asn1::BitStringRef<'a>>,
}

/// `TimeStampResp` (RFC 3161 §2.4.2).
#[derive(Clone, Sequence)]
pub(crate) struct TimeStampResp<'a> {
    pub status: PkiStatusInfo<'a>,
    #[asn1(optional)]
    pub token: Option<ContentInfo<'a>>,
}

/// `TSTInfo` (RFC 3161 §2.4.3).
#[derive(Clone, Sequence)]
pub(crate) struct TstInfo<'a> {
    pub version: UintRef<'a>,
    pub policy: ObjectIdentifierRef<'a>,
    pub message_imprint: MessageImprint<'a>,
    pub serial_number: UintRef<'a>,
    pub gen_time: GeneralizedTime,
    #[asn1(optional)]
    pub accuracy: Option<Accuracy<'a>>,
    #[asn1(optional)]
    pub ordering: Option<bool>,
    #[asn1(optional)]
    pub nonce: Option<UintRef<'a>>,
    #[asn1(context_specific = "0", constructed, optional)]
    pub tsa: Option<GeneralName<'a>>,
    #[asn1(context_specific = "1", constructed, optional)]
    pub extensions: Option<AnyRef<'a>>,
}

/// `Accuracy` (RFC 3161 §2.4.3).
#[derive(Clone, Sequence)]
pub(crate) struct Accuracy<'a> {
    #[asn1(optional)]
    pub seconds: Option<UintRef<'a>>,
    #[asn1(context_specific = "0", optional)]
    pub millis: Option<UintRef<'a>>,
    #[asn1(context_specific = "1", optional)]
    pub micros: Option<UintRef<'a>>,
}

/// `GeneralName` (subset used by `tsa`, RFC 3161 §2.4.3 / RFC 5280).
#[derive(Clone, der::Choice)]
pub(crate) enum GeneralName<'a> {
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
    DnsName(der::asn1::Ia5StringRef<'a>),
    #[asn1(context_specific = "4", tag_mode = "EXPLICIT", constructed)]
    DirectoryName(Name),
}

// ---------------------------------------------------------------------------
// CMS (RFC 5652) structures.
// ---------------------------------------------------------------------------

/// `ContentInfo` — `{ contentType, content [0] EXPLICIT ANY }`.
#[derive(Clone, Sequence)]
pub(crate) struct ContentInfo<'a> {
    pub content_type: ObjectIdentifierRef<'a>,
    #[asn1(context_specific = "0", constructed)]
    pub content: AnyRef<'a>,
}

impl<'a> ContentInfo<'a> {
    /// Decode the inner `content` as `T` (e.g. `SignedData`).
    pub fn content_as<T: der::Decode<'a>>(&self) -> der::Result<T> {
        T::from_der(self.content.value())
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
    /// The raw encapsulated content bytes (e.g. the DER-encoded `TSTInfo`).
    pub fn content_bytes(&self) -> der::Result<Vec<u8>> {
        match &self.e_content {
            Some(any) => {
                let os = OctetStringRef::from_der(any.value())?;
                Ok(os.as_bytes().to_vec())
            }
            None => Ok(Vec::new()),
        }
    }
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
    pub crls: Option<AnyRef<'a>>,
    pub signer_infos: SignerInfos<'a>,
}

/// `IssuerAndSerialNumber` (RFC 5652 §10.2.4).
#[derive(Clone, Sequence)]
pub(crate) struct IssuerAndSerialNumber<'a> {
    pub issuer: Name,
    pub serial_number: UintRef<'a>,
}

/// `SignerIdentifier` (RFC 5652 §10.2.3) — only the `IssuerAndSerialNumber`
/// alternative is produced/consumed here (the commonly deployed form).
#[derive(Clone)]
pub(crate) struct SignerIdentifier<'a>(pub IssuerAndSerialNumber<'a>);

impl<'a> der::Encode for SignerIdentifier<'a> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        self.0.encoded_len()
    }
    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

impl<'a> der::Decode<'a> for SignerIdentifier<'a> {
    fn decode(decoder: &mut impl der::Reader<'a>) -> der::Result<Self> {
        Ok(SignerIdentifier(IssuerAndSerialNumber::decode(decoder)?))
    }
}

/// `SignerInfo` (RFC 5652 §5.3).
#[derive(Clone, Sequence)]
pub(crate) struct SignerInfo<'a> {
    pub version: UintRef<'a>,
    pub sid: SignerIdentifier,
    pub digest_algorithm: AlgorithmIdentifierRef<'a>,
    #[asn1(context_specific = "0", constructed, optional)]
    pub signed_attrs: Option<RawContent>,
    pub signature_algorithm: AlgorithmIdentifierRef<'a>,
    pub signature: OctetStringRef<'a>,
}

/// Reconstruct the DER `SET` TLV from `IMPLICIT [0]` signed-attributes content.
pub(crate) fn signed_attrs_set_tlv(content: &[u8]) -> Vec<u8> {
    let mut out = vec![0x31];
    out.extend_from_slice(&der::Length::try_from(content.len()).unwrap().to_der().unwrap());
    out.extend_from_slice(content);
    out
}

/// Build a CMS `Attribute` `{ attrType, attrValues SET OF value }` from a single
/// value TLV.
pub(crate) fn cms_attribute(attr_type: &ObjectIdentifier, value_tlv: &[u8]) -> der::Result<Vec<u8>> {
    let set = set_tlv(&[value_tlv.to_vec()])?;
    let mut attr = Vec::new();
    attr.extend_from_slice(&attr_type.to_der()?);
    attr.extend_from_slice(&set);
    let mut out = Vec::new();
    out.push(0x30);
    out.extend_from_slice(&der::Length::try_from(attr.len())?.to_der()?);
    out.extend_from_slice(&attr);
    Ok(out)
}
