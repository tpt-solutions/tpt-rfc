//! ASN.1/DER wire types for RFC 3161 (TSP) and the CMS `SignedData` wrapper
//! (RFC 5652) used to convey the `timeStampToken`.
//!
//! All types that borrow from an input buffer use the `der` 0.8 DST `*Ref`
//! types (`OctetString`, `ObjectIdentifier`, `BitString`, `Ia5String` are the
//! owned forms used for struct fields; `UintRef`/`AlgorithmIdentifierRef`/
//! `AnyRef` keep an explicit lifetime). The TSA responder builds these same
//! types referencing short-lived scratch buffers and calls `to_der()`.

use const_oid::ObjectIdentifier;
use der::{
    asn1::{AnyRef, BitString, GeneralizedTime, Ia5String, OctetString, UintRef},
    Choice, Decode, DecodeValue, Encode, EncodeValue, FixedTag, Sequence, Tagged,
};
use spki::AlgorithmIdentifierRef;
use x509_cert::name::Name;

/// Raw SET/IMPLICIT content: the inner bytes of an `IMPLICIT [N] constructed`
/// field (used for `signedAttrs` and `certificates`). The context tag itself is
/// emitted by the `der` `#[asn1(context_specific = "N", constructed, optional)]`
/// wrapper; this type only carries the *content* octets (a SET OF TLVs).
///
/// We tag it as a `SET` so the surrounding `context_specific` (constructed)
/// field produces `[N] EXPLICIT SET { content }`, which is exactly what RFC
/// 5652 requires for `signedAttrs` and the `certificates` set.
#[derive(Clone)]
pub(crate) struct RawContent(pub Vec<u8>);

impl Tagged for RawContent {
    const TAG: der::Tag = der::Tag::Set;
}

impl FixedTag for RawContent {
    const TAG: der::Tag = der::Tag::Set;
}

impl EncodeValue for RawContent {
    fn value_len(&self) -> der::Result<der::Length> {
        der::Length::try_from(self.0.len())
    }
    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        encoder.write(&self.0)
    }
}

impl DecodeValue<'_> for RawContent {
    type Error = der::Error;
    fn decode_value<R: der::Reader<'_>>(reader: &mut R, header: der::Header) -> der::Result<Self> {
        let bytes = reader.read_vec(header.length)?;
        Ok(RawContent(bytes))
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
        let tlv_len = AnyRef::from_der(rest)?.value().len();
        let elem = T::from_der(&rest[..tlv_len])
            .map_err(|e| der::Error::new(der::ErrorKind::Failed, der::Length::ZERO))?;
        out.push(elem);
        rest = &rest[tlv_len..];
    }
    Ok(out)
}

/// `DigestAlgorithmIdentifiers` — `SET OF AlgorithmIdentifier` (RFC 5652).
#[derive(Clone)]
pub(crate) struct DigestAlgorithmIdentifiers<'a>(pub Vec<AlgorithmIdentifierRef<'a>>);

impl<'a> Tagged for DigestAlgorithmIdentifiers<'a> {
    const TAG: der::Tag = der::Tag::Set;
}

impl<'a> FixedTag for DigestAlgorithmIdentifiers<'a> {
    const TAG: der::Tag = der::Tag::Set;
}

impl<'a> EncodeValue for DigestAlgorithmIdentifiers<'a> {
    fn value_len(&self) -> der::Result<der::Length> {
        let mut total = der::Length::ZERO;
        for a in &self.0 {
            total = total + a.encoded_len()?;
        }
        total
    }
    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        for a in &self.0 {
            a.encode(encoder)?;
        }
        Ok(())
    }
}

impl<'a> DecodeValue<'a> for DigestAlgorithmIdentifiers<'a> {
    type Error = der::Error;
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, _header: der::Header) -> der::Result<Self> {
        let mut v = Vec::new();
        while !reader.is_finished() {
            v.push(AlgorithmIdentifierRef::decode(reader)?);
        }
        Ok(DigestAlgorithmIdentifiers(v))
    }
}

/// `SignerInfos` — `SET OF SignerInfo` (RFC 5652).
#[derive(Clone)]
pub(crate) struct SignerInfos<'a>(pub Vec<SignerInfo<'a>>);

impl<'a> Tagged for SignerInfos<'a> {
    const TAG: der::Tag = der::Tag::Set;
}

impl<'a> FixedTag for SignerInfos<'a> {
    const TAG: der::Tag = der::Tag::Set;
}

impl<'a> EncodeValue for SignerInfos<'a> {
    fn value_len(&self) -> der::Result<der::Length> {
        let mut total = der::Length::ZERO;
        for s in &self.0 {
            total = total + s.encoded_len()?;
        }
        total
    }
    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        for s in &self.0 {
            s.encode(encoder)?;
        }
        Ok(())
    }
}

impl<'a> DecodeValue<'a> for SignerInfos<'a> {
    type Error = der::Error;
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, _header: der::Header) -> der::Result<Self> {
        let mut v = Vec::new();
        while !reader.is_finished() {
            v.push(SignerInfo::decode(reader)?);
        }
        Ok(SignerInfos(v))
    }
}

/// `MessageImprint` (RFC 3161 §2.4.1).
#[derive(Clone, Sequence)]
pub(crate) struct MessageImprint<'a> {
    pub hash_algorithm: AlgorithmIdentifierRef<'a>,
    pub hashed_message: OctetString,
}

/// `TimeStampReq` (RFC 3161 §2.4.1).
#[derive(Clone, Sequence)]
pub(crate) struct TimeStampReq<'a> {
    pub version: UintRef<'a>,
    pub message_imprint: MessageImprint<'a>,
    #[asn1(optional = "true")]
    pub req_policy: Option<ObjectIdentifier>,
    #[asn1(optional = "true")]
    pub nonce: Option<UintRef<'a>>,
    #[asn1(optional = "true")]
    pub cert_req: Option<bool>,
    #[asn1(context_specific = "0", constructed = "true", optional = "true")]
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
    #[asn1(optional = "true")]
    pub status_string: Option<AnyRef<'a>>,
    #[asn1(optional = "true")]
    pub fail_info: Option<BitString>,
}

/// `TimeStampResp` (RFC 3161 §2.4.2).
#[derive(Clone, Sequence)]
pub(crate) struct TimeStampResp<'a> {
    pub status: PkiStatusInfo<'a>,
    #[asn1(optional = "true")]
    pub token: Option<ContentInfo<'a>>,
}

/// `TSTInfo` (RFC 3161 §2.4.3).
#[derive(Clone, Sequence)]
pub(crate) struct TstInfo<'a> {
    pub version: UintRef<'a>,
    pub policy: ObjectIdentifier,
    pub message_imprint: MessageImprint<'a>,
    pub serial_number: UintRef<'a>,
    pub gen_time: GeneralizedTime,
    #[asn1(optional = "true")]
    pub accuracy: Option<Accuracy<'a>>,
    #[asn1(optional = "true")]
    pub ordering: Option<bool>,
    #[asn1(optional = "true")]
    pub nonce: Option<UintRef<'a>>,
    #[asn1(context_specific = "0", constructed = "true", optional = "true")]
    pub tsa: Option<GeneralName<'a>>,
    #[asn1(context_specific = "1", constructed = "true", optional = "true")]
    pub extensions: Option<AnyRef<'a>>,
}

/// `Accuracy` (RFC 3161 §2.4.3).
#[derive(Clone, Sequence)]
pub(crate) struct Accuracy<'a> {
    #[asn1(optional = "true")]
    pub seconds: Option<UintRef<'a>>,
    #[asn1(context_specific = "0", optional = "true")]
    pub millis: Option<UintRef<'a>>,
    #[asn1(context_specific = "1", optional = "true")]
    pub micros: Option<UintRef<'a>>,
}

/// `GeneralName` (subset used by `tsa`, RFC 3161 §2.4.3 / RFC 5280).
#[derive(Clone, Choice)]
pub(crate) enum GeneralName<'a> {
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
    DnsName(Ia5String),
    #[asn1(context_specific = "4", tag_mode = "EXPLICIT", constructed = "true")]
    DirectoryName(Name),
}

// ---------------------------------------------------------------------------
// CMS (RFC 5652) structures.
// ---------------------------------------------------------------------------

/// `ContentInfo` — `{ contentType, content [0] EXPLICIT ANY }`.
#[derive(Clone, Sequence)]
pub(crate) struct ContentInfo<'a> {
    pub content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", constructed = "true")]
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
    pub e_content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", constructed = "true", optional = "true")]
    pub e_content: Option<AnyRef<'a>>,
}

impl<'a> EncapsulatedContentInfo<'a> {
    /// The raw encapsulated content bytes (e.g. the DER-encoded `TSTInfo`).
    pub fn content_bytes(&self) -> der::Result<Vec<u8>> {
        match &self.e_content {
            Some(any) => {
                let os = OctetString::from_der(any.value())?;
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
    #[asn1(context_specific = "0", constructed = "true", optional = "true")]
    pub certificates: Option<RawContent>,
    #[asn1(context_specific = "1", constructed = "true", optional = "true")]
    pub crls: Option<AnyRef<'a>>,
    pub signer_infos: SignerInfos<'a>,
}

/// `IssuerAndSerialNumber` (RFC 5652 §10.2.4).
#[derive(Clone, Sequence)]
pub(crate) struct IssuerAndSerialNumber<'a> {
    pub issuer: Name,
    pub serial_number: UintRef<'a>,
}

/// `SignerInfo` (RFC 5652 §5.3).
#[derive(Clone, Sequence)]
pub(crate) struct SignerInfo<'a> {
    pub version: UintRef<'a>,
    pub sid: IssuerAndSerialNumber<'a>,
    pub digest_algorithm: AlgorithmIdentifierRef<'a>,
    #[asn1(context_specific = "0", constructed = "true", optional = "true")]
    pub signed_attrs: Option<RawContent>,
    pub signature_algorithm: AlgorithmIdentifierRef<'a>,
    pub signature: OctetString,
}

/// Reconstruct the DER `SET` TLV from `IMPLICIT [0]` signed-attributes content.
pub(crate) fn signed_attrs_set_tlv(content: &[u8]) -> Vec<u8> {
    let mut out = vec![0x31];
    out.extend_from_slice(
        &der::Length::try_from(content.len())
            .unwrap()
            .to_der()
            .unwrap(),
    );
    out.extend_from_slice(content);
    out
}

/// A single CMS `Attribute` `{ attrType, attrValues SET OF value }`, decoded
/// when verifying the signed attributes of a token.
#[derive(Clone, Sequence)]
pub(crate) struct Attribute<'a> {
    pub attr_type: ObjectIdentifier,
    pub attr_values: der::asn1::SetOfVec<AnyRef<'a>>,
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
