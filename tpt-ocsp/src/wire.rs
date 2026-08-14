// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ASN.1/DER wire types for RFC 6960 (OCSP).
//!
//! All types borrow from the input buffer (`'a`) so they can be decoded cheaply
//! and then copied out into owned public values by the client/responder paths.
//! The responder builds these same types referencing short-lived scratch
//! buffers and calls `to_der()`.

use const_oid::ObjectIdentifier;
use der::{
    asn1::{
        AnyRef, BitStringRef, GeneralizedTime, Null, ObjectIdentifierRef, OctetStringRef, UintRef,
    },
    Choice, Enumerated, Sequence,
};
use spki::AlgorithmIdentifierRef;
use x509_cert::name::Name;
use x509_cert::Certificate;

/// `OCSPResponseStatus` (RFC 6960 §4.2.1) — `ENUMERATED`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Enumerated)]
#[repr(u8)]
pub(crate) enum OcspResponseStatus {
    /// `successful` (0)
    Success = 0,
    /// `malformedRequest` (1)
    MalformedRequest = 1,
    /// `internalError` (2)
    InternalError = 2,
    /// `tryLater` (3)
    TryLater = 3,
    /// `sigRequired` (5)
    SigRequired = 5,
    /// `unauthorized` (6)
    Unauthorized = 6,
}

/// `OCSPResponse` (RFC 6960 §4.2.1).
#[derive(Clone, Sequence)]
pub(crate) struct OcspResponse<'a> {
    pub response_status: OcspResponseStatus,
    #[asn1(context_specific = "0", constructed, optional)]
    pub response_bytes: Option<ResponseBytes<'a>>,
}

/// `ResponseBytes` (RFC 6960 §4.2.1).
#[derive(Clone, Sequence)]
pub(crate) struct ResponseBytes<'a> {
    pub response_type: ObjectIdentifierRef<'a>,
    pub response: OctetStringRef<'a>,
}

/// `BasicOCSPResponse` (RFC 6960 §4.2.1).
#[derive(Clone, Sequence)]
pub(crate) struct BasicOcspResponse<'a> {
    /// Captured raw DER of `tbsResponseData` so the verifier hashes exactly the
    /// bytes that were signed.
    pub tbs_response_data: AnyRef<'a>,
    pub signature_algorithm: AlgorithmIdentifierRef<'a>,
    pub signature: BitStringRef<'a>,
    #[asn1(context_specific = "0", constructed, optional)]
    pub certs: Option<Vec<Certificate<'a>>>,
}

/// `ResponseData` (RFC 6960 §4.2.1).
#[derive(Clone, Sequence)]
pub(crate) struct ResponseData<'a> {
    #[asn1(context_specific = "0", constructed, optional)]
    pub version: Option<UintRef<'a>>,
    pub responder_id: ResponderId<'a>,
    pub produced_at: GeneralizedTime,
    pub responses: Vec<SingleResponse<'a>>,
    #[asn1(context_specific = "1", constructed, optional)]
    pub response_extensions: Option<Vec<Extension<'a>>>,
}

/// `ResponderID` (RFC 6960 §4.2.1).
#[derive(Clone, Choice)]
pub(crate) enum ResponderId<'a> {
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT")]
    ByName(Name),
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
    ByKey(OctetStringRef<'a>),
}

/// `SingleResponse` (RFC 6960 §4.2.1).
#[derive(Clone, Sequence)]
pub(crate) struct SingleResponse<'a> {
    pub cert_id: CertIdWire<'a>,
    pub cert_status: CertStatus<'a>,
    pub this_update: GeneralizedTime,
    #[asn1(context_specific = "0", constructed, optional)]
    pub next_update: Option<GeneralizedTime>,
    #[asn1(context_specific = "1", constructed, optional)]
    pub single_extensions: Option<Vec<Extension<'a>>>,
}

/// `CertStatus` (RFC 6960 §4.2.1).
#[derive(Clone, Choice)]
pub(crate) enum CertStatus<'a> {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Good(Null),
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed)]
    Revoked(RevokedInfo<'a>),
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
    Unknown(Null),
}

/// `RevokedInfo` (RFC 6960 §4.2.1).
#[derive(Clone, Sequence)]
pub(crate) struct RevokedInfo<'a> {
    pub revocation_time: GeneralizedTime,
    #[asn1(context_specific = "0", constructed, optional)]
    pub revocation_reason: Option<CrlReason>,
}

/// `CRLReason` (RFC 5280 §5.3.1) — used for `RevokedInfo.revocationReason`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Enumerated)]
#[repr(u8)]
pub(crate) enum CrlReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCrl = 8,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10,
}

impl CrlReason {
    /// Map a raw reason code to `CrlReason`, if recognised.
    pub(crate) fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(CrlReason::Unspecified),
            1 => Some(CrlReason::KeyCompromise),
            2 => Some(CrlReason::CaCompromise),
            3 => Some(CrlReason::AffiliationChanged),
            4 => Some(CrlReason::Superseded),
            5 => Some(CrlReason::CessationOfOperation),
            6 => Some(CrlReason::CertificateHold),
            8 => Some(CrlReason::RemoveFromCrl),
            9 => Some(CrlReason::PrivilegeWithdrawn),
            10 => Some(CrlReason::AaCompromise),
            _ => None,
        }
    }

    /// The numeric reason code.
    pub(crate) fn code(self) -> u8 {
        self as u8
    }
}

/// `CertID` (RFC 6960 §4.1.1).
#[derive(Clone, Sequence)]
pub(crate) struct CertIdWire<'a> {
    pub hash_algorithm: AlgorithmIdentifierRef<'a>,
    pub issuer_name_hash: OctetStringRef<'a>,
    pub issuer_key_hash: OctetStringRef<'a>,
    pub serial_number: UintRef<'a>,
}

/// `Extension` — a single `Extensions` member (RFC 5280 §4.1 / RFC 6960).
#[derive(Clone, Sequence)]
pub(crate) struct Extension<'a> {
    pub extn_id: ObjectIdentifier,
    #[asn1(default)]
    pub critical: bool,
    pub extn_value: OctetStringRef<'a>,
}

/// `OCSPRequest` (RFC 6960 §4.1.1).
#[derive(Clone, Sequence)]
pub(crate) struct OcspRequest<'a> {
    pub tbs_request: TbsRequest<'a>,
    #[asn1(context_specific = "0", constructed, optional)]
    pub optional_signature: Option<Signature<'a>>,
}

/// `TBSRequest` (RFC 6960 §4.1.1).
#[derive(Clone, Sequence)]
pub(crate) struct TbsRequest<'a> {
    #[asn1(context_specific = "0", constructed, optional)]
    pub version: Option<UintRef<'a>>,
    #[asn1(context_specific = "1", constructed, optional)]
    pub requestor_name: Option<AnyRef<'a>>,
    pub request_list: Vec<Request<'a>>,
    #[asn1(context_specific = "2", constructed, optional)]
    pub request_extensions: Option<Vec<Extension<'a>>>,
}

/// `Request` (RFC 6960 §4.1.1).
#[derive(Clone, Sequence)]
pub(crate) struct Request<'a> {
    pub req_cert: CertIdWire<'a>,
    #[asn1(context_specific = "0", constructed, optional)]
    pub single_request_extensions: Option<Vec<Extension<'a>>>,
}

/// `Signature` (RFC 6960 §4.1.1) — the optional `optionalSignature` field.
#[derive(Clone, Sequence)]
pub(crate) struct Signature<'a> {
    pub signature_algorithm: AlgorithmIdentifierRef<'a>,
    pub signature: BitStringRef<'a>,
    #[asn1(context_specific = "0", constructed, optional)]
    pub certs: Option<Vec<Certificate<'a>>>,
}
