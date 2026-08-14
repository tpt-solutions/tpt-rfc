// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 4511 LDAP message model: encoding/decoding of requests and responses,
//! search scope handling, and search-filter evaluation.
//!
//! The wire format is BER, provided by [`crate::ber`]. This module maps the
//! ASN.1 definitions in RFC 4511 onto Rust types and implements the filter
//! matching rules and DN scope logic the server needs.

use crate::backend::{Attribute, Entry, Modification, ModifyDnRequest, SaslCredentials};
use crate::ber::{universal, BerElement, BerError, Tag};

/// An attribute value assertion (RFC 4511 §4.1.8): a type and a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeValueAssertion {
    /// The attribute description (type).
    pub attribute_desc: String,
    /// The assertion value bytes.
    pub assertion_value: Vec<u8>,
}

/// LDAP `resultCode` values (RFC 4511 §4.1.9 / RFC 4510 Appendix A.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
#[repr(i64)]
pub enum ResultCode {
    Success = 0,
    OperationsError = 1,
    ProtocolError = 2,
    TimeLimitExceeded = 3,
    SizeLimitExceeded = 4,
    CompareFalse = 5,
    CompareTrue = 6,
    AuthMethodNotSupported = 7,
    StrongAuthRequired = 8,
    Referral = 10,
    AdminLimitExceeded = 11,
    UnavailableCriticalExtension = 12,
    ConfidentialityRequired = 13,
    SaslBindInProgress = 14,
    NoSuchAttribute = 16,
    UndefinedAttributeType = 17,
    InappropriateMatching = 18,
    ConstraintViolation = 19,
    AttributeOrValueExists = 20,
    InvalidAttributeSyntax = 21,
    NoSuchObject = 32,
    AliasProblem = 33,
    InvalidDnSyntax = 34,
    AliasDereferencingProblem = 36,
    InappropriateAuthentication = 48,
    InvalidCredentials = 49,
    InsufficientAccessRights = 50,
    Busy = 51,
    Unavailable = 52,
    UnwillingToPerform = 53,
    LoopDetect = 54,
    NamingViolation = 64,
    ObjectClassViolation = 65,
    NotAllowedOnNonLeaf = 66,
    NotAllowedOnRdn = 67,
    EntryAlreadyExists = 68,
    AffectsMultipleDsas = 71,
    Other = 80,
}

impl ResultCode {
    /// The integer tag value as used on the wire.
    pub fn as_i64(self) -> i64 {
        self as i64
    }

    /// Map a backend error onto the closest LDAP `resultCode`.
    pub fn from_backend_error(e: &crate::error::BackendError) -> Self {
        use crate::error::BackendError;
        match e {
            BackendError::AuthenticationFailed => ResultCode::InvalidCredentials,
            BackendError::NotFound => ResultCode::NoSuchObject,
            BackendError::EntryAlreadyExists => ResultCode::EntryAlreadyExists,
            BackendError::NoSuchAttribute => ResultCode::NoSuchAttribute,
            BackendError::AttributeOrValueExists => ResultCode::AttributeOrValueExists,
            BackendError::InsufficientAccess => ResultCode::InsufficientAccessRights,
            BackendError::ConstraintViolation => ResultCode::ConstraintViolation,
            BackendError::Unsupported => ResultCode::UnavailableCriticalExtension,
            BackendError::Other(_) => ResultCode::Other,
        }
    }
}

/// The standard LDAP `LDAPResult` (RFC 4511 §4.1.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapResult {
    /// The result code.
    pub code: ResultCode,
    /// The `matchedDN` (usually empty for a reference server).
    pub matched_dn: String,
    /// A human-readable diagnostic message (may be empty).
    pub diagnostic: String,
}

impl LdapResult {
    /// A successful result with empty `matchedDN` and diagnostic.
    pub fn success() -> Self {
        Self {
            code: ResultCode::Success,
            matched_dn: String::new(),
            diagnostic: String::new(),
        }
    }

    /// A result with the given code and a diagnostic message.
    pub fn error(code: ResultCode, diagnostic: impl Into<String>) -> Self {
        Self {
            code,
            matched_dn: String::new(),
            diagnostic: diagnostic.into(),
        }
    }
}

/// A control attached to a message (RFC 4511 §4.1.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control {
    /// The control OID.
    pub oid: String,
    /// Whether the control is critical (unrecognized critical controls must be
    /// rejected with `unavailableCriticalExtension`).
    pub criticality: bool,
    /// The control value (absent if the control carries none).
    pub value: Option<Vec<u8>>,
}

/// The authentication choice inside a `BindRequest` (RFC 4511 §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthChoice {
    /// `simple` bind: the raw password octets.
    Simple(Vec<u8>),
    /// `sasl` bind: mechanism plus optional credentials.
    Sasl(SaslCredentials),
}

/// A `BindRequest` (RFC 4511 §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindRequest {
    /// The protocol version (LDAPv3 = 3).
    pub version: i32,
    /// The bind DN (name).
    pub name: String,
    /// The authentication choice.
    pub auth: AuthChoice,
}

/// Search scope (RFC 4511 §4.5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Search only the base object.
    Base,
    /// Search the base object's immediate children.
    SingleLevel,
    /// Search the base object and the whole subtree beneath it.
    WholeSubtree,
}

/// A search filter (RFC 4511 §4.5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    /// `(& ...)` — all sub-filters must match.
    And(Vec<Filter>),
    /// `(| ...)` — at least one sub-filter must match.
    Or(Vec<Filter>),
    /// `(! ...)` — negation of a single sub-filter.
    Not(Box<Filter>),
    /// `(=)` equality match.
    Equality(AttributeValueAssertion),
    /// `(attr=*...*)` substring match.
    Substrings(SubstringFilter),
    /// `(>=)` ordering match.
    GreaterOrEqual(AttributeValueAssertion),
    /// `(<=)` ordering match.
    LessOrEqual(AttributeValueAssertion),
    /// `(attr=*)` attribute presence.
    Present(String),
    /// `(~=)` approximate match (treated as equality by this reference server).
    ApproxMatch(AttributeValueAssertion),
    /// Extensible match (no matching rules implemented; never matches here).
    ExtensibleMatch(MatchingRuleAssertion),
}

/// A substring assertion (RFC 4511 §4.5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstringFilter {
    /// The attribute description.
    pub r#type: String,
    /// The ordered list of substring components.
    pub substrings: Vec<Substring>,
}

/// A single component of a [`SubstringFilter`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Substring {
    /// Whether this is the initial (prefix), any (infix), or final (suffix) part.
    pub kind: SubstringKind,
    /// The assertion value bytes.
    pub value: Vec<u8>,
}

/// The position of a [`Substring`] component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubstringKind {
    /// Must appear at the start of the value.
    Initial,
    /// Must appear somewhere inside the value.
    Any,
    /// Must appear at the end of the value.
    Final,
}

/// An extensible match assertion (RFC 4511 §4.5.1). Matching rules are not
/// implemented by this reference server, so these never match during evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchingRuleAssertion {
    /// Optional matching-rule OID.
    pub matching_rule: Option<String>,
    /// The attribute description (required unless `dn_attributes` is true).
    pub attribute: Option<String>,
    /// The assertion value.
    pub value: Vec<u8>,
    /// Whether the match is against DN attributes rather than the entry.
    pub dn_attributes: bool,
}

/// A `SearchRequest` (RFC 4511 §4.5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRequest {
    /// The base object DN.
    pub base: String,
    /// The search scope.
    pub scope: Scope,
    /// Alias dereferencing behaviour (passed through; not specially handled).
    pub deref_aliases: i32,
    /// Maximum number of entries to return (0 = unlimited).
    pub size_limit: i32,
    /// Maximum search time in seconds (0 = unlimited).
    pub time_limit: i32,
    /// When `true`, return attribute types but not values.
    pub types_only: bool,
    /// The search filter.
    pub filter: Filter,
    /// The requested attributes (empty means "all user attributes"; `*` likewise).
    pub attributes: Vec<String>,
}

/// A `PartialAttribute` as carried in search/add/modify messages (RFC 4511 §4.1.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialAttribute {
    /// The attribute type.
    pub r#type: String,
    /// The attribute values.
    pub values: Vec<Vec<u8>>,
}

/// A `SearchResultEntry` (RFC 4511 §4.5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResultEntry {
    /// The matched entry's DN.
    pub object_name: String,
    /// The returned attributes.
    pub attributes: Vec<PartialAttribute>,
}

/// A `ModifyRequest` (RFC 4511 §4.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifyRequest {
    /// The DN of the entry to modify.
    pub object: String,
    /// The ordered list of modifications.
    pub changes: Vec<Modification>,
}

/// An `AddRequest` (RFC 4511 §4.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddRequest {
    /// The entry to add (DN + attributes).
    pub entry: Entry,
}

/// A `CompareRequest` (RFC 4511 §4.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareRequest {
    /// The DN of the entry to compare against.
    pub entry: String,
    /// The attribute value assertion to test.
    pub ava: AttributeValueAssertion,
}

/// An `ExtendedRequest` (RFC 4511 §4.12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedRequest {
    /// The request OID.
    pub name: String,
    /// The optional request value.
    pub value: Option<Vec<u8>>,
}

/// The request operation of an `LDAPMessage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestOp {
    /// A bind request.
    Bind(BindRequest),
    /// An unbind request (no response; closes the connection).
    Unbind,
    /// A search request.
    Search(SearchRequest),
    /// A modify request.
    Modify(ModifyRequest),
    /// An add request.
    Add(AddRequest),
    /// A delete request (the target DN).
    Delete(String),
    /// A modify DN (rename) request.
    ModifyDn(ModifyDnRequest),
    /// A compare request.
    Compare(CompareRequest),
    /// An abandon request (the message ID to abandon).
    Abandon(i32),
    /// An extended request.
    Extended(ExtendedRequest),
}

/// A decoded LDAP request message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapRequest {
    /// The message ID.
    pub id: i32,
    /// The request operation.
    pub op: RequestOp,
    /// Any controls attached to the message.
    pub controls: Vec<Control>,
}

/// The response operation of an `LDAPMessage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseOp {
    /// A bind response.
    Bind(LdapResult),
    /// A search result entry.
    SearchResultEntry(SearchResultEntry),
    /// A search result done (terminal search result).
    SearchResultDone(LdapResult),
    /// A modify response.
    Modify(LdapResult),
    /// An add response.
    Add(LdapResult),
    /// A delete response.
    Delete(LdapResult),
    /// A modify DN response.
    ModifyDn(LdapResult),
    /// A compare response.
    Compare(LdapResult),
    /// An extended response.
    Extended(LdapResult),
}

/// An LDAP response message to be sent to a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapResponse {
    /// The message ID (echoes the request's).
    pub id: i32,
    /// The response operation.
    pub op: ResponseOp,
    /// Any controls to attach (none sent by the reference server).
    pub controls: Vec<Control>,
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Decode a single LDAP request message, returning the message and the number
/// of bytes consumed.
pub fn decode_request(buf: &[u8]) -> Result<(LdapRequest, usize), BerError> {
    let (el, consumed) = BerElement::decode_partial(buf)?;
    let children = el.as_children().ok_or(BerError::Unexpected)?.to_vec();
    if children.len() < 2 {
        return Err(BerError::Unexpected);
    }
    let id = children[0].as_int().map_err(|_| BerError::Unexpected)?;
    let id: i32 = id.try_into().map_err(|_| BerError::IntegerRange)?;
    let op_el = &children[1];
    let controls = if children.len() > 2 {
        parse_controls(&children[2])?
    } else {
        Vec::new()
    };
    let op = decode_request_op(op_el)?;
    Ok((LdapRequest { id, op, controls }, consumed))
}

fn decode_request_op(el: &BerElement) -> Result<RequestOp, BerError> {
    let tag = el.tag;
    if tag.class != crate::ber::CLASS_APPLICATION {
        return Err(BerError::Unexpected);
    }
    let op = match tag.number {
        // BindRequest and the remaining constructed operations carry nested
        // elements; the primitive operations (Unbind, DelRequest, Abandon)
        // do not and are handled without descending into children.
        0 => RequestOp::Bind(decode_bind_request(
            el.as_children().ok_or(BerError::Unexpected)?,
        )?),
        2 => RequestOp::Unbind,
        10 => {
            let dn = el.as_str()?.to_string();
            RequestOp::Delete(dn)
        }
        16 => {
            let mid = el.as_int()?;
            RequestOp::Abandon(mid.try_into().map_err(|_| BerError::IntegerRange)?)
        }
        3 => RequestOp::Search(decode_search_request(
            el.as_children().ok_or(BerError::Unexpected)?,
        )?),
        6 => RequestOp::Modify(decode_modify_request(
            el.as_children().ok_or(BerError::Unexpected)?,
        )?),
        8 => RequestOp::Add(decode_add_request(
            el.as_children().ok_or(BerError::Unexpected)?,
        )?),
        12 => RequestOp::ModifyDn(decode_modify_dn_request(
            el.as_children().ok_or(BerError::Unexpected)?,
        )?),
        14 => RequestOp::Compare(decode_compare_request(
            el.as_children().ok_or(BerError::Unexpected)?,
        )?),
        23 => RequestOp::Extended(decode_extended_request(
            el.as_children().ok_or(BerError::Unexpected)?,
        )?),
        _ => return Err(BerError::Unexpected),
    };
    Ok(op)
}

fn decode_bind_request(kids: &[BerElement]) -> Result<BindRequest, BerError> {
    if kids.len() < 3 {
        return Err(BerError::Unexpected);
    }
    let version = kids[0].as_int().map_err(|_| BerError::Unexpected)? as i32;
    let name = kids[1].as_str()?.to_string();
    let auth_el = &kids[2];
    let auth = if auth_el.tag.class == crate::ber::CLASS_CONTEXT && auth_el.tag.number == 0 {
        AuthChoice::Simple(auth_el.as_bytes().ok_or(BerError::Unexpected)?.to_vec())
    } else if auth_el.tag.class == crate::ber::CLASS_CONTEXT && auth_el.tag.number == 3 {
        let sasl_kids = auth_el.as_children().ok_or(BerError::Unexpected)?;
        let mechanism = sasl_kids
            .first()
            .ok_or(BerError::Unexpected)?
            .as_str()?
            .to_string();
        let credentials = if sasl_kids.len() > 1 {
            sasl_kids[1]
                .as_bytes()
                .ok_or(BerError::Unexpected)?
                .to_vec()
        } else {
            Vec::new()
        };
        AuthChoice::Sasl(SaslCredentials {
            mechanism,
            credentials,
        })
    } else {
        return Err(BerError::Unexpected);
    };
    Ok(BindRequest {
        version,
        name,
        auth,
    })
}

fn decode_search_request(kids: &[BerElement]) -> Result<SearchRequest, BerError> {
    if kids.len() < 8 {
        return Err(BerError::Unexpected);
    }
    let base = kids[0].as_str()?.to_string();
    let scope = match kids[1].as_int().map_err(|_| BerError::Unexpected)? {
        0 => Scope::Base,
        1 => Scope::SingleLevel,
        2 => Scope::WholeSubtree,
        _ => return Err(BerError::Unexpected),
    };
    let deref_aliases = kids[2].as_int().map_err(|_| BerError::Unexpected)? as i32;
    let size_limit = kids[3].as_int().map_err(|_| BerError::Unexpected)? as i32;
    let time_limit = kids[4].as_int().map_err(|_| BerError::Unexpected)? as i32;
    let types_only = kids[5].as_bool().map_err(|_| BerError::Unexpected)?;
    let filter = decode_filter(&kids[6])?;
    let attributes = decode_attribute_selection(&kids[7])?;
    Ok(SearchRequest {
        base,
        scope,
        deref_aliases,
        size_limit,
        time_limit,
        types_only,
        filter,
        attributes,
    })
}

fn decode_filter(el: &BerElement) -> Result<Filter, BerError> {
    if el.tag.class != crate::ber::CLASS_CONTEXT {
        return Err(BerError::Unexpected);
    }
    let n = el.tag.number;
    match n {
        0 | 1 => {
            // And / Or: SET OF Filter
            let kids = el.as_children().ok_or(BerError::Unexpected)?;
            let mut sub = Vec::with_capacity(kids.len());
            for k in kids {
                sub.push(decode_filter(k)?);
            }
            Ok(if n == 0 {
                Filter::And(sub)
            } else {
                Filter::Or(sub)
            })
        }
        2 => {
            // Not: a single Filter
            let kids = el.as_children().ok_or(BerError::Unexpected)?;
            if kids.len() != 1 {
                return Err(BerError::Unexpected);
            }
            Ok(Filter::Not(Box::new(decode_filter(&kids[0])?)))
        }
        3 | 5 | 6 | 8 => {
            // Equality / GreaterOrEqual / LessOrEqual / ApproxMatch: AVA
            let ava = decode_ava(el)?;
            Ok(match n {
                3 => Filter::Equality(ava),
                5 => Filter::GreaterOrEqual(ava),
                6 => Filter::LessOrEqual(ava),
                8 => Filter::ApproxMatch(ava),
                _ => unreachable!(),
            })
        }
        4 => {
            // Substrings
            let kids = el.as_children().ok_or(BerError::Unexpected)?;
            if kids.len() != 2 {
                return Err(BerError::Unexpected);
            }
            let r#type = kids[0].as_str()?.to_string();
            let subs_el = kids[1].as_children().ok_or(BerError::Unexpected)?;
            let mut substrings = Vec::with_capacity(subs_el.len());
            for s in subs_el {
                if s.tag.class != crate::ber::CLASS_CONTEXT {
                    return Err(BerError::Unexpected);
                }
                let kind = match s.tag.number {
                    0 => SubstringKind::Initial,
                    1 => SubstringKind::Any,
                    2 => SubstringKind::Final,
                    _ => return Err(BerError::Unexpected),
                };
                substrings.push(Substring {
                    kind,
                    value: s.as_bytes().ok_or(BerError::Unexpected)?.to_vec(),
                });
            }
            Ok(Filter::Substrings(SubstringFilter { r#type, substrings }))
        }
        7 => {
            // Present: OCTET STRING (the attribute description)
            Ok(Filter::Present(el.as_str()?.to_string()))
        }
        9 => {
            // ExtensibleMatch
            let kids = el.as_children().ok_or(BerError::Unexpected)?;
            let mut matching_rule = None;
            let mut attribute = None;
            let mut value = Vec::new();
            let mut dn_attributes = false;
            for k in kids {
                if k.tag == Tag::context(1) {
                    matching_rule = Some(k.as_str()?.to_string());
                } else if k.tag == Tag::context(2) {
                    attribute = Some(k.as_str()?.to_string());
                } else if k.tag == Tag::context(3) {
                    value = k.as_bytes().ok_or(BerError::Unexpected)?.to_vec();
                } else if k.tag == Tag::context(4) {
                    dn_attributes = k.as_bool().map_err(|_| BerError::Unexpected)?;
                }
            }
            Ok(Filter::ExtensibleMatch(MatchingRuleAssertion {
                matching_rule,
                attribute,
                value,
                dn_attributes,
            }))
        }
        _ => Err(BerError::Unexpected),
    }
}

fn decode_ava(el: &BerElement) -> Result<AttributeValueAssertion, BerError> {
    let kids = el.as_children().ok_or(BerError::Unexpected)?;
    if kids.len() != 2 {
        return Err(BerError::Unexpected);
    }
    Ok(AttributeValueAssertion {
        attribute_desc: kids[0].as_str()?.to_string(),
        assertion_value: kids[1].as_bytes().ok_or(BerError::Unexpected)?.to_vec(),
    })
}

fn decode_attribute_selection(el: &BerElement) -> Result<Vec<String>, BerError> {
    let kids = el.as_children().ok_or(BerError::Unexpected)?;
    let mut out = Vec::with_capacity(kids.len());
    for k in kids {
        out.push(k.as_str()?.to_string());
    }
    Ok(out)
}

fn decode_modify_request(kids: &[BerElement]) -> Result<ModifyRequest, BerError> {
    if kids.len() < 2 {
        return Err(BerError::Unexpected);
    }
    let object = kids[0].as_str()?.to_string();
    let changes_el = kids[1].as_children().ok_or(BerError::Unexpected)?;
    let mut changes = Vec::with_capacity(changes_el.len());
    for c in changes_el {
        let ck = c.as_children().ok_or(BerError::Unexpected)?;
        if ck.len() != 2 {
            return Err(BerError::Unexpected);
        }
        let op = match ck[0].as_int().map_err(|_| BerError::Unexpected)? {
            0 => crate::backend::ModificationOp::Add,
            1 => crate::backend::ModificationOp::Delete,
            2 => crate::backend::ModificationOp::Replace,
            _ => return Err(BerError::Unexpected),
        };
        let pa = decode_partial_attribute(&ck[1])?;
        changes.push(Modification {
            op,
            name: pa.r#type,
            values: pa.values,
        });
    }
    Ok(ModifyRequest { object, changes })
}

fn decode_partial_attribute(el: &BerElement) -> Result<PartialAttribute, BerError> {
    let kids = el.as_children().ok_or(BerError::Unexpected)?;
    if kids.len() != 2 {
        return Err(BerError::Unexpected);
    }
    let r#type = kids[0].as_str()?.to_string();
    let vals_el = kids[1].as_children().ok_or(BerError::Unexpected)?;
    let mut values = Vec::with_capacity(vals_el.len());
    for v in vals_el {
        values.push(v.as_bytes().ok_or(BerError::Unexpected)?.to_vec());
    }
    Ok(PartialAttribute { r#type, values })
}

fn decode_add_request(kids: &[BerElement]) -> Result<AddRequest, BerError> {
    if kids.len() < 2 {
        return Err(BerError::Unexpected);
    }
    let dn = kids[0].as_str()?.to_string();
    let attrs_el = kids[1].as_children().ok_or(BerError::Unexpected)?;
    let mut attributes = Vec::with_capacity(attrs_el.len());
    for a in attrs_el {
        let pa = decode_partial_attribute(a)?;
        attributes.push(Attribute {
            name: pa.r#type,
            values: pa.values,
        });
    }
    Ok(AddRequest {
        entry: Entry { dn, attributes },
    })
}

fn decode_modify_dn_request(kids: &[BerElement]) -> Result<ModifyDnRequest, BerError> {
    if kids.len() < 3 {
        return Err(BerError::Unexpected);
    }
    let dn = kids[0].as_str()?.to_string();
    let new_rdn = kids[1].as_str()?.to_string();
    let delete_old_rdn = kids[2].as_bool().map_err(|_| BerError::Unexpected)?;
    let new_superior = if kids.len() > 3 {
        let ns = &kids[3];
        if ns.tag == Tag::context(0) {
            Some(ns.as_str()?.to_string())
        } else {
            None
        }
    } else {
        None
    };
    Ok(ModifyDnRequest {
        dn,
        new_rdn,
        delete_old_rdn,
        new_superior,
    })
}

fn decode_compare_request(kids: &[BerElement]) -> Result<CompareRequest, BerError> {
    if kids.len() < 2 {
        return Err(BerError::Unexpected);
    }
    let entry = kids[0].as_str()?.to_string();
    let ava = decode_ava(&kids[1])?;
    Ok(CompareRequest { entry, ava })
}

fn decode_extended_request(kids: &[BerElement]) -> Result<ExtendedRequest, BerError> {
    if kids.is_empty() {
        return Err(BerError::Unexpected);
    }
    let name = kids[0].as_str()?.to_string();
    let value = if kids.len() > 1 {
        Some(kids[1].as_bytes().ok_or(BerError::Unexpected)?.to_vec())
    } else {
        None
    };
    Ok(ExtendedRequest { name, value })
}

fn parse_controls(el: &BerElement) -> Result<Vec<Control>, BerError> {
    if el.tag != Tag::context(0).constructed() {
        return Err(BerError::Unexpected);
    }
    let list = el.as_children().ok_or(BerError::Unexpected)?;
    let mut out = Vec::with_capacity(list.len());
    for c in list {
        let ck = c.as_children().ok_or(BerError::Unexpected)?;
        if ck.is_empty() {
            return Err(BerError::Unexpected);
        }
        let oid = ck[0].as_str()?.to_string();
        let mut criticality = false;
        let mut value = None;
        for k in &ck[1..] {
            if k.tag == Tag::universal(universal::BOOLEAN) {
                criticality = k.as_bool().map_err(|_| BerError::Unexpected)?;
            } else if k.tag == Tag::universal(universal::OCTET_STRING) {
                value = Some(k.as_bytes().ok_or(BerError::Unexpected)?.to_vec());
            }
        }
        out.push(Control {
            oid,
            criticality,
            value,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

impl LdapResponse {
    /// Serialize this response message to BER.
    pub fn encode(&self) -> Vec<u8> {
        let op_el = match &self.op {
            ResponseOp::Bind(r) => BerElement::application_sequence(1, ldap_result_children(r)),
            ResponseOp::SearchResultEntry(e) => {
                BerElement::application_sequence(4, search_entry_children(e))
            }
            ResponseOp::SearchResultDone(r) => {
                BerElement::application_sequence(5, ldap_result_children(r))
            }
            ResponseOp::Modify(r) => BerElement::application_sequence(7, ldap_result_children(r)),
            ResponseOp::Add(r) => BerElement::application_sequence(9, ldap_result_children(r)),
            ResponseOp::Delete(r) => BerElement::application_sequence(11, ldap_result_children(r)),
            ResponseOp::ModifyDn(r) => {
                BerElement::application_sequence(13, ldap_result_children(r))
            }
            ResponseOp::Compare(r) => BerElement::application_sequence(15, ldap_result_children(r)),
            ResponseOp::Extended(r) => {
                BerElement::application_sequence(24, ldap_result_children(r))
            }
        };

        let mut children = vec![BerElement::integer(self.id as i64), op_el];
        if let Some(ce) = controls_element(&self.controls) {
            children.push(ce);
        }
        BerElement::sequence(children).encode()
    }
}

/// Build a `[0]` controls element, or `None` when there are no controls.
fn controls_element(controls: &[Control]) -> Option<BerElement> {
    if controls.is_empty() {
        return None;
    }
    Some(BerElement::context_sequence(
        0,
        controls
            .iter()
            .map(|c| {
                let mut ck = vec![BerElement::octet_string(c.oid.as_bytes())];
                if c.criticality {
                    ck.push(BerElement::boolean(true));
                }
                if let Some(v) = &c.value {
                    ck.push(BerElement::octet_string(v));
                }
                BerElement::sequence(ck)
            })
            .collect(),
    ))
}

impl LdapRequest {
    /// Serialize this request message to BER.
    pub fn encode(&self) -> Vec<u8> {
        let op_el = encode_request_op(&self.op);
        let mut children = vec![BerElement::integer(self.id as i64), op_el];
        if let Some(ce) = controls_element(&self.controls) {
            children.push(ce);
        }
        BerElement::sequence(children).encode()
    }
}

/// Serialize a [`Filter`] into its context-tagged BER element.
pub fn encode_filter(filter: &Filter) -> BerElement {
    match filter {
        Filter::And(subs) => {
            BerElement::context_sequence(0, subs.iter().map(encode_filter).collect())
        }
        Filter::Or(subs) => {
            BerElement::context_sequence(1, subs.iter().map(encode_filter).collect())
        }
        Filter::Not(f) => BerElement::context_sequence(2, vec![encode_filter(f)]),
        Filter::Equality(ava) => ava_element(3, ava),
        Filter::GreaterOrEqual(ava) => ava_element(5, ava),
        Filter::LessOrEqual(ava) => ava_element(6, ava),
        Filter::ApproxMatch(ava) => ava_element(8, ava),
        Filter::Present(name) => BerElement::context_primitive(7, name.as_bytes()),
        Filter::Substrings(sf) => BerElement::context_sequence(
            4,
            vec![
                BerElement::octet_string(sf.r#type.as_bytes()),
                BerElement::sequence(
                    sf.substrings
                        .iter()
                        .map(|s| {
                            let tag = match s.kind {
                                SubstringKind::Initial => 0,
                                SubstringKind::Any => 1,
                                SubstringKind::Final => 2,
                            };
                            BerElement::context_primitive(tag, &s.value)
                        })
                        .collect(),
                ),
            ],
        ),
        Filter::ExtensibleMatch(m) => {
            let mut kids = Vec::new();
            if let Some(r) = &m.matching_rule {
                kids.push(BerElement::context_primitive(1, r.as_bytes()));
            }
            if let Some(a) = &m.attribute {
                kids.push(BerElement::context_primitive(2, a.as_bytes()));
            }
            kids.push(BerElement::context_primitive(3, &m.value));
            if m.dn_attributes {
                kids.push(BerElement::context_primitive(4, &[]));
            }
            BerElement::context_sequence(9, kids)
        }
    }
}

fn ava_element(tag: u32, ava: &AttributeValueAssertion) -> BerElement {
    BerElement::context_sequence(
        tag,
        vec![
            BerElement::octet_string(ava.attribute_desc.as_bytes()),
            BerElement::octet_string(&ava.assertion_value),
        ],
    )
}

fn encode_request_op(op: &RequestOp) -> BerElement {
    match op {
        RequestOp::Bind(b) => {
            let auth = match &b.auth {
                AuthChoice::Simple(pw) => BerElement::context_primitive(0, pw),
                AuthChoice::Sasl(s) => BerElement::context_sequence(3, {
                    let mut v = vec![BerElement::octet_string(s.mechanism.as_bytes())];
                    if !s.credentials.is_empty() {
                        v.push(BerElement::octet_string(&s.credentials));
                    }
                    v
                }),
            };
            BerElement::application_sequence(
                0,
                vec![
                    BerElement::integer(b.version as i64),
                    BerElement::octet_string(b.name.as_bytes()),
                    auth,
                ],
            )
        }
        RequestOp::Unbind => BerElement::application_primitive(2, &[]),
        RequestOp::Search(s) => BerElement::application_sequence(
            3,
            vec![
                BerElement::octet_string(s.base.as_bytes()),
                BerElement::enumerated(s.scope as i64),
                BerElement::enumerated(s.deref_aliases as i64),
                BerElement::integer(s.size_limit as i64),
                BerElement::integer(s.time_limit as i64),
                BerElement::boolean(s.types_only),
                encode_filter(&s.filter),
                BerElement::sequence(
                    s.attributes
                        .iter()
                        .map(|a| BerElement::octet_string(a.as_bytes()))
                        .collect(),
                ),
            ],
        ),
        RequestOp::Modify(m) => BerElement::application_sequence(
            6,
            vec![
                BerElement::octet_string(m.object.as_bytes()),
                BerElement::sequence(
                    m.changes
                        .iter()
                        .map(|c| {
                            BerElement::sequence(vec![
                                BerElement::enumerated(c.op as i64),
                                BerElement::sequence(vec![
                                    BerElement::octet_string(c.name.as_bytes()),
                                    BerElement::set(
                                        c.values
                                            .iter()
                                            .map(|v| BerElement::octet_string(v))
                                            .collect(),
                                    ),
                                ]),
                            ])
                        })
                        .collect(),
                ),
            ],
        ),
        RequestOp::Add(a) => BerElement::application_sequence(
            8,
            vec![
                BerElement::octet_string(a.entry.dn.as_bytes()),
                BerElement::sequence(
                    a.entry
                        .attributes
                        .iter()
                        .map(|at| {
                            BerElement::sequence(vec![
                                BerElement::octet_string(at.name.as_bytes()),
                                BerElement::set(
                                    at.values
                                        .iter()
                                        .map(|v| BerElement::octet_string(v))
                                        .collect(),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ],
        ),
        RequestOp::Delete(dn) => BerElement::application_primitive(10, dn.as_bytes()),
        RequestOp::ModifyDn(d) => {
            let mut kids = vec![
                BerElement::octet_string(d.dn.as_bytes()),
                BerElement::octet_string(d.new_rdn.as_bytes()),
                BerElement::boolean(d.delete_old_rdn),
            ];
            if let Some(sup) = &d.new_superior {
                kids.push(BerElement::context_primitive(0, sup.as_bytes()));
            }
            BerElement::application_sequence(12, kids)
        }
        RequestOp::Compare(c) => BerElement::application_sequence(
            14,
            vec![
                BerElement::octet_string(c.entry.as_bytes()),
                BerElement::sequence(vec![
                    BerElement::octet_string(c.ava.attribute_desc.as_bytes()),
                    BerElement::octet_string(&c.ava.assertion_value),
                ]),
            ],
        ),
        RequestOp::Abandon(mid) => {
            let int_el = BerElement::integer(*mid as i64);
            BerElement::application_primitive(16, int_el.as_bytes().unwrap_or(&[]))
        }
        RequestOp::Extended(e) => {
            let mut kids = vec![BerElement::octet_string(e.name.as_bytes())];
            if let Some(v) = &e.value {
                kids.push(BerElement::octet_string(v));
            }
            BerElement::application_sequence(23, kids)
        }
    }
}

fn ldap_result_children(r: &LdapResult) -> Vec<BerElement> {
    vec![
        BerElement::enumerated(r.code.as_i64()),
        BerElement::octet_string(r.matched_dn.as_bytes()),
        BerElement::octet_string(r.diagnostic.as_bytes()),
    ]
}

fn search_entry_children(e: &SearchResultEntry) -> Vec<BerElement> {
    let attrs = e
        .attributes
        .iter()
        .map(|a| {
            let vals = BerElement::set(
                a.values
                    .iter()
                    .map(|v| BerElement::octet_string(v))
                    .collect(),
            );
            BerElement::sequence(vec![BerElement::octet_string(a.r#type.as_bytes()), vals])
        })
        .collect();
    vec![
        BerElement::octet_string(e.object_name.as_bytes()),
        BerElement::sequence(attrs),
    ]
}

// ---------------------------------------------------------------------------
// Filter evaluation and scope
// ---------------------------------------------------------------------------

/// `true` if `entry` satisfies `filter` (RFC 4511 §4.5.1).
pub fn filter_matches(filter: &Filter, entry: &Entry) -> bool {
    match filter {
        Filter::And(subs) => subs.iter().all(|f| filter_matches(f, entry)),
        Filter::Or(subs) => subs.iter().any(|f| filter_matches(f, entry)),
        Filter::Not(f) => !filter_matches(f, entry),
        Filter::Equality(ava) => match entry.attribute(&ava.attribute_desc) {
            Some(a) => a.values.contains(&ava.assertion_value),
            None => false,
        },
        Filter::GreaterOrEqual(ava) => match entry.attribute(&ava.attribute_desc) {
            Some(a) => a
                .values
                .iter()
                .any(|v| v.as_slice() >= ava.assertion_value.as_slice()),
            None => false,
        },
        Filter::LessOrEqual(ava) => match entry.attribute(&ava.attribute_desc) {
            Some(a) => a
                .values
                .iter()
                .any(|v| v.as_slice() <= ava.assertion_value.as_slice()),
            None => false,
        },
        Filter::ApproxMatch(ava) => match entry.attribute(&ava.attribute_desc) {
            Some(a) => a.values.contains(&ava.assertion_value),
            None => false,
        },
        Filter::Present(name) => entry
            .attributes
            .iter()
            .any(|a| a.name.eq_ignore_ascii_case(name)),
        Filter::Substrings(sf) => match entry.attribute(&sf.r#type) {
            Some(a) => a.values.iter().any(|v| substring_match(v, &sf.substrings)),
            None => false,
        },
        // No matching rules implemented; an extensible match never matches.
        Filter::ExtensibleMatch(_) => false,
    }
}

fn substring_match(value: &[u8], subs: &[Substring]) -> bool {
    let mut cursor = 0usize;
    for s in subs {
        match s.kind {
            SubstringKind::Initial => {
                if !value[cursor..].starts_with(&s.value) {
                    return false;
                }
                cursor += s.value.len();
            }
            SubstringKind::Any => {
                let remaining = &value[cursor..];
                if s.value.len() > remaining.len() {
                    return false;
                }
                match remaining
                    .windows(s.value.len())
                    .position(|w| w == s.value.as_slice())
                {
                    Some(pos) => cursor += pos + s.value.len(),
                    None => return false,
                }
            }
            SubstringKind::Final => {
                if !value[cursor..].ends_with(&s.value) {
                    return false;
                }
            }
        }
    }
    true
}

/// Returns the parent DN of `dn`, or `None` if it is a top-level DN.
///
/// Honors backslash escapes (so an escaped comma is not treated as a separator).
/// Quoting is not specially handled.
pub fn dn_parent(dn: &str) -> Option<String> {
    let bytes = dn.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2; // skip the escaped octet (at least two hex digits)
            continue;
        }
        if bytes[i] == b',' {
            return Some(dn[i + 1..].trim_start().to_string());
        }
        i += 1;
    }
    None
}

/// `true` if `dn` falls within `scope` of `base` (RFC 4511 §4.5.1).
pub fn scope_match(scope: Scope, base: &str, dn: &str) -> bool {
    let base_l = base.to_ascii_lowercase();
    let dn_l = dn.to_ascii_lowercase();
    match scope {
        Scope::Base => dn_l == base_l,
        Scope::SingleLevel => match dn_parent(dn) {
            Some(parent) => parent.to_ascii_lowercase() == base_l && dn_l != base_l,
            None => false,
        },
        Scope::WholeSubtree => dn_l == base_l || dn_l.ends_with(&format!(",{}", base_l)),
    }
}

/// Build a [`SearchResultEntry`] from `entry`, honoring `types_only` and the
/// requested attribute selection (`*` or an empty list means "all user
/// attributes").
pub fn entry_to_result(
    entry: &Entry,
    types_only: bool,
    attributes: &[String],
) -> SearchResultEntry {
    let all = attributes.is_empty() || attributes.iter().any(|a| a == "*");
    let attrs = entry
        .attributes
        .iter()
        .filter(|a| {
            all || attributes
                .iter()
                .any(|sel| sel.eq_ignore_ascii_case(&a.name))
        })
        .map(|a| PartialAttribute {
            r#type: a.name.clone(),
            values: if types_only {
                Vec::new()
            } else {
                a.values.clone()
            },
        })
        .collect();
    SearchResultEntry {
        object_name: entry.dn.clone(),
        attributes: attrs,
    }
}
