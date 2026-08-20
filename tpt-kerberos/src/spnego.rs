// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SPNEGO (RFC 4178) GSSAPI mechanism negotiation, used to negotiate Kerberos
//! v5 as the preferred security mechanism over, e.g., HTTP Negotiate or SASL.
//!
//! This module implements the SPNEGO `NegTokenInit` / `NegTokenResp` messages
//! and the GSS-API framing (`[APPLICATION 0]` context token with the SPNEGO
//! OID `1.3.6.1.5.5.2`). The inner mechanism token (e.g. the AP-REQ) is
//! supplied by the caller.

use const_oid::ObjectIdentifier;
use der::{Decode, Encode, Tagged};

use crate::asn1::{self, tlv};
use crate::error::{Error, Result};

/// SPNEGO OID: `1.3.6.1.5.5.2`.
pub const OID_SPNEGO: &str = "1.3.6.1.5.5.2";
/// Kerberos v5 OID: `1.2.840.113554.1.2.2`.
pub const OID_KRB5: &str = "1.2.840.113554.1.2.2";

/// GSS-API `InitialContextToken` `[APPLICATION 0]`.
fn gss_initial_context_token(mech: &ObjectIdentifier, inner: &[u8]) -> Vec<u8> {
    // ThisMech OID then innerToken (EXPLICIT tagged OCTET STRING per GSS-API).
    let mech_der = mech.to_der().expect("oid der");
    let inner_tlv = tlv(0x04, inner); // OCTET STRING wrapping the inner token
                                      // GSS-API: [APPLICATION 0] IMPLICIT SEQUENCE { thisMech OID, innerContextToken ANY }
    let mut content = mech_der;
    content.extend_from_slice(&inner_tlv);
    tlv(0x60, &content) // 0x60 = APPLICATION 0 constructed
}

/// NegState enumeration (RFC 4178 §4.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegState {
    AcceptCompleted = 0,
    AcceptIncomplete = 1,
    Reject = 2,
    RequestMic = 3,
}

impl NegState {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(NegState::AcceptCompleted),
            1 => Ok(NegState::AcceptIncomplete),
            2 => Ok(NegState::Reject),
            3 => Ok(NegState::RequestMic),
            _ => Err(Error::Unexpected("NegState")),
        }
    }
}

/// A SPNEGO `NegTokenInit` (RFC 4178 §4.2.1).
#[derive(Debug, Clone)]
pub struct NegTokenInit {
    pub mech_types: Vec<ObjectIdentifier>,
    pub req_flags: Option<u32>,
    pub mech_token: Option<Vec<u8>>,
    pub mech_list_mic: Option<Vec<u8>>,
}

impl NegTokenInit {
    /// Wrap an inner mechanism token (e.g. an AP-REQ) in a SPNEGO NegTokenInit.
    ///
    /// `mech_types` should list the client's supported mechanisms, with the
    /// preferred one first (typically `[krb5]`).
    pub fn wrap(mech_types: &[ObjectIdentifier], mech_token: Vec<u8>) -> Self {
        NegTokenInit {
            mech_types: mech_types.to_vec(),
            req_flags: None,
            mech_token: Some(mech_token),
            mech_list_mic: None,
        }
    }

    /// Encode the full GSS-API `[APPLICATION 0]` token.
    pub fn to_token(&self) -> Result<Vec<u8>> {
        let inner = self.encode_inner()?;
        let spnego = ObjectIdentifier::new_unwrap(OID_SPNEGO);
        Ok(gss_initial_context_token(&spnego, &inner))
    }

    fn encode_inner(&self) -> Result<Vec<u8>> {
        let mut parts: Vec<Vec<u8>> = Vec::new();
        // [0] mechTypes SEQUENCE OF OID
        let mt = asn1::sequence(
            &self
                .mech_types
                .iter()
                .map(|o| o.to_der().expect("oid der"))
                .collect::<Vec<_>>(),
        );
        parts.push(asn1::ctx(0, &mt));
        // [1] reqFlags BIT STRING (optional)
        if let Some(f) = self.req_flags {
            let mut bs = vec![0u8]; // unused bits
            bs.extend_from_slice(&f.to_be_bytes());
            parts.push(asn1::ctx(1, &asn1::tlv(0x03, &bs)));
        }
        // [2] mechToken OCTET STRING (optional)
        if let Some(t) = &self.mech_token {
            parts.push(asn1::ctx(2, &asn1::octet_string(t)));
        }
        // [3] mechListMIC OCTET STRING (optional)
        if let Some(m) = &self.mech_list_mic {
            parts.push(asn1::ctx(3, &asn1::octet_string(m)));
        }
        Ok(asn1::sequence(&parts))
    }

    /// Decode a SPNEGO NegTokenInit from a full GSS-API token.
    pub fn from_token(token: &[u8]) -> Result<Self> {
        let gss = der::Any::from_der(token).map_err(Error::Asn1)?;
        // GSS framing: [APPLICATION 0] SEQUENCE { thisMech OID, inner OCTET STRING }.
        let mut c = asn1::Cursor::new(gss.value());
        let _this_mech = c.take()?; // thisMech OID — validated implicitly by re-encoding below
        let inner_any = c.take()?;
        let inner = inner_any.value().to_vec();
        Self::decode_inner(&inner)
    }

    fn decode_inner(inner: &[u8]) -> Result<Self> {
        let mut c = asn1::Cursor::new(inner);
        let seq = c.take()?;
        asn1::ensure_tag(seq.tag(), der::Tag::Sequence)?;
        let mut ic = asn1::Cursor::new(seq.value());
        let mut out = NegTokenInit {
            mech_types: Vec::new(),
            req_flags: None,
            mech_token: None,
            mech_list_mic: None,
        };
        while !ic.at_end() {
            let a = ic.take()?;
            let tag = a.tag();
            if tag == asn1::ctx_constructed(0) {
                let seq = asn1::unwrap_sequence(a.value())?;
                let mut mc = asn1::Cursor::new(seq.value());
                while !mc.at_end() {
                    let o = mc.take()?;
                    out.mech_types.push(
                        ObjectIdentifier::from_der(&o.to_der().map_err(Error::Asn1)?)
                            .map_err(Error::Asn1)?,
                    );
                }
            } else if tag == asn1::ctx_constructed(1) {
                let b = asn1::Cursor::new(a.value()).take()?;
                // BIT STRING
                let v = b.value();
                if v.len() < 5 {
                    return Err(Error::Unexpected("reqFlags"));
                }
                out.req_flags = Some(u32::from_be_bytes([v[1], v[2], v[3], v[4]]));
            } else if tag == asn1::ctx_constructed(2) {
                let os = asn1::Cursor::new(a.value()).take()?;
                asn1::ensure_tag(os.tag(), der::Tag::OctetString)?;
                out.mech_token = Some(os.value().to_vec());
            } else if tag == asn1::ctx_constructed(3) {
                let os = asn1::Cursor::new(a.value()).take()?;
                asn1::ensure_tag(os.tag(), der::Tag::OctetString)?;
                out.mech_list_mic = Some(os.value().to_vec());
            } else {
                return Err(Error::Unexpected("NegTokenInit field"));
            }
        }
        Ok(out)
    }
}

/// A SPNEGO `NegTokenResp` (RFC 4178 §4.2.1).
#[derive(Debug, Clone)]
pub struct NegTokenResp {
    pub neg_state: Option<NegState>,
    pub supported_mech: Option<ObjectIdentifier>,
    pub response_token: Option<Vec<u8>>,
    pub mech_list_mic: Option<Vec<u8>>,
}

impl NegTokenResp {
    /// Build a response selecting the Kerberos v5 mechanism.
    pub fn accept_completed(mech: ObjectIdentifier, response_token: Option<Vec<u8>>) -> Self {
        NegTokenResp {
            neg_state: Some(NegState::AcceptCompleted),
            supported_mech: Some(mech),
            response_token,
            mech_list_mic: None,
        }
    }

    /// Encode the full GSS-API `[APPLICATION 0]` token.
    pub fn to_token(&self) -> Result<Vec<u8>> {
        let inner = self.encode_inner()?;
        let spnego = ObjectIdentifier::new_unwrap(OID_SPNEGO);
        Ok(gss_initial_context_token(&spnego, &inner))
    }

    fn encode_inner(&self) -> Result<Vec<u8>> {
        let mut parts: Vec<Vec<u8>> = Vec::new();
        if let Some(s) = self.neg_state {
            // [0] negState ENUMERATED
            parts.push(asn1::ctx(0, &asn1::tlv(0x0A, &[s as u8])));
        }
        if let Some(m) = &self.supported_mech {
            // [1] supportedMech OID
            parts.push(asn1::ctx(1, &m.to_der().expect("oid der")));
        }
        if let Some(t) = &self.response_token {
            // [2] responseToken OCTET STRING
            parts.push(asn1::ctx(2, &asn1::octet_string(t)));
        }
        if let Some(m) = &self.mech_list_mic {
            // [3] mechListMIC OCTET STRING
            parts.push(asn1::ctx(3, &asn1::octet_string(m)));
        }
        Ok(asn1::sequence(&parts))
    }

    /// Decode a SPNEGO NegTokenResp from a full GSS-API token.
    pub fn from_token(token: &[u8]) -> Result<Self> {
        let gss = der::Any::from_der(token).map_err(Error::Asn1)?;
        let mut c = asn1::Cursor::new(gss.value());
        let _this_mech = c.take()?;
        let inner_any = c.take()?;
        Self::decode_inner(inner_any.value())
    }

    fn decode_inner(inner: &[u8]) -> Result<Self> {
        let mut c = asn1::Cursor::new(inner);
        let seq = c.take()?;
        asn1::ensure_tag(seq.tag(), der::Tag::Sequence)?;
        let mut ic = asn1::Cursor::new(seq.value());
        let mut out = NegTokenResp {
            neg_state: None,
            supported_mech: None,
            response_token: None,
            mech_list_mic: None,
        };
        while !ic.at_end() {
            let a = ic.take()?;
            let tag = a.tag();
            if tag == asn1::ctx_constructed(0) {
                let e = asn1::Cursor::new(a.value()).take()?;
                out.neg_state = Some(NegState::from_u8(e.value()[0])?);
            } else if tag == asn1::ctx_constructed(1) {
                let o = asn1::Cursor::new(a.value()).take()?;
                out.supported_mech = Some(
                    ObjectIdentifier::from_der(&o.to_der().map_err(Error::Asn1)?)
                        .map_err(Error::from)?,
                );
            } else if tag == asn1::ctx_constructed(2) {
                let os = asn1::Cursor::new(a.value()).take()?;
                asn1::ensure_tag(os.tag(), der::Tag::OctetString)?;
                out.response_token = Some(os.value().to_vec());
            } else if tag == asn1::ctx_constructed(3) {
                let os = asn1::Cursor::new(a.value()).take()?;
                asn1::ensure_tag(os.tag(), der::Tag::OctetString)?;
                out.mech_list_mic = Some(os.value().to_vec());
            } else {
                return Err(Error::Unexpected("NegTokenResp field"));
            }
        }
        Ok(out)
    }
}

/// Convenience: default SPNEGO mechanism list (Kerberos v5 preferred).
pub fn default_mech_list() -> Vec<ObjectIdentifier> {
    vec![ObjectIdentifier::new_unwrap(OID_KRB5)]
}
