// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Parsing and serialization of the `Signature-Input` and `Signature`
//! Structured Field headers (RFC 9421 §4).

use crate::components::ComponentId;
use crate::error::{HttpSigError, Result};
use crate::sf::{parse_dictionary, serialize_dictionary, serialize_inner_list, InnerList, MemberValue, SfParam};

/// A parsed `Signature-Input` value: the ordered covered components plus the
/// signature parameters for one signature.
#[derive(Debug, Clone)]
pub struct SignatureInput {
    /// Ordered covered component identifiers.
    pub components: Vec<ComponentId>,
    /// Signature parameters (`created`, `keyid`, `alg`, `nonce`, `expires`,
    /// `tag`) in order.
    pub params: Vec<(String, SfParam)>,
}

/// Parse the value of a `Signature-Input` header field (a Dictionary of
/// parameterized inner lists) into `(label, SignatureInput)` pairs.
pub fn parse_signature_input(field_value: &str) -> Result<Vec<(String, SignatureInput)>> {
    let dict = parse_dictionary(field_value)?;
    let mut out = Vec::new();
    for (label, member) in dict {
        match member {
            MemberValue::InnerList(inner) => {
                let mut components = Vec::new();
                for (name, item_params) in &inner.items {
                    let effective = if name.starts_with('@') {
                        name.clone()
                    } else {
                        name.to_ascii_lowercase()
                    };
                    components.push(ComponentId {
                        name: effective,
                        params: item_params.clone(),
                    });
                }
                out.push((
                    label,
                    SignatureInput {
                        components,
                        params: inner.params.clone(),
                    },
                ));
            }
            MemberValue::ByteSeq(_) => {
                return Err(HttpSigError::StructuredField(
                    "Signature-Input member must be an inner list".into(),
                ))
            }
        }
    }
    Ok(out)
}

/// Serialize a single [`SignatureInput`] back to its inner-list value (the
/// text that follows `label=` in the `Signature-Input` header).
pub fn serialize_signature_input(input: &SignatureInput) -> String {
    let inner = InnerList {
        items: input
            .components
            .iter()
            .map(|c| (c.name.clone(), c.params.clone()))
            .collect(),
        params: input.params.clone(),
    };
    serialize_inner_list(&inner)
}

/// Parse the value of a `Signature` header field (a Dictionary of byte
/// sequences) into `(label, raw_signature_bytes)` pairs.
pub fn parse_signature(field_value: &str) -> Result<Vec<(String, Vec<u8>)>> {
    let dict = parse_dictionary(field_value)?;
    let mut out = Vec::new();
    for (label, member) in dict {
        match member {
            MemberValue::ByteSeq(b) => out.push((label, b)),
            MemberValue::InnerList(_) => {
                return Err(HttpSigError::StructuredField(
                    "Signature member must be a byte sequence".into(),
                ))
            }
        }
    }
    Ok(out)
}

/// Serialize `(label, signature_bytes)` pairs into a `Signature` header value.
pub fn serialize_signature(members: &[(String, Vec<u8>)]) -> String {
    let m: Vec<(String, MemberValue)> = members
        .iter()
        .map(|(l, b)| (l.clone(), MemberValue::ByteSeq(b.clone())))
        .collect();
    serialize_dictionary(&m)
}

/// Parse a single inner-list value (the text after `label=` in a
/// `Signature-Input` entry) into a [`SignatureInput`].
pub fn parse_signature_input_value(value: &str) -> Result<SignatureInput> {
    let inner = crate::sf::parse_inner_list_str(value)?;
    let mut components = Vec::new();
    for (name, item_params) in &inner.items {
        let effective = if name.starts_with('@') {
            name.clone()
        } else {
            name.to_ascii_lowercase()
        };
        components.push(ComponentId {
            name: effective,
            params: item_params.clone(),
        });
    }
    Ok(SignatureInput {
        components,
        params: inner.params.clone(),
    })
}
