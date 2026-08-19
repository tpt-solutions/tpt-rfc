// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A focused, dependency-free subset of [RFC 8941](https://www.rfc-editor.org/rfc/rfc8941)
//! Structured Field parsing/serialization, sufficient for RFC 9421's
//! `Signature-Input` (Dictionary of parameterized Inner Lists) and `Signature`
//! (Dictionary of Byte Sequences) fields, plus component identifiers (quoted
//! strings with parameters, e.g. `"@query-param";name="Pet"`).
//!
//! Only the constructs actually used by this crate are implemented: String
//! items, Integer and Boolean parameters, Byte Sequences, Inner Lists with
//! parameters, and Dictionaries of those. No attempt is made to be a general
//! Structured Fields implementation.

use crate::error::{HttpSigError, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// A parameter value on a component identifier or signature-input item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SfParam {
    Int(i64),
    Str(String),
    Bool(bool),
}

/// An ordered set of covered components (quoted strings, each optionally
/// carrying its own parameters such as `"@query-param";name="Pet"`) plus the
/// signature parameters of a single signature.
#[derive(Debug, Clone)]
pub(crate) struct InnerList {
    pub items: Vec<(String, Vec<(String, SfParam)>)>,
    pub params: Vec<(String, SfParam)>,
}

/// One member of a Structured Field Dictionary (the whole `Signature-Input`
/// or `Signature` field).
#[derive(Debug, Clone)]
pub(crate) enum MemberValue {
    InnerList(InnerList),
    ByteSeq(Vec<u8>),
}

fn is_lcalpha(b: u8) -> bool {
    b.is_ascii_lowercase()
}

fn is_key_char(b: u8) -> bool {
    is_lcalpha(b) || b.is_ascii_digit() || b == b'_' || b == b'-' || b == b'*' || b == b'.'
}

fn is_param_name_char(b: u8) -> bool {
    is_lcalpha(b) || b.is_ascii_digit() || b == b'_' || b == b'-'
}

fn skip_sp(b: &[u8], i: &mut usize) {
    while *i < b.len() && b[*i] == b' ' {
        *i += 1;
    }
}

fn expect(b: &[u8], i: &mut usize, c: u8) -> Result<()> {
    if *i >= b.len() || b[*i] != c {
        return Err(HttpSigError::StructuredField(format!(
            "expected '{}' at position {i}",
            c as char
        )));
    }
    *i += 1;
    Ok(())
}

fn parse_key(b: &[u8], i: &mut usize) -> Result<String> {
    let start = *i;
    if *i >= b.len() || !is_key_char(b[*i]) {
        return Err(HttpSigError::StructuredField("invalid dictionary key".into()));
    }
    while *i < b.len() && is_key_char(b[*i]) {
        *i += 1;
    }
    Ok(std::str::from_utf8(&b[start..*i])
        .map_err(|_| HttpSigError::StructuredField("non-utf8 key".into()))?
        .to_string())
}

fn parse_param_name(b: &[u8], i: &mut usize) -> Result<String> {
    let start = *i;
    if *i >= b.len() || !is_param_name_char(b[*i]) {
        return Err(HttpSigError::StructuredField("invalid parameter name".into()));
    }
    while *i < b.len() && is_param_name_char(b[*i]) {
        *i += 1;
    }
    Ok(std::str::from_utf8(&b[start..*i])
        .map_err(|_| HttpSigError::StructuredField("non-utf8 param name".into()))?
        .to_string())
}

/// Parse a Structured Field string (`"..."`) with `\` escaping.
fn parse_string(b: &[u8], i: &mut usize) -> Result<String> {
    expect(b, i, b'"')?;
    let mut out = String::new();
    loop {
        if *i >= b.len() {
            return Err(HttpSigError::StructuredField("unterminated string".into()));
        }
        let c = b[*i];
        if c == b'"' {
            *i += 1;
            break;
        }
        if c == b'\\' {
            *i += 1;
            if *i >= b.len() {
                return Err(HttpSigError::StructuredField("bad escape".into()));
            }
            let e = b[*i];
            match e {
                b'\\' | b'"' => out.push(e as char),
                _ => {
                    return Err(HttpSigError::StructuredField(
                        "only \\\\ and \\\" escapes are supported".into(),
                    ))
                }
            }
            *i += 1;
        } else {
            // Reject control characters and unescaped DEL/non-ASCII lightly.
            if c < 0x20 || c == 0x7f {
                return Err(HttpSigError::StructuredField(
                    "control characters not allowed in strings".into(),
                ));
            }
            out.push(c as char);
            *i += 1;
        }
    }
    Ok(out)
}

fn parse_integer(b: &[u8], i: &mut usize) -> Result<i64> {
    let start = *i;
    if *i < b.len() && b[*i] == b'-' {
        *i += 1;
    }
    if *i >= b.len() || !b[*i].is_ascii_digit() {
        return Err(HttpSigError::StructuredField("invalid integer".into()));
    }
    while *i < b.len() && b[*i].is_ascii_digit() {
        *i += 1;
    }
    let s = std::str::from_utf8(&b[start..*i])
        .map_err(|_| HttpSigError::StructuredField("non-utf8 integer".into()))?;
    s.parse::<i64>()
        .map_err(|_| HttpSigError::StructuredField("integer out of range".into()))
}

fn parse_param_value(b: &[u8], i: &mut usize) -> Result<SfParam> {
    if *i < b.len() && b[*i] == b'"' {
        return Ok(SfParam::Str(parse_string(b, i)?));
    }
    if *i < b.len() && (b[*i] == b'-' || b[*i].is_ascii_digit()) {
        return Ok(SfParam::Int(parse_integer(b, i)?));
    }
    if *i < b.len() && b[*i] == b'?' {
        *i += 1;
        if *i >= b.len() || (b[*i] != b'0' && b[*i] != b'1') {
            return Err(HttpSigError::StructuredField("invalid boolean".into()));
        }
        let v = b[*i] == b'1';
        *i += 1;
        return Ok(SfParam::Bool(v));
    }
    Err(HttpSigError::StructuredField("invalid parameter value".into()))
}

fn parse_parameters(b: &[u8], i: &mut usize) -> Result<Vec<(String, SfParam)>> {
    let mut params = Vec::new();
    loop {
        skip_sp(b, i);
        if *i >= b.len() || b[*i] != b';' {
            break;
        }
        *i += 1;
        skip_sp(b, i);
        let name = parse_param_name(b, i)?;
        skip_sp(b, i);
        if *i < b.len() && b[*i] == b'=' {
            *i += 1;
            skip_sp(b, i);
            let val = parse_param_value(b, i)?;
            params.push((name, val));
        } else {
            // A bare parameter is a Boolean flag set to true (e.g. `req`).
            params.push((name, SfParam::Bool(true)));
        }
    }
    Ok(params)
}

fn parse_inner_list(b: &[u8], i: &mut usize) -> Result<InnerList> {
    expect(b, i, b'(')?;
    let mut items = Vec::new();
    skip_sp(b, i);
    while *i < b.len() && b[*i] != b')' {
        skip_sp(b, i);
        if *i < b.len() && b[*i] == b')' {
            break;
        }
        // Each item is a quoted string, optionally carrying its own
        // parameters (e.g. `"@query-param";name="Pet"`).
        let name = parse_string(b, i)?;
        skip_sp(b, i);
        let item_params = parse_parameters(b, i)?;
        items.push((name, item_params));
        skip_sp(b, i);
        if *i < b.len() && b[*i] == b',' {
            *i += 1;
            continue;
        }
        if *i < b.len() && b[*i] == b')' {
            break;
        }
        if *i < b.len() && b[*i] == b';' {
            // Parameters may immediately follow the final item without a
            // closing paren in some inputs; treat as end of items.
            break;
        }
        return Err(HttpSigError::StructuredField(
            "expected ',' or ')' in inner list".into(),
        ));
    }
    // Consume the closing paren if present.
    if *i < b.len() && b[*i] == b')' {
        *i += 1;
    }
    skip_sp(b, i);
    let params = parse_parameters(b, i)?;
    Ok(InnerList { items, params })
}

fn parse_byte_seq(b: &[u8], i: &mut usize) -> Result<Vec<u8>> {
    expect(b, i, b':')?;
    let start = *i;
    while *i < b.len() && b[*i] != b':' {
        *i += 1;
    }
    if *i >= b.len() {
        return Err(HttpSigError::StructuredField("unterminated byte sequence".into()));
    }
    let raw = &b[start..*i];
    *i += 1;
    STANDARD
        .decode(raw)
        .map_err(|e| HttpSigError::StructuredField(format!("base64: {e}")))
}

fn parse_member(b: &[u8], i: &mut usize) -> Result<MemberValue> {
    skip_sp(b, i);
    if *i < b.len() && b[*i] == b'(' {
        Ok(MemberValue::InnerList(parse_inner_list(b, i)?))
    } else if *i < b.len() && b[*i] == b':' {
        Ok(MemberValue::ByteSeq(parse_byte_seq(b, i)?))
    } else {
        Err(HttpSigError::StructuredField(
            "expected inner list or byte sequence".into(),
        ))
    }
}

/// Parse a full Structured Field Dictionary (used for `Signature-Input` and
/// `Signature` fields).
pub(crate) fn parse_dictionary(input: &str) -> Result<Vec<(String, MemberValue)>> {
    let b = input.as_bytes();
    let mut i = 0;
    let mut members = Vec::new();
    loop {
        skip_sp(b, &mut i);
        if i >= b.len() {
            break;
        }
        let key = parse_key(b, &mut i)?;
        skip_sp(b, &mut i);
        expect(b, &mut i, b'=')?;
        skip_sp(b, &mut i);
        let member = parse_member(b, &mut i)?;
        members.push((key, member));
        skip_sp(b, &mut i);
        if i >= b.len() {
            break;
        }
        if b[i] == b',' {
            i += 1;
            continue;
        }
        return Err(HttpSigError::StructuredField(
            "expected ',' between dictionary members".into(),
        ));
    }
    Ok(members)
}

/// Parse a single component identifier (`"name";param=value;flag`).
pub(crate) fn parse_component_item(input: &str) -> Result<(String, Vec<(String, SfParam)>)> {
    let b = input.as_bytes();
    let mut i = 0;
    skip_sp(b, &mut i);
    let name = parse_string(b, &mut i)?;
    skip_sp(b, &mut i);
    let params = parse_parameters(b, &mut i)?;
    Ok((name, params))
}

/// Parse a single inner-list value (the text after `label=` in a
/// `Signature-Input` entry) into an [`InnerList`].
pub(crate) fn parse_inner_list_str(input: &str) -> Result<InnerList> {
    let b = input.as_bytes();
    let mut i = 0;
    parse_inner_list(b, &mut i)
}

fn escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

fn serialize_param_value(v: &SfParam) -> String {
    match v {
        SfParam::Int(n) => n.to_string(),
        SfParam::Str(s) => escape_string(s),
        SfParam::Bool(true) => "?1".to_string(),
        SfParam::Bool(false) => "?0".to_string(),
    }
}

pub(crate) fn serialize_params(params: &[(String, SfParam)]) -> String {
    let mut out = String::new();
    for (name, val) in params {
        out.push(';');
        out.push_str(name);
        // A Boolean `true` is emitted as a bare parameter flag; all other
        // values carry an `=`.
        if let SfParam::Bool(true) = val {
            // no value
        } else {
            out.push('=');
            out.push_str(&serialize_param_value(val));
        }
    }
    out
}

pub(crate) fn serialize_inner_list(inner: &InnerList) -> String {
    let mut out = String::from("(");
    for (idx, (name, item_params)) in inner.items.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        out.push_str(&escape_string(name));
        out.push_str(&serialize_params(item_params));
    }
    out.push(')');
    out.push_str(&serialize_params(&inner.params));
    out
}

pub(crate) fn serialize_member(m: &MemberValue) -> String {
    match m {
        MemberValue::InnerList(inner) => serialize_inner_list(inner),
        MemberValue::ByteSeq(bytes) => {
            let mut s = String::from(":");
            STANDARD.encode_string(bytes, &mut s);
            s.push(':');
            s
        }
    }
}

/// Serialize a Structured Field Dictionary from a list of (label, member)
/// pairs, in order.
pub(crate) fn serialize_dictionary(members: &[(String, MemberValue)]) -> String {
    let mut out = String::new();
    for (idx, (key, m)) in members.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        out.push_str(key);
        out.push('=');
        out.push_str(&serialize_member(m));
    }
    out
}
