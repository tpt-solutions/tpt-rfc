// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A small, dependency-free XML DOM used by this crate for NETCONF message
//! handling.
//!
//! NETCONF (RFC 6241) exchanges well-formed XML documents, but the protocol
//! logic only needs a modest subset of XML: elements with attributes, text
//! content, and (for config payloads) nested elements. This module provides a
//! minimal, clean-room parser and serializer sufficient for that subset. It is
//! intentionally tiny and auditable rather than a full XML implementation.

use crate::error::NetconfError;

/// A single XML element (or, when it has no element children, a leaf carrying
/// `text`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Xml {
    /// Qualified element name (e.g. `rpc` or `nc:rpc`).
    pub name: String,
    /// Attribute `(name, value)` pairs.
    pub attributes: Vec<(String, String)>,
    /// Child elements.
    pub children: Vec<Xml>,
    /// Text content (for leaf elements).
    pub text: String,
}

impl Xml {
    /// Create a new element with the given name and no attributes/children.
    pub fn new(name: impl Into<String>) -> Xml {
        Xml {
            name: name.into(),
            attributes: Vec::new(),
            children: Vec::new(),
            text: String::new(),
        }
    }

    /// Add an attribute and return `self` for chaining.
    pub fn attr(mut self, name: impl Into<String>, value: impl Into<String>) -> Xml {
        self.attributes.push((name.into(), value.into()));
        self
    }

    /// Add a child element and return `self` for chaining.
    pub fn child(mut self, child: Xml) -> Xml {
        self.children.push(child);
        self
    }

    /// Set the text content and return `self` for chaining.
    pub fn text(mut self, text: impl Into<String>) -> Xml {
        self.text = text.into();
        self
    }

    /// The local part of `name` (everything after the last `:`).
    pub fn local_name(&self) -> &str {
        local_name(&self.name)
    }

    /// Look up an attribute by (local) name.
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(n, _)| local_name(n) == name)
            .map(|(_, v)| v.as_str())
    }

    /// Return the first child element whose local name matches `name`.
    pub fn child_named(&self, name: &str) -> Option<&Xml> {
        self.children.iter().find(|c| c.local_name() == name)
    }

    /// Return all child elements whose local name matches `name`.
    pub fn children_named(&self, name: &str) -> Vec<&Xml> {
        self.children
            .iter()
            .filter(|c| c.local_name() == name)
            .collect()
    }

    /// The text content of this element, if it is a leaf.
    pub fn text_content(&self) -> &str {
        &self.text
    }
}

fn local_name(name: &str) -> &str {
    match name.rfind(':') {
        Some(i) => &name[i + 1..],
        None => name,
    }
}

/// Errors produced while parsing XML.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum XmlError {
    /// The input ended unexpectedly while parsing.
    #[error("unexpected end of input")]
    UnexpectedEof,
    /// A malformed token was encountered.
    #[error("malformed xml: {0}")]
    Malformed(String),
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn parse_root(&mut self) -> Result<Xml, XmlError> {
        self.skip_markup_and_ws();
        self.parse_element()
    }

    fn skip_markup_and_ws(&mut self) {
        loop {
            self.skip_ws();
            if self.peek(0) == Some(b'<') {
                if self.peek(1) == Some(b'?') {
                    // Processing instruction / XML declaration.
                    self.skip_until(b"?>");
                    self.pos += 2;
                    continue;
                } else if self.peek(1) == Some(b'!')
                    && self.peek(2) == Some(b'-')
                    && self.peek(3) == Some(b'-')
                {
                    // Comment.
                    self.skip_until(b"-->");
                    self.pos += 3;
                    continue;
                }
            }
            break;
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(0), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.pos += 1;
        }
    }

    fn peek(&self, off: usize) -> Option<u8> {
        self.bytes.get(self.pos + off).copied()
    }

    fn skip_until(&mut self, needle: &[u8]) {
        while self.pos + needle.len() <= self.bytes.len() {
            if &self.bytes[self.pos..self.pos + needle.len()] == needle {
                return;
            }
            self.pos += 1;
        }
        self.pos = self.bytes.len();
    }

    fn parse_element(&mut self) -> Result<Xml, XmlError> {
        if self.peek(0) != Some(b'<') {
            return Err(XmlError::Malformed("expected `<`".into()));
        }
        self.pos += 1;

        // CDATA open?
        if self.peek(0) == Some(b'!') && self.peek(1) == Some(b'[') {
            self.pos += 2; // past <!
            self.skip_until(b"CDATA[");
            self.pos += 7; // skip CDATA[
            let start = self.pos;
            self.skip_until(b"]]>");
            let text = decode_entities(&self.bytes[start..self.pos]);
            self.pos += 3; // skip ]]>
            return Ok(Xml::new("#cdata").text(text));
        }

        let name = self.read_name()?;
        let mut element = Xml::new(name);
        self.parse_attributes(&mut element)?;

        // After attributes: `>` or `/>`.
        self.skip_ws();
        if self.peek(0) == Some(b'/') && self.peek(1) == Some(b'>') {
            self.pos += 2;
            return Ok(element);
        }
        if self.peek(0) != Some(b'>') {
            return Err(XmlError::Malformed("expected `>` after attributes".into()));
        }
        self.pos += 1;

        // Parse content: text and child elements until the closing tag.
        self.parse_content(&mut element)?;
        Ok(element)
    }

    fn read_name(&mut self) -> Result<String, XmlError> {
        self.skip_ws();
        let start = self.pos;
        while let Some(c) = self.peek(0) {
            if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b':' || c == b'.' {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(XmlError::Malformed("empty element name".into()));
        }
        Ok(std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| XmlError::Malformed("non-utf8 name".into()))?
            .to_string())
    }

    fn parse_attributes(&mut self, element: &mut Xml) -> Result<(), XmlError> {
        loop {
            self.skip_ws();
            match self.peek(0) {
                Some(b'>') | Some(b'/') => return Ok(()),
                None => return Err(XmlError::UnexpectedEof),
                _ => {}
            }
            let name = self.read_name()?;
            self.skip_ws();
            if self.peek(0) != Some(b'=') {
                return Err(XmlError::Malformed("expected `=` in attribute".into()));
            }
            self.pos += 1;
            self.skip_ws();
            let quote = self.peek(0).ok_or(XmlError::UnexpectedEof)?;
            if quote != b'"' && quote != b'\'' {
                return Err(XmlError::Malformed("expected quote in attribute".into()));
            }
            self.pos += 1;
            let start = self.pos;
            while self.peek(0) != Some(quote) {
                if self.peek(0).is_none() {
                    return Err(XmlError::UnexpectedEof);
                }
                self.pos += 1;
            }
            let value = decode_entities(&self.bytes[start..self.pos]);
            self.pos += 1; // consume closing quote
            element.attributes.push((name, value));
        }
    }

    fn parse_content(&mut self, element: &mut Xml) -> Result<(), XmlError> {
        let mut text_buf = String::new();
        loop {
            // Read text until the next `<` (or EOF).
            let start = self.pos;
            while let Some(c) = self.peek(0) {
                if c == b'<' {
                    break;
                }
                self.pos += 1;
            }
            if self.pos > start {
                text_buf.push_str(&decode_entities(&self.bytes[start..self.pos]));
            }
            match self.peek(0) {
                None => return Err(XmlError::UnexpectedEof),
                Some(b'<') => {
                    if self.peek(1) == Some(b'/') {
                        // Closing tag.
                        self.pos += 2;
                        let close_name = self.read_name()?;
                        self.skip_ws();
                        if self.peek(0) != Some(b'>') {
                            return Err(XmlError::Malformed("expected `>` in closing tag".into()));
                        }
                        self.pos += 1;
                        if close_name != element.name {
                            return Err(XmlError::Malformed(format!(
                                "mismatched closing tag </{}> for <{}>",
                                close_name, element.name
                            )));
                        }
                        if !text_buf.trim().is_empty() {
                            element.text = text_buf.trim().to_string();
                        }
                        return Ok(());
                    } else if self.peek(1) == Some(b'!') || self.peek(1) == Some(b'?') {
                        // Comment / PI inside content: skip.
                        self.skip_markup_and_ws();
                        continue;
                    } else {
                        // Child element.
                        let child = self.parse_element()?;
                        element.children.push(child);
                    }
                }
                _ => return Err(XmlError::UnexpectedEof),
            }
        }
    }
}

fn decode_entities(input: &[u8]) -> String {
    let s = match std::str::from_utf8(input) {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '&' {
            let mut ent = String::new();
            for e in chars.by_ref() {
                if e == ';' {
                    break;
                }
                ent.push(e);
            }
            match ent.as_str() {
                "amp" => out.push('&'),
                "lt" => out.push('<'),
                "gt" => out.push('>'),
                "quot" => out.push('"'),
                "apos" => out.push('\''),
                other if other.starts_with('#') => {
                    let code = if let Some(h) = other.strip_prefix("x") {
                        u32::from_str_radix(h, 16).ok()
                    } else {
                        other[1..].parse::<u32>().ok()
                    };
                    if let Some(cp) = code.and_then(char::from_u32) {
                        out.push(cp);
                    }
                }
                _ => out.push('&'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Parse the first (root) XML element from `input`.
pub fn parse_root(input: &str) -> Result<Xml, NetconfError> {
    let mut p = Parser {
        bytes: input.as_bytes(),
        pos: 0,
    };
    p.parse_root()
        .map_err(|e| NetconfError::XmlParse(e.to_string()))
}

/// Pretty-print an [`Xml`] tree as an indented XML document.
pub fn to_string(root: &Xml) -> String {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    write_element(root, 0, &mut out);
    out
}

fn write_element(el: &Xml, indent: usize, out: &mut String) {
    let pad = "  ".repeat(indent);
    let attrs = el
        .attributes
        .iter()
        .map(|(k, v)| format!(" {}=\"{}\"", k, escape_attr(v)))
        .collect::<String>();
    if el.children.is_empty() {
        if el.text.is_empty() {
            out.push_str(&format!("{}<{}{}/>\n", pad, el.name, attrs));
        } else {
            out.push_str(&format!(
                "{}<{}{}>{}</{}>\n",
                pad,
                el.name,
                attrs,
                escape_text(&el.text),
                el.name
            ));
        }
    } else {
        out.push_str(&format!("{}<{}{}>\n", pad, el.name, attrs));
        for child in &el.children {
            write_element(child, indent + 1, out);
        }
        out.push_str(&format!("{}</{}>\n", pad, el.name));
    }
}

fn escape_text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_attr(s: &str) -> String {
    escape_text(s).replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_simple() {
        let doc =
            "<rpc message-id=\"1\"><get-config><source><running/></source></get-config></rpc>";
        let root = parse_root(doc).unwrap();
        assert_eq!(root.name, "rpc");
        assert_eq!(root.attribute("message-id"), Some("1"));
        let gc = root.child_named("get-config").unwrap();
        let src = gc.child_named("source").unwrap();
        assert!(src.child_named("running").is_some());
    }

    #[test]
    fn decodes_entities_and_text() {
        let doc = "<x>alpha &amp; beta &lt; 3 &quot;q&quot;</x>";
        let root = parse_root(doc).unwrap();
        assert_eq!(root.text_content(), "alpha & beta < 3 \"q\"");
    }

    #[test]
    fn handles_namespaces_and_self_closing() {
        let doc = "<nc:rpc xmlns:nc=\"urn:x\"><nc:get/></nc:rpc>";
        let root = parse_root(doc).unwrap();
        assert_eq!(root.local_name(), "rpc");
        assert!(root.child_named("get").is_some());
    }

    #[test]
    fn serialize_is_well_formed() {
        let mut el = Xml::new("rpc").attr("message-id", "1");
        let mut gc = Xml::new("get-config");
        gc.children
            .push(Xml::new("source").child(Xml::new("running")));
        el.children.push(gc);
        let s = to_string(&el);
        assert!(s.contains("<rpc message-id=\"1\">"));
        assert!(s.contains("<running/>"));
        // Re-parse to confirm well-formedness.
        let reparsed = parse_root(&s).unwrap();
        assert_eq!(
            reparsed.child_named("get-config").unwrap().local_name(),
            "get-config"
        );
    }
}
