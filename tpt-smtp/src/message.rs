// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Internet Message Format (RFC 5322) parsing/generation plus MIME
//! (RFC 2045/2046) decoding and RFC 2047 encoded-word decoding.
//!
//! This module is transport-agnostic: it knows nothing about SMTP. It parses a
//! raw message (headers + body) and, optionally, decodes its MIME structure
//! (multipart messages, `Content-Transfer-Encoding`, etc.). A small
//! [`MessageBuilder`] produces well-formed messages for sending.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

/// A single RFC 5322 header field (name + unfolded value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The field name (e.g. `Subject`), with original casing preserved.
    pub name: String,
    /// The field value, with any folding whitespace (`\r\n `) unfolded to a
    /// single space and surrounding whitespace trimmed.
    pub value: String,
}

/// A parsed electronic mail address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// Optional display name from a `Name <addr>` construction.
    pub display_name: Option<String>,
    /// The local-part of the address (everything before `@`).
    pub local_part: String,
    /// The domain part of the address (everything after `@`). Empty for
    /// addresses that have no domain (e.g. postmaster when written bare).
    pub domain: String,
}

impl Address {
    /// Construct an address from a local-part and domain.
    pub fn new(local_part: impl Into<String>, domain: impl Into<String>) -> Self {
        Self {
            display_name: None,
            local_part: local_part.into(),
            domain: domain.into(),
        }
    }

    /// The bare `local@domain` form (empty string if there is no domain).
    pub fn address(&self) -> String {
        if self.domain.is_empty() {
            self.local_part.clone()
        } else {
            format!("{}@{}", self.local_part, self.domain)
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.display_name {
            Some(name) if !name.is_empty() => write!(f, "{} <{}>", name, self.address()),
            _ => write!(f, "{}", self.address()),
        }
    }
}

/// A parsed Internet message: header block plus body.
#[derive(Debug, Clone)]
pub struct Message {
    /// Header fields in order of appearance.
    pub headers: Vec<Header>,
    /// The raw body bytes (after the blank line separating headers from body),
    /// kept as-is (NOT decoded for transfer-encoding).
    pub body: Vec<u8>,
}

impl Message {
    /// Parse a raw message from `bytes`. Headers are unfolded and the body is
    /// captured verbatim. A message with no header/body separator is treated as
    /// a body-only message.
    pub fn parse(bytes: &[u8]) -> Message {
        // Locate the header/body separator (the first blank line).
        let sep = find_separator(bytes);
        match sep {
            Some(pos) => {
                let header_end = pos + separator_len(bytes, pos);
                let header_bytes = &bytes[..pos];
                let body = bytes[header_end..].to_vec();
                Message {
                    headers: parse_headers(header_bytes),
                    body,
                }
            }
            None => Message {
                headers: parse_headers(bytes),
                body: Vec::new(),
            },
        }
    }

    /// All header names/values, lower-cased name lookup.
    fn header_values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
            .collect()
    }

    /// The (decoded) value of the first matching header, if present.
    pub fn header(&self, name: &str) -> Option<String> {
        self.header_values(name).into_iter().next().map(decode_header)
    }

    /// All (decoded) values of the matching headers.
    pub fn headers_all(&self, name: &str) -> Vec<String> {
        self.header_values(name)
            .into_iter()
            .map(decode_header)
            .collect()
    }

    /// The decoded `Subject` header, if present.
    pub fn subject(&self) -> Option<String> {
        self.header("Subject")
    }

    /// The `From` addresses.
    pub fn from(&self) -> Vec<Address> {
        self.addresses("From")
    }

    /// The `To` addresses.
    pub fn to(&self) -> Vec<Address> {
        self.addresses("To")
    }

    /// The `Cc` addresses.
    pub fn cc(&self) -> Vec<Address> {
        self.addresses("Cc")
    }

    /// The raw `Date` header string, if present.
    pub fn date(&self) -> Option<&str> {
        self.header_values("Date").into_iter().next()
    }

    /// Parse the addresses from the first matching address header
    /// (`From`/`To`/`Cc`/`Reply-To`/etc.), decoding any RFC 2047 encoded words
    /// in display names.
    pub fn addresses(&self, name: &str) -> Vec<Address> {
        match self.header_values(name).into_iter().next() {
            Some(v) => parse_addresses(&v),
            None => Vec::new(),
        }
    }

    /// Parse the MIME structure of this message (recursively for multipart
    /// messages). If the message has no usable `Content-Type`, it is treated as
    /// a single `text/plain` body.
    pub fn mime(&self) -> MimePart {
        parse_mime(&self.headers, &self.body)
    }
}

// --- Header parsing ---------------------------------------------------------

fn find_separator(content: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + 3 < content.len() {
        if &content[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
        i += 1;
    }
    let mut i = 0;
    while i + 1 < content.len() {
        if content[i] == b'\n' && content[i + 1] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn separator_len(content: &[u8], pos: usize) -> usize {
    if content[pos..].starts_with(b"\r\n\r\n") {
        4
    } else {
        2
    }
}

fn parse_headers(bytes: &[u8]) -> Vec<Header> {
    // Normalise to a single String, preserving structure.
    let text = String::from_utf8_lossy(bytes);
    let mut headers = Vec::new();
    let mut current: Option<Header> = None;

    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            break; // end of headers
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // Folding: append to the current header, unfolded.
            if let Some(h) = current.as_mut() {
                if !h.value.is_empty() {
                    h.value.push(' ');
                }
                h.value.push_str(line.trim_start());
            }
        } else {
            if let Some(h) = current.take() {
                headers.push(h);
            }
            if let Some((name, value)) = line.split_once(':') {
                current = Some(Header {
                    name: name.trim().to_string(),
                    value: value.trim().to_string(),
                });
            }
        }
    }
    if let Some(h) = current.take() {
        headers.push(h);
    }
    headers
}

// --- Address parsing (RFC 5322 §3.4) ----------------------------------------

/// Parse a comma-separated address list, handling `mailbox`, `mailbox-list`,
/// and `group: ... ;` syntax. Display names with RFC 2047 encoded words are
/// decoded.
pub fn parse_addresses(value: &str) -> Vec<Address> {
    let mut out = Vec::new();
    let chars: Vec<char> = value.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        // Skip whitespace and commas.
        if chars[i].is_whitespace() || chars[i] == ',' {
            i += 1;
            continue;
        }
        // Detect a group: "Name: ..." until ';'
        if let Some(colon) = find_group_colon(&chars, i) {
            let group_name = decode_header(&chars[i..colon].iter().collect::<String>());
            let group_end = find_matching_semicolon(&chars, colon + 1);
            if let Some(end) = group_end {
                let inner: String = chars[colon + 1..end].iter().collect();
                for addr in parse_addresses(&inner) {
                    out.push(addr);
                }
                i = end + 1;
                let _ = group_name;
                continue;
            }
        }
        // Parse a single mailbox.
        match parse_one_mailbox(&chars, i) {
            Some((addr, next)) => {
                out.push(addr);
                i = next;
            }
            None => {
                // Skip to the next comma to stay resilient.
                match chars[i..].iter().position(|c| *c == ',') {
                    Some(p) => i += p + 1,
                    None => break,
                }
            }
        }
    }
    out
}

fn find_group_colon(chars: &[char], start: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut j = start;
    while j < chars.len() {
        match chars[j] {
            '<' => depth += 1,
            '>' => depth -= 1,
            '"' => {
                // Skip quoted string.
                j += 1;
                while j < chars.len() && chars[j] != '"' {
                    if chars[j] == '\\' {
                        j += 1;
                    }
                    j += 1;
                }
            }
            ':' if depth == 0 => return Some(j),
            _ => {}
        }
        j += 1;
    }
    None
}

fn find_matching_semicolon(chars: &[char], start: usize) -> Option<usize> {
    let mut j = start;
    while j < chars.len() {
        if chars[j] == ';' {
            return Some(j);
        }
        j += 1;
    }
    None
}

fn parse_one_mailbox(chars: &[char], start: usize) -> Option<(Address, usize)> {
    let mut i = start;
    // Skip leading whitespace.
    while i < chars.len() && chars[i].is_whitespace() {
        i += 1;
    }
    if i >= chars.len() {
        return None;
    }

    // Quoted or bare display name before an angle address. The scan advances
    // `i` so the address parse below starts right after the display name.
    let mut display: Option<String> = None;
    if chars[i] == '"' {
        // quoted display name up to closing quote
        let end = chars[i + 1..]
            .iter()
            .position(|c| *c == '"')
            .map(|p| i + 1 + p);
        if let Some(end) = end {
            display = Some(chars[i + 1..end].iter().collect());
            i = end + 1;
        }
    } else {
        // Read a run of display-name chars until we hit '<' or end.
        let save = i;
        while i < chars.len() && chars[i] != '<' {
            if chars[i] == ',' {
                break;
            }
            i += 1;
        }
        if i > save && (i == chars.len() || chars[i] == '<') {
            let name: String = chars[save..i].iter().collect();
            let name = name.trim();
            if !name.is_empty() && !name.contains('@') {
                display = Some(decode_header(name));
            }
        }
    }

    // Angle address <local@domain> or bare local@domain.
    let addr: String;
    let next;
    if i < chars.len() && chars[i] == '<' {
        let end = chars[i + 1..].iter().position(|c| *c == '>').map(|p| i + 1 + p);
        match end {
            Some(end) => {
                addr = chars[i + 1..end].iter().collect();
                next = end + 1;
            }
            None => return None,
        }
    } else {
        // Bare address up to a comma, ';', or whitespace.
        let save = i;
        while i < chars.len() && chars[i] != ',' && chars[i] != ';' && !chars[i].is_whitespace() {
            i += 1;
        }
        if i == save {
            return None;
        }
        addr = chars[save..i].iter().collect();
        next = i;
    }

    let addr = addr.trim();
    let (local, domain) = match addr.split_once('@') {
        Some((l, d)) => (l.to_string(), d.to_string()),
        None => (addr.to_string(), String::new()),
    };
    Some((
        Address {
            display_name: display,
            local_part: local,
            domain,
        },
        next,
    ))
}

// --- RFC 2047 encoded-word decoding -----------------------------------------

/// Decode RFC 2047 `=?charset?encoding?text?=` encoded words in a header value,
/// leaving un-encoded text untouched. Multiple encoded words separated by
/// linear whitespace are concatenated without a separator.
pub fn decode_header(value: &str) -> String {
    let mut out = String::new();
    let mut last_was_encoded = false;
    let mut iter = value.chars().peekable();
    let s: String = iter.by_ref().collect();
    let mut rest = s.as_str();

    while !rest.is_empty() {
        if let Some(pos) = rest.find("=?") {
            // Push the literal text before the encoded word.
            let (literal, after) = rest.split_at(pos);
            let trimmed = if last_was_encoded {
                literal.trim_start()
            } else {
                literal
            };
            out.push_str(trimmed);
            match decode_encoded_word(after) {
                Some((decoded, remainder)) => {
                    out.push_str(&decoded);
                    last_was_encoded = true;
                    rest = remainder;
                }
                None => {
                    // Not a valid encoded word; emit literally and advance one char.
                    out.push_str(&rest[..1]);
                    last_was_encoded = false;
                    rest = &rest[1..];
                }
            }
        } else {
            out.push_str(rest);
            break;
        }
    }
    out
}

fn decode_encoded_word(s: &str) -> Option<(String, &str)> {
    // s starts with "=?". Find "? encoding ? text ?=".
    let s = s.strip_prefix("=?")?;
    let (charset, rest) = s.split_once("?")?;
    let (encoding, rest) = rest.split_once("?")?;
    let rest = rest.strip_prefix('?')?;
    let (text, rest) = rest.split_once("?=")?;
    let _ = charset;
    let decoded = match encoding.to_ascii_uppercase().as_str() {
        "B" => {
            let bytes = BASE64.decode(text.replace(' ', "").as_bytes()).ok()?;
            String::from_utf8_lossy(&bytes).into_owned()
        }
        "Q" => decode_q(text),
        _ => return None,
    };
    Some((decoded, rest))
}

fn decode_q(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'_' => out.push(b' '),
            b'=' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi * 16 + lo) as u8);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b => out.push(b),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// --- MIME parsing -----------------------------------------------------------

/// A decoded MIME part (RFC 2045/2046).
#[derive(Debug, Clone)]
pub struct MimePart {
    /// The part's header fields.
    pub headers: Vec<Header>,
    /// The decoded (transfer-encoding-decoded) content bytes of this part. For
    /// multipart parts this is empty; the parts live in [`MimePart::children`].
    pub content: Vec<u8>,
    /// For `multipart/*` parts, the nested child parts. Empty otherwise.
    pub children: Vec<MimePart>,
    /// The effective media type, e.g. `text/plain`. Derived from `Content-Type`
    /// (defaulting to `text/plain` per RFC 2045 §5.2).
    pub content_type: String,
}

impl MimePart {
    /// The (decoded) value of the first matching header.
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| decode_header(&h.value))
    }

    /// The `Content-Type` media type (e.g. `multipart/mixed`).
    pub fn media_type(&self) -> &str {
        &self.content_type
    }

    /// Convenience accessor for leaf content interpreted as UTF-8 (lossy).
    pub fn content_text(&self) -> String {
        String::from_utf8_lossy(&self.content).into_owned()
    }
}

fn header_value<'a>(headers: &'a [Header], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

fn parse_mime(headers: &[Header], body: &[u8]) -> MimePart {
    let content_type = header_value(headers, "Content-Type").unwrap_or("text/plain");
    let (mtype, _params) = split_content_type(content_type);
    let mtype = mtype.to_ascii_lowercase();

    if mtype.starts_with("multipart/") {
        let boundary = content_type
            .split(';')
            .skip(1)
            .find_map(|p| {
                let p = p.trim();
                if p.to_ascii_lowercase().starts_with("boundary=") {
                    let b = &p["boundary=".len()..];
                    Some(strip_quotes(b).to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();
        let children = if boundary.is_empty() {
            Vec::new()
        } else {
            split_multipart(body, &boundary)
        };
        MimePart {
            headers: headers.to_vec(),
            content: Vec::new(),
            children,
            content_type: mtype,
        }
    } else {
        let cte = header_value(headers, "Content-Transfer-Encoding")
            .unwrap_or("7bit")
            .trim()
            .to_ascii_lowercase();
        let content = decode_transfer_encoding(body, &cte);
        MimePart {
            headers: headers.to_vec(),
            content,
            children: Vec::new(),
            content_type: mtype,
        }
    }
}

fn split_content_type(ct: &str) -> (&str, Vec<(String, String)>) {
    let mut parts = ct.split(';');
    let mtype = parts.next().unwrap_or("text/plain").trim();
    let params = parts
        .map(|p| {
            let p = p.trim();
            match p.split_once('=') {
                Some((k, v)) => (k.trim().to_string(), strip_quotes(v.trim()).to_string()),
                None => (p.to_string(), String::new()),
            }
        })
        .collect();
    (mtype, params)
}

fn strip_quotes(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s)
}

fn split_multipart(body: &[u8], boundary: &str) -> Vec<MimePart> {
    let delim = format!("--{}", boundary);
    let text = String::from_utf8_lossy(body);
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_part = false;

    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line == delim || line.starts_with(&format!("--{}--", boundary)) {
            if in_part {
                parts.push(parse_part(&current));
                current.clear();
            }
            in_part = !line.ends_with("--");
            continue;
        }
        if in_part {
            current.push_str(line);
            current.push('\n');
        }
    }
    if in_part && !current.is_empty() {
        parts.push(parse_part(&current));
    }

    // Drop the preamble/epilogue (anything before the first boundary, and
    // trailing empty parts).
    parts
        .into_iter()
        .filter(|p| !p.headers.is_empty() || !p.content.is_empty() || !p.children.is_empty())
        .collect()
}

fn parse_part(raw: &str) -> MimePart {
    let bytes = raw.as_bytes();
    let sep = find_separator(bytes);
    match sep {
        Some(pos) => {
            let header_end = pos + separator_len(bytes, pos);
            let header_bytes = &bytes[..pos];
            let body = &bytes[header_end..];
            let headers = parse_headers(header_bytes);
            parse_mime(&headers, body)
        }
        None => MimePart {
            headers: parse_headers(bytes),
            content: Vec::new(),
            children: Vec::new(),
            content_type: "text/plain".to_string(),
        },
    }
}

fn decode_transfer_encoding(body: &[u8], cte: &str) -> Vec<u8> {
    match cte {
        "base64" => {
            let text: String = body
                .iter()
                .filter(|b| !(**b == b'\r' || **b == b'\n' || **b == b' ' || **b == b'\t'))
                .map(|b| *b as char)
                .collect();
            BASE64.decode(text.as_bytes()).unwrap_or_else(|_| body.to_vec())
        }
        "quoted-printable" => decode_quoted_printable(body),
        _ => body.to_vec(),
    }
}

fn decode_quoted_printable(body: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        match body[i] {
            b'=' if i + 1 < body.len() => {
                let c1 = (body[i + 1] as char).to_digit(16);
                if i + 2 < body.len() {
                    let c2 = (body[i + 2] as char).to_digit(16);
                    if let (Some(hi), Some(lo)) = (c1, c2) {
                        out.push((hi * 16 + lo) as u8);
                        i += 3;
                        continue;
                    }
                    // Soft line break "=\r\n" or "=\n".
                    if (body[i + 1] == b'\r' && i + 2 < body.len() && body[i + 2] == b'\n')
                        || (body[i + 1] == b'\n')
                    {
                        i += if body[i + 1] == b'\r' { 3 } else { 2 };
                        continue;
                    }
                }
                out.push(body[i]);
                i += 1;
            }
            b => out.push(b),
        }
    }
    out
}

// --- Message builder --------------------------------------------------------

/// Builds a well-formed RFC 5322 message with CRLF line endings.
///
/// Headers are emitted in the order added. If `From` and `Date` are absent they
/// are filled automatically (both are required by RFC 5322 §3.6). The `Subject`
/// and address headers are encoded as RFC 2047 `B` encoded-words when they
/// contain non-ASCII characters.
#[derive(Debug, Clone, Default)]
pub struct MessageBuilder {
    headers: Vec<(String, String)>,
    body: String,
}

impl MessageBuilder {
    /// Create an empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a raw header (value must not contain CR/LF).
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let value = value.into();
        let value = if value.contains(['\r', '\n']) {
            value.replace(['\r', '\n'], " ")
        } else {
            value
        };
        self.headers.push((name.into(), value));
        self
    }

    /// Set the `From` header from an [`Address`].
    pub fn from_mailbox(self, addr: &Address) -> Self {
        self.header("From", encode_address_header(addr))
    }

    /// Set the `To` header from a list of [`Address`]es.
    pub fn to_mailboxes(self, addrs: &[Address]) -> Self {
        let joined = addrs
            .iter()
            .map(encode_address_header)
            .collect::<Vec<_>>()
            .join(", ");
        self.header("To", joined)
    }

    /// Set the `Subject` header, encoding it as RFC 2047 if non-ASCII.
    pub fn subject(self, subject: &str) -> Self {
        self.header("Subject", encode_header_if_needed(subject))
    }

    /// Set the `Date` header to the given RFC 5322 date string.
    pub fn date(self, date: &str) -> Self {
        self.header("Date", date)
    }

    /// Set the `Date` header to the current UTC time.
    pub fn date_now(self) -> Self {
        self.header("Date", format_rfc5322_date())
    }

    /// Set the message body. Lines will be CRLF-normalized.
    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = body.into();
        self
    }

    /// Build the message bytes with CRLF line endings, auto-filling `From` and
    /// `Date` if missing.
    pub fn build(self) -> Vec<u8> {
        let mut has_from = false;
        let mut has_date = false;
        let mut head = String::new();
        for (name, value) in &self.headers {
            if name.eq_ignore_ascii_case("From") {
                has_from = true;
            }
            if name.eq_ignore_ascii_case("Date") {
                has_date = true;
            }
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
        if !has_from {
            head.push_str("From: postmaster@localhost\r\n");
        }
        if !has_date {
            head.push_str(&format!("Date: {}\r\n", format_rfc5322_date()));
        }
        let mut out = head.into_bytes();
        out.extend_from_slice(b"\r\n");
        let body = self.body.replace('\n', "\r\n");
        out.extend_from_slice(body.as_bytes());
        // Ensure the body ends with CRLF.
        if !out.ends_with(b"\r\n") {
            out.extend_from_slice(b"\r\n");
        }
        out
    }
}

fn encode_address_header(addr: &Address) -> String {
    match &addr.display_name {
        Some(name) if !name.is_empty() => {
            format!("{} <{}>", encode_header_if_needed(name), addr.address())
        }
        _ => addr.address(),
    }
}

/// Encode a header value as an RFC 2047 `B` encoded-word when it contains
/// non-ASCII bytes; otherwise return it unchanged.
pub fn encode_header_if_needed(value: &str) -> String {
    if value.is_ascii() {
        return value.to_string();
    }
    let encoded = BASE64.encode(value.as_bytes());
    format!("=?UTF-8?B?{}?=", encoded)
}

fn format_rfc5322_date() -> String {
    // RFC 5322 §3.3 day/month names (English, fixed). No external time crate.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    const DAYS: &[&str] = &["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: &[&str] = &[
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    // Days since epoch (1970-01-01 was a Thursday).
    const SECS_PER_DAY: u64 = 86400;
    let days = now / SECS_PER_DAY;
    let secs = now % SECS_PER_DAY;
    let weekday = DAYS[((days + 4) % 7) as usize];
    let mut y = 1970i64;
    let mut rem = days as i64;
    loop {
        let leap = is_leap(y);
        let ydays = if leap { 366 } else { 365 };
        if rem < ydays {
            break;
        }
        rem -= ydays;
        y += 1;
    }
    // rem is day-of-year (0-based). Walk months.
    let month_days = |y: i64, m: usize| -> i64 {
        let md = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        if m == 1 && is_leap(y) {
            29
        } else {
            md[m]
        }
    };
    let mut m = 0;
    let mut d = rem;
    while m < 12 {
        let md = month_days(y, m);
        if d < md {
            break;
        }
        d -= md;
        m += 1;
    }
    let hour = secs / 3600;
    let minute = (secs % 3600) / 60;
    let second = secs % 60;
    format!(
        "{} {:02} {} {:04} {:02}:{:02}:{:02} +0000",
        weekday,
        d + 1,
        MONTHS[m],
        y,
        hour,
        minute,
        second
    )
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
