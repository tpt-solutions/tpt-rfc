// SPDX-License-Identifier: MIT OR Apache-2.0
//! SIP and SIPS URI parsing and serialisation (RFC 3261 §19.1).

use crate::error::{Result, SipError};

/// URI scheme: `sip:` (plain) or `sips:` (TLS-protected).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// `sip:` — transport may be any (UDP/TCP/TLS/SCTP), negotiated.
    Sip,
    /// `sips:` — TLS is required end-to-end.
    Sips,
}

impl Scheme {
    fn as_str(self) -> &'static str {
        match self {
            Scheme::Sip => "sip",
            Scheme::Sips => "sips",
        }
    }

    fn parse(s: &str) -> Result<Scheme> {
        match s {
            "sip" => Ok(Scheme::Sip),
            "sips" => Ok(Scheme::Sips),
            other => Err(SipError::InvalidUri(format!("unknown scheme `{other}`"))),
        }
    }
}

/// A single URI parameter of the form `name` or `name=value`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    /// Parameter name (e.g. `transport`, `lr`).
    pub name: String,
    /// Optional parameter value; `None` for valueless flags.
    pub value: Option<String>,
}

impl Param {
    /// Construct a valueless flag parameter (e.g. `lr`).
    pub fn flag(name: impl Into<String>) -> Param {
        Param {
            name: name.into(),
            value: None,
        }
    }

    /// Construct a `name=value` parameter.
    pub fn with_value(name: impl Into<String>, value: impl Into<String>) -> Param {
        Param {
            name: name.into(),
            value: Some(value.into()),
        }
    }

    /// The parameter value, or `None` when absent.
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

/// A parsed `sip:` / `sips:` URI.
///
/// Per RFC 3261 §19.1 the syntax is:
/// `sip:user:password@host:port;uri-parameters?headers`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uri {
    /// Scheme (`sip` or `sips`).
    pub scheme: Scheme,
    /// User part of the userinfo, if present.
    pub user: Option<String>,
    /// Password part of the userinfo, if present.
    pub password: Option<String>,
    /// Host (reg-name, IPv4, or IPv6 in brackets).
    pub host: String,
    /// Port, if explicitly present.
    pub port: Option<u16>,
    /// URI parameters (transport, user, method, ttl, maddr, lr, …).
    pub params: Vec<Param>,
    /// Header parameters carried after `?` (e.g. `subject=...`).
    pub headers: Vec<Param>,
}

impl Uri {
    /// Parse a SIP URI from its textual form.
    pub fn parse(input: &str) -> Result<Uri> {
        let rest = input
            .strip_prefix("sip:")
            .or_else(|| input.strip_prefix("sips:"))
            .map(|s| (s, input[..input.len() - s.len()].trim_end_matches(':')))
            .ok_or_else(|| SipError::InvalidUri(format!("missing sip:/sips: scheme: {input}")))?;
        let (body, scheme_str) = rest;
        let scheme = Scheme::parse(scheme_str)?;

        // Split headers (after the first '?').
        let (body, headers) = match body.split_once('?') {
            Some((b, h)) => {
                let parsed = parse_params(h, '&')?;
                (b, parsed)
            }
            None => (body, Vec::new()),
        };

        // Split URI parameters (after the first ';').
        let (body, params) = match body.split_once(';') {
            Some((b, p)) => (b, parse_params(p, ';')?),
            None => (body, Vec::new()),
        };

        // Split userinfo (before '@').
        let (userinfo, hostport) = match body.split_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, body),
        };

        // hostport: host optionally followed by ':port'.
        let (host, port) = split_host_port(hostport)?;

        // userinfo: user optionally followed by ':password'.
        let (user, password) = match userinfo {
            Some(u) => match u.split_once(':') {
                Some((u2, p2)) => (Some(unescape(u2)?), Some(unescape(p2)?)),
                None => (Some(unescape(u)?), None),
            },
            None => (None, None),
        };

        if host.is_empty() {
            return Err(SipError::InvalidUri("empty host".into()));
        }

        Ok(Uri {
            scheme,
            user,
            password,
            host,
            port,
            params,
            headers,
        })
    }

    /// Return the value of the first URI parameter with the given name.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case(name))
            .and_then(|p| p.value.as_deref())
    }

    /// Look up the `transport` URI parameter.
    pub fn transport(&self) -> Option<&str> {
        self.param("transport")
    }

    /// Return the `maddr` URI parameter, if present.
    pub fn maddr(&self) -> Option<&str> {
        self.param("maddr")
    }

    /// Whether the `lr` (loose routing) parameter is present.
    pub fn is_lr(&self) -> bool {
        self.params
            .iter()
            .any(|p| p.name.eq_ignore_ascii_case("lr"))
    }

    /// Serialise back to canonical `sip:` / `sips:` text.
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        s.push_str(self.scheme.as_str());
        s.push(':');
        if let Some(user) = &self.user {
            s.push_str(&escape(user));
            if let Some(pw) = &self.password {
                s.push(':');
                s.push_str(&escape(pw));
            }
            s.push('@');
        }
        s.push_str(&self.host);
        if let Some(p) = self.port {
            s.push(':');
            s.push_str(&p.to_string());
        }
        for p in &self.params {
            s.push(';');
            s.push_str(&p.name);
            if let Some(v) = &p.value {
                s.push('=');
                s.push_str(v);
            }
        }
        if !self.headers.is_empty() {
            s.push('?');
            let mut first = true;
            for p in &self.headers {
                if !first {
                    s.push('&');
                }
                first = false;
                s.push_str(&p.name);
                if let Some(v) = &p.value {
                    s.push('=');
                    s.push_str(v);
                }
            }
        }
        s
    }
}

impl std::fmt::Display for Uri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_text())
    }
}

impl std::str::FromStr for Uri {
    type Err = SipError;
    fn from_str(s: &str) -> Result<Self> {
        Uri::parse(s)
    }
}

/// Public (crate-internal) form of [`split_host_port`], used by the
/// header parsers for `Via`/`Contact` sent-by fields.
pub(crate) fn split_host_port_pub(s: &str) -> Result<(String, Option<u16>)> {
    split_host_port(s)
}

fn split_host_port(s: &str) -> Result<(String, Option<u16>)> {
    // IPv6 in brackets.
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| SipError::InvalidUri(format!("unterminated IPv6 literal: {s}")))?;
        let host = rest[..end].to_string();
        let after = &rest[end + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            Some(parse_port(p)?)
        } else {
            None
        };
        return Ok((host, port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.parse::<u16>().is_ok() && !h.contains(':') => {
            Ok((h.to_string(), Some(parse_port(p)?)))
        }
        _ => Ok((s.to_string(), None)),
    }
}

fn parse_port(s: &str) -> Result<u16> {
    s.parse::<u16>()
        .map_err(|_| SipError::InvalidUri(format!("invalid port: {s}")))
}

/// Split a parameter string on `sep` into `name`/`name=value` pairs.
/// Used for both URI parameters (`;`) and header parameters (`;`).
pub(crate) fn parse_params(s: &str, sep: char) -> Result<Vec<Param>> {
    let mut out = Vec::new();
    for part in s.split(sep) {
        if part.is_empty() {
            continue;
        }
        match part.split_once('=') {
            Some((n, v)) => out.push(Param {
                name: n.to_string(),
                value: Some(unescape(v)?),
            }),
            None => out.push(Param {
                name: part.to_string(),
                value: None,
            }),
        }
    }
    Ok(out)
}

/// Minimal percent-decode of a userinfo component. SIP only permits a
/// restricted set of characters unescaped; we decode `%XX` escapes and
/// leave everything else verbatim.
fn unescape(s: &str) -> Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).map_err(|e| SipError::InvalidUri(e.to_string()))
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' | '~' => out.push(c),
            _ => {
                for b in c.to_string().as_bytes() {
                    out.push('%');
                    out.push_str(&format!("{b:02X}"));
                }
            }
        }
    }
    out
}
