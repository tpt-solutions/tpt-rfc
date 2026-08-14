// SPDX-License-Identifier: MIT OR Apache-2.0
//! Typed representations of the SIP header fields most commonly needed by
//! the transaction and dialog layers, plus parsers that turn raw header
//! values into these structures (RFC 3261 §20).
//!
//! The [`crate::message::Message`] model stores headers as opaque
//! `name: value` pairs; the functions here provide structured views over
//! those raw values and are also used to build them for transmission.

use crate::error::{Result, SipError};
use crate::method::Method;
use crate::uri::{parse_params, Param, Uri};

/// A single `Via` header entry (one `via-parm`).
///
/// Example: `SIP/2.0/UDP pc.example.com:5060;branch=z9hG4bK74bf9`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViaEntry {
    /// Protocol token, e.g. `SIP/2.0/UDP` or `SIP/2.0/TCP`.
    pub protocol: String,
    /// Sent-by host (reg-name, IPv4, or IPv6-in-brackets).
    pub host: String,
    /// Sent-by port, if present.
    pub port: Option<u16>,
    /// Via parameters: `branch`, `received`, `rport`, `maddr`, `ttl`,
    /// `alias`, or arbitrary extensions.
    pub params: Vec<Param>,
}

impl ViaEntry {
    /// The `branch` parameter value, used as the transaction identifier.
    pub fn branch(&self) -> Option<&str> {
        self.params
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case("branch"))
            .and_then(|p| p.value.as_deref())
    }

    /// The `received` parameter, if present (the observed source address).
    pub fn received(&self) -> Option<&str> {
        self.params
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case("received"))
            .and_then(|p| p.value.as_deref())
    }

    /// The `rport` parameter value, if present.
    pub fn rport(&self) -> Option<&str> {
        self.params
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case("rport"))
            .and_then(|p| p.value.as_deref())
    }
}

impl std::fmt::Display for ViaEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.protocol, self.host)?;
        if let Some(p) = self.port {
            write!(f, ":{p}")?;
        }
        for param in &self.params {
            write!(f, ";{}", param.name)?;
            if let Some(v) = &param.value {
                write!(f, "={v}")?;
            }
        }
        Ok(())
    }
}

/// A `name-addr` or `addr-spec` production used by `From`, `To`,
/// `Contact`, `Route`, and `Record-Route`: an optional display name, a
/// URI, and a set of parameters (`tag`, `expires`, `q`, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameAddr {
    /// Display name (quoted or token), if present.
    pub display: Option<String>,
    /// The URI.
    pub uri: Uri,
    /// Parameters following the URI.
    pub params: Vec<Param>,
}

impl NameAddr {
    /// The `tag` parameter value, if present.
    pub fn tag(&self) -> Option<&str> {
        self.params
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case("tag"))
            .and_then(|p| p.value.as_deref())
    }
}

impl std::fmt::Display for NameAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(d) = &self.display {
            if d.contains(' ') {
                write!(f, "\"{d}\" ")?;
            } else {
                write!(f, "{d} ")?;
            }
        }
        write!(f, "<{}>", self.uri)?;
        for p in &self.params {
            write!(f, ";{}", p.name)?;
            if let Some(v) = &p.value {
                write!(f, "={v}")?;
            }
        }
        Ok(())
    }
}

/// A `CSeq` header: a 32-bit sequence number and the associated method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CSeq {
    /// Sequence number.
    pub seq: u32,
    /// Method associated with this CSeq.
    pub method: Method,
}

/// Parse one `Via:` header value into its (possibly multiple) entries.
pub fn parse_via(value: &str) -> Result<Vec<ViaEntry>> {
    let mut out = Vec::new();
    for entry in value.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let mut parts = entry.splitn(2, ' ');
        let protocol = parts
            .next()
            .ok_or_else(|| SipError::InvalidHeader {
                name: "Via".into(),
                reason: "missing protocol token".into(),
            })?
            .to_string();
        let rest = parts.next().unwrap_or("");
        let (sent_by, params) = match rest.split_once(';') {
            Some((sb, p)) => (sb.trim(), parse_params(p, ';')?),
            None => (rest.trim(), Vec::new()),
        };
        let (host, port) =
            crate::uri::split_host_port_pub(sent_by).map_err(|e| SipError::InvalidHeader {
                name: "Via".into(),
                reason: e.to_string(),
            })?;
        out.push(ViaEntry {
            protocol,
            host,
            port,
            params,
        });
    }
    if out.is_empty() {
        return Err(SipError::InvalidHeader {
            name: "Via".into(),
            reason: "no Via entries".into(),
        });
    }
    Ok(out)
}

/// Parse a `From:` / `To:` / `Contact:` / `Route:` / `Record-Route:`
/// header value into a [`NameAddr`].
pub fn parse_name_addr(value: &str) -> Result<NameAddr> {
    let value = value.trim();

    // Quoted display name: "Display" <uri>... or "Display" uri...
    let (display, after_display) = if let Some(rest) = value.strip_prefix('"') {
        let end = rest.find('"').ok_or_else(|| SipError::InvalidHeader {
            name: "name-addr".into(),
            reason: "unterminated quoted display name".into(),
        })?;
        (Some(rest[..end].to_string()), rest[end + 1..].trim_start())
    } else {
        // Unquoted display name extends until '<' (if present) or the URI.
        if let Some(idx) = value.find('<') {
            let disp = value[..idx].trim();
            if disp.is_empty() {
                (None, value[idx..].trim_start())
            } else {
                (Some(disp.to_string()), &value[idx..])
            }
        } else {
            (None, value)
        }
    };

    // Extract the URI (either <...> or a bare URI).
    let (uri_part, params_part) = if let Some(inner) = after_display.strip_prefix('<') {
        let end = inner.find('>').ok_or_else(|| SipError::InvalidHeader {
            name: "name-addr".into(),
            reason: "unterminated angle-bracket URI".into(),
        })?;
        (inner[..end].trim(), &inner[end + 1..])
    } else {
        // Bare URI: up to the first ';' (parameters) or end.
        match after_display.split_once(';') {
            Some((u, p)) => (u.trim(), p),
            None => (after_display.trim(), ""),
        }
    };

    let uri = Uri::parse(uri_part).map_err(|e| SipError::InvalidHeader {
        name: "name-addr".into(),
        reason: e.to_string(),
    })?;

    let params = if params_part.trim().is_empty() {
        Vec::new()
    } else {
        parse_params(params_part, ';')?
    };

    Ok(NameAddr {
        display,
        uri,
        params,
    })
}

/// Parse a `CSeq:` header value (`314159 INVITE`).
pub fn parse_cseq(value: &str) -> Result<CSeq> {
    let mut it = value.split_whitespace();
    let seq = it.next().ok_or_else(|| SipError::InvalidHeader {
        name: "CSeq".into(),
        reason: "missing sequence number".into(),
    })?;
    let seq: u32 = seq.parse().map_err(|_| SipError::InvalidHeader {
        name: "CSeq".into(),
        reason: format!("invalid sequence number `{seq}`"),
    })?;
    let method = it.next().ok_or_else(|| SipError::InvalidHeader {
        name: "CSeq".into(),
        reason: "missing method".into(),
    })?;
    let method = Method::parse(method).map_err(|e| SipError::InvalidHeader {
        name: "CSeq".into(),
        reason: e.to_string(),
    })?;
    Ok(CSeq { seq, method })
}
