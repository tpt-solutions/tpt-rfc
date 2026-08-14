// SPDX-License-Identifier: MIT OR Apache-2.0
//! SIP message model: start line, header fields, and the body, with
//! parse and serialise support (RFC 3261 §7).

use crate::error::{Result, SipError};
use crate::headers::{parse_cseq, parse_name_addr, parse_via, CSeq, NameAddr, ViaEntry};
use crate::method::Method;
use crate::uri::Uri;

/// The start line of a SIP message: either a request line or a status
/// line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartLine {
    /// A request line (`METHOD Request-URI SIP/2.0`).
    Request(RequestLine),
    /// A status line (`SIP/2.0 CODE REASON`).
    Status(StatusLine),
}

/// A SIP request line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestLine {
    /// The method being invoked.
    pub method: Method,
    /// The request URI (the resource the request targets).
    pub uri: Uri,
    /// SIP version, always `(2, 0)` for RFC 3261.
    pub version: (u8, u8),
}

impl RequestLine {
    /// Construct a request line.
    pub fn new(method: Method, uri: Uri) -> RequestLine {
        RequestLine {
            method,
            uri,
            version: (2, 0),
        }
    }
}

/// A SIP status line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusLine {
    /// SIP version, always `(2, 0)` for RFC 3261.
    pub version: (u8, u8),
    /// The 3-digit status code.
    pub code: u16,
    /// The reason phrase (informational text).
    pub reason: String,
}

impl StatusLine {
    /// Construct a status line and use the canonical reason phrase for
    /// well-known codes when `reason` is empty.
    pub fn new(code: u16, reason: impl Into<String>) -> StatusLine {
        let reason = reason.into();
        let reason = if reason.is_empty() {
            reason_phrase(code).to_string()
        } else {
            reason
        };
        StatusLine {
            version: (2, 0),
            code,
            reason,
        }
    }
}

/// A single SIP header field (`name: value`), stored with its original
/// casing but matched case-insensitively (RFC 3261 §7.3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The header-field name (e.g. `Via`, `From`).
    pub name: String,
    /// The (unfolded) header value.
    pub value: String,
}

impl Header {
    /// Construct a header.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Header {
        Header {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// A complete SIP message: start line, headers, and optional body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Start line (request or status).
    pub start: StartLine,
    /// Header fields, in transmission order.
    pub headers: Vec<Header>,
    /// Message body bytes (already decoded; Content-Length is derived).
    pub body: Vec<u8>,
}

impl Message {
    /// Build a request message from a request line and headers.
    pub fn request(line: RequestLine, headers: Vec<Header>, body: Vec<u8>) -> Message {
        Message {
            start: StartLine::Request(line),
            headers,
            body,
        }
    }

    /// Build a response message from a status line and headers.
    pub fn response(line: StatusLine, headers: Vec<Header>, body: Vec<u8>) -> Message {
        Message {
            start: StartLine::Status(line),
            headers,
            body,
        }
    }

    /// Whether this is a request.
    pub fn is_request(&self) -> bool {
        matches!(self.start, StartLine::Request(_))
    }

    /// Whether this is a response.
    pub fn is_response(&self) -> bool {
        matches!(self.start, StartLine::Status(_))
    }

    /// If a request, return the request line.
    pub fn request_line(&self) -> Option<&RequestLine> {
        match &self.start {
            StartLine::Request(r) => Some(r),
            _ => None,
        }
    }

    /// If a response, return the status line.
    pub fn status_line(&self) -> Option<&StatusLine> {
        match &self.start {
            StartLine::Status(s) => Some(s),
            _ => None,
        }
    }

    /// The method for a request, or the CSeq method for a response.
    pub fn method(&self) -> Option<Method> {
        match &self.start {
            StartLine::Request(r) => Some(r.method.clone()),
            StartLine::Status(_) => self.cseq().map(|c| c.method),
        }
    }

    /// The `Call-ID` value, if present.
    pub fn call_id(&self) -> Option<&str> {
        self.header_value("Call-ID")
            .or_else(|| self.header_value("CallId"))
    }

    /// All `Via` entries (across all `Via:` headers), in order.
    pub fn via(&self) -> Vec<ViaEntry> {
        let mut out = Vec::new();
        for h in self.headers_for("Via") {
            if let Ok(mut v) = parse_via(&h.value) {
                out.append(&mut v);
            }
        }
        out
    }

    /// The topmost (first) `Via` entry.
    pub fn top_via(&self) -> Option<ViaEntry> {
        self.via().into_iter().next()
    }

    /// The `From:` header as a [`NameAddr`].
    pub fn from(&self) -> Option<NameAddr> {
        self.header_value("From")
            .and_then(|v| parse_name_addr(v).ok())
    }

    /// The `To:` header as a [`NameAddr`].
    pub fn to(&self) -> Option<NameAddr> {
        self.header_value("To")
            .and_then(|v| parse_name_addr(v).ok())
    }

    /// The `Contact:` header(s) as [`NameAddr`].
    pub fn contact(&self) -> Vec<NameAddr> {
        self.headers_for("Contact")
            .filter_map(|h| parse_name_addr(&h.value).ok())
            .collect()
    }

    /// The `CSeq:` header as a [`CSeq`].
    pub fn cseq(&self) -> Option<CSeq> {
        self.header_value("CSeq").and_then(|v| parse_cseq(v).ok())
    }

    /// The `Max-Forwards` value, if present and well-formed.
    pub fn max_forwards(&self) -> Option<u32> {
        self.header_value("Max-Forwards")
            .and_then(|v| v.trim().parse::<u32>().ok())
    }

    /// The `Content-Length` value, if present and well-formed.
    pub fn content_length(&self) -> Option<usize> {
        self.header_value("Content-Length")
            .and_then(|v| v.trim().parse::<usize>().ok())
    }

    /// The first header with `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&Header> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
    }

    /// The value of the first header with `name` (case-insensitive).
    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.header(name).map(|h| h.value.as_str())
    }

    /// All headers with `name` (case-insensitive).
    pub fn headers_for(&self, name: &str) -> impl Iterator<Item = &Header> + '_ {
        let name = name.to_string();
        self.headers
            .iter()
            .filter(move |h| h.name.eq_ignore_ascii_case(&name))
    }

    /// Append a header to the message.
    pub fn add_header(&mut self, header: Header) -> &mut Self {
        self.headers.push(header);
        self
    }

    /// Set (replace any existing) all headers with `name` by appending a
    /// single header. Existing headers with the same name are dropped.
    pub fn set_header(&mut self, header: Header) -> &mut Self {
        self.headers
            .retain(|h| !h.name.eq_ignore_ascii_case(&header.name));
        self.headers.push(header);
        self
    }

    /// Remove all headers with the given name.
    pub fn remove_header(&mut self, name: &str) -> &mut Self {
        self.headers.retain(|h| !h.name.eq_ignore_ascii_case(name));
        self
    }

    /// Serialise the message to bytes, computing `Content-Length` when the
    /// body is non-empty and the header is absent.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // Start line.
        match &self.start {
            StartLine::Request(r) => {
                out.extend_from_slice(r.method.to_string().as_bytes());
                out.push(b' ');
                out.extend_from_slice(r.uri.to_string().as_bytes());
                out.push(b' ');
                out.extend_from_slice(format!("SIP/{}.{}", r.version.0, r.version.1).as_bytes());
            }
            StartLine::Status(s) => {
                out.extend_from_slice(format!("SIP/{}.{}", s.version.0, s.version.1).as_bytes());
                out.push(b' ');
                out.extend_from_slice(s.code.to_string().as_bytes());
                out.push(b' ');
                out.extend_from_slice(s.reason.as_bytes());
            }
        }
        out.extend_from_slice(b"\r\n");

        // Headers.
        let mut need_cl = true;
        for h in &self.headers {
            if h.name.eq_ignore_ascii_case("Content-Length") {
                need_cl = false;
            }
            out.extend_from_slice(h.name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(h.value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        if need_cl && !self.body.is_empty() {
            out.extend_from_slice(b"Content-Length: ");
            out.extend_from_slice(self.body.len().to_string().as_bytes());
            out.extend_from_slice(b"\r\n");
        }

        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }

    /// Parse a complete SIP message from bytes (RFC 3261 §7.5 framing:
    /// headers end at the empty line; the body is bounded by
    /// `Content-Length` when present).
    pub fn parse(buf: &[u8]) -> Result<Message> {
        let text = std::str::from_utf8(buf)
            .map_err(|e| SipError::InvalidMessage(format!("message is not valid UTF-8: {e}")))?;

        let split = text.find("\r\n\r\n").ok_or_else(|| {
            SipError::InvalidMessage("missing empty line separating headers and body".into())
        })?;
        let header_section = &text[..split];
        let mut body = text[split + 4..].to_string();

        // Unfold continuation lines (CRLF + LWS) before splitting.
        let header_section = header_section.replace("\r\n\t", " ").replace("\r\n ", " ");

        let mut lines = header_section.split("\r\n").peekable();
        let start_line = lines
            .next()
            .ok_or_else(|| SipError::InvalidMessage("empty message (no start line)".into()))?;

        let start = parse_start_line(start_line)?;

        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let (name, value) = line.split_once(':').ok_or_else(|| {
                SipError::InvalidMessage(format!("malformed header (no colon): {line}"))
            })?;
            headers.push(Header::new(name.trim(), value.trim().to_string()));
        }

        // Determine body length from Content-Length.
        let declared = headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("Content-Length"))
            .and_then(|h| h.value.trim().parse::<usize>().ok());

        let body_bytes = match declared {
            Some(n) => {
                let chars: Vec<char> = body.chars().collect();
                if chars.len() < n {
                    return Err(SipError::InvalidMessage(format!(
                        "Content-Length {n} exceeds available body {}",
                        chars.len()
                    )));
                }
                chars[..n].iter().collect::<String>()
            }
            None => body.clone(),
        };
        body = body_bytes;

        Ok(Message {
            start,
            headers,
            body: body.into_bytes(),
        })
    }
}

fn parse_start_line(line: &str) -> Result<StartLine> {
    let line = line.trim_end();
    if let Some(rest) = line.strip_prefix("SIP/") {
        // Status line: SIP/2.0 CODE REASON
        let mut it = rest.splitn(3, ' ');
        let _ver = it.next();
        let code = it
            .next()
            .ok_or_else(|| SipError::InvalidMessage("status line missing code".into()))?;
        let code: u16 = code
            .parse()
            .map_err(|_| SipError::InvalidMessage(format!("invalid status code `{code}`")))?;
        let reason = it.next().unwrap_or("").to_string();
        Ok(StartLine::Status(StatusLine::new(code, reason)))
    } else {
        // Request line: METHOD URI SIP/2.0
        let mut it = line.splitn(3, ' ');
        let method = it
            .next()
            .ok_or_else(|| SipError::InvalidMessage("request line missing method".into()))?;
        let uri = it
            .next()
            .ok_or_else(|| SipError::InvalidMessage("request line missing URI".into()))?;
        let uri = Uri::parse(uri).map_err(|e| SipError::InvalidMessage(e.to_string()))?;
        Ok(StartLine::Request(RequestLine::new(
            Method::parse(method).map_err(|e| SipError::InvalidMessage(e.to_string()))?,
            uri,
        )))
    }
}

/// Canonical reason phrases for the SIP response classes (RFC 3261
/// §21.3). Used when a status line carries an empty reason.
pub fn reason_phrase(code: u16) -> &'static str {
    match code {
        100 => "Trying",
        180 => "Ringing",
        181 => "Call Is Being Forwarded",
        182 => "Queued",
        183 => "Session Progress",
        200 => "OK",
        202 => "Accepted",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Moved Temporarily",
        305 => "Use Proxy",
        380 => "Alternative Service",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        410 => "Gone",
        413 => "Request Entity Too Large",
        414 => "Request-URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Unsupported URI Scheme",
        417 => "Unknown Resource-Priority",
        420 => "Bad Extension",
        421 => "Extension Required",
        422 => "Session Interval Too Small",
        423 => "Interval Too Brief",
        480 => "Temporarily Unavailable",
        481 => "Call/Transaction Does Not Exist",
        482 => "Loop Detected",
        483 => "Too Many Hops",
        484 => "Address Incomplete",
        485 => "Ambiguous",
        486 => "Busy Here",
        487 => "Request Terminated",
        488 => "Not Acceptable Here",
        489 => "Bad Event",
        491 => "Request Pending",
        493 => "Undecipherable",
        500 => "Server Internal Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Server Time-out",
        505 => "Version Not Supported",
        513 => "Message Too Large",
        600 => "Busy Everywhere",
        603 => "Decline",
        604 => "Does Not Exist Anywhere",
        606 => "Not Acceptable",
        _ => "Unknown",
    }
}
