// SPDX-License-Identifier: MIT OR Apache-2.0
//! Constructors for SIP requests and responses, including the core
//! methods REGISTER, INVITE, ACK, BYE, CANCEL, and OPTIONS (RFC 3261
//! §10).

use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::Result;
use crate::headers::NameAddr;
use crate::message::{Header, Message, RequestLine, StatusLine};
use crate::method::Method;
use crate::uri::Param;
use crate::uri::Uri;

static BRANCH_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate an RFC 3261 compliant branch parameter value, prefixed with
/// the magic cookie `z9hG4bK` and followed by an entropy-derived suffix.
pub fn generate_branch() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = BRANCH_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mix = n ^ nanos ^ (nans_mix(nanos));
    format!("z9hG4bK{mix:x}")
}

fn nans_mix(v: u64) -> u64 {
    v.wrapping_mul(0x9E3779B97F4A7C15)
}

/// Generate a short opaque tag string for `To`/`From` headers.
pub fn generate_tag() -> String {
    let n = BRANCH_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{n:x}{:x}", n.wrapping_mul(2654435761))
}

/// Builder for outbound SIP requests.
pub struct RequestBuilder {
    method: Method,
    uri: Uri,
    from: NameAddr,
    to: NameAddr,
    call_id: String,
    cseq: u32,
    cseq_method: Method,
    via_protocol: String,
    via_host: String,
    via_port: u16,
    via_branch: String,
    contact: Option<NameAddr>,
    max_forwards: Option<u32>,
    extra: Vec<Header>,
    body: Vec<u8>,
}

impl RequestBuilder {
    /// Start building a request with the given method, request URI, and
    /// local identity (`From`). The `To` is initialised to the same URI
    /// (override with [`RequestBuilder::to`]).
    pub fn new(method: Method, uri: Uri, from: NameAddr) -> RequestBuilder {
        let to = NameAddr {
            display: from.display.clone(),
            uri: uri.clone(),
            params: Vec::new(),
        };
        RequestBuilder {
            method: method.clone(),
            uri,
            from,
            to,
            call_id: generate_branch(), // call-id uses a different shape; see build()
            cseq: 1,
            cseq_method: method,
            via_protocol: "SIP/2.0/UDP".into(),
            via_host: "localhost".into(),
            via_port: 5060,
            via_branch: generate_branch(),
            contact: None,
            max_forwards: Some(70),
            extra: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Set the `To` header (its URI and display name).
    pub fn to(mut self, to: NameAddr) -> Self {
        self.to = to;
        self
    }

    /// Set the `Call-ID`.
    pub fn call_id(mut self, id: impl Into<String>) -> Self {
        self.call_id = id.into();
        self
    }

    /// Set the `CSeq` number and (optionally) the CSeq method. For `ACK`
    /// and `CANCEL` the CSeq method must match the original request
    /// (typically `INVITE`).
    pub fn cseq(mut self, seq: u32, method: Option<Method>) -> Self {
        self.cseq = seq;
        if let Some(m) = method {
            self.cseq_method = m;
        }
        self
    }

    /// Set the local `Via` sent-by host/port and transport.
    pub fn via(mut self, protocol: impl Into<String>, host: impl Into<String>, port: u16) -> Self {
        self.via_protocol = protocol.into();
        self.via_host = host.into();
        self.via_port = port;
        self
    }

    /// Override the `Via` branch parameter.
    pub fn via_branch(mut self, branch: impl Into<String>) -> Self {
        self.via_branch = branch.into();
        self
    }

    /// Set the `Contact` header.
    pub fn contact(mut self, contact: NameAddr) -> Self {
        self.contact = Some(contact);
        self
    }

    /// Set `Max-Forwards` (defaults to 70).
    pub fn max_forwards(mut self, n: u32) -> Self {
        self.max_forwards = Some(n);
        self
    }

    /// Add an arbitrary header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.push(Header::new(name, value));
        self
    }

    /// Set the message body.
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Build the [`Message`].
    pub fn build(self) -> Message {
        let mut via = self.via_protocol.clone();
        via.push(' ');
        via.push_str(&self.via_host);
        via.push(':');
        via.push_str(&self.via_port.to_string());
        via.push_str(";branch=");
        via.push_str(&self.via_branch);

        let mut headers = vec![
            Header::new("Via", via),
            Header::new("Max-Forwards", self.max_forwards.unwrap_or(70).to_string()),
            Header::new("From", self.from.to_string()),
            Header::new("To", self.to.to_string()),
            Header::new("Call-ID", self.call_id),
            Header::new("CSeq", format!("{} {}", self.cseq, self.cseq_method)),
        ];
        if let Some(c) = self.contact {
            headers.push(Header::new("Contact", c.to_string()));
        }
        for h in self.extra {
            headers.push(h);
        }
        Message::request(RequestLine::new(self.method, self.uri), headers, self.body)
    }
}

/// Builder for SIP responses derived from a received request.
pub struct ResponseBuilder {
    code: u16,
    reason: String,
    request: Message,
    to_tag: Option<String>,
    contact: Option<NameAddr>,
    extra: Vec<Header>,
    body: Vec<u8>,
}

impl ResponseBuilder {
    /// Begin a response with `code` to a received `request`, copying the
    /// request's `Via`/`From`/`Call-ID`/`CSeq` headers verbatim.
    pub fn from_request(request: &Message, code: u16, reason: &str) -> ResponseBuilder {
        ResponseBuilder {
            code,
            reason: reason.to_string(),
            request: request.clone(),
            to_tag: None,
            contact: None,
            extra: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Add a `tag` parameter to the `To` header (recommended for
    /// dialog-forming responses).
    pub fn to_tag(mut self, tag: impl Into<String>) -> Self {
        self.to_tag = Some(tag.into());
        self
    }

    /// Set the `Contact` header.
    pub fn contact(mut self, contact: NameAddr) -> Self {
        self.contact = Some(contact);
        self
    }

    /// Add an arbitrary header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.push(Header::new(name, value));
        self
    }

    /// Set the message body.
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Build the [`Message`].
    pub fn build(self) -> Message {
        let mut headers: Vec<Header> = Vec::new();
        // Copy all Via headers in order.
        for h in self.request.headers_for("Via") {
            headers.push(Header::new("Via", h.value.clone()));
        }
        headers.push(Header::new(
            "From",
            self.request.header_value("From").unwrap_or("").to_string(),
        ));

        // To: copy request To, append tag if requested/needed.
        let mut to_value = self.request.header_value("To").unwrap_or("").to_string();
        if !self
            .to_tag
            .as_ref()
            .map(|t| to_value.contains(&format!("tag={t}")))
            .unwrap_or(false)
        {
            if let Some(t) = &self.to_tag {
                to_value.push_str(&format!(";tag={t}"));
            }
        }
        headers.push(Header::new("To", to_value));

        headers.push(Header::new(
            "Call-ID",
            self.request.call_id().unwrap_or("").to_string(),
        ));
        headers.push(Header::new(
            "CSeq",
            self.request.header_value("CSeq").unwrap_or("").to_string(),
        ));
        if let Some(c) = self.contact {
            headers.push(Header::new("Contact", c.to_string()));
        }
        for h in self.extra {
            headers.push(h);
        }
        Message::response(
            StatusLine::new(self.code, self.reason.clone()),
            headers,
            self.body,
        )
    }
}

/// Build a `REGISTER` request.
pub fn register(uri: Uri, from: NameAddr, contact: NameAddr) -> RequestBuilder {
    RequestBuilder::new(Method::Register, uri, from).contact(contact)
}

/// Build an `INVITE` request.
pub fn invite(uri: Uri, from: NameAddr, contact: NameAddr) -> RequestBuilder {
    RequestBuilder::new(Method::Invite, uri, from).contact(contact)
}

/// Build an `OPTIONS` request.
pub fn options(uri: Uri, from: NameAddr) -> RequestBuilder {
    RequestBuilder::new(Method::Options, uri, from)
}

/// Build a `BYE` request to terminate a dialog.
pub fn bye(uri: Uri, from: NameAddr) -> RequestBuilder {
    RequestBuilder::new(Method::Bye, uri, from)
}

/// Build an `ACK` for a successful (`2xx`) `INVITE` response.
///
/// The `CSeq` method of an ACK for an INVITE is `INVITE`, so the caller
/// must supply the original CSeq number.
pub fn ack(
    uri: Uri,
    from: NameAddr,
    to: NameAddr,
    call_id: &str,
    cseq: u32,
    via_branch: &str,
) -> Result<Message> {
    let b = RequestBuilder::new(Method::Ack, uri, from)
        .to(to)
        .call_id(call_id)
        .cseq(cseq, Some(Method::Ack))
        .via_branch(via_branch);
    Ok(b.build())
}

/// Build a `CANCEL` for a pending `INVITE`-class request.
pub fn cancel(original: &Message, via_branch: &str) -> Result<Message> {
    let from = original
        .from()
        .ok_or_else(|| crate::error::SipError::Transaction("CANCEL: missing From".into()))?;
    let to = original
        .to()
        .ok_or_else(|| crate::error::SipError::Transaction("CANCEL: missing To".into()))?;
    let uri = original
        .request_line()
        .map(|r| r.uri.clone())
        .ok_or_else(|| crate::error::SipError::Transaction("CANCEL: not a request".into()))?;
    let call_id = original.call_id().unwrap_or("").to_string();
    let cseq = original.cseq().map(|c| c.seq).unwrap_or(1);
    let b = RequestBuilder::new(Method::Cancel, uri, from)
        .to(to)
        .call_id(call_id)
        .cseq(cseq, Some(Method::Cancel))
        .via_branch(via_branch);
    Ok(b.build())
}

/// Helper to construct a [`NameAddr`] from a URI with no display name and
/// no parameters.
pub fn named(uri: Uri) -> NameAddr {
    NameAddr {
        display: None,
        uri,
        params: Vec::new(),
    }
}

/// Helper to add a `tag` parameter to a [`NameAddr`]'s params.
pub fn with_tag(na: &mut NameAddr, tag: impl Into<String>) {
    na.params.push(Param::with_value("tag", tag));
}
