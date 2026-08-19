// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A framework-agnostic abstraction over the message being signed or
//! verified. The core API operates on [`HttpMessage`]; an in-crate
//! [`Message`] implementation is provided for convenience and testing, and
//! an optional `http` feature adapts `http::Request`/`http::Response`.

/// Whether a message is an HTTP request or response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MessageKind {
    #[default]
    Request,
    Response,
}

impl MessageKind {
    /// `true` if this is a response message.
    pub fn is_response(self) -> bool {
        matches!(self, MessageKind::Response)
    }
    /// `true` if this is a request message.
    pub fn is_request(self) -> bool {
        matches!(self, MessageKind::Request)
    }
}

/// Source of HTTP message components for signature base construction.
///
/// Implementors provide the control data (method, authority, path, query,
/// status, ...) and the header field values needed to derive covered
/// components. The trait is intentionally minimal so any HTTP framework can
/// be adapted without a hard dependency on a particular crate.
pub trait HttpMessage {
    /// Request or response.
    fn kind(&self) -> MessageKind;

    /// The HTTP method (requests only).
    fn method(&self) -> Option<&str> {
        None
    }
    /// The authority (host) of the request target.
    fn authority(&self) -> Option<&str> {
        None
    }
    /// The scheme of the request target (e.g. `https`).
    fn scheme(&self) -> Option<&str> {
        None
    }
    /// The full target URI of the request, if reconstructable.
    fn target_uri(&self) -> Option<&str> {
        None
    }
    /// The request target: path and optional `?query` (no authority/scheme).
    fn request_target(&self) -> Option<&str> {
        None
    }
    /// The absolute path portion of the request target.
    fn path(&self) -> Option<&str> {
        None
    }
    /// The query portion of the request target, including the leading `?`.
    fn query(&self) -> Option<&str> {
        None
    }
    /// The response status code (responses only).
    fn status(&self) -> Option<u16> {
        None
    }

    /// All values (in order) of the named header field. Names are matched
    /// case-insensitively.
    fn header_values(&self, name: &str) -> Vec<String>;

    /// The related request message, used when a response signs request
    /// components via the `req` parameter. Defaults to `None`.
    fn request_context(&self) -> Option<&dyn HttpMessage> {
        None
    }

    /// Combined header field value: individual values joined with `", "` per
    /// RFC 9421 §2.1. Returns `None` if the field is absent.
    fn header(&self, name: &str) -> Option<String> {
        let values = self.header_values(name);
        if values.is_empty() {
            None
        } else {
            Some(values.join(", "))
        }
    }
}

/// A simple in-memory [`HttpMessage`] implementation.
///
/// This is handy for tests, examples, and for callers that do not use a full
/// HTTP framework. It stores method/target/authority/etc. plus an ordered
/// list of header fields.
#[derive(Debug, Clone, Default)]
pub struct Message {
    kind: MessageKind,
    method: Option<String>,
    /// Request target: path and optional `?query` (no authority or scheme).
    target: Option<String>,
    scheme: Option<String>,
    authority: Option<String>,
    /// Explicit full target URI (for the `@target-uri` derived component).
    full_uri: Option<String>,
    status: Option<u16>,
    /// Header fields as `(lowercased-name, value)` pairs, in order.
    headers: Vec<(String, String)>,
    /// Optional related request message (for `req` parameter signing).
    request_ctx: Option<Box<Message>>,
}

impl Message {
    /// Start building a request message.
    pub fn request(method: impl Into<String>, target: impl Into<String>) -> Self {
        Message {
            kind: MessageKind::Request,
            method: Some(method.into()),
            target: Some(target.into()),
            ..Default::default()
        }
    }

    /// Start building a response message with the given status code.
    pub fn response(status: u16) -> Self {
        Message {
            kind: MessageKind::Response,
            status: Some(status),
            ..Default::default()
        }
    }

    /// Set the scheme (e.g. `https`).
    pub fn scheme(mut self, scheme: impl Into<String>) -> Self {
        self.scheme = Some(scheme.into());
        self
    }

    /// Set the authority. If unset, it is taken from the `host` header.
    pub fn authority(mut self, authority: impl Into<String>) -> Self {
        self.authority = Some(authority.into());
        self
    }

    /// Set the full target URI (used for the `@target-uri` derived component).
    pub fn target_uri(mut self, uri: impl Into<String>) -> Self {
        self.full_uri = Some(uri.into());
        self
    }

    /// Add a header field. The name is lowercased on storage. Multiple calls
    /// with the same name append additional values (preserving order).
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into().to_ascii_lowercase(), value.into()));
        self
    }

    /// Attach a related request message (for signing response components with
    /// the `req` parameter).
    pub fn with_request_context(mut self, req: Message) -> Self {
        self.request_ctx = Some(Box::new(req));
        self
    }

    /// Borrow the underlying header list (name, value) for inspection/tests.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }
}

impl HttpMessage for Message {
    fn kind(&self) -> MessageKind {
        self.kind
    }

    fn method(&self) -> Option<&str> {
        self.method.as_deref()
    }

    fn authority(&self) -> Option<&str> {
        if let Some(a) = &self.authority {
            Some(a)
        } else {
            self.headers
                .iter()
                .find(|(n, _)| n == "host")
                .map(|(_, v)| v.as_str())
        }
    }

    fn scheme(&self) -> Option<&str> {
        self.scheme.as_deref()
    }

    fn target_uri(&self) -> Option<&str> {
        self.full_uri.as_deref()
    }

    fn request_target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    fn path(&self) -> Option<&str> {
        self.target
            .as_deref()
            .map(|t| t.split_once('?').map(|(p, _)| p).unwrap_or(t))
    }

    fn query(&self) -> Option<&str> {
        self.target.as_deref().and_then(|t| t.find('?').map(|i| &t[i..]))
    }

    fn status(&self) -> Option<u16> {
        self.status
    }

    fn header_values(&self, name: &str) -> Vec<String> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .filter(|(n, _)| *n == name)
            .map(|(_, v)| v.clone())
            .collect()
    }

    fn request_context(&self) -> Option<&dyn HttpMessage> {
        self.request_ctx.as_deref().map(|m| m as &dyn HttpMessage)
    }
}

#[cfg(feature = "http")]
mod http_impls {
    use super::*;

    impl<B> HttpMessage for http::Request<B> {
        fn kind(&self) -> MessageKind {
            MessageKind::Request
        }
        fn method(&self) -> Option<&str> {
            Some(self.method().as_str())
        }
        fn authority(&self) -> Option<&str> {
            if let Some(a) = self.uri().authority() {
                return Some(a.as_str());
            }
            self.headers()
                .get(http::header::HOST)
                .and_then(|h| h.to_str().ok())
        }
        fn scheme(&self) -> Option<&str> {
            self.uri().scheme().map(|s| s.as_str())
        }
        fn target_uri(&self) -> Option<&str> {
            // The full target URI would need to be freshly allocated and we
            // cannot return a borrowed `&str` to an owned value. Callers
            // wanting `@target-uri` should set it explicitly or use the
            // in-crate `Message` type. The other request-derived components
            // (`@authority`, `@path`, `@query`, `@scheme`) are fully supported.
            let _ = self.uri();
            None
        }
        fn request_target(&self) -> Option<&str> {
            self.uri().path_and_query().map(|p| p.as_str())
        }
        fn path(&self) -> Option<&str> {
            self.uri().path_and_query().map(|p| {
                let s = p.as_str();
                s.split_once('?').map(|(p, _)| p).unwrap_or(s)
            })
        }
        fn query(&self) -> Option<&str> {
            self.uri().path_and_query().and_then(|p| {
                let s = p.as_str();
                s.find('?').map(|i| &s[i..])
            })
        }
        fn header_values(&self, name: &str) -> Vec<String> {
            let name = http::header::HeaderName::from_bytes(name.as_bytes()).ok();
            match name {
                Some(n) => self
                    .headers()
                    .get_all(n)
                    .iter()
                    .filter_map(|v| v.to_str().ok().map(str::to_string))
                    .collect(),
                None => Vec::new(),
            }
        }
    }

    impl<B> HttpMessage for http::Response<B> {
        fn kind(&self) -> MessageKind {
            MessageKind::Response
        }
        fn status(&self) -> Option<u16> {
            Some(self.status().as_u16())
        }
        fn header_values(&self, name: &str) -> Vec<String> {
            let name = http::header::HeaderName::from_bytes(name.as_bytes()).ok();
            match name {
                Some(n) => self
                    .headers()
                    .get_all(n)
                    .iter()
                    .filter_map(|v| v.to_str().ok().map(str::to_string))
                    .collect(),
                None => Vec::new(),
            }
        }
    }
}
