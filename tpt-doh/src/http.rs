// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pluggable HTTP transport.
//!
//! `tpt-doh` core carries no HTTP implementation. Callers supply a transport
//! by implementing [`HttpClient`] (mirroring the bring-your-own-HTTP pattern
//! used by `oauth2`/`openidconnect`). An implementation backed by `reqwest` is
//! provided behind the `reqwest` feature.

/// HTTP methods supported by DoH (RFC 8484 §4.1 / §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

impl Method {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
        }
    }
}

/// A transport-agnostic HTTP request.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

/// A transport-agnostic HTTP response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Look up the first header value (case-insensitive) matching `name`.
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == lower)
            .map(|(_, v)| v.as_str())
    }
}

/// A pluggable HTTP transport.
///
/// Implement this trait to use `tpt-doh` with any HTTP stack. The crate itself
/// only depends on the request/response shapes above. The provided `reqwest`
/// backend (feature `reqwest`) is a drop-in example.
pub trait HttpClient {
    /// Send `req` and return the response, or an error if the transport failed.
    ///
    /// Note this is called for the *transport* layer only; non-2xx HTTP status
    /// codes are delivered as successful responses with that status and are
    /// interpreted by the DoH client.
    fn send(
        &self,
        req: &HttpRequest,
    ) -> std::result::Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>>;
}

impl<T: HttpClient + ?Sized> HttpClient for &T {
    fn send(
        &self,
        req: &HttpRequest,
    ) -> std::result::Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>> {
        (**self).send(req)
    }
}
