// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The DoH client.

use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::SystemTime;

use crate::base64::encode_nopad;
use crate::cache::Cache;
use crate::dns::{Message, RData, CLASS_IN};
use crate::error::{Error, Result};
use crate::http::{HttpClient, HttpRequest, Method};

const DNS_MESSAGE_MEDIA: &str = "application/dns-message";

/// A DNS-over-HTTPS client (RFC 8484).
///
/// The client is generic over the HTTP transport ([`HttpClient`]), so it can be
/// driven by `reqwest`, `hyper`, a test double, or anything else. Create it
/// with [`DohClient::new`], then call [`DohClient::query`] / [`DohClient::query_raw`]
/// or the convenience lookup helpers.
///
/// ```
/// use tpt_doh::{DohClient, HttpClient, HttpRequest, HttpResponse, Method};
///
/// // A trivial in-memory transport for illustration; real use supplies reqwest.
/// struct Dummy;
/// impl HttpClient for Dummy {
///     fn send(&self, _req: &HttpRequest)
///         -> std::result::Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>>
///     {
///         Ok(HttpResponse { status: 200, headers: vec![], body: vec![] })
///     }
/// }
///
/// let client = DohClient::new("https://dns.google/dns-query", Dummy);
/// assert_eq!(client.method(), Method::Post);
/// ```
pub struct DohClient<H: HttpClient> {
    base_url: String,
    http: H,
    method: Method,
    cache: Option<Mutex<Cache>>,
}

impl<H: HttpClient> DohClient<H> {
    /// Create a client targeting `base_url` (e.g. `https://dns.google/dns-query`)
    /// using the default `POST` method.
    pub fn new(base_url: impl Into<String>, http: H) -> Self {
        DohClient {
            base_url: base_url.into(),
            http,
            method: Method::Post,
            cache: None,
        }
    }

    /// Select the request method. RFC 8484 §4.1 (GET) and §4.2 (POST) are both
    /// supported; POST is the default.
    pub fn with_method(mut self, method: Method) -> Self {
        self.method = method;
        self
    }

    /// The configured request method.
    pub fn method(&self) -> Method {
        self.method
    }

    /// Enable an in-memory response cache keyed by request, honoring HTTP
    /// freshness signals (`Cache-Control`/`Expires`). See [`crate::cache`].
    pub fn with_cache(mut self) -> Self {
        self.cache = Some(Mutex::new(Cache::new()));
        self
    }

    /// Send a raw DNS message (wire format) and return the raw response bytes.
    pub fn query_raw(&self, raw: &[u8]) -> Result<Vec<u8>> {
        let (url, body) = match self.method {
            Method::Post => (self.base_url.clone(), Some(raw.to_vec())),
            Method::Get => {
                let sep = if self.base_url.contains('?') {
                    '&'
                } else {
                    '?'
                };
                let url = format!("{}{}dns={}", self.base_url, sep, encode_nopad(raw));
                (url, None)
            }
        };

        let mut headers = vec![("Accept".to_string(), DNS_MESSAGE_MEDIA.to_string())];
        if self.method == Method::Post {
            headers.push(("Content-Type".to_string(), DNS_MESSAGE_MEDIA.to_string()));
        }

        let key = self
            .cache
            .as_ref()
            .map(|_| Cache::key(self.method, &url, body.as_deref()));

        if let (Some(cache), Some(key)) = (self.cache.as_ref(), key.as_ref()) {
            let now = SystemTime::now();
            if let Some(cached) = cache.lock().unwrap().get(key, now) {
                return Ok(cached.to_vec());
            }
        }

        let req = HttpRequest {
            method: self.method,
            url,
            headers,
            body,
        };

        let resp = self.http.send(&req)?;

        if resp.status != 200 {
            return Err(Error::HttpStatus {
                status: resp.status,
            });
        }

        if let (Some(cache), Some(key)) = (self.cache.as_ref(), key.as_ref()) {
            let now = SystemTime::now();
            if let Err(e) = cache.lock().unwrap().store(key, &resp, now) {
                return Err(Error::Cache(e));
            }
        }

        Ok(resp.body)
    }

    /// Send a DNS [`Message`] (interpreted as a query) and parse the response.
    ///
    /// Returns an error if the response's message id does not match the query's
    /// (a basic consistency check).
    pub fn query(&self, msg: &Message) -> Result<Message> {
        let raw = msg.to_bytes();
        let response_raw = self.query_raw(&raw)?;
        let response = Message::from_bytes(&response_raw)
            .map_err(|e| Error::InvalidResponse(e.to_string()))?;
        if response.id != msg.id {
            return Err(Error::InvalidResponse(format!(
                "response id {:#06x} does not match query id {:#06x}",
                response.id, msg.id
            )));
        }
        Ok(response)
    }

    /// Resolve `A` records for `name`, returning the IPv4 addresses found.
    pub fn lookup_a(&self, name: &str) -> Result<Vec<Ipv4Addr>> {
        let msg = Message::a_query(name);
        let resp = self.query(&msg)?;
        Ok(resp
            .answers
            .into_iter()
            .filter_map(|r| match r.rdata {
                RData::A(addr) => Some(addr),
                _ => None,
            })
            .collect())
    }

    /// Resolve `AAAA` records for `name`, returning the IPv6 addresses found.
    pub fn lookup_aaaa(&self, name: &str) -> Result<Vec<std::net::Ipv6Addr>> {
        let msg = Message::aaaa_query(name);
        let resp = self.query(&msg)?;
        Ok(resp
            .answers
            .into_iter()
            .filter_map(|r| match r.rdata {
                RData::Aaaa(addr) => Some(addr),
                _ => None,
            })
            .collect())
    }
}

/// Build a query for an arbitrary record type.
pub fn build_query(name: &str, qtype: u16) -> Message {
    let mut msg = Message::query(name, qtype);
    msg.flags.recursion_desired = true;
    msg.questions[0].qclass = CLASS_IN;
    msg
}
