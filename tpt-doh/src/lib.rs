// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # tpt-doh
//!
//! A clean-room, dual-licensed ([`MIT OR Apache-2.0`](../LICENSE-MIT)) client
//! for **DNS-over-HTTPS** ([RFC 8484](https://www.rfc-editor.org/rfc/rfc8484)).
//!
//! The crate is deliberately focused: it implements the DoH wire contract
//! (the standard DNS message format carried over HTTP with the
//! `application/dns-message` media type, in both `GET` and `POST` modes) and
//! leaves the HTTP transport pluggable. Unlike `hickory-dns`, which exposes DoH
//! only as a feature buried inside a large resolver, `tpt-doh` is a small,
//! composable building block you can drop into any HTTP stack.
//!
//! ## Features
//!
//! - `GET` and `POST` request modes (RFC 8484 §4.1 / §4.2).
//! - Pluggable [`HttpClient`] transport; a `reqwest` backend is provided behind
//!   the `reqwest` feature.
//! - Minimal, dependency-free DNS wire codec ([`dns`]) for building queries and
//!   parsing responses (including name compression).
//! - Optional in-memory response cache honoring `Cache-Control`/`Expires`
//!   freshness (see [`cache`]).
//!
//! ## Example
//!
//! ```no_run
//! # #[cfg(feature = "reqwest")]
//! # {
//! use tpt_doh::{DohClient, ReqwestClient};
//!
//! let client = DohClient::new(
//!     "https://dns.google/dns-query",
//!     ReqwestClient::new().unwrap(),
//! );
//! let answers = client.lookup_a("example.com").unwrap();
//! println!("{:?}", answers);
//! # }
//! ```
//!
//! Without the `reqwest` feature you supply your own [`HttpClient`]
//! implementation (e.g. backed by `hyper`, `isahc`, or a test stub).

pub mod base64;
pub mod cache;
pub mod client;
pub mod dns;
pub mod error;
pub mod http;

pub use client::{build_query, DohClient};
pub use dns::{rtype, Flags, Message, Question, RData, Record};
pub use error::{DnsError, Error, Result};
pub use http::{HttpClient, HttpRequest, HttpResponse, Method};

#[cfg(feature = "reqwest")]
pub use reqwest_backend::ReqwestClient;

#[cfg(feature = "reqwest")]
mod reqwest_backend {
    use crate::error::Error;
    use crate::http::{HttpClient, HttpRequest, HttpResponse};

    /// An [`HttpClient`] backed by the synchronous [`reqwest::blocking`] client.
    ///
    /// Requires the `reqwest` feature. A single shared client is used for all
    /// requests.
    pub struct ReqwestClient {
        client: reqwest::blocking::Client,
    }

    impl ReqwestClient {
        /// Create a new backend with default client settings.
        pub fn new() -> std::result::Result<Self, Error> {
            let client = reqwest::blocking::Client::builder()
                .build()
                .map_err(|e| Error::Http(Box::new(e)))?;
            Ok(ReqwestClient { client })
        }

        /// Wrap an existing blocking client.
        pub fn from_client(client: reqwest::blocking::Client) -> Self {
            ReqwestClient { client }
        }
    }

    impl HttpClient for ReqwestClient {
        fn send(
            &self,
            req: &HttpRequest,
        ) -> std::result::Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>> {
            let response = self.client.execute(build_request(&self.client, req)?)?;
            let status = response.status().as_u16();
            let headers = response
                .headers()
                .iter()
                .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            let body = response.bytes()?.to_vec();
            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        }
    }

    fn build_request(
        client: &reqwest::blocking::Client,
        req: &HttpRequest,
    ) -> std::result::Result<reqwest::blocking::Request, Box<dyn std::error::Error + Send + Sync>>
    {
        let method = match req.method {
            crate::http::Method::Get => reqwest::Method::GET,
            crate::http::Method::Post => reqwest::Method::POST,
        };
        let mut builder = client.request(method, &req.url);
        for (k, v) in &req.headers {
            builder = builder.header(k, v);
        }
        if let Some(body) = &req.body {
            builder = builder.body(body.clone());
        }
        builder
            .build()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }
}
