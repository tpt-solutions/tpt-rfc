// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # tpt-http-cache
//!
//! A clean-room, dual-licensed implementation of **HTTP caching semantics** —
//! [RFC 9111](https://www.rfc-editor.org/rfc/rfc9111) (and the `stale-while-revalidate`
//! / `stale-if-error` extensions of [RFC 5861](https://www.rfc-editor.org/rfc/rfc5861)).
//!
//! It answers the question "*Can I reuse this stored response to satisfy this
//! new request?*" taking into account `Cache-Control`, `Expires`, `Age`,
//! `ETag`, `Last-Modified`, and `Vary`, including the subtle cases (shared vs
//! private caches, heuristic freshness, revalidation).
//!
//! The public API is modelled on the proven interface shape of
//! `http-cache-semantics`, reimplemented clean-room from the RFC behaviour
//! (no source code copied).
//!
//! ```
//! use std::time::Duration;
//! use tpt_http_cache::{CachePolicy, Options, RequestInfo, ResponseInfo};
//! use http::{HeaderMap, Method, StatusCode};
//!
//! let mut req_h = HeaderMap::new();
//! let mut res_h = HeaderMap::new();
//! res_h.insert("cache-control", "public, max-age=3600".parse().unwrap());
//!
//! let policy = CachePolicy::new(
//!     RequestInfo::from_headers(Method::GET, req_h),
//!     ResponseInfo::from_status(StatusCode::OK, res_h),
//! );
//! assert!(policy.is_storable());
//! assert!(!policy.stale());
//! ```
//!
//! ## Working with `http` types
//!
//! The crate is framework-agnostic but integrates naturally with the
//! dual-licensed [`http`](https://crates.io/crates/http) crate: construct a
//! [`RequestInfo`] / [`ResponseInfo`] from an `http::Request` /
//! `http::Response` via the provided `From` conversions, or build them
//! directly from a [`HeaderMap`].

mod headers;
mod policy;
mod time;

pub use policy::{CacheDecision, CachePolicy, Revalidation, RevalidationResult, SerializedPolicy};

use http::{HeaderMap, Method, StatusCode};

/// Configuration for a [`CachePolicy`].
///
/// All fields have sensible RFC-compliant defaults (see [`Options::default`]);
/// override only what you need.
#[derive(Debug, Clone)]
pub struct Options {
    /// Evaluate the response from the perspective of a *shared* cache (a
    /// public proxy). When `true` (the default), `private` responses are not
    /// cacheable and `s-maxage` is honoured. When `false` (a single-user
    /// cache), `private` is cacheable and `s-maxage` is ignored.
    pub shared: bool,

    /// Heuristic freshness as a fraction of the response's age (the interval
    /// between `Date` and `Last-Modified`). Default `0.1` (10%), matching the
    /// recommendation in RFC 9111 §4.2.2.
    pub cache_heuristic: f64,

    /// Minimum freshness lifetime to assume for `Cache-Control: immutable`
    /// responses (and the floor applied to heuristic lifetimes). Default 24h.
    pub immutable_min_ttl: std::time::Duration,

    /// If `true`, the legacy `pre-check`/`post-check` anti-cache cargo-cult
    /// directives cause the other copy-pasted anti-cache directives
    /// (`no-cache`, `no-store`, `must-revalidate`) to be ignored. Default
    /// `false`.
    pub ignore_cargo_cult: bool,

    /// Fixed "now" used by the policy clock. When `None` (the default), the
    /// policy reads the real wall clock, so age advances over time. When set,
    /// the clock is frozen — used for deterministic tests.
    pub now: Option<std::time::SystemTime>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            shared: true,
            cache_heuristic: 0.1,
            immutable_min_ttl: std::time::Duration::from_secs(24 * 3600),
            ignore_cargo_cult: false,
            now: None,
        }
    }
}

/// Information about the request that produced (or is being matched against) a
/// cached response.
#[derive(Debug, Clone)]
pub struct RequestInfo {
    /// HTTP method (defaults to `GET`).
    pub method: Method,
    /// Effective request URI (used for cache-key matching; `None` matches any).
    pub url: Option<String>,
    /// Full request headers.
    pub headers: HeaderMap,
}

impl RequestInfo {
    /// Build from a method and a `HeaderMap`, with no URL (matches any URL).
    pub fn from_headers(method: Method, headers: HeaderMap) -> Self {
        RequestInfo {
            method,
            url: None,
            headers,
        }
    }

    /// Build a `GET` request from a `HeaderMap`.
    pub fn get(headers: HeaderMap) -> Self {
        Self::from_headers(Method::GET, headers)
    }
}

impl From<HeaderMap> for RequestInfo {
    fn from(headers: HeaderMap) -> Self {
        Self::get(headers)
    }
}

impl<B> From<&http::Request<B>> for RequestInfo {
    fn from(req: &http::Request<B>) -> Self {
        RequestInfo {
            method: req.method().clone(),
            url: req.uri().to_string().into(),
            headers: req.headers().clone(),
        }
    }
}

/// Information about the response being stored.
#[derive(Debug, Clone)]
pub struct ResponseInfo {
    /// HTTP status code (defaults to `200`).
    pub status: StatusCode,
    /// Full response headers.
    pub headers: HeaderMap,
}

impl ResponseInfo {
    /// Build from a status code and a `HeaderMap`.
    pub fn from_status(status: StatusCode, headers: HeaderMap) -> Self {
        ResponseInfo { status, headers }
    }
}

impl<B> From<&http::Response<B>> for ResponseInfo {
    fn from(res: &http::Response<B>) -> Self {
        ResponseInfo {
            status: res.status(),
            headers: res.headers().clone(),
        }
    }
}
