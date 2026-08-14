// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The core [`CachePolicy`] type and its decision outputs.

use std::time::{Duration, SystemTime};

use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};

use crate::headers::{cc_delta, cc_has, combined, first, parse_cache_control, CacheControl};
use crate::time::{format_http_date, parse_http_date};
use crate::{Options, RequestInfo, ResponseInfo};

/// Set of status codes a cache is required to *understand* (responses with
/// other codes are never stored). RFC 9111 §3 / RFC 7231 considerations.
const UNDERSTOOD_STATUSES: &[u16] = &[
    200, 203, 204, 300, 301, 302, 303, 307, 308, 404, 405, 410, 414, 501,
];

/// Status codes cacheable by default even without explicit freshness info.
const CACHEABLE_BY_DEFAULT: &[u16] = &[200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501];

/// Status codes treated as server errors (for `stale-if-error`).
const ERROR_STATUSES: &[u16] = &[500, 502, 503, 504];

/// Hop-by-hop headers removed from stored/revalidation headers (RFC 9110 §7.6.1).
const HOP_BY_HOP: &[&str] = &[
    "date",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Response headers never updated from a 304 (the cached body is reused).
const EXCLUDED_FROM_REVALIDATION_UPDATE: &[&str] = &[
    "content-length",
    "content-encoding",
    "transfer-encoding",
    "content-range",
];

/// The clock source used when computing the current time.
#[derive(Debug, Clone, Copy)]
enum Clock {
    /// Read the real wall clock; age advances over time.
    Real,
    /// A frozen instant — used for deterministic tests.
    Fixed(SystemTime),
}

impl Clock {
    fn now(&self) -> SystemTime {
        match self {
            Clock::Real => SystemTime::now(),
            Clock::Fixed(t) => *t,
        }
    }
}

/// Errors produced while operating on a [`CachePolicy`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The response passed to [`CachePolicy::revalidated_policy`] had no
    /// headers.
    #[error("response headers missing for revalidation")]
    MissingResponseHeaders,
}

/// A decision about how a stored response may be used to satisfy a request.
///
/// Mirrors the object returned by `evaluateRequest` in the reference library:
/// if `response` is `Some`, the cached (and possibly updated) response may be
/// served; if `revalidation` is `Some`, a conditional request must be sent to
/// the origin first. Both can be `Some` in the `stale-while-revalidate` case
/// (serve stale now, revalidate asynchronously).
#[derive(Debug, Clone)]
pub struct CacheDecision {
    /// If `Some`, these are the (updated) cached response headers to serve.
    pub response: Option<HeaderMap>,
    /// If `Some`, these are the request headers to send for revalidation.
    pub revalidation: Option<Revalidation>,
}

/// A revalidation request to send to the origin server.
#[derive(Debug, Clone)]
pub struct Revalidation {
    /// Conditional request headers (`If-None-Match`, `If-Modified-Since`, ...).
    pub headers: HeaderMap,
    /// If `true`, the caller MUST wait for the origin before responding. If
    /// `false`, this is a `stale-while-revalidate` case and the stale cached
    /// response may be served while revalidation happens in the background.
    pub synchronous: bool,
}

/// The result of [`CachePolicy::revalidated_policy`].
#[derive(Debug, Clone)]
pub struct RevalidationResult {
    /// The (possibly updated) cache policy for the stored entry.
    pub policy: CachePolicy,
    /// Whether the cached response body must be replaced (the origin returned a
    /// full response, not a 304).
    pub modified: bool,
    /// Whether the revalidation response matched the stored entry.
    pub matches: bool,
}

/// A serialized snapshot of a [`CachePolicy`], suitable for persisting a cache
/// entry (e.g. to disk or a cache store) and reconstructing it later via
/// [`CachePolicy::from_object`].
#[derive(Debug, Clone)]
pub struct SerializedPolicy {
    /// Seconds since the Unix epoch when the response was received.
    pub response_time_secs: i64,
    /// Whether the policy uses shared-cache semantics.
    pub shared: bool,
    /// Heuristic freshness fraction.
    pub cache_heuristic: f64,
    /// Minimum TTL for immutable responses, in seconds.
    pub immutable_min_ttl_secs: u64,
    /// Whether cargo-cult directives are ignored.
    pub ignore_cargo_cult: bool,
    /// Response status code.
    pub status: u16,
    /// Response headers as `(name, value)` pairs.
    pub response_headers: Vec<(String, String)>,
    /// Parsed response `Cache-Control` directives.
    pub response_cache_control: Vec<(String, Option<String>)>,
    /// Request method.
    pub method: String,
    /// Request URL (if any).
    pub url: Option<String>,
    /// Request `Host` header (if any).
    pub host: Option<String>,
    /// Whether the original request lacked `Authorization`.
    pub no_authorization: bool,
    /// Original request headers (only present when `Vary` was set).
    pub request_headers: Option<Vec<(String, String)>>,
    /// Parsed request `Cache-Control` directives.
    pub request_cache_control: Vec<(String, Option<String>)>,
}

/// An immutable snapshot of request/response metadata used to make HTTP cache
/// decisions per RFC 9111.
///
/// Construct with [`CachePolicy::new`] (or [`CachePolicy::new_with_options`]).
/// The policy captures the state of the world at construction time; subsequent
/// checks (e.g. [`CachePolicy::stale`]) read the clock to determine current
/// freshness.
#[derive(Debug, Clone)]
pub struct CachePolicy {
    response_time: SystemTime,
    clock: Clock,
    is_shared: bool,
    cache_heuristic: f64,
    immutable_min_ttl: Duration,
    ignore_cargo_cult: bool,

    status: StatusCode,
    response_headers: HeaderMap,
    response_cc: CacheControl,

    method: Method,
    url: Option<String>,
    host: Option<String>,
    no_authorization: bool,
    /// Original request headers, retained only when a `Vary` header exists
    /// (needed to match subsequent requests).
    request_headers: Option<HeaderMap>,
    request_cc: CacheControl,
}

impl CachePolicy {
    /// Create a policy with default [`Options`].
    pub fn new(request: RequestInfo, response: ResponseInfo) -> Self {
        Self::new_with_options(request, response, Options::default())
    }

    /// Create a policy with explicit [`Options`].
    pub fn new_with_options(
        request: RequestInfo,
        response: ResponseInfo,
        options: Options,
    ) -> Self {
        let clock = match options.now {
            Some(t) => Clock::Fixed(t),
            None => Clock::Real,
        };
        let response_time = clock.now();

        let response_cc =
            parse_cache_control(&combined(&response.headers, "cache-control").unwrap_or_default());
        let request_cc =
            parse_cache_control(&combined(&request.headers, "cache-control").unwrap_or_default());

        // Cargo-cult handling: if `pre-check`/`post-check` are present and
        // ignore_cargo_cult is set, drop the copy-pasted anti-cache directives.
        let (response_cc, response_headers) = if options.ignore_cargo_cult
            && (response_cc.contains_key("pre-check") && response_cc.contains_key("post-check"))
        {
            let mut cc = response_cc.clone();
            cc.remove("pre-check");
            cc.remove("post-check");
            cc.remove("no-cache");
            cc.remove("no-store");
            cc.remove("must-revalidate");
            let mut headers = response.headers.clone();
            headers.remove("expires");
            headers.remove("pragma");
            if let Some(formatted) = format_cache_control(&cc) {
                headers.insert(
                    HeaderName::from_static("cache-control"),
                    HeaderValue::from_str(&formatted)
                        .unwrap_or_else(|_| HeaderValue::from_static("")),
                );
            } else {
                headers.remove("cache-control");
            }
            (cc, headers)
        } else {
            (response_cc, response.headers.clone())
        };

        // `Pragma: no-cache` on a response with no Cache-Control acts like
        // `Cache-Control: no-cache`.
        let mut response_cc = response_cc;
        if !cc_has(&response_cc, "no-cache")
            && !cc_has(&response_cc, "no-store")
            && first(&response_headers, "cache-control").is_none()
        {
            if let Some(pragma) = first(&response_headers, "pragma") {
                if pragma.contains("no-cache") {
                    response_cc.insert("no-cache".to_string(), None);
                }
            }
        }

        let request_headers = if first(&response_headers, "vary").is_some() {
            Some(request.headers.clone())
        } else {
            None
        };

        CachePolicy {
            response_time,
            clock,
            is_shared: options.shared,
            cache_heuristic: options.cache_heuristic,
            immutable_min_ttl: options.immutable_min_ttl,
            ignore_cargo_cult: options.ignore_cargo_cult,
            status: response.status,
            response_headers,
            response_cc,
            method: request.method,
            url: request.url,
            host: combined(&request.headers, "host"),
            no_authorization: first(&request.headers, "authorization").is_none(),
            request_headers,
            request_cc,
        }
    }

    // ---- internal clock / raw time helpers ----

    fn now(&self) -> SystemTime {
        self.clock.now()
    }

    /// The `Date` header value, or the time the response was received if the
    /// `Date` header is missing/invalid.
    pub fn response_date(&self) -> SystemTime {
        match first(&self.response_headers, "date").and_then(|d| parse_http_date(&d)) {
            Some(t) => t,
            None => self.response_time,
        }
    }

    // ---- RFC 9111 §4.2.3: Age ----

    /// The value of the `Age` header (seconds), used as the initial age.
    fn age_value(&self) -> f64 {
        first(&self.response_headers, "age")
            .and_then(|a| a.parse::<f64>().ok())
            .unwrap_or(0.0)
    }

    /// The current age of the response in seconds, per RFC 9111 §4.2.3:
    /// `corrected_initial_age + resident_time`, where
    /// `corrected_initial_age = max(age_value, apparent_age)` and
    /// `apparent_age = max(0, now - date_value)`.
    pub fn age(&self) -> f64 {
        let age_value = self.age_value();
        let now = self.now();
        let apparent_age = now
            .duration_since(self.response_date())
            .unwrap_or_default()
            .as_secs_f64()
            .max(0.0);
        let corrected_age_value = age_value.max(apparent_age);
        // The request that produced this response is not tracked separately,
        // so the response delay (response_time - request_time) is 0.
        let resident_time = now
            .duration_since(self.response_time)
            .unwrap_or_default()
            .as_secs_f64()
            .max(0.0);
        corrected_age_value + resident_time
    }

    // ---- RFC 9111 §4.2: Freshness lifetime ----

    fn has_explicit_expiration(&self) -> bool {
        (self.is_shared && cc_has(&self.response_cc, "s-maxage"))
            || cc_has(&self.response_cc, "max-age")
            || first(&self.response_headers, "expires").is_some()
    }

    /// The applicable freshness lifetime in seconds (the `max-age` or heuristic
    /// equivalent), regardless of how much time has elapsed.
    ///
    /// Returns `0` when the response is not cacheable or has `no-cache`.
    pub fn max_age(&self) -> f64 {
        if !self.is_storable() || cc_has(&self.response_cc, "no-cache") {
            return 0.0;
        }

        // Shared caches must not store shared Set-Cookie responses unless
        // explicitly marked public/immutable.
        if self.is_shared
            && first(&self.response_headers, "set-cookie").is_some()
            && !cc_has(&self.response_cc, "public")
            && !cc_has(&self.response_cc, "immutable")
        {
            return 0.0;
        }

        if first(&self.response_headers, "vary").as_deref() == Some("*") {
            return 0.0;
        }

        if self.is_shared {
            if cc_has(&self.response_cc, "proxy-revalidate") {
                return 0.0;
            }
            if cc_has(&self.response_cc, "s-maxage") {
                return cc_delta(&self.response_cc, "s-maxage") as f64;
            }
        }

        if cc_has(&self.response_cc, "max-age") {
            return cc_delta(&self.response_cc, "max-age") as f64;
        }

        let default_min_ttl = if cc_has(&self.response_cc, "immutable") {
            self.immutable_min_ttl.as_secs_f64()
        } else {
            0.0
        };

        if let Some(expires) = first(&self.response_headers, "expires") {
            let server_date = self.response_date();
            match parse_http_date(&expires) {
                Some(expires_t) if expires_t >= server_date => {
                    let secs = expires_t
                        .duration_since(server_date)
                        .unwrap_or_default()
                        .as_secs_f64();
                    return secs.max(default_min_ttl);
                }
                _ => return 0.0,
            }
        }

        if let Some(lm) = first(&self.response_headers, "last-modified") {
            if let Some(lm_t) = parse_http_date(&lm) {
                let server_date = self.response_date();
                if server_date > lm_t {
                    let age = server_date
                        .duration_since(lm_t)
                        .unwrap_or_default()
                        .as_secs_f64();
                    return (age * self.cache_heuristic).max(default_min_ttl);
                }
            }
        }

        default_min_ttl
    }

    /// Remaining useful lifetime in milliseconds, including any
    /// `stale-while-revalidate` / `stale-if-error` allowance. Use this as the
    /// expiration time for your cache storage.
    pub fn time_to_live(&self) -> Duration {
        let remaining = self.max_age() - self.age();
        let stale_if_error = remaining + cc_delta(&self.response_cc, "stale-if-error") as f64;
        let stale_while_revalidate =
            remaining + cc_delta(&self.response_cc, "stale-while-revalidate") as f64;
        let best = remaining
            .max(stale_if_error)
            .max(stale_while_revalidate)
            .max(0.0);
        Duration::from_secs_f64(best)
    }

    /// True if the response is past its freshness lifetime.
    pub fn stale(&self) -> bool {
        self.max_age() <= self.age()
    }

    fn use_stale_if_error(&self) -> bool {
        self.max_age() + cc_delta(&self.response_cc, "stale-if-error") as f64 > self.age()
    }

    /// True if `stale-while-revalidate` currently permits serving the stale
    /// response while revalidating asynchronously.
    pub fn use_stale_while_revalidate(&self) -> bool {
        let swr = cc_delta(&self.response_cc, "stale-while-revalidate") as f64;
        swr > 0.0 && self.max_age() + swr > self.age()
    }

    // ---- RFC 9111 §3: Storability ----

    /// Whether the response may be stored in a cache at all. When `false`, the
    /// caller MUST NOT store either the request or the response.
    pub fn is_storable(&self) -> bool {
        let method_ok = matches!(self.method, Method::GET | Method::HEAD)
            || (self.method == Method::POST && self.has_explicit_expiration());
        let allows_authenticated = cc_has(&self.response_cc, "must-revalidate")
            || cc_has(&self.response_cc, "public")
            || cc_has(&self.response_cc, "s-maxage");

        !cc_has(&self.request_cc, "no-store")
            && method_ok
            && UNDERSTOOD_STATUSES.contains(&self.status.as_u16())
            && !cc_has(&self.response_cc, "no-store")
            && (!self.is_shared || !cc_has(&self.response_cc, "private"))
            && (!self.is_shared || self.no_authorization || allows_authenticated)
            && (first(&self.response_headers, "expires").is_some()
                || cc_has(&self.response_cc, "max-age")
                || (self.is_shared && cc_has(&self.response_cc, "s-maxage"))
                || cc_has(&self.response_cc, "public")
                || CACHEABLE_BY_DEFAULT.contains(&self.status.as_u16()))
    }

    // ---- Vary / request matching ----

    fn request_matches(&self, req: &RequestInfo, allow_head: bool) -> bool {
        let url_ok = match &self.url {
            Some(u) => *u == req.url.as_deref().unwrap_or(""),
            None => true,
        };
        let host_ok = match &self.host {
            Some(h) => *h == combined(&req.headers, "host").unwrap_or_default(),
            None => true,
        };
        let method_ok = self.method == req.method || (allow_head && req.method == Method::HEAD);
        url_ok && host_ok && method_ok && self.vary_matches(req)
    }

    fn vary_matches(&self, req: &RequestInfo) -> bool {
        let Some(vary) = first(&self.response_headers, "vary") else {
            return true;
        };
        if vary.trim() == "*" {
            return false;
        }
        let original = match &self.request_headers {
            Some(h) => h,
            None => return true,
        };
        for field in vary.split(',').map(|f| f.trim().to_ascii_lowercase()) {
            if field.is_empty() {
                continue;
            }
            let new_val = combined(&req.headers, &field).unwrap_or_default();
            let old_val = combined(original, &field).unwrap_or_default();
            if new_val != old_val {
                return false;
            }
        }
        true
    }

    /// True if the cached response satisfies `req` without contacting the
    /// origin (i.e. it is fresh and compatible). Equivalent to
    /// `evaluate_request(req).revalidation.is_none()`.
    pub fn satisfies_without_revalidation(&self, req: &RequestInfo) -> bool {
        self.evaluate_request(req).revalidation.is_none()
    }

    /// Evaluate whether (and how) the cached response may satisfy `req`.
    ///
    /// See [`CacheDecision`] for how to interpret the result.
    pub fn evaluate_request(&self, req: &RequestInfo) -> CacheDecision {
        // A cache MUST NOT ignore must-revalidate.
        if cc_has(&self.response_cc, "must-revalidate") {
            return self.miss(req);
        }

        if !self.request_matches(req, false) {
            return self.miss(req);
        }

        let req_cc =
            parse_cache_control(&combined(&req.headers, "cache-control").unwrap_or_default());

        // no-cache (or Pragma: no-cache) on the request forces revalidation.
        if cc_has(&req_cc, "no-cache")
            || first(&req.headers, "pragma").is_some_and(|p| p.contains("no-cache"))
        {
            return self.miss(req);
        }

        if cc_has(&req_cc, "max-age") && self.age() > cc_delta(&req_cc, "max-age") as f64 {
            return self.miss(req);
        }

        if cc_has(&req_cc, "min-fresh")
            && (self.max_age() - self.age()) < cc_delta(&req_cc, "min-fresh") as f64
        {
            return self.miss(req);
        }

        if self.stale() {
            // max-stale: client tolerates some staleness without revalidation.
            let allows_stale = if cc_has(&req_cc, "max-stale") {
                match req_cc.get("max-stale") {
                    Some(None) => true, // "max-stale" with no value = any amount
                    Some(Some(v)) => v.parse::<f64>().unwrap_or(0.0) > self.age() - self.max_age(),
                    None => false,
                }
            } else {
                false
            };
            if allows_stale {
                return self.hit();
            }
            if self.use_stale_while_revalidate() {
                return self.hit_with_revalidation(req, false);
            }
            return self.miss(req);
        }

        self.hit()
    }

    fn hit(&self) -> CacheDecision {
        CacheDecision {
            response: Some(self.response_headers()),
            revalidation: None,
        }
    }

    fn hit_with_revalidation(&self, req: &RequestInfo, synchronous: bool) -> CacheDecision {
        CacheDecision {
            response: Some(self.response_headers()),
            revalidation: Some(Revalidation {
                headers: self.revalidation_headers(req),
                synchronous,
            }),
        }
    }

    fn miss(&self, req: &RequestInfo) -> CacheDecision {
        CacheDecision {
            response: None,
            revalidation: Some(Revalidation {
                headers: self.revalidation_headers(req),
                synchronous: true,
            }),
        }
    }

    // ---- Response / revalidation header construction ----

    /// The cached response headers adjusted for serving: hop-by-hop headers
    /// removed, and `Age`/`Date` updated to reflect current time. A `113`
    /// warning is added when a heuristic TTL exceeds 24h and the response is
    /// old (RFC 9111 §5.5.4).
    pub fn response_headers(&self) -> HeaderMap {
        let mut headers = copy_without_hop_by_hop(&self.response_headers);
        let age = self.age();

        if age > 86_400.0 && !self.has_explicit_expiration() && self.max_age() > 86_400.0 {
            let extra = r#"113 - "rfc7234 5.5.4""#;
            let warning = match combined(&headers, "warning") {
                Some(existing) => format!("{existing}, {extra}"),
                None => extra.to_string(),
            };
            set_header(&mut headers, "warning", &warning);
        }

        set_header(&mut headers, "age", &format!("{}", age.round()));
        set_header(&mut headers, "date", &format_http_date(self.now()));
        headers
    }

    /// Conditional request headers to send to the origin when revalidating this
    /// cached response.
    pub fn revalidation_headers(&self, incoming: &RequestInfo) -> HeaderMap {
        let mut headers = copy_without_hop_by_hop(&incoming.headers);
        headers.remove("if-range");

        if !self.request_matches(incoming, true) || !self.is_storable() {
            headers.remove("if-none-match");
            headers.remove("if-modified-since");
            return headers;
        }

        if let Some(etag) = first(&self.response_headers, "etag") {
            let new = match combined(&headers, "if-none-match") {
                Some(existing) => format!("{existing}, {etag}"),
                None => etag,
            };
            set_header(&mut headers, "if-none-match", &new);
        }

        let forbids_weak = combined(&headers, "accept-ranges").is_some()
            || combined(&headers, "if-match").is_some()
            || combined(&headers, "if-unmodified-since").is_some()
            || self.method != Method::GET;

        if forbids_weak {
            headers.remove("if-modified-since");
            if let Some(inm) = combined(&headers, "if-none-match") {
                let strong: Vec<&str> = inm
                    .split(',')
                    .map(|e| e.trim())
                    .filter(|e| !e.starts_with("W/"))
                    .collect();
                if strong.is_empty() {
                    headers.remove("if-none-match");
                } else {
                    set_header(&mut headers, "if-none-match", &strong.join(","));
                }
            }
        } else if let Some(lm) = first(&self.response_headers, "last-modified") {
            if combined(&headers, "if-modified-since").is_none() {
                set_header(&mut headers, "if-modified-since", &lm);
            }
        }

        headers
    }

    /// Combine the stored response with a revalidation response from the origin,
    /// producing an updated [`CachePolicy`].
    ///
    /// `request` is the request that triggered revalidation; `response` is the
    /// origin's reply (typically a 304). When the reply is a server error and
    /// `stale-if-error` applies, the stale entry is returned unchanged.
    pub fn revalidated_policy(
        &self,
        request: &RequestInfo,
        response: &ResponseInfo,
    ) -> Result<RevalidationResult, Error> {
        if self.use_stale_if_error() && is_error_response(response) {
            return Ok(RevalidationResult {
                policy: self.clone(),
                modified: false,
                matches: true,
            });
        }

        let response_headers = &response.headers;
        if response_headers.is_empty() {
            return Err(Error::MissingResponseHeaders);
        }

        let res_etag = first(response_headers, "etag");
        let res_lm = first(response_headers, "last-modified");
        let stored_etag = first(&self.response_headers, "etag");
        let stored_lm = first(&self.response_headers, "last-modified");

        let mut matches = false;
        if response.status != StatusCode::NOT_MODIFIED {
            matches = false;
        } else if let Some(etag) = &res_etag {
            if !etag.starts_with("W/") {
                matches = stored_etag
                    .as_deref()
                    .map(|s| strip_weak(s) == strip_weak(etag))
                    .unwrap_or(false);
            }
        } else if let (Some(se), Some(re)) = (&stored_etag, &res_etag) {
            matches = strip_weak(se) == strip_weak(re);
        } else if stored_lm.is_some() {
            matches = stored_lm == res_lm;
        } else if stored_etag.is_none()
            && stored_lm.is_none()
            && res_etag.is_none()
            && res_lm.is_none()
        {
            matches = true;
        }

        let mut merged = HeaderMap::new();
        for (name, value) in self.response_headers.iter() {
            let name_str = name.as_str();
            if let Some(new_val) = response_headers.get(name) {
                if !EXCLUDED_FROM_REVALIDATION_UPDATE.contains(&name_str) {
                    merged.append(name, new_val.clone());
                    continue;
                }
            }
            if let Ok(v) = value.to_str() {
                if let Ok(hv) = HeaderValue::from_str(v) {
                    merged.append(name, hv);
                }
            }
        }

        let new_response = ResponseInfo {
            status: self.status,
            headers: merged,
        };

        let options = Options {
            shared: self.is_shared,
            cache_heuristic: self.cache_heuristic,
            immutable_min_ttl: self.immutable_min_ttl,
            ignore_cargo_cult: self.ignore_cargo_cult,
            now: Some(self.clock.now()),
        };

        if !matches {
            return Ok(RevalidationResult {
                policy: CachePolicy::new_with_options(request.clone(), new_response, options),
                modified: response.status != StatusCode::NOT_MODIFIED,
                matches: false,
            });
        }

        Ok(RevalidationResult {
            policy: CachePolicy::new_with_options(request.clone(), new_response, options),
            modified: false,
            matches: true,
        })
    }

    // ---- Serialization ----

    /// Serialize the policy to a persistable snapshot.
    pub fn to_object(&self) -> SerializedPolicy {
        let response_time_secs = self
            .response_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        SerializedPolicy {
            response_time_secs,
            shared: self.is_shared,
            cache_heuristic: self.cache_heuristic,
            immutable_min_ttl_secs: self.immutable_min_ttl.as_secs(),
            ignore_cargo_cult: self.ignore_cargo_cult,
            status: self.status.as_u16(),
            response_headers: headers_to_pairs(&self.response_headers),
            response_cache_control: cc_to_pairs(&self.response_cc),
            method: self.method.to_string(),
            url: self.url.clone(),
            host: self.host.clone(),
            no_authorization: self.no_authorization,
            request_headers: self.request_headers.as_ref().map(headers_to_pairs),
            request_cache_control: cc_to_pairs(&self.request_cc),
        }
    }

    /// Reconstruct a policy from a snapshot produced by [`CachePolicy::to_object`].
    pub fn from_object(obj: SerializedPolicy) -> Option<CachePolicy> {
        let response_time = if obj.response_time_secs >= 0 {
            SystemTime::UNIX_EPOCH + Duration::from_secs(obj.response_time_secs as u64)
        } else {
            SystemTime::UNIX_EPOCH
        };
        Some(CachePolicy {
            response_time,
            clock: Clock::Real,
            is_shared: obj.shared,
            cache_heuristic: obj.cache_heuristic,
            immutable_min_ttl: Duration::from_secs(obj.immutable_min_ttl_secs),
            ignore_cargo_cult: obj.ignore_cargo_cult,
            status: StatusCode::from_u16(obj.status).ok()?,
            response_headers: pairs_to_headers(obj.response_headers),
            response_cc: pairs_to_cc(obj.response_cache_control),
            method: obj.method.parse().unwrap_or(Method::GET),
            url: obj.url,
            host: obj.host,
            no_authorization: obj.no_authorization,
            request_headers: obj.request_headers.map(pairs_to_headers),
            request_cc: pairs_to_cc(obj.request_cache_control),
        })
    }
}

// ---- free helpers ----

fn is_error_response(response: &ResponseInfo) -> bool {
    ERROR_STATUSES.contains(&response.status.as_u16())
}

fn strip_weak(etag: &str) -> &str {
    etag.trim().strip_prefix("W/").unwrap_or(etag)
}

fn copy_without_hop_by_hop(headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers.iter() {
        if HOP_BY_HOP.contains(&name.as_str()) {
            continue;
        }
        out.append(name, value.clone());
    }
    // Remove any header named in the Connection header.
    if let Some(conn) = combined(headers, "connection") {
        for token in conn.split(',').map(|t| t.trim().to_ascii_lowercase()) {
            if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
                out.remove(name);
            }
        }
    }
    // Drop 1xx warnings (RFC 9111 §5.5.4 handling of stale warnings).
    if let Some(warning) = combined(&out, "warning") {
        let kept: Vec<&str> = warning
            .split(',')
            .filter(|w| !w.trim_start().starts_with("1"))
            .collect();
        if kept.is_empty() {
            out.remove("warning");
        } else {
            set_header(&mut out, "warning", &kept.join(","));
        }
    }
    out
}

fn set_header(headers: &mut HeaderMap, name: &str, value: &str) {
    if let (Ok(n), Ok(v)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        headers.insert(n, v);
    }
}

fn format_cache_control(cc: &CacheControl) -> Option<String> {
    let mut parts = Vec::new();
    for (k, v) in cc {
        match v {
            Some(val) => parts.push(format!("{k}={val}")),
            None => parts.push(k.clone()),
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

fn headers_to_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(n, v)| {
            v.to_str()
                .ok()
                .map(|v| (n.as_str().to_string(), v.to_string()))
        })
        .collect()
}

fn pairs_to_headers(pairs: Vec<(String, String)>) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            map.append(n, v);
        }
    }
    map
}

fn cc_to_pairs(cc: &CacheControl) -> Vec<(String, Option<String>)> {
    cc.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

fn pairs_to_cc(pairs: Vec<(String, Option<String>)>) -> CacheControl {
    pairs.into_iter().collect()
}
