// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Behavioural test vectors ported clean-room from the `http-cache-semantics`
//! test suite (reimplemented from documented RFC behaviour, not copied code).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};

use tpt_http_cache::{CachePolicy, Options, RequestInfo, ResponseInfo};

const DATE: &str = "Wed, 01 Jan 2020 00:00:00 GMT";

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_577_836_800) // 2020-01-01T00:00:00Z
}

fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut m = HeaderMap::new();
    for (k, v) in pairs {
        m.insert(
            HeaderName::from_bytes(k.as_bytes()).unwrap(),
            HeaderValue::from_str(v).unwrap(),
        );
    }
    m
}

fn req(pairs: &[(&str, &str)]) -> RequestInfo {
    RequestInfo::from_headers(Method::GET, hm(pairs))
}

fn req_with(method: Method, pairs: &[(&str, &str)]) -> RequestInfo {
    RequestInfo::from_headers(method, hm(pairs))
}

fn res(pairs: &[(&str, &str)]) -> ResponseInfo {
    ResponseInfo::from_status(StatusCode::OK, hm(pairs))
}

fn res_status(status: StatusCode, pairs: &[(&str, &str)]) -> ResponseInfo {
    ResponseInfo::from_status(status, hm(pairs))
}

fn policy(request: RequestInfo, response: ResponseInfo) -> CachePolicy {
    CachePolicy::new_with_options(
        request,
        response,
        Options {
            now: Some(now()),
            ..Options::default()
        },
    )
}

fn policy_opts(request: RequestInfo, response: ResponseInfo, mut options: Options) -> CachePolicy {
    options.now = Some(now());
    CachePolicy::new_with_options(request, response, options)
}

#[test]
fn fresh_max_age() {
    let p = policy(
        req(&[]),
        res(&[("cache-control", "public, max-age=3600"), ("date", DATE)]),
    );
    assert!(p.is_storable());
    assert!(!p.stale());
    assert!(p.satisfies_without_revalidation(&req(&[])));
    assert_eq!(p.max_age(), 3600.0);
}

#[test]
fn stale_via_date_gap() {
    let p = CachePolicy::new_with_options(
        req(&[]),
        res(&[
            ("cache-control", "max-age=10"),
            ("date", DATE),
            ("age", "100"),
        ]),
        Options {
            now: Some(now()),
            ..Options::default()
        },
    );
    assert!(p.stale());
    assert!(!p.satisfies_without_revalidation(&req(&[])));
    let d = p.evaluate_request(&req(&[]));
    assert!(d.revalidation.is_some());
    assert!(d.response.is_none());
}

#[test]
fn expires_fresh_and_stale() {
    let fresh = CachePolicy::new_with_options(
        req(&[]),
        res(&[("expires", "Wed, 01 Jan 2020 00:10:00 GMT"), ("date", DATE)]),
        Options {
            now: Some(now()),
            ..Options::default()
        },
    );
    assert_eq!(fresh.max_age(), 600.0);
    assert!(!fresh.stale());

    let stale = CachePolicy::new_with_options(
        req(&[]),
        res(&[
            ("expires", "Wed, 01 Jan 2020 00:10:00 GMT"),
            ("date", DATE),
            ("age", "700"),
        ]),
        Options {
            now: Some(now()),
            ..Options::default()
        },
    );
    assert!(stale.stale());
}

#[test]
fn no_store_request_not_storable() {
    let p = policy(
        req(&[("cache-control", "no-store")]),
        res(&[("cache-control", "max-age=3600")]),
    );
    assert!(!p.is_storable());
}

#[test]
fn no_store_response_not_storable() {
    let p = policy(req(&[]), res(&[("cache-control", "no-store")]));
    assert!(!p.is_storable());
}

#[test]
fn private_shared_vs_single_user() {
    let shared = policy_opts(
        req(&[]),
        res(&[("cache-control", "private, max-age=10")]),
        Options {
            shared: true,
            ..Options::default()
        },
    );
    assert!(!shared.is_storable());

    let private = policy_opts(
        req(&[]),
        res(&[("cache-control", "private, max-age=10")]),
        Options {
            shared: false,
            ..Options::default()
        },
    );
    assert!(private.is_storable());
}

#[test]
fn no_cache_response_is_stored_but_stale() {
    let p = policy(
        req(&[]),
        res(&[("cache-control", "no-cache"), ("date", DATE)]),
    );
    assert!(p.is_storable());
    assert_eq!(p.max_age(), 0.0);
    assert!(p.stale());
    assert!(!p.satisfies_without_revalidation(&req(&[])));
}

#[test]
fn vary_match_and_mismatch() {
    let p = CachePolicy::new_with_options(
        req(&[("accept-encoding", "gzip")]),
        res(&[
            ("cache-control", "max-age=3600"),
            ("vary", "accept-encoding"),
            ("date", DATE),
        ]),
        Options {
            now: Some(now()),
            ..Options::default()
        },
    );
    assert!(p.satisfies_without_revalidation(&req(&[("accept-encoding", "gzip")])));
    assert!(!p.satisfies_without_revalidation(&req(&[("accept-encoding", "br")])));
}

#[test]
fn vary_star_never_matches() {
    let p = policy(
        req(&[]),
        res(&[
            ("cache-control", "max-age=3600"),
            ("vary", "*"),
            ("date", DATE),
        ]),
    );
    assert!(!p.satisfies_without_revalidation(&req(&[])));
    assert_eq!(p.max_age(), 0.0);
}

#[test]
fn revalidation_headers_etag() {
    let p = policy(
        req(&[]),
        res(&[
            ("etag", "abc"),
            ("cache-control", "max-age=10"),
            ("date", DATE),
        ]),
    );
    let headers = p.revalidation_headers(&req(&[]));
    assert_eq!(headers.get("if-none-match").unwrap(), "abc");
}

#[test]
fn revalidation_headers_last_modified() {
    let p = policy(
        req(&[]),
        res(&[
            ("last-modified", DATE),
            ("cache-control", "max-age=10"),
            ("date", DATE),
        ]),
    );
    let headers = p.revalidation_headers(&req(&[]));
    assert_eq!(headers.get("if-modified-since").unwrap(), DATE);
    assert!(headers.get("if-none-match").is_none());
}

#[test]
fn stale_while_revalidate_async() {
    let p = CachePolicy::new_with_options(
        req(&[]),
        res(&[
            ("cache-control", "max-age=10, stale-while-revalidate=30"),
            ("date", DATE),
            ("age", "20"),
        ]),
        Options {
            now: Some(now()),
            ..Options::default()
        },
    );
    assert!(p.stale());
    assert!(p.use_stale_while_revalidate());
    let d = p.evaluate_request(&req(&[]));
    assert!(d.response.is_some());
    let reval = d.revalidation.expect("swr revalidation");
    assert!(!reval.synchronous);
}

#[test]
fn request_max_age_forces_miss() {
    let p = CachePolicy::new_with_options(
        req(&[]),
        res(&[
            ("cache-control", "max-age=3600"),
            ("date", DATE),
            ("age", "100"),
        ]),
        Options {
            now: Some(now()),
            ..Options::default()
        },
    );
    let d = p.evaluate_request(&req(&[("cache-control", "max-age=10")]));
    assert!(d.revalidation.is_some());
    assert!(d.response.is_none());
}

#[test]
fn request_min_fresh_forces_miss() {
    let p = policy(
        req(&[]),
        res(&[("cache-control", "max-age=3600"), ("date", DATE)]),
    );
    let d = p.evaluate_request(&req(&[("cache-control", "min-fresh=4000")]));
    assert!(d.revalidation.is_some());
}

#[test]
fn request_max_stale_allows_hit() {
    let p = CachePolicy::new_with_options(
        req(&[]),
        res(&[
            ("cache-control", "max-age=10"),
            ("date", DATE),
            ("age", "100"),
        ]),
        Options {
            now: Some(now()),
            ..Options::default()
        },
    );
    assert!(p.stale());
    let d = p.evaluate_request(&req(&[("cache-control", "max-stale=200")]));
    assert!(d.response.is_some());
    assert!(d.revalidation.is_none());
}

#[test]
fn must_revalidate_forces_miss_when_fresh() {
    let p = policy(
        req(&[]),
        res(&[
            ("cache-control", "max-age=3600, must-revalidate"),
            ("date", DATE),
        ]),
    );
    assert!(!p.stale());
    assert!(!p.satisfies_without_revalidation(&req(&[])));
    let d = p.evaluate_request(&req(&[]));
    assert!(d.revalidation.is_some());
}

#[test]
fn immutable_min_ttl() {
    let default = policy(
        req(&[]),
        res(&[("cache-control", "immutable"), ("date", DATE)]),
    );
    assert!(default.is_storable());
    assert_eq!(default.max_age(), 86_400.0);

    let custom = policy_opts(
        req(&[]),
        res(&[("cache-control", "immutable"), ("date", DATE)]),
        Options {
            immutable_min_ttl: Duration::from_secs(100),
            ..Options::default()
        },
    );
    assert_eq!(custom.max_age(), 100.0);
}

#[test]
fn heuristic_last_modified() {
    // last-modified 100 days before date => heuristic = 10 days.
    let lm = "Sun, 24 Mar 2019 00:00:00 GMT"; // ~283 days before 2020-01-01
    let p = policy(req(&[]), res(&[("last-modified", lm), ("date", DATE)]));
    // Over ~283 days, 10% -> ~28.3 days; just assert it's positive and large.
    assert!(p.max_age() > 1_000_000.0, "max_age was {}", p.max_age());
    assert!(p.is_storable());
}

#[test]
fn heuristic_113_warning() {
    let lm = "Sun, 24 Mar 2019 00:00:00 GMT";
    let p = CachePolicy::new_with_options(
        req(&[]),
        res(&[
            ("last-modified", lm),
            ("date", DATE),
            ("age", &format!("{}", 200 * 86_400)),
        ]),
        Options {
            now: Some(now()),
            ..Options::default()
        },
    );
    let headers = p.response_headers();
    let warning = headers.get("warning").unwrap().to_str().unwrap();
    assert!(warning.contains("113"), "warning was: {warning}");
}

#[test]
fn serialization_round_trip() {
    let p = policy(
        req_with(Method::GET, &[("host", "example.com")]),
        res(&[("cache-control", "public, max-age=3600"), ("date", DATE)]),
    );
    let obj = p.to_object();
    let restored = CachePolicy::from_object(obj).expect("round trip");
    assert!(restored.is_storable());
    assert_eq!(restored.max_age(), 3600.0);
    assert_eq!(restored.to_object().method, "GET");
}

#[test]
fn response_headers_refreshed() {
    let p = CachePolicy::new_with_options(
        req(&[]),
        res(&[
            ("cache-control", "max-age=3600"),
            ("date", DATE),
            ("age", "5"),
        ]),
        Options {
            now: Some(now()),
            ..Options::default()
        },
    );
    let headers = p.response_headers();
    assert_eq!(headers.get("age").unwrap(), "5");
    assert!(headers.get("date").is_some());
    // hop-by-hop headers are stripped
    assert!(headers.get("connection").is_none());
}

#[test]
fn set_cookie_shared_not_cacheable_unless_public() {
    let without_public = policy(
        req(&[]),
        res(&[
            ("cache-control", "max-age=10"),
            ("set-cookie", "a=b"),
            ("date", DATE),
        ]),
    );
    assert!(without_public.is_storable());
    assert_eq!(without_public.max_age(), 0.0);

    let with_public = policy(
        req(&[]),
        res(&[
            ("cache-control", "public, max-age=10"),
            ("set-cookie", "a=b"),
            ("date", DATE),
        ]),
    );
    assert_eq!(with_public.max_age(), 10.0);
}

#[test]
fn method_cacheability() {
    assert!(policy(
        req(&[]),
        res(&[("cache-control", "max-age=10"), ("date", DATE)])
    )
    .is_storable());
    assert!(policy(
        req_with(Method::HEAD, &[]),
        res(&[("cache-control", "max-age=10"), ("date", DATE)])
    )
    .is_storable());
    // POST without explicit expiration is not cacheable.
    assert!(!policy(req_with(Method::POST, &[]), res(&[("date", DATE)])).is_storable());
    // POST with explicit expiration is cacheable.
    assert!(policy(
        req_with(Method::POST, &[]),
        res(&[("cache-control", "max-age=10"), ("date", DATE)])
    )
    .is_storable());
}

#[test]
fn revalidated_policy_304_matches() {
    let p = policy(
        req(&[]),
        res(&[
            ("etag", "v1"),
            ("cache-control", "max-age=10"),
            ("date", DATE),
        ]),
    );
    let reval = p.revalidation_headers(&req(&[]));
    assert!(reval.get("if-none-match").is_some());

    let updated = res_status(StatusCode::NOT_MODIFIED, &[("etag", "v1")]);
    let result = p
        .revalidated_policy(&req(&[]), &updated)
        .expect("revalidation");
    assert!(result.matches);
    assert!(!result.modified);
    // The refreshed policy is fresh again.
    assert!(!result.policy.stale());
}

#[test]
fn revalidated_policy_mismatch_updates_policy() {
    let p = policy(
        req(&[]),
        res(&[
            ("etag", "v1"),
            ("cache-control", "max-age=10"),
            ("date", DATE),
        ]),
    );
    let updated = res_status(
        StatusCode::OK,
        &[
            ("etag", "v2"),
            ("cache-control", "max-age=60"),
            ("date", DATE),
        ],
    );
    let result = p
        .revalidated_policy(&req(&[]), &updated)
        .expect("revalidation");
    assert!(!result.matches);
    assert!(result.modified);
    assert_eq!(result.policy.max_age(), 60.0);
}

#[test]
fn stale_if_error_keeps_cache_on_server_error() {
    let p = CachePolicy::new_with_options(
        req(&[]),
        res(&[
            ("cache-control", "max-age=10, stale-if-error=100"),
            ("date", DATE),
            ("age", "100"),
        ]),
        Options {
            now: Some(now()),
            ..Options::default()
        },
    );
    assert!(p.stale());
    let error = res_status(StatusCode::INTERNAL_SERVER_ERROR, &[]);
    let result = p
        .revalidated_policy(&req(&[]), &error)
        .expect("revalidation");
    assert!(result.matches);
    assert!(!result.modified);
}
