// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Helpers for reading and parsing the HTTP headers that drive cache
//! semantics (RFC 9111): `Cache-Control`, `Expires`, `Age`, `Date`,
//! `Last-Modified`, `ETag`, `Vary`, and `Pragma`.

use std::collections::HashMap;

use http::HeaderMap;

/// A parsed `Cache-Control` directive set.
///
/// Boolean directives (e.g. `no-cache`, `private`) are stored as `None`
/// values; directives with an argument (e.g. `max-age=10`) are stored as
/// `Some(value)`.
pub(crate) type CacheControl = HashMap<String, Option<String>>;

/// Read a single header, joining any repeated values with a comma the way the
/// `Cache-Control` grammar expects multiple header lines to be combined.
///
/// `Set-Cookie` and friends that must NOT be combined are handled by callers;
/// this crate only combines the specific headers it reads here.
pub(crate) fn combined(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut out = String::new();
    let mut first = true;
    for value in headers.get_all(name) {
        let Ok(s) = value.to_str() else { continue };
        if !first {
            out.push(',');
        }
        out.push_str(s);
        first = false;
    }
    if first {
        None
    } else {
        Some(out)
    }
}

/// Read a single header value (first occurrence).
pub(crate) fn first(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Parse a `Cache-Control` (or `Pragma`) header value into directives.
///
/// Multiple comma-separated directives are handled, and a directive may be
/// repeated; only the first occurrence of a given directive is kept (matching
/// the reference behaviour where duplicate directives make the value invalid,
/// but we keep the first for leniency).
pub(crate) fn parse_cache_control(header: &str) -> CacheControl {
    let mut cc = CacheControl::new();
    for part in header.split(',') {
        let mut kv = part.splitn(2, '=');
        let key = kv.next().unwrap_or("").trim().to_ascii_lowercase();
        if key.is_empty() {
            continue;
        }
        let value = kv.next().map(|v| v.trim().trim_matches('"').to_string());
        cc.entry(key).or_insert(value);
    }
    cc
}

/// Get the value of a `delta-seconds` cache directive as a non-negative integer,
/// returning `0` if absent or unparseable (mirrors the reference's
/// "toNumberOrZero" behaviour).
pub(crate) fn cc_delta(cc: &CacheControl, name: &str) -> u64 {
    cc.get(name)
        .and_then(|v| v.as_ref())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
}

/// True if the directive is present (as a boolean flag or with a value).
pub(crate) fn cc_has(cc: &CacheControl, name: &str) -> bool {
    cc.contains_key(name)
}
