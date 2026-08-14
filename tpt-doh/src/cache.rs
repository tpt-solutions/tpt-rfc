// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal HTTP response cache honoring RFC 9111 freshness signals.
//!
//! This is intentionally simple: it computes a freshness lifetime from
//! `Cache-Control: max-age` (relative to `Date`, if present) or `Expires`, and
//! serves stored entries while fresh. `no-store` and `no-cache` responses are
//! never cached (the latter requires revalidation, which this client does not
//! implement). Once `tpt-http-cache` exists, callers can instead route through
//! that crate for full RFC 9111 semantics.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::http::{HttpResponse, Method};

#[derive(Default)]
pub(crate) struct Cache {
    entries: HashMap<String, Entry>,
}

struct Entry {
    body: Vec<u8>,
    expires_at: SystemTime,
}

impl Cache {
    pub(crate) fn new() -> Self {
        Cache::default()
    }

    pub(crate) fn key(method: Method, url: &str, body: Option<&[u8]>) -> String {
        match body {
            Some(b) => format!("{} {} {}", method.as_str(), url, hex_short(b)),
            None => format!("{} {}", method.as_str(), url),
        }
    }

    /// Return a cached response body if one exists and is still fresh.
    pub(crate) fn get(&self, key: &str, now: SystemTime) -> Option<&[u8]> {
        match self.entries.get(key) {
            Some(e) if e.expires_at > now => Some(&e.body),
            _ => None,
        }
    }

    /// Store `body` for `key` if `response` is cacheable, using `now` as the
    /// reference time.
    pub(crate) fn store(
        &mut self,
        key: &str,
        response: &HttpResponse,
        now: SystemTime,
    ) -> Result<(), String> {
        let Some(expires_at) = freshness_lifetime(response, now) else {
            return Ok(());
        };
        if expires_at <= now {
            return Ok(());
        }
        self.entries.insert(
            key.to_string(),
            Entry {
                body: response.body.clone(),
                expires_at,
            },
        );
        Ok(())
    }
}

fn hex_short(b: &[u8]) -> String {
    // Cheap, collision-tolerant fingerprint for the POST body cache key.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in b {
        h ^= byte as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// Compute the freshness expiry `SystemTime` for a response, or `None` if the
/// response is not cacheable.
fn freshness_lifetime(response: &HttpResponse, now: SystemTime) -> Option<SystemTime> {
    let cc = response
        .header("cache-control")
        .unwrap_or("")
        .to_ascii_lowercase();

    for directive in cc.split(',') {
        let directive = directive.trim();
        if directive == "no-store" || directive == "no-cache" {
            return None;
        }
        if let Some(rest) = directive.strip_prefix("max-age") {
            let rest = rest.trim_start_matches('=').trim();
            if let Ok(secs) = rest.parse::<u64>() {
                let base = response
                    .header("date")
                    .and_then(parse_http_date)
                    .unwrap_or(now);
                return Some(base + Duration::from_secs(secs));
            }
        }
    }

    if let Some(expires) = response.header("expires") {
        if let Some(t) = parse_http_date(expires) {
            if t > now {
                return Some(t);
            }
        }
    }

    None
}

/// Parse an HTTP-date in the IMF-fixdate form (`Day, DD Mon YYYY HH:MM:SS GMT`),
/// the format mandated by RFC 7231 for `Date`/`Expires`.
fn parse_http_date(s: &str) -> Option<SystemTime> {
    // "Mon, 02 Jan 2006 15:04:05 GMT"
    let s = s.trim();
    let parts: Vec<&str> = s.split(' ').collect();
    if parts.len() != 6 {
        return None;
    }
    if parts[5] != "GMT" {
        return None;
    }
    let day: u64 = parts[1].parse().ok()?;
    let month = MONTHS
        .iter()
        .position(|m| *m == parts[2].to_ascii_lowercase())? as u64
        + 1;
    let year: u64 = parts[3].parse().ok()?;
    let (hh, mm, ss) = parse_hms(parts[4])?;

    // Days since epoch via a simple civil-date algorithm (Howard Hinnant).
    let y = if month <= 2 {
        year as i64 - 1
    } else {
        year as i64
    };
    let m = if month <= 2 {
        month as i64 + 12
    } else {
        month as i64
    };
    let days = 365 * y + y / 4 - y / 100
        + y / 400
        + (367 * m - 362) / 12
        + (if m <= 14 { 0 } else { -1 })
        + day as i64
        - 719163;
    let secs = days * 86_400 + hh as i64 * 3600 + mm as i64 * 60 + ss as i64;
    UNIX_EPOCH.checked_add(Duration::from_secs(secs as u64))
}

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

fn parse_hms(s: &str) -> Option<(u64, u64, u64)> {
    let p: Vec<&str> = s.split(':').collect();
    if p.len() != 3 {
        return None;
    }
    Some((p[0].parse().ok()?, p[1].parse().ok()?, p[2].parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{HttpResponse, Method};

    fn resp_with(headers: &[(&str, &str)]) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: b"cached".to_vec(),
        }
    }

    #[test]
    fn no_store_not_cached() {
        let mut c = Cache::new();
        let r = resp_with(&[("cache-control", "no-store")]);
        c.store("k", &r, SystemTime::now()).unwrap();
        assert!(c.entries.is_empty());
    }

    #[test]
    fn max_age_is_cached_and_served() {
        let now = SystemTime::now();
        // No `Date` header -> freshness is relative to `now`.
        let r = resp_with(&[("cache-control", "max-age=60")]);
        let mut c = Cache::new();
        c.store("k", &r, now).unwrap();
        assert!(c.get("k", now).is_some());
        // Still fresh 30s later.
        let later = now + Duration::from_secs(30);
        assert!(c.get("k", later).is_some());
        // Expired 90s later.
        let expired = now + Duration::from_secs(90);
        assert!(c.get("k", expired).is_none());
    }

    #[test]
    fn max_age_relative_to_date() {
        let now = SystemTime::now();
        // A `Date` in the past with a short `max-age` is already expired.
        let r = resp_with(&[
            ("cache-control", "max-age=60"),
            ("date", "Mon, 02 Jan 2006 15:04:05 GMT"),
        ]);
        let mut c = Cache::new();
        c.store("k", &r, now).unwrap();
        assert!(c.get("k", now).is_none());
    }

    #[test]
    fn expires_header_is_honored() {
        let now = SystemTime::now();
        let future = "Thu, 01 Jan 2037 00:00:00 GMT";
        let r = resp_with(&[("expires", future)]);
        let mut c = Cache::new();
        c.store("k", &r, now).unwrap();
        assert!(c.get("k", now).is_some());
    }

    #[test]
    fn cache_key_distinguishes_post_bodies() {
        let a = Cache::key(Method::Post, "https://x/dns-query", Some(b"abc"));
        let b = Cache::key(Method::Post, "https://x/dns-query", Some(b"abd"));
        assert_ne!(a, b);
        let get = Cache::key(Method::Get, "https://x/dns-query?dns=ZZZ", None);
        assert_ne!(get, a);
    }
}
