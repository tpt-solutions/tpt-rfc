// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Live interop tests against public DoH resolvers.
//!
//! These require network access and are therefore marked `#[ignore]`. Run them
//! with: `cargo test --features reqwest --test live -- --ignored`.

#![cfg(feature = "reqwest")]

use tpt_doh::{DohClient, ReqwestClient};

const RESOLVERS: &[&str] = &[
    "https://dns.google/dns-query",         // Cloudflare? no — Google
    "https://cloudflare-dns.com/dns-query", // Cloudflare
    "https://dns.quad9.net/dns-query",      // Quad9
];

fn client_for(url: &str) -> DohClient<ReqwestClient> {
    DohClient::new(url, ReqwestClient::new().unwrap())
}

#[test]
#[ignore]
fn live_post_a_lookup() {
    for url in RESOLVERS {
        let client = client_for(url);
        let addrs = client.lookup_a("example.com").unwrap();
        assert!(!addrs.is_empty(), "no A records from {url}");
    }
}

#[test]
#[ignore]
fn live_get_a_lookup() {
    for url in RESOLVERS {
        let client = client_for(url).with_method(tpt_doh::Method::Get);
        let addrs = client.lookup_a("example.com").unwrap();
        assert!(!addrs.is_empty(), "no A records from {url} (GET)");
    }
}

#[test]
#[ignore]
fn live_aaaa_lookup() {
    for url in RESOLVERS {
        let client = client_for(url);
        let addrs = client.lookup_aaaa("example.com").unwrap();
        // example.com historically has no AAAA; success is defined as a valid
        // (possibly empty) response, not an error.
        let _ = addrs;
    }
}
