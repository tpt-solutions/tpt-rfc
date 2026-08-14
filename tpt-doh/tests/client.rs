// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Offline integration tests using an in-memory stub transport.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use tpt_doh::dns::{rtype, Message, RData};
use tpt_doh::http::{HttpClient, HttpRequest, HttpResponse, Method};
use tpt_doh::{DohClient, Error};

/// A stub transport that returns a canned A-record response and records the
/// last request it saw.
struct Stub {
    last: Mutex<Option<HttpRequest>>,
    calls: AtomicUsize,
}

impl Stub {
    fn new() -> Self {
        Stub {
            last: Mutex::new(None),
            calls: AtomicUsize::new(0),
        }
    }

    /// A response for `example.com` A query: id 0, answer 93.184.216.34.
    fn canned_response() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u16.to_be_bytes()); // id
        bytes.extend_from_slice(&0x8180u16.to_be_bytes()); // flags
        bytes.extend_from_slice(&1u16.to_be_bytes()); // qd
        bytes.extend_from_slice(&1u16.to_be_bytes()); // an
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        for label in ["example", "com"] {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
        bytes.extend_from_slice(&rtype::A.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes()); // class IN
        bytes.extend_from_slice(&0xC00Cu16.to_be_bytes()); // name ptr -> offset 12
        bytes.extend_from_slice(&rtype::A.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&60u32.to_be_bytes()); // ttl
        bytes.extend_from_slice(&4u16.to_be_bytes()); // rdlen
        bytes.extend_from_slice(&[93, 184, 216, 34]);
        bytes
    }
}

impl HttpClient for Stub {
    fn send(
        &self,
        req: &HttpRequest,
    ) -> std::result::Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>> {
        *self.last.lock().unwrap() = Some(req.clone());
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(HttpResponse {
            status: 200,
            headers: vec![
                (
                    "Content-Type".to_string(),
                    "application/dns-message".to_string(),
                ),
                // Cacheable so the GET+cache test exercises the cache path.
                ("Cache-Control".to_string(), "max-age=60".to_string()),
            ],
            body: Self::canned_response(),
        })
    }
}

#[test]
fn post_mode_sends_body_and_parses() {
    let stub = Stub::new();
    let client = DohClient::new("https://dns.google/dns-query", &stub);

    let msg = Message::a_query("example.com");
    let resp = client.query(&msg).unwrap();

    let last = stub.last.lock().unwrap();
    let req = last.as_ref().unwrap();
    assert_eq!(req.method, Method::Post);
    assert_eq!(req.url, "https://dns.google/dns-query");
    let hdr = |name: &str| {
        req.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(hdr("content-type").unwrap(), "application/dns-message");
    assert_eq!(hdr("accept").unwrap(), "application/dns-message");
    assert!(req.body.is_some());

    assert_eq!(resp.answers.len(), 1);
    assert_eq!(
        resp.answers[0].rdata,
        RData::A("93.184.216.34".parse().unwrap())
    );
}

#[test]
fn get_mode_uses_dns_query_param() {
    let stub = Stub::new();
    let client = DohClient::new("https://dns.google/dns-query", &stub).with_method(Method::Get);

    let msg = Message::a_query("example.com");
    let raw = msg.to_bytes();
    client.query_raw(&raw).unwrap();

    let last = stub.last.lock().unwrap();
    let req = last.as_ref().unwrap();
    assert_eq!(req.method, Method::Get);
    assert!(req.url.starts_with("https://dns.google/dns-query?dns="));
    assert!(req.body.is_none());
    // The dns parameter must be base64url without padding.
    let param = req.url.rsplit('=').next().unwrap();
    assert!(!param.contains('='));
    assert!(!param.contains('+'));
    assert!(!param.contains('/'));
}

#[test]
fn caching_avoids_second_request() {
    let stub = Stub::new();
    let client = DohClient::new("https://dns.google/dns-query", &stub)
        .with_method(Method::Get)
        .with_cache();

    let raw = Message::a_query("example.com").to_bytes();
    let _ = client.query_raw(&raw).unwrap();
    let _ = client.query_raw(&raw).unwrap();

    // Second identical GET should be served from cache -> only one HTTP call.
    assert_eq!(stub.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn non_200_status_is_an_error() {
    struct FailStub;
    impl HttpClient for FailStub {
        fn send(
            &self,
            _req: &HttpRequest,
        ) -> std::result::Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>> {
            Ok(HttpResponse {
                status: 503,
                headers: vec![],
                body: vec![],
            })
        }
    }
    let client = DohClient::new("https://x/dns-query", FailStub);
    let err = client.query_raw(&[0; 12]).unwrap_err();
    assert!(matches!(err, Error::HttpStatus { status: 503 }));
}
