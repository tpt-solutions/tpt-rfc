// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Resolve a name over DoH using the `reqwest` backend.
//!
//! Run with: `cargo run --features reqwest --example basic -- example.com`

#[cfg(feature = "reqwest")]
fn main() {
    use tpt_doh::{DohClient, ReqwestClient};

    let name = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "example.com".to_string());
    let client = DohClient::new(
        "https://dns.google/dns-query",
        ReqwestClient::new().unwrap(),
    );

    println!("A records for {name}:");
    match client.lookup_a(&name) {
        Ok(addrs) => {
            for a in addrs {
                println!("  {a}");
            }
        }
        Err(e) => eprintln!("lookup failed: {e}"),
    }

    println!("AAAA records for {name}:");
    match client.lookup_aaaa(&name) {
        Ok(addrs) => {
            for a in addrs {
                println!("  {a}");
            }
        }
        Err(e) => eprintln!("lookup failed: {e}"),
    }
}

#[cfg(not(feature = "reqwest"))]
fn main() {
    eprintln!("enable the `reqwest` feature to run this example: --features reqwest");
}
