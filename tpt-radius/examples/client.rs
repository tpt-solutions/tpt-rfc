// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Example RADIUS authentication client.
//!
//! Run the `server` example (or any RADIUS server) first, then:
//!
//! ```text
//! cargo run -p tpt-radius --example client
//! ```

use std::time::Duration;

use tpt_radius::Client;

fn main() -> std::io::Result<()> {
    let mut client = Client::new("secret");
    let request = client
        .access_request("alice", "s3cret")
        .expect("failed to build request");

    match client.exchange("127.0.0.1:1812", &request, Duration::from_secs(5)) {
        Ok(reply) => {
            let ok = client.verify_response(&request, &reply);
            println!(
                "received reply code {} (authenticator valid: {ok})",
                reply.code.to_u8()
            );
        }
        Err(e) => eprintln!("exchange failed: {e}"),
    }
    Ok(())
}
