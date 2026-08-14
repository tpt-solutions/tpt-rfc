// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Example DHCP server. Binds a UDP socket and serves leases from the
//! in-memory backend. Binding to port 67 normally requires privileges; run as
//! root or grant the capability, or change `BIND` to a high port for testing.

use tpt_dhcp::memory::PoolConfig;
use tpt_dhcp::server::Server;

fn main() -> std::io::Result<()> {
    let config = PoolConfig::default();
    let mut server = Server::new(config);
    println!(
        "tpt-dhcp server listening on 0.0.0.0:67 (pool {}-{})",
        server.config().pool_start,
        server.config().pool_end
    );
    // Serving is blocking; see `Server::process_bytes` for a custom transport.
    server.run("0.0.0.0:67")
}
