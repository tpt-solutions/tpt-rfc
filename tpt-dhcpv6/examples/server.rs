// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Example DHCPv6 server. Binds a UDP socket and serves leases from the
//! in-memory backend. Binding to port 547 normally requires privileges; run as
//! root or grant the capability, or change `BIND` to a high port for testing.

use tpt_dhcpv6::memory::PoolConfig;
use tpt_dhcpv6::server::Server;

fn main() -> std::io::Result<()> {
    let config = PoolConfig::default();
    let mut server = Server::new(config);
    println!(
        "tpt-dhcpv6 server listening on [::]:547 (server DUID {:?})",
        server.config().server_duid
    );
    // Serving is blocking; see `Server::process_bytes` for a custom transport.
    server.run("[::]:547")
}
