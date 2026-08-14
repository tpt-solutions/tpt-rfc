// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A minimal `std::net` TCP server that runs a [`crate::session::Session`] per
//! accepted connection.

use std::io::{BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use crate::backend::MailboxBackend;
use crate::session::Session;

/// A POP3 server bound to a TCP listener.
///
/// Construct with [`Server::new`] from any [`MailboxBackend`], then call
/// [`Server::serve`] to block accepting connections (one thread per client).
pub struct Server {
    backend: Arc<dyn MailboxBackend>,
}

impl Server {
    /// Create a server using `backend` for all connections.
    pub fn new(backend: Arc<dyn MailboxBackend>) -> Self {
        Self { backend }
    }

    /// Bind to `addr` and serve clients forever. Each connection is handled in
    /// its own thread. Returns only on a fatal listener error.
    pub fn serve(&self, addr: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr)?;
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let backend = Arc::clone(&self.backend);
                    std::thread::spawn(move || {
                        if let Err(e) = handle(stream, backend) {
                            // A connection-level error (reset, etc.) is logged
                            // but does not tear down the server.
                            eprintln!("pop3 connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("pop3 accept error: {}", e);
                }
            }
        }
        Ok(())
    }
}

fn handle(stream: TcpStream, backend: Arc<dyn MailboxBackend>) -> std::io::Result<()> {
    let peer = stream.peer_addr().ok();
    let mut read_half = BufReader::new(stream.try_clone()?);
    let mut write_half = stream;
    let mut session = Session::new(backend);
    session.run(&mut read_half, &mut write_half)?;
    write_half.flush()?;
    if let Some(peer) = peer {
        eprintln!("pop3 session closed for {}", peer);
    }
    Ok(())
}
