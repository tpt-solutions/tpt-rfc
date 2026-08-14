// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A minimal `std::net` TCP server that runs a [`crate::session::Session`] per
//! accepted connection.

use std::io::{BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use crate::backend::MailDelivery;
use crate::session::{Extensions, Session};

/// A blocking SMTP server bound to a TCP listener.
///
/// Construct with [`Server::new`], optionally configure ESMTP [`Extensions`],
/// then call [`Server::serve`] to accept clients (one thread per connection).
pub struct Server {
    backend: Arc<dyn MailDelivery>,
    hostname: String,
    extensions: Extensions,
    max_message: usize,
}

impl Server {
    /// Create a server using `backend` and the host's name as the advertised
    /// hostname.
    pub fn new(backend: Arc<dyn MailDelivery>) -> Self {
        let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
        Self {
            backend,
            hostname,
            extensions: Extensions::default(),
            max_message: 25 * 1024 * 1024,
        }
    }

    /// Create a server advertising `hostname` to clients.
    pub fn with_hostname(backend: Arc<dyn MailDelivery>, hostname: impl Into<String>) -> Self {
        Self {
            backend,
            hostname: hostname.into(),
            extensions: Extensions::default(),
            max_message: 25 * 1024 * 1024,
        }
    }

    /// Configure the ESMTP extensions advertised by the server.
    pub fn set_extensions(&mut self, extensions: Extensions) -> &mut Self {
        self.extensions = extensions;
        self
    }

    /// Set the maximum accepted message size in octets.
    pub fn set_max_message(&mut self, max: usize) -> &mut Self {
        self.max_message = max;
        self
    }

    /// Bind to `addr` and serve clients forever. Each connection is handled in
    /// its own thread. Returns only on a fatal listener error.
    pub fn serve(&self, addr: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr)?;
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let backend = Arc::clone(&self.backend);
                    let hostname = self.hostname.clone();
                    let extensions = self.extensions.clone();
                    let max_message = self.max_message;
                    std::thread::spawn(move || {
                        if let Err(e) = handle(stream, backend, hostname, extensions, max_message) {
                            eprintln!("smtp connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("smtp accept error: {}", e);
                }
            }
        }
        Ok(())
    }
}

fn handle(
    stream: TcpStream,
    backend: Arc<dyn MailDelivery>,
    hostname: String,
    extensions: Extensions,
    max_message: usize,
) -> std::io::Result<()> {
    let peer = stream.peer_addr().ok();
    let mut read_half = BufReader::new(stream.try_clone()?);
    let mut write_half = stream;
    let mut session = Session::with_hostname(backend, hostname);
    session.set_extensions(extensions).set_max_message(max_message);
    session.run(&mut read_half, &mut write_half)?;
    write_half.flush()?;
    if let Some(peer) = peer {
        eprintln!("smtp session closed for {}", peer);
    }
    Ok(())
}
