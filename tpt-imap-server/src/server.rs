// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! TCP server: binds a listener, accepts connections, and runs one
//! [`Session`](crate::session::Session) per connection on its own thread.

use std::io::{BufReader, BufWriter};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use crate::session::Session;
use crate::store::MailboxStore;

/// An IMAP4rev2 server over a [`MailboxStore`].
pub struct Server<S: MailboxStore> {
    store: Arc<S>,
}

impl<S: MailboxStore> Server<S> {
    /// Create a server backed by the given store.
    pub fn new(store: S) -> Self {
        Server {
            store: Arc::new(store),
        }
    }

    /// Bind to `addr` and serve forever (one thread per connection).
    pub fn serve(self, addr: impl ToSocketAddrs) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr)?;
        self.accept_loop(listener)
    }

    /// Bind to `addr`, serve in a background thread, and return the resolved
    /// local address plus the join handle. Useful for tests.
    pub fn spawn(self, addr: impl ToSocketAddrs) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
        let listener = TcpListener::bind(addr)?;
        let local = listener.local_addr()?;
        let handle = thread::spawn(move || {
            let _ = self.accept_loop(listener);
        });
        Ok((local, handle))
    }

    fn accept_loop(self, listener: TcpListener) -> std::io::Result<()> {
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    let store = self.store.clone();
                    thread::spawn(move || {
                        let _ = handle_connection(s, store);
                    });
                }
                Err(_) => continue,
            }
        }
        Ok(())
    }
}

fn handle_connection<S: MailboxStore>(stream: TcpStream, store: Arc<S>) -> std::io::Result<()> {
    let reader = BufReader::new(stream.try_clone()?);
    let writer = BufWriter::new(stream);
    let mut session = Session::new(store);
    session.run(reader, writer)
}
