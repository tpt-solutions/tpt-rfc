// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal reference server: an in-memory store with one user, serving on
//! `127.0.0.1:143` (change the address via the single constant below, or run
//! as a non-privileged user on a high port).

use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;

use tpt_imap_server::{Flag, InMemoryStore, Server, SystemFlag};

fn main() -> io::Result<()> {
    let addr: SocketAddr = "127.0.0.1:143".parse().expect("valid socket address");
    eprintln!("tpt-imap-server listening on {addr}");

    let store = InMemoryStore::new().with_user("alice", "secret");
    store.add_mailbox("alice", "INBOX").ok();

    let welcome = b"From: alice@example.com\r\nSubject: Welcome\r\n\r\nHello, world!\r\n".to_vec();
    store
        .add_message("alice", "INBOX", welcome, HashSet::new(), 0)
        .ok();

    let seen: HashSet<Flag> = [Flag::System(SystemFlag::Seen)].into_iter().collect();
    let second = b"From: bob@example.com\r\nSubject: Second\r\n\r\nAnother message.\r\n".to_vec();
    store.add_message("alice", "INBOX", second, seen, 0).ok();

    Server::new(store).serve(addr)
}
