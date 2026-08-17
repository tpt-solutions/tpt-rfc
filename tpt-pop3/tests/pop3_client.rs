// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for the POP3 [`Client`] protocol core, driven against an in-memory
//! [`Session`] (no network) and against a real in-crate [`Server`] over TCP.

use std::io::{Cursor, Write};
use std::sync::Arc;

use tpt_pop3::client::{Client, Error, TcpClient};
use tpt_pop3::memory::MemoryBackend;
use tpt_pop3::session::Session;

fn backend() -> MemoryBackend {
    let b = MemoryBackend::new();
    b.add_user(
        "alice",
        "secret",
        vec![
            b"From: bob@example.com\r\nSubject: first\r\n\r\nHello, world!\r\n".to_vec(),
            b"From: carol@example.com\r\nSubject: second\r\n\r\nAnother message.\r\n".to_vec(),
        ],
    );
    b
}

#[test]
fn client_parses_multiline_and_status() {
    // A server greeting + STAT + a LIST listing + QUIT, hand-authored to mirror
    // what the in-crate Session produces. Exercises the Client parser without a
    // live Session.
    let script = concat!(
        "+OK POP3 server ready <1.2@host>\r\n",
        "+OK 2 118\r\n", // STAT
        "+OK 2 messages\r\n",
        "1 56\r\n",
        "2 62\r\n",
        ".\r\n",
        "+OK\r\n", // QUIT
    );
    let mut reader = Cursor::new(script.as_bytes().to_vec());
    let mut writer: Vec<u8> = Vec::new();

    let mut client = Client::new(&mut reader, &mut writer).unwrap();
    let stat = client.stat().unwrap();
    assert_eq!(stat.count, 2);
    assert_eq!(stat.octets, 118);

    let list = client.list(None).unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].num, 1);
    assert_eq!(list[0].size, Some(56));
    assert_eq!(list[1].num, 2);
    assert_eq!(list[1].size, Some(62));

    client.quit().unwrap();
    let sent = String::from_utf8(writer).unwrap();
    assert!(sent.contains("STAT\r\n"));
    assert!(sent.contains("LIST\r\n"));
    assert!(sent.contains("QUIT\r\n"));
}

#[test]
fn client_propagates_server_error() {
    let script = concat!(
        "+OK POP3 server ready <1.2@host>\r\n",
        "-ERR no such message\r\n", // DELE 9
    );
    let mut reader = Cursor::new(script.as_bytes().to_vec());
    let mut writer: Vec<u8> = Vec::new();
    let mut client = Client::new(&mut reader, &mut writer).unwrap();
    let err = client.dele(9).unwrap_err();
    assert!(matches!(err, Error::ServerError(_)));
    if let Error::ServerError(msg) = err {
        assert_eq!(msg, "no such message");
    }
}

#[test]
fn client_unstuffs_dotted_multiline() {
    // RETR 1 returns a message whose first line begins with a dot.
    let msg = b".hidden\r\nnormal line\r\n";
    let script = format!(
        concat!(
            "+OK POP3 server ready <1.2@host>\r\n",
            "+OK 8 octets\r\n",
            "{}",
            ".\r\n",
            "+OK\r\n"
        ),
        // escaped leading dot in the wire form:
        "..hidden\r\nnormal line\r\n"
    );
    let mut reader = Cursor::new(script.into_bytes());
    let mut writer: Vec<u8> = Vec::new();
    let mut client = Client::new(&mut reader, &mut writer).unwrap();
    let got = client.retr(1).unwrap();
    assert_eq!(got, msg.to_vec());
    let _ = msg;
}

#[test]
fn client_over_tcp_against_in_crate_server() {
    use std::net::TcpListener;
    use std::thread;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let backend = Arc::new(backend());

    let server_thread = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;
            let mut session = Session::new(backend);
            let _ = session.run(&mut reader, &mut writer);
            let _ = writer.flush();
            let _ = writer.flush();
        }
    });

    let mut client = TcpClient::connect(&addr.to_string()).unwrap();
    client.login("alice", "secret").unwrap();

    let stat = client.stat().unwrap();
    assert_eq!(stat.count, 2);

    let list = client.list(None).unwrap();
    assert_eq!(list.len(), 2);

    let uidl = client.uidl(None).unwrap();
    assert_eq!(uidl.len(), 2);
    assert!(uidl[0].uid.as_deref().unwrap().starts_with("alice:"));

    let msg = client.retr(1).unwrap();
    assert!(String::from_utf8_lossy(&msg).contains("Subject: first"));

    let top = client.top(1, 0).unwrap();
    assert!(String::from_utf8_lossy(&top).contains("Subject: first"));

    client.dele(1).unwrap();
    let stat2 = client.stat().unwrap();
    assert_eq!(stat2.count, 1);

    client.rset().unwrap();
    let stat3 = client.stat().unwrap();
    assert_eq!(stat3.count, 2);

    client.quit().unwrap();
    server_thread.join().unwrap();
}

#[test]
fn client_apop_against_in_crate_server() {
    use std::net::TcpListener;
    use std::thread;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let backend = Arc::new(backend());

    let server_thread = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;
            let mut session = Session::new(backend);
            let _ = session.run(&mut reader, &mut writer);
            let _ = writer.flush();
            let _ = writer.flush();
        }
    });

    let mut client = TcpClient::connect(&addr.to_string()).unwrap();
    // Extract the <timestamp> from the greeting.
    let greeting = client.greeting().to_string();
    let ts = greeting
        .trim_start_matches("POP3 server ready <")
        .trim_end_matches('>')
        .to_string();
    client.apop("alice", "secret", &ts).unwrap();

    let stat = client.stat().unwrap();
    assert_eq!(stat.count, 2);

    client.quit().unwrap();
    server_thread.join().unwrap();
}
