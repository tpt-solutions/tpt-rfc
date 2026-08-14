// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end session tests driving a [`Session`] over in-memory I/O. These
//! stand in for the real-POP3-client interop test that requires an external
//! client (not available in this environment) and exercise the RFC-required
//! command/response behaviour directly.

use std::io::Cursor;
use std::sync::Arc;

use tpt_pop3::memory::MemoryBackend;
use tpt_pop3::session::Session;

fn run(backend: Arc<MemoryBackend>, script: &str) -> String {
    let mut reader = Cursor::new(script.as_bytes().to_vec());
    let mut writer: Vec<u8> = Vec::new();
    let mut session = Session::new(backend);
    session.run(&mut reader, &mut writer).unwrap();
    String::from_utf8(writer).unwrap()
}

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
fn greeting_is_sent_on_connect() {
    let out = run(Arc::new(backend()), "");
    assert!(out.starts_with("+OK POP3 server ready <"), "got: {}", out);
}

#[test]
fn authorization_rejects_bad_password() {
    let out = run(Arc::new(backend()), "USER alice\r\nPASS wrong\r\nQUIT\r\n");
    assert!(out.contains("\r\n-ERR authentication failed\r\n"));
}

#[test]
fn full_transaction_core_commands() {
    let out = run(
        Arc::new(backend()),
        concat!(
            "USER alice\r\n",
            "PASS secret\r\n",
            "STAT\r\n",
            "LIST\r\n",
            "RETR 1\r\n",
            "DELE 1\r\n",
            "STAT\r\n",
            "RSET\r\n",
            "STAT\r\n",
            "QUIT\r\n",
        ),
    );

    assert!(out.contains("\r\n+OK mailbox has been opened\r\n"));
    // STAT: 2 messages.
    assert!(out.contains("\r\n+OK 2 "));
    // LIST multi-line for 2 messages.
    assert!(out.contains("\r\n1 56\r\n"));
    assert!(out.contains("\r\n2 62\r\n"));
    assert!(out.contains("\r\n.\r\n"));
    // RETR 1 returns the first message content (CRLF + terminating ".").
    assert!(out.contains("Subject: first\r\n"));
    assert!(out.contains("Hello, world!\r\n"));
    assert!(out.contains("\r\n.\r\n"));
    // After DELE 1, STAT shows 1.
    assert!(out.contains("\r\n+OK 1 "));
    // After RSET, back to 2.
    assert!(out.contains("\r\n+OK 2 "));
    assert!(out.ends_with("+OK POP3 server signing off\r\n"));
}

#[test]
fn retr_of_deleted_message_is_rejected() {
    let out = run(
        Arc::new(backend()),
        "USER alice\r\nPASS secret\r\nDELE 1\r\nRETR 1\r\nQUIT\r\n",
    );
    assert!(out.contains("\r\n-ERR no such message\r\n"));
}

#[test]
fn uidl_lists_unique_ids() {
    let out = run(
        Arc::new(backend()),
        "USER alice\r\nPASS secret\r\nUIDL\r\nQUIT\r\n",
    );
    assert!(out.contains("\r\n1 alice:0\r\n"));
    assert!(out.contains("\r\n2 alice:1\r\n"));
}

#[test]
fn top_returns_headers_and_n_body_lines() {
    let out = run(
        Arc::new(backend()),
        "USER alice\r\nPASS secret\r\nTOP 1 0\r\nTOP 1 1\r\nQUIT\r\n",
    );
    // TOP 1 0: headers only, no body line.
    let header_block = "Subject: first\r\n\r\n";
    assert!(out.contains(header_block));
    // TOP 1 1: one body line.
    assert!(out.contains("Hello, world!\r\n"));
}

#[test]
fn dot_stuffing_on_multiline_response() {
    let b = MemoryBackend::new();
    b.add_user(
        "alice",
        "secret",
        vec![b".hidden\r\nnormal line\r\n".to_vec()],
    );
    let out = run(
        Arc::new(b),
        "USER alice\r\nPASS secret\r\nRETR 1\r\nQUIT\r\n",
    );
    // Leading dot must be escaped to "..".
    assert!(out.contains("..hidden\r\n"));
    assert!(!out.contains("\r\n.hidden\r\n"));
}

#[test]
fn quit_expunges_deleted_messages() {
    let backend = Arc::new(backend());
    // First session deletes message 1 and quits (committing the deletion).
    let first = run(
        Arc::clone(&backend),
        "USER alice\r\nPASS secret\r\nDELE 1\r\nQUIT\r\n",
    );
    assert!(first.contains("+OK POP3 server signing off"));

    // Second session should now see only 1 message (the deleted one is gone).
    let second = run(
        Arc::clone(&backend),
        "USER alice\r\nPASS secret\r\nSTAT\r\nQUIT\r\n",
    );
    assert!(second.contains("\r\n+OK 1 "), "got: {}", second);
}

#[test]
fn apop_authenticates() {
    // Compute the expected APOP digest for the timestamp using the same scheme
    // the backend uses (md5(timestamp + password)).
    use md5::{Digest, Md5};
    let b = MemoryBackend::new();
    b.add_user("alice", "secret", vec![b"msg\r\n".to_vec()]);
    // We need the timestamp the session generated; capture it from the greeting.
    let out = run(Arc::new(b), "QUIT\r\n");
    let ts = out
        .lines()
        .next()
        .unwrap()
        .trim_start_matches("+OK POP3 server ready <")
        .trim_end_matches('>');
    let mut h = Md5::new();
    h.update(ts.as_bytes());
    h.update(b"secret");
    let digest = format!("{:x}", h.finalize());

    let b2 = MemoryBackend::new();
    b2.add_user("alice", "secret", vec![b"msg\r\n".to_vec()]);
    let out = run(
        Arc::new(b2),
        &format!("APOP alice {}\r\nSTAT\r\nQUIT\r\n", digest),
    );
    assert!(out.contains("\r\n+OK mailbox has been opened\r\n"));
    assert!(out.contains("\r\n+OK 1 "));
}

#[test]
fn apop_wrong_digest_rejected() {
    let out = run(Arc::new(backend()), "APOP alice deadbeef\r\nQUIT\r\n");
    assert!(out.contains("\r\n-ERR authentication failed\r\n"));
}

#[test]
fn unknown_command_in_transaction_is_err() {
    let out = run(
        Arc::new(backend()),
        "USER alice\r\nPASS secret\r\nFROBNICATE\r\nQUIT\r\n",
    );
    assert!(out.contains("\r\n-ERR command not recognized\r\n"));
}

#[test]
fn pass_before_user_is_err() {
    let out = run(Arc::new(backend()), "PASS secret\r\nQUIT\r\n");
    assert!(out.contains("\r\n-ERR send USER first\r\n"));
}
