// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end server session tests driving a [`Session`] over in-memory I/O.
//! These stand in for the real-SMTP-client interop test that requires an
//! external client (not available in this environment) and exercise the
//! RFC 5321-required command/response behaviour directly.

use std::io::Cursor;
use std::sync::Arc;

use tpt_smtp::memory::MemoryBackend;
use tpt_smtp::session::{Extensions, Session};

fn run(backend: Arc<MemoryBackend>, script: &str) -> String {
    let mut reader = Cursor::new(script.as_bytes().to_vec());
    let mut writer: Vec<u8> = Vec::new();
    let mut session = Session::with_hostname(Arc::clone(&backend), "mail.example");
    session.set_extensions(Extensions {
        size: true,
        ..Default::default()
    });
    session.run(&mut reader, &mut writer).unwrap();
    String::from_utf8(writer).unwrap()
}

fn backend() -> MemoryBackend {
    MemoryBackend::new()
}

#[test]
fn greeting_and_ehlo() {
    let out = run(Arc::new(backend()), "EHLO client.example\r\nQUIT\r\n");
    assert!(out.starts_with("220 mail.example SMTP tpt-smtp ready"));
    assert!(out.contains("250-mail.example greets client.example\r\n"));
    assert!(out.contains("250-SIZE "));
    assert!(out.contains("250 8BITMIME\r\n"));
    assert!(out.ends_with("221 Service closing transmission channel\r\n"));
}

#[test]
fn helo_is_plain() {
    let out = run(Arc::new(backend()), "HELO client.example\r\nQUIT\r\n");
    assert!(out.contains("\r\n250 mail.example greets client.example\r\n"));
    // HELO must not advertise ESMTP extensions.
    assert!(!out.contains("SIZE"));
}

#[test]
fn command_before_helo_is_bad_sequence() {
    let out = run(Arc::new(backend()), "MAIL FROM:<a@b>\r\nQUIT\r\n");
    assert!(out.contains("\r\n503 Bad sequence of commands\r\n"));
}

#[test]
fn full_mail_transaction() {
    let b = Arc::new(backend());
    let script = concat!(
        "EHLO client.example\r\n",
        "MAIL FROM:<alice@example.com>\r\n",
        "RCPT TO:<bob@example.org>\r\n",
        "DATA\r\n",
        "From: alice@example.com\r\n",
        "To: bob@example.org\r\n",
        "Subject: Hi\r\n",
        "\r\n",
        "Hello Bob.\r\n",
        ".\r\n",
        "QUIT\r\n",
    );
    let out = run(Arc::clone(&b), script);
    assert!(out.contains("\r\n250 OK\r\n")); // MAIL
    assert!(out.contains("\r\n250 OK\r\n")); // RCPT
    assert!(out.contains("\r\n354 Start mail input")); // DATA
    assert!(out.contains("\r\n250 OK: queued as tpt-id\r\n")); // accept
    assert_eq!(b.total_stored(), 1);
    let stored = b.messages_for("bob@example.org");
    assert_eq!(stored.len(), 1);
    let msg = String::from_utf8(stored[0].clone()).unwrap();
    assert!(msg.contains("Subject: Hi"));
    assert!(msg.contains("Hello Bob."));
}

#[test]
fn rset_clears_transaction() {
    let b = Arc::new(backend());
    let script = concat!(
        "EHLO c\r\n",
        "MAIL FROM:<a@b>\r\n",
        "RCPT TO:<x@y>\r\n",
        "RSET\r\n",
        "MAIL FROM:<a@b>\r\n",
        "RCPT TO:<z@w>\r\n",
        "DATA\r\n",
        "Subject: x\r\n\r\nbody\r\n.\r\n",
        "QUIT\r\n",
    );
    let out = run(Arc::clone(&b), script);
    assert!(out.contains("\r\n250 OK\r\n"));
    // Only the post-RSET recipient should have received mail.
    assert_eq!(b.messages_for("z@w").len(), 1);
    assert_eq!(b.messages_for("x@y").len(), 0);
}

#[test]
fn dot_transparency_on_inbound() {
    let b = Arc::new(backend());
    let script = concat!(
        "EHLO c\r\n",
        "MAIL FROM:<a@b>\r\n",
        "RCPT TO:<x@y>\r\n",
        "DATA\r\n",
        "..leading dot\r\n",
        "normal\r\n",
        ".\r\n",
        "QUIT\r\n",
    );
    run(Arc::clone(&b), script);
    let msg = String::from_utf8(b.messages_for("x@y")[0].clone()).unwrap();
    assert!(msg.contains("\r\n.leading dot\r\n"));
    assert!(!msg.contains("\r\n..leading dot\r\n"));
}

#[test]
fn mail_before_ehlo_rejected() {
    let out = run(Arc::new(backend()), "MAIL FROM:<a@b>\r\nQUIT\r\n");
    assert!(out.contains("\r\n503 Bad sequence of commands\r\n"));
}

#[test]
fn rcpt_before_mail_rejected() {
    let out = run(Arc::new(backend()), "EHLO c\r\nRCPT TO:<x@y>\r\nQUIT\r\n");
    assert!(out.contains("\r\n503 Bad sequence of commands\r\n"));
}

#[test]
fn data_without_recipient_rejected() {
    let out = run(Arc::new(backend()), "EHLO c\r\nMAIL FROM:<a@b>\r\nDATA\r\nQUIT\r\n");
    assert!(out.contains("\r\n503 Bad sequence of commands\r\n"));
}

#[test]
fn unknown_command_is_syntax_error() {
    let out = run(Arc::new(backend()), "EHLO c\r\nFROBNICATE\r\nQUIT\r\n");
    assert!(out.contains("\r\n500 Syntax error, command unrecognized\r\n"));
}

#[test]
fn null_reverse_path_accepted() {
    let b = Arc::new(backend());
    let script = concat!(
        "EHLO c\r\n",
        "MAIL FROM:<>\r\n",
        "RCPT TO:<x@y>\r\n",
        "DATA\r\n",
        "Subject: bounce\r\n\r\nhi\r\n.\r\n",
        "QUIT\r\n",
    );
    let out = run(Arc::clone(&b), script);
    assert!(out.contains("\r\n250 OK\r\n"));
    assert_eq!(b.total_stored(), 1);
}

#[test]
fn size_too_large_rejected() {
    let b = Arc::new(backend());
    let out = run(
        Arc::clone(&b),
        "EHLO c\r\nMAIL FROM:<a@b> SIZE=999999999\r\nQUIT\r\n",
    );
    assert!(out.contains("\r\n552 Message exceeds fixed maximum message size\r\n"));
}

#[test]
fn recipient_not_allowed_rejected() {
    let b = Arc::new(backend());
    b.set_allowed_recipients(vec!["bob@example.org".to_string()]);
    let out = run(
        Arc::clone(&b),
        "EHLO c\r\nMAIL FROM:<a@b>\r\nRCPT TO:<eve@evil>\r\nQUIT\r\n",
    );
    assert!(out.contains("\r\n550 No such recipient: eve@evil\r\n"));
}

#[test]
fn starttls_advertised_and_accepted() {
    let b = Arc::new(backend());
    let mut session = Session::with_hostname(Arc::clone(&b), "mail.example");
    session.set_extensions(Extensions {
        starttls: true,
        ..Default::default()
    });
    let mut reader = Cursor::new(b"EHLO c\r\nSTARTTLS\r\nQUIT\r\n".to_vec());
    let mut writer: Vec<u8> = Vec::new();
    session.run(&mut reader, &mut writer).unwrap();
    let out = String::from_utf8(writer).unwrap();
    assert!(out.contains("250-STARTTLS\r\n"));
    assert!(out.contains("\r\n220 Ready to start TLS\r\n"));
}
