// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Client tests driving [`Client`] against a scripted in-memory "server"
//! (a `Cursor` of canned replies as the reader, a `Cursor` sink as the writer).
//! This stands in for the real-MTA interop test that requires a network peer
//! (not available in this environment).

use std::io::Cursor;

use tpt_smtp::client::Client;

#[test]
fn client_full_transaction() {
    // Server replies in the order the client will read them.
    let replies = concat!(
        "220 mail.example ESMTP ready\r\n",
        "250-mail.example greets client\r\n",
        "250 8BITMIME\r\n",
        "250 OK\r\n",               // MAIL FROM
        "250 OK\r\n",               // RCPT TO
        "354 Start mail input\r\n", // DATA
        "250 OK: queued\r\n",       // final
        "221 Bye\r\n",              // QUIT
    );
    let reader = Cursor::new(replies.as_bytes().to_vec());
    let writer: Cursor<Vec<u8>> = Cursor::new(Vec::new());

    let mut client = Client::new(reader, writer).unwrap();
    let ehlo = client.ehlo("client").unwrap();
    assert!(ehlo.is_success());
    assert!(client.is_extended());

    let final_reply = client
        .send_mail(
            Some("alice@example.com"),
            &["bob@example.org"],
            b"From: alice@example.com\r\nTo: bob@example.org\r\nSubject: Hi\r\n\r\nHello\r\n",
        )
        .unwrap();
    assert!(final_reply.is_success());

    let quit = client.quit().unwrap();
    assert!(quit.code == 221);
}

#[test]
fn client_rejects_negative_greeting() {
    let reader = Cursor::new(b"421 service unavailable\r\n".to_vec());
    let writer: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    let result = Client::new(reader, writer);
    assert!(result.is_err());
}

#[test]
fn client_negative_data_reply_is_error() {
    let replies = concat!(
        "220 ready\r\n",
        "554 transaction failed\r\n", // DATA rejected (client only calls data())
    );
    let reader = Cursor::new(replies.as_bytes().to_vec());
    let writer: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    let mut client = Client::new(reader, writer).unwrap();
    let res = client.data(b"Subject: x\r\n\r\nbody\r\n");
    assert!(res.is_err());
}

#[test]
fn client_dot_stuffing_on_data() {
    let replies = concat!(
        "220 ready\r\n",
        "250 ok\r\n",
        "250 ok\r\n",
        "354 go\r\n",
        "250 queued\r\n",
    );
    let reader = Cursor::new(replies.as_bytes().to_vec());
    let mut writer: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    let mut client = Client::new(reader, &mut writer).unwrap();
    let _ = client.data(b".hidden line\r\nnormal\r\n");
    let sent = String::from_utf8(writer.get_ref().clone()).unwrap();
    // The leading dot of the first line must be escaped.
    assert!(sent.contains("..hidden line\r\n"));
    assert!(sent.ends_with("\r\n.\r\n"));
}
