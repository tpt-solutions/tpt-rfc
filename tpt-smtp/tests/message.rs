// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for the Internet Message Format / MIME module (RFC 5322 + MIME).

use tpt_smtp::message::{
    decode_header, encode_header_if_needed, parse_addresses, Message, MessageBuilder,
};

#[test]
fn parse_basic_headers_and_addresses() {
    let raw = concat!(
        "From: Alice <alice@example.com>\r\n",
        "To: Bob <bob@example.org>\r\n",
        "Subject: Hello\r\n",
        "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n",
        "\r\n",
        "Body text.\r\n",
    );
    let msg = Message::parse(raw.as_bytes());
    assert_eq!(msg.subject().as_deref(), Some("Hello"));
    assert_eq!(msg.date(), Some("Mon, 01 Jan 2024 00:00:00 +0000"));

    let from = msg.from();
    assert_eq!(from.len(), 1);
    assert_eq!(from[0].local_part, "alice");
    assert_eq!(from[0].domain, "example.com");
    assert_eq!(from[0].display_name.as_deref(), Some("Alice"));

    let to = msg.to();
    assert_eq!(to.len(), 1);
    assert_eq!(to[0].address(), "bob@example.org");

    assert!(String::from_utf8_lossy(&msg.body).contains("Body text."));
}

#[test]
fn parse_address_list_and_group() {
    let addrs = parse_addresses("a@x.example, Group: b@y.example, c@z.example; d@w.example");
    let addresses: Vec<String> = addrs.iter().map(|a| a.address()).collect();
    assert_eq!(
        addresses,
        vec![
            "a@x.example".to_string(),
            "b@y.example".to_string(),
            "c@z.example".to_string(),
            "d@w.example".to_string(),
        ]
    );
}

#[test]
fn rfc2047_base64_subject_decodes() {
    // =?UTF-8?B?SGVsbG8=?= decodes to "Hello".
    let decoded = decode_header("=?UTF-8?B?SGVsbG8=?=");
    assert_eq!(decoded, "Hello");
}

#[test]
fn rfc2047_q_encoded_word_decodes() {
    let decoded = decode_header("=?ISO-8859-1?Q?Hello_World=3Dtest?=");
    assert_eq!(decoded, "Hello World=test");
}

#[test]
fn mixed_encoded_and_plain_header() {
    let decoded = decode_header("Re: =?UTF-8?B?SGVsbG8=?= there");
    assert_eq!(decoded, "Re: Hello there");
}

#[test]
fn mime_multipart_parses_children() {
    let raw = concat!(
        "Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n",
        "\r\n",
        "--BOUND\r\n",
        "Content-Type: text/plain\r\n",
        "\r\n",
        "Part one\r\n",
        "--BOUND\r\n",
        "Content-Type: text/plain\r\n",
        "\r\n",
        "Part two\r\n",
        "--BOUND--\r\n",
    );
    let msg = Message::parse(raw.as_bytes());
    let mime = msg.mime();
    assert_eq!(mime.media_type(), "multipart/mixed");
    assert_eq!(mime.children.len(), 2);
    assert_eq!(mime.children[0].content_text(), "Part one\n");
    assert_eq!(mime.children[1].content_text(), "Part two\n");
}

#[test]
fn mime_base64_part_decodes() {
    // "Hello" base64-encoded is "SGVsbG8=".
    let raw = concat!(
        "Content-Type: text/plain\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "\r\n",
        "SGVsbG8=\r\n",
    );
    let msg = Message::parse(raw.as_bytes());
    let mime = msg.mime();
    assert_eq!(mime.content_text(), "Hello");
}

#[test]
fn mime_quoted_printable_decodes() {
    let raw = concat!(
        "Content-Transfer-Encoding: quoted-printable\r\n",
        "\r\n",
        "Hello=20World=3Dtest\r\n",
    );
    let msg = Message::parse(raw.as_bytes());
    let mime = msg.mime();
    assert_eq!(mime.content_text(), "Hello World=test\r\n");
}

#[test]
fn builder_produces_well_formed_message() {
    use tpt_smtp::message::Address;
    let msg = MessageBuilder::new()
        .from_mailbox(&Address::new("alice", "example.com"))
        .to_mailboxes(&[Address::new("bob", "example.org")])
        .subject("Hi Bob")
        .body("Hello there.\r\n")
        .build();
    let text = String::from_utf8(msg).unwrap();

    // Headers present and CRLF terminated.
    assert!(text.starts_with("From: alice@example.com\r\n"));
    assert!(text.contains("To: bob@example.org\r\n"));
    assert!(text.contains("Subject: Hi Bob\r\n"));
    // Date is auto-filled (required by RFC 5322).
    assert!(text.contains("Date: "));
    // Blank line separator then body.
    assert!(text.contains("\r\n\r\nHello there.\r\n"));

    // Round-trips back through the parser.
    let parsed = Message::parse(text.as_bytes());
    assert_eq!(parsed.subject().as_deref(), Some("Hi Bob"));
    assert_eq!(parsed.from()[0].address(), "alice@example.com");
}

#[test]
fn builder_encodes_non_ascii_subject() {
    let encoded = encode_header_if_needed("Café");
    assert!(encoded.starts_with("=?UTF-8?B?"));
    // Round-trip decode.
    assert_eq!(decode_header(&encoded), "Café");
}
