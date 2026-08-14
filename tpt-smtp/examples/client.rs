// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Example: a tiny SMTP client that submits a message over TCP.
//!
//! ```no_run
//! cargo run --example client -- 127.0.0.1:2525 alice@example.com bob@example.org
//! ```
//!
//! Connects, issues `EHLO`, `MAIL`, `RCPT`, `DATA`, then `QUIT`.

use std::io::{BufReader, Write};
use std::net::TcpStream;

use tpt_smtp::client::Client;
use tpt_smtp::message::{Address, MessageBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: client <host:port> <from> <to> [<to> ...]");
        std::process::exit(2);
    }
    let addr = &args[1];
    let from = &args[2];
    let recipients: Vec<&str> = args[3..].iter().map(|s| s.as_str()).collect();

    let stream = TcpStream::connect(addr)?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;

    let mut client = Client::new(&mut reader, &mut writer)?;
    let ehlo = client.ehlo("tpt-smtp-client")?;
    println!("EHLO -> {}", ehlo.code);

    let msg = MessageBuilder::new()
        .from_mailbox(&Address::new(
            from.split('@').next().unwrap_or("sender"),
            from.split('@').nth(1).unwrap_or("localhost"),
        ))
        .to_mailboxes(
            &recipients
                .iter()
                .map(|r| {
                    Address::new(
                        r.split('@').next().unwrap_or("rcpt"),
                        r.split('@').nth(1).unwrap_or("localhost"),
                    )
                })
                .collect::<Vec<_>>(),
        )
        .subject("Test message from tpt-smtp")
        .body("Hello from the tpt-smtp example client.\r\n")
        .build();

    let reply = client.send_mail(Some(from), &recipients, &msg)?;
    println!("DATA -> {} {}", reply.code, reply.message());

    client.quit()?;
    Ok(())
}
