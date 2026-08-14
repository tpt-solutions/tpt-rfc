// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Example: a tiny interactive POP3 client for interop-checking a server.
//!
//! ```no_run
//! cargo run --example client -- 127.0.0.1:1110 alice secret
//! ```
//!
//! Reads commands from stdin (one per line) and prints the server's responses.
//! Useful for manually exercising `tpt-pop3` (or any POP3 server) during
//! development.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: client <host:port> <user> <pass>");
        std::process::exit(2);
    }
    let addr = &args[1];
    let user = &args[2];
    let pass = &args[3];

    let stream = TcpStream::connect(addr)?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;

    // Server greeting.
    println!("S: {}", read_line(&mut reader)?);

    send(&mut writer, &mut reader, &format!("USER {}", user))?;
    send(&mut writer, &mut reader, &format!("PASS {}", pass))?;

    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        send(&mut writer, &mut reader, &line)?;
        if line.eq_ignore_ascii_case("QUIT") {
            break;
        }
    }
    Ok(())
}

fn send(writer: &mut impl Write, reader: &mut impl BufRead, line: &str) -> std::io::Result<()> {
    writer.write_all(line.as_bytes())?;
    writer.write_all(b"\r\n")?;
    writer.flush()?;

    let status = read_line(reader)?;
    println!("S: {}", status);
    let upper = line.to_ascii_uppercase();
    if upper.starts_with("RETR")
        || upper.starts_with("TOP")
        || upper.starts_with("LIST")
        || upper.starts_with("UIDL")
    {
        // Drain the multi-line response up to the terminating ".".
        loop {
            let l = read_line(reader)?;
            println!("S: {}", l);
            if l == "." {
                break;
            }
        }
    }
    Ok(())
}

fn read_line(reader: &mut impl BufRead) -> std::io::Result<String> {
    let mut buf = String::new();
    reader.read_line(&mut buf)?;
    Ok(buf.trim_end().to_string())
}
