// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Example: an interactive POP3 client built on `tpt_pop3::client::TcpClient`.
//!
//! ```no_run
//! cargo run --example client -- 127.0.0.1:1110 alice secret
//! ```
//!
//! Connects, authenticates with USER/PASS, then prints the mailbox summary and
//! drops you into a tiny REPL that accepts `STAT`, `LIST`, `UIDL`, `RETR n`,
//! `TOP n k`, `DELE n`, `RSET`, and `QUIT`. Handy for exercising `tpt-pop3`
//! (or any POP3 server) during development.

use std::io::{BufRead, Write};

use tpt_pop3::client::{Error, TcpClient};

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: client <host:port> <user> <pass>");
        std::process::exit(2);
    }
    let addr = &args[1];
    let user = &args[2];
    let pass = &args[3];

    let mut client = TcpClient::connect(addr)?;
    client.login(user, pass)?;
    println!("connected; greeting: {}", client.greeting());

    let stat = client.stat()?;
    println!("STAT: {} messages, {} octets", stat.count, stat.octets);

    let stdin = std::io::stdin();
    print_help();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if !dispatch(&mut client, line) {
            break;
        }
        println!("---");
    }

    client.quit()?;
    Ok(())
}

/// Returns `false` if the session should end (QUIT/EOF).
fn dispatch(client: &mut TcpClient, line: &str) -> bool {
    let upper = line.to_ascii_uppercase();
    match upper.split_whitespace().collect::<Vec<_>>().as_slice() {
        ["QUIT"] => {
            let _ = client.quit();
            return false;
        }
        ["STAT"] => match client.stat() {
            Ok(s) => println!("{} messages, {} octets", s.count, s.octets),
            Err(e) => println!("error: {}", e),
        },
        ["LIST"] => match client.list(None) {
            Ok(entries) => {
                for e in entries {
                    println!("{}: {} octets", e.num, e.size.unwrap_or(0));
                }
            }
            Err(e) => println!("error: {}", e),
        },
        ["UIDL"] => match client.uidl(None) {
            Ok(entries) => {
                for e in entries {
                    println!("{}: {}", e.num, e.uid.clone().unwrap_or_default());
                }
            }
            Err(e) => println!("error: {}", e),
        },
        ["RETR", n] => match n.parse::<usize>() {
            Ok(num) => match client.retr(num) {
                Ok(bytes) => {
                    let _ = std::io::stdout().write_all(&bytes);
                }
                Err(e) => println!("error: {}", e),
            },
            Err(_) => println!("usage: RETR <n>"),
        },
        ["TOP", n, k] => match (n.parse::<usize>(), k.parse::<usize>()) {
            (Ok(num), Ok(k)) => match client.top(num, k) {
                Ok(bytes) => {
                    let _ = std::io::stdout().write_all(&bytes);
                }
                Err(e) => println!("error: {}", e),
            },
            _ => println!("usage: TOP <n> <k>"),
        },
        ["DELE", n] => match n.parse::<usize>() {
            Ok(num) => match client.dele(num) {
                Ok(()) => println!("message {} marked deleted", num),
                Err(e) => println!("error: {}", e),
            },
            Err(_) => println!("usage: DELE <n>"),
        },
        ["RSET"] => match client.rset() {
            Ok(()) => println!("deletions reset"),
            Err(e) => println!("error: {}", e),
        },
        _ => print_help(),
    }
    true
}

fn print_help() {
    println!("commands: STAT LIST UIDL RETR n TOP n k DELE n RSET QUIT");
}
