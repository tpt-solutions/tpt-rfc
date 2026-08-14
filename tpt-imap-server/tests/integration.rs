// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end protocol tests exercised over a real TCP connection against a
//! running [`Server`] backed by the in-memory store.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::thread::JoinHandle;
use std::time::Duration;

use base64::Engine;
use tpt_imap_server::{Flag, InMemoryStore, Server, SystemFlag};

struct Client {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
    tag: u32,
}

impl Client {
    fn connect(addr: std::net::SocketAddr) -> Client {
        let stream = TcpStream::connect(addr).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut greet = String::new();
        reader.read_line(&mut greet).unwrap();
        assert!(greet.starts_with("* OK"), "greeting was: {greet:?}");
        Client {
            stream,
            reader,
            tag: 0,
        }
    }

    fn cmd(&mut self, command: &str) -> Vec<String> {
        self.tag += 1;
        let tag = format!("a{}", self.tag);
        self.stream
            .write_all(format!("{tag} {command}\r\n").as_bytes())
            .unwrap();
        self.stream.flush().unwrap();
        self.read_until(&tag)
    }

    fn read_until(&mut self, tag: &str) -> Vec<String> {
        let mut out = Vec::new();
        loop {
            let mut line = String::new();
            let n = self.reader.read_line(&mut line).unwrap();
            if n == 0 {
                break;
            }
            let line = line
                .trim_end_matches('\n')
                .trim_end_matches('\r')
                .to_string();
            if line.is_empty() {
                continue;
            }
            out.push(line.clone());
            if line.starts_with(&format!("{tag} ")) {
                break;
            }
        }
        out
    }

    fn append(&mut self, mailbox: &str, flags: &str, data: &[u8]) -> Vec<String> {
        self.tag += 1;
        let tag = format!("a{}", self.tag);
        self.stream
            .write_all(
                format!("{tag} APPEND {mailbox} ({flags}) {{{}}}\r\n", data.len()).as_bytes(),
            )
            .unwrap();
        self.stream.flush().unwrap();
        let mut cont = String::new();
        self.reader.read_line(&mut cont).unwrap();
        assert!(cont.starts_with('+'), "expected continuation, got {cont:?}");
        self.stream.write_all(data).unwrap();
        self.stream.write_all(b"\r\n").unwrap();
        self.stream.flush().unwrap();
        self.read_until(&tag)
    }

    fn idle(&mut self) -> (String, String) {
        self.tag += 1;
        let tag = format!("a{}", self.tag);
        self.stream
            .write_all(format!("{tag} IDLE\r\n").as_bytes())
            .unwrap();
        self.stream.flush().unwrap();
        let mut cont = String::new();
        self.reader.read_line(&mut cont).unwrap();
        assert!(
            cont.starts_with('+'),
            "expected + continuation, got {cont:?}"
        );
        (tag, cont)
    }

    fn send_done(&mut self, tag: &str) -> Vec<String> {
        self.stream.write_all(b"DONE\r\n").unwrap();
        self.stream.flush().unwrap();
        self.read_until(tag)
    }
}

fn setup() -> (Client, JoinHandle<()>) {
    let store = InMemoryStore::new().with_user("alice", "secret");
    store.add_mailbox("alice", "INBOX").unwrap();
    let m1 = b"From: a@example.com\r\nSubject: First\r\n\r\nBody one\r\n".to_vec();
    let m2 = b"From: b@example.com\r\nSubject: Second\r\n\r\nBody two\r\n".to_vec();
    store
        .add_message("alice", "INBOX", m1, HashSet::new(), 0)
        .unwrap();
    let seen: HashSet<Flag> = [Flag::System(SystemFlag::Seen)].into_iter().collect();
    store.add_message("alice", "INBOX", m2, seen, 0).unwrap();
    let (addr, handle) = Server::new(store).spawn("127.0.0.1:0").unwrap();
    (Client::connect(addr), handle)
}

#[test]
fn greeting_and_capability() {
    let (mut c, _h) = setup();
    let r = c.cmd("CAPABILITY");
    assert!(
        r.iter()
            .any(|l| l.starts_with("* CAPABILITY") && l.contains("IMAP4rev2")),
        "capability response: {r:?}"
    );
    assert!(r.last().unwrap().starts_with("a1 OK"));
}

#[test]
fn login_rejects_bad_password() {
    let (mut c, _h) = setup();
    let r = c.cmd("LOGIN alice wrong");
    assert!(r.last().unwrap().contains("NO"), "response: {r:?}");
}

#[test]
fn login_then_list() {
    let (mut c, _h) = setup();
    assert!(c.cmd("LOGIN alice secret").last().unwrap().contains("OK"));
    let r = c.cmd("LIST \"\" \"*\"");
    assert!(
        r.iter().any(|l| l.contains("INBOX")),
        "list response: {r:?}"
    );
    assert!(r.last().unwrap().contains("OK"));
}

#[test]
fn create_and_list_mailbox() {
    let (mut c, _h) = setup();
    c.cmd("LOGIN alice secret");
    assert!(c.cmd("CREATE Trash").last().unwrap().contains("OK"));
    let r = c.cmd("LIST \"\" \"*\"");
    assert!(r.iter().any(|l| l.contains("Trash")), "list: {r:?}");
}

#[test]
fn append_and_status() {
    let (mut c, _h) = setup();
    c.cmd("LOGIN alice secret");
    let data = b"From: x@example.com\r\nSubject: Appended\r\n\r\nhi there\r\n".to_vec();
    let r = c.append("INBOX", "", &data);
    assert!(r.last().unwrap().contains("OK"), "append: {r:?}");
    let r = c.cmd("STATUS INBOX (MESSAGES)");
    assert!(r.iter().any(|l| l.contains("MESSAGES 3")), "status: {r:?}");
}

#[test]
fn select_and_fetch() {
    let (mut c, _h) = setup();
    c.cmd("LOGIN alice secret");
    let r = c.cmd("SELECT INBOX");
    assert!(r.iter().any(|l| l.contains("* 2 EXISTS")), "select: {r:?}");
    let r = c.cmd("FETCH 1 (UID FLAGS RFC822.SIZE)");
    assert!(
        r.iter()
            .any(|l| l.contains("FETCH") && l.contains("RFC822.SIZE")),
        "fetch: {r:?}"
    );
}

#[test]
fn store_sets_flag() {
    let (mut c, _h) = setup();
    c.cmd("LOGIN alice secret");
    c.cmd("SELECT INBOX");
    let r = c.cmd("STORE 1 +FLAGS (\\Flagged)");
    assert!(r.last().unwrap().contains("OK"));
    assert!(
        r.iter().any(|l| l.contains("\\Flagged")),
        "store response missing flag: {r:?}"
    );
}

#[test]
fn search_all() {
    let (mut c, _h) = setup();
    c.cmd("LOGIN alice secret");
    c.cmd("SELECT INBOX");
    let r = c.cmd("SEARCH ALL");
    assert!(r.iter().any(|l| l.starts_with("* SEARCH")), "search: {r:?}");
}

#[test]
fn uid_fetch_and_expunge() {
    let (mut c, _h) = setup();
    c.cmd("LOGIN alice secret");
    c.cmd("SELECT INBOX");
    let r = c.cmd("UID FETCH 1:* (UID FLAGS)");
    assert!(r.iter().any(|l| l.contains("UID 1")), "uid fetch: {r:?}");
    assert!(r.iter().any(|l| l.contains("UID 2")), "uid fetch: {r:?}");

    c.cmd("STORE 1 +FLAGS (\\Deleted)");
    let r = c.cmd("EXPUNGE");
    assert!(r.iter().any(|l| l.contains("1 EXPUNGE")), "expunge: {r:?}");
    let r = c.cmd("STATUS INBOX (MESSAGES)");
    assert!(r.iter().any(|l| l.contains("MESSAGES 1")), "status: {r:?}");
}

#[test]
fn authenticate_plain() {
    let (mut c, _h) = setup();
    let creds = format!("\0alice\0secret");
    let b64 = base64::engine::general_purpose::STANDARD.encode(creds);
    let r = c.cmd(&format!("AUTHENTICATE PLAIN {b64}"));
    assert!(r.last().unwrap().contains("OK"), "plain auth failed: {r:?}");
}

#[test]
fn idle_round_trip() {
    let (mut c, _h) = setup();
    c.cmd("LOGIN alice secret");
    c.cmd("SELECT INBOX");
    let (tag, cont) = c.idle();
    assert!(cont.contains("idling"), "idle continuation: {cont:?}");
    let r = c.send_done(&tag);
    assert!(r.last().unwrap().contains("OK"), "idle done: {r:?}");
}

#[test]
fn logout() {
    let (mut c, _h) = setup();
    c.cmd("LOGIN alice secret");
    let r = c.cmd("LOGOUT");
    assert!(r.iter().any(|l| l.contains("BYE")));
    assert!(r.last().unwrap().contains("OK"));
}
