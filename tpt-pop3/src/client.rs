// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A clean-room POP3 **client** (RFC 1939), transport-agnostic over
//! [`std::io::BufRead`] + [`std::io::Write`].
//!
//! The protocol core, [`Client`], is driven over any readable/writable pair so
//! it can be exercised against an in-memory server in tests. A convenience
//! wrapper, [`TcpClient`], runs the protocol over a [`std::net::TcpStream`].
//!
//! ## Example
//!
//! ```no_run
//! use tpt_pop3::client::TcpClient;
//!
//! let mut client = TcpClient::connect("mail.example.com:110")?;
//! client.login("alice", "secret")?;
//! let stat = client.stat()?;
//! println!("{} messages, {} octets", stat.count, stat.octets);
//! client.quit()?;
//! # Ok::<(), tpt_pop3::client::Error>(())
//! ```

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

use thiserror::Error;

/// Errors produced by the POP3 client.
#[derive(Debug, Error)]
pub enum Error {
    /// An I/O error talking to the server.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The server's greeting or a response was not a `+OK`/`-ERR` status line,
    /// or it was missing entirely (connection closed).
    #[error("bad server response: {0}")]
    BadResponse(String),

    /// The server returned `-ERR` for a command. The string is the server's
    /// response text (trimmed of its `-ERR` prefix).
    #[error("server error: {0}")]
    ServerError(String),

    /// The server returned a `+OK` status but the trailing payload did not end
    /// with the POP3 multi-line terminator (`\r\n.\r\n`), or a line in the
    /// payload was malformed.
    #[error("malformed multi-line response: {0}")]
    MalformedMultiline(String),

    /// A command argument was invalid (e.g. a non-numeric message number).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

/// The result of a [`Client::stat`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stat {
    /// Number of messages in the mailbox (visible to this session).
    pub count: usize,
    /// Total size of the visible messages in octets.
    pub octets: usize,
}

/// A single entry from a `LIST` or `UIDL` listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// 1-based message number.
    pub num: usize,
    /// For `LIST`: the message size in octets. For `UIDL`: unused (`None`).
    pub size: Option<usize>,
    /// For `UIDL`: the unique identifier. For `LIST`: unused (`None`).
    pub uid: Option<String>,
}

/// A POP3 protocol driver over any `BufRead + Write` transport.
///
/// This is the transport-agnostic core used by [`TcpClient`]; you can construct
/// it over an in-memory pair for testing. The connection must already be
/// established — the server's greeting is consumed by [`Client::new`].
pub struct Client<R, W>
where
    R: BufRead,
    W: Write,
{
    reader: R,
    writer: W,
}

impl<R: BufRead, W: Write> Client<R, W> {
    /// Create a client over an already-open transport. Consumes and validates
    /// the server greeting; returns an error if the greeting is missing or a
    /// `-ERR`.
    pub fn new(mut reader: R, writer: W) -> Result<Self, Error> {
        let status = read_status(&mut reader)?;
        if !status.ok {
            return Err(Error::BadResponse(status.text));
        }
        Ok(Self { reader, writer })
    }

    fn command(&mut self, line: &str) -> Result<Status, Error> {
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\r\n")?;
        self.writer.flush()?;
        read_status(&mut self.reader)
    }

    /// Read a single-line response. On a `+OK` status the text after `+OK` is
    /// returned (trimmed); on `-ERR` an error is produced.
    fn command_ok_text(&mut self, line: &str) -> Result<String, Error> {
        let status = self.command(line)?;
        if status.ok {
            Ok(status.text)
        } else {
            Err(Error::ServerError(status.text))
        }
    }

    /// Authenticate with the `USER`/`PASS` sequence (RFC 1939 §6.1).
    pub fn login(&mut self, user: &str, pass: &str) -> Result<(), Error> {
        if user.is_empty() {
            return Err(Error::InvalidArgument("USER requires a name".into()));
        }
        self.command_ok_text(&format!("USER {}", user))?;
        if pass.is_empty() {
            return Err(Error::InvalidArgument("PASS requires a password".into()));
        }
        self.command_ok_text(&format!("PASS {}", pass))?;
        Ok(())
    }

    /// Authenticate with `APOP` (RFC 1939 §7) using the timestamp from the
    /// server greeting and the user's password. `timestamp` must be the exact
    /// `<...>`-free string from the greeting (see [`Client::capabilities`] note
    /// below); `digest` is `md5(timestamp + password)` hex-encoded.
    ///
    /// Convenience [`Client::apop`] is provided if you do not want to compute
    /// the digest yourself.
    pub fn apop_raw(&mut self, user: &str, digest: &str) -> Result<(), Error> {
        if user.is_empty() || digest.is_empty() {
            return Err(Error::InvalidArgument(
                "APOP requires user and digest".into(),
            ));
        }
        self.command_ok_text(&format!("APOP {} {}", user, digest))?;
        Ok(())
    }

    /// `STAT` (RFC 1939 §6.2) — total message count and octet size.
    pub fn stat(&mut self) -> Result<Stat, Error> {
        let text = self.command_ok_text("STAT")?;
        let mut parts = text.split_whitespace();
        let count = parts
            .next()
            .ok_or_else(|| Error::MalformedMultiline(text.clone()))?
            .parse::<usize>()
            .map_err(|_| Error::MalformedMultiline(text.clone()))?;
        let octets = parts
            .next()
            .ok_or_else(|| Error::MalformedMultiline(text.clone()))?
            .parse::<usize>()
            .map_err(|_| Error::MalformedMultiline(text.clone()))?;
        Ok(Stat { count, octets })
    }

    /// `LIST` (RFC 1939 §6.2). With no message number, returns one entry per
    /// visible message. With a number, returns a single entry (or an error if
    /// the message does not exist).
    pub fn list(&mut self, num: Option<usize>) -> Result<Vec<Entry>, Error> {
        self.listing("LIST", num, true)
    }

    /// `UIDL` (RFC 1939 §7). Returns unique identifiers, one per visible message
    /// (or a single one when a number is supplied).
    pub fn uidl(&mut self, num: Option<usize>) -> Result<Vec<Entry>, Error> {
        self.listing("UIDL", num, false)
    }

    fn listing(
        &mut self,
        cmd: &str,
        num: Option<usize>,
        with_size: bool,
    ) -> Result<Vec<Entry>, Error> {
        let line = match num {
            Some(n) => {
                if n == 0 {
                    return Err(Error::InvalidArgument("message number must be >= 1".into()));
                }
                format!("{} {}", cmd, n)
            }
            None => cmd.to_string(),
        };
        let status = self.command(&line)?;
        if !status.ok {
            return Err(Error::ServerError(status.text));
        }
        let body = read_multiline(&mut self.reader)?;
        let mut entries = Vec::new();
        for raw in body {
            let mut parts = raw.splitn(3, ' ');
            let n = match parts.next().and_then(|s| s.parse::<usize>().ok()) {
                Some(n) => n,
                None => return Err(Error::MalformedMultiline(raw)),
            };
            if with_size {
                let size = parts
                    .next()
                    .and_then(|s| s.parse::<usize>().ok())
                    .ok_or(Error::MalformedMultiline(raw))?;
                entries.push(Entry {
                    num: n,
                    size: Some(size),
                    uid: None,
                });
            } else {
                let uid = parts.next().unwrap_or("").to_string();
                entries.push(Entry {
                    num: n,
                    size: None,
                    uid: Some(uid),
                });
            }
        }
        Ok(entries)
    }

    /// `RETR msg` (RFC 1939 §6.2) — retrieve a message's full content.
    pub fn retr(&mut self, num: usize) -> Result<Vec<u8>, Error> {
        self.multiline_bytes("RETR", num)
    }

    /// `TOP msg n` (RFC 1939 §7) — retrieve headers plus the first `n` body
    /// lines of a message.
    pub fn top(&mut self, num: usize, lines: usize) -> Result<Vec<u8>, Error> {
        if num == 0 {
            return Err(Error::InvalidArgument("message number must be >= 1".into()));
        }
        let status = self.command(&format!("TOP {} {}", num, lines))?;
        if !status.ok {
            return Err(Error::ServerError(status.text));
        }
        read_multiline_bytes(&mut self.reader)
    }

    /// `DELE msg` (RFC 1939 §6.2) — mark a message for deletion (committed on
    /// `QUIT`).
    pub fn dele(&mut self, num: usize) -> Result<(), Error> {
        if num == 0 {
            return Err(Error::InvalidArgument("message number must be >= 1".into()));
        }
        self.command_ok_text(&format!("DELE {}", num))?;
        Ok(())
    }

    /// `RSET` (RFC 1939 §6.2) — undo all deletions made in this session.
    pub fn rset(&mut self) -> Result<(), Error> {
        self.command_ok_text("RSET")?;
        Ok(())
    }

    /// `NOOP` (RFC 1939 §6.2) — no-op round-trip; verifies the session is alive.
    pub fn noop(&mut self) -> Result<(), Error> {
        self.command_ok_text("NOOP")?;
        Ok(())
    }

    /// `QUIT` (RFC 1939 §6.1/§6.3) — enter the UPDATE state (committing any
    /// deletions) and close the connection.
    pub fn quit(&mut self) -> Result<(), Error> {
        self.command_ok_text("QUIT")?;
        Ok(())
    }

    fn multiline_bytes(&mut self, cmd: &str, num: usize) -> Result<Vec<u8>, Error> {
        if num == 0 {
            return Err(Error::InvalidArgument("message number must be >= 1".into()));
        }
        let status = self.command(&format!("{} {}", cmd, num))?;
        if !status.ok {
            return Err(Error::ServerError(status.text));
        }
        read_multiline_bytes(&mut self.reader)
    }
}

/// A POP3 client over a [`TcpStream`].
///
/// This is the ergonomic entry point for real use. It wraps [`Client`] and
/// owns the stream's buffered reader.
pub struct TcpClient {
    inner: Client<BufReader<TcpStream>, TcpStream>,
    /// The server greeting text (captured at connect time), kept so APOP can be
    /// performed.
    greeting: String,
}

impl TcpClient {
    /// Connect to `addr` (e.g. `"mail.example.com:110"`) and consume the
    /// greeting.
    pub fn connect(addr: &str) -> Result<Self, Error> {
        let stream = TcpStream::connect(addr)?;
        let reader = BufReader::new(stream.try_clone()?);
        // Capture the greeting directly so we can recover the APOP timestamp.
        let mut buf_reader = reader;
        let greeting = read_status(&mut buf_reader)?;
        if !greeting.ok {
            return Err(Error::BadResponse(greeting.text));
        }
        let inner = Client {
            reader: buf_reader,
            writer: stream,
        };
        Ok(Self {
            inner,
            greeting: greeting.text,
        })
    }

    /// The raw server greeting text, including the leading `+OK `. Useful for
    /// extracting the APOP `<timestamp>` and computing the APOP digest.
    pub fn greeting(&self) -> &str {
        &self.greeting
    }

    /// Authenticate with `APOP` (RFC 1939 §7). `timestamp` must be the exact
    /// string found inside `<...>` in the greeting; the digest
    /// `md5(timestamp + password)` is computed internally.
    pub fn apop(&mut self, user: &str, password: &str, timestamp: &str) -> Result<(), Error> {
        use md5::{Digest, Md5};
        let mut hasher = Md5::new();
        hasher.update(timestamp.as_bytes());
        hasher.update(password.as_bytes());
        let digest = format!("{:x}", hasher.finalize());
        self.inner.apop_raw(user, &digest)
    }

    /// Authenticate with `USER`/`PASS` (RFC 1939 §6.1).
    pub fn login(&mut self, user: &str, pass: &str) -> Result<(), Error> {
        self.inner.login(user, pass)
    }

    /// `STAT` — total message count and octet size.
    pub fn stat(&mut self) -> Result<Stat, Error> {
        self.inner.stat()
    }

    /// `LIST` (all messages, or one).
    pub fn list(&mut self, num: Option<usize>) -> Result<Vec<Entry>, Error> {
        self.inner.list(num)
    }

    /// `UIDL` (all messages, or one).
    pub fn uidl(&mut self, num: Option<usize>) -> Result<Vec<Entry>, Error> {
        self.inner.uidl(num)
    }

    /// `RETR msg` — full message content.
    pub fn retr(&mut self, num: usize) -> Result<Vec<u8>, Error> {
        self.inner.retr(num)
    }

    /// `TOP msg n` — headers plus `n` body lines.
    pub fn top(&mut self, num: usize, lines: usize) -> Result<Vec<u8>, Error> {
        self.inner.top(num, lines)
    }

    /// `DELE msg` — mark for deletion.
    pub fn dele(&mut self, num: usize) -> Result<(), Error> {
        self.inner.dele(num)
    }

    /// `RSET` — undo deletions.
    pub fn rset(&mut self) -> Result<(), Error> {
        self.inner.rset()
    }

    /// `NOOP` — liveness check.
    pub fn noop(&mut self) -> Result<(), Error> {
        self.inner.noop()
    }

    /// `QUIT` — commit deletions and disconnect.
    pub fn quit(&mut self) -> Result<(), Error> {
        self.inner.quit()
    }
}

/// A POP3 status line, split into success flag and text.
struct Status {
    ok: bool,
    text: String,
}

/// Read one status line from `reader`. Returns an error if the connection closed
/// before a line arrived or the line did not begin with `+OK`/`-ERR`.
fn read_status<R: BufRead>(reader: &mut R) -> Result<Status, Error> {
    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    if n == 0 {
        return Err(Error::BadResponse("connection closed".into()));
    }
    let line = line.trim_end_matches(['\r', '\n']);
    if let Some(rest) = line.strip_prefix("+OK") {
        Ok(Status {
            ok: true,
            text: rest.trim_start().to_string(),
        })
    } else if let Some(rest) = line.strip_prefix("-ERR") {
        Ok(Status {
            ok: false,
            text: rest.trim_start().to_string(),
        })
    } else {
        Err(Error::BadResponse(line.to_string()))
    }
}

/// Read a POP3 multi-line response (after a `+OK` status has been consumed),
/// returning the unstuffed payload as a list of text lines (CRLF stripped).
/// Terminates at the lone `.` line. POP3 "byte-unstuffing" (a leading `..`
/// collapses to `.`) is applied to each line.
fn read_multiline<R: BufRead>(reader: &mut R) -> Result<Vec<String>, Error> {
    let mut out: Vec<String> = Vec::new();
    let mut buf = String::new();
    loop {
        buf.clear();
        let n = reader.read_line(&mut buf)?;
        if n == 0 {
            return Err(Error::MalformedMultiline(
                "connection closed mid-response".into(),
            ));
        }
        let line = buf.trim_end_matches(['\r', '\n']);
        if line == "." {
            break;
        }
        // Byte-unstuff a leading doubled dot: a line the server escaped as `..`
        // represents a literal `.` at the start of the original line.
        let stripped = if line.starts_with("..") {
            &line[1..]
        } else {
            line
        };
        out.push(stripped.to_string());
    }
    Ok(out)
}

/// Read a POP3 multi-line response and return the raw unstuffed payload bytes
/// (each line re-terminated with CRLF), suitable for message bodies.
fn read_multiline_bytes<R: BufRead>(reader: &mut R) -> Result<Vec<u8>, Error> {
    let lines = read_multiline(reader)?;
    let mut out: Vec<u8> = Vec::new();
    for line in lines {
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    Ok(out)
}
