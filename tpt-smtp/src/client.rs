// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A minimal, RFC 5321-compliant SMTP client (submission side).
//!
//! The client is transport-agnostic: it operates over any `BufRead + Write`,
//! which makes it testable without a network and lets callers supply their own
//! transport (TCP socket, TLS stream, in-memory pipe, etc.). A high-level
//! [`Client::send_mail`] drives the full `MAIL`/`RCPT`/`DATA`/`QUIT` exchange.

use std::io::{BufRead, Write};

use crate::error::SmtpError;
use crate::reply::Reply;

/// An SMTP client session.
///
/// The reader `R` is used to read server replies; the writer `W` sends client
/// commands. They may be the same object (e.g. an in-memory pipe that is both
/// `BufRead` and `Write`) or two halves of a socket. Construct with
/// [`Client::new`], then call [`Client::ehlo`] (or [`Client::helo`]) before
/// sending mail.
pub struct Client<R, W> {
    reader: R,
    writer: W,
    extended: bool,
}

impl<R: BufRead, W: Write> Client<R, W> {
    /// Wrap a connected transport (reader + writer) and consume the server's
    /// `220` greeting.
    ///
    /// Returns an error if the peer does not greet with a positive reply.
    pub fn new(mut reader: R, mut writer: W) -> Result<Self, SmtpError> {
        let reply = Reply::parse(&mut reader)?;
        if !reply.is_positive() {
            return Err(SmtpError::Rejected(reply));
        }
        // Flush in case the greeting read consumed any buffered bytes.
        let _ = writer.flush();
        Ok(Client {
            reader,
            writer,
            extended: false,
        })
    }

    /// Send `EHLO` (ESMTP) and record whether the server supports extensions.
    pub fn ehlo(&mut self, hostname: &str) -> Result<Reply, SmtpError> {
        let reply = self.command(&format!("EHLO {}", hostname))?;
        if reply.is_success() {
            self.extended = true;
        }
        Ok(reply)
    }

    /// Send `HELO` (plain SMTP). Clears the ESMTP flag.
    pub fn helo(&mut self, hostname: &str) -> Result<Reply, SmtpError> {
        let reply = self.command(&format!("HELO {}", hostname))?;
        self.extended = false;
        Ok(reply)
    }

    /// Send `MAIL FROM:<path>` (or `MAIL FROM:<>` for a null reverse-path).
    pub fn mail_from(&mut self, reverse_path: Option<&str>) -> Result<Reply, SmtpError> {
        let path = reverse_path.unwrap_or("");
        self.command(&format!("MAIL FROM:<{}>", path))
    }

    /// Send `RCPT TO:<path>`.
    pub fn rcpt_to(&mut self, forward_path: &str) -> Result<Reply, SmtpError> {
        self.command(&format!("RCPT TO:<{}>", forward_path))
    }

    /// Begin a `DATA` exchange. On a `354` intermediate reply, `data` is sent
    /// (dot-transparency applied) and terminated with `<CRLF>.<CRLF>`, after
    /// which the server's final reply is returned.
    pub fn data(&mut self, data: &[u8]) -> Result<Reply, SmtpError> {
        let reply = self.command("DATA")?;
        if !reply.is_positive() {
            return Err(SmtpError::Rejected(reply));
        }
        // Write the message with dot-transparency, then the terminator.
        let mut out = Vec::new();
        write_dot_stuffed(&mut out, data);
        out.extend_from_slice(b"\r\n.\r\n");
        self.writer.write_all(&out)?;
        self.writer.flush()?;
        Reply::parse(&mut self.reader)
    }

    /// Send `RSET`.
    pub fn rset(&mut self) -> Result<Reply, SmtpError> {
        self.command("RSET")
    }

    /// Send `NOOP`.
    pub fn noop(&mut self) -> Result<Reply, SmtpError> {
        self.command("NOOP")
    }

    /// Send `QUIT` and return the server's closing reply.
    pub fn quit(&mut self) -> Result<Reply, SmtpError> {
        self.command("QUIT")
    }

    /// Whether the last `EHLO` reported ESMTP support.
    pub fn is_extended(&self) -> bool {
        self.extended
    }

    /// High-level helper: send a full message.
    ///
    /// `from` is the reverse-path (or `None` for `<>`), `recipients` are the
    /// forward-paths, and `message` is the raw RFC 5322 bytes. Returns the
    /// server's final reply to `DATA`.
    pub fn send_mail(
        &mut self,
        from: Option<&str>,
        recipients: &[&str],
        message: &[u8],
    ) -> Result<Reply, SmtpError> {
        if recipients.is_empty() {
            return Err(SmtpError::InvalidArgument("no recipients".to_string()));
        }
        self.mail_from(from)?;
        for rcpt in recipients {
            let reply = self.rcpt_to(rcpt)?;
            if !reply.is_success() {
                return Err(SmtpError::Rejected(reply));
            }
        }
        self.data(message)
    }

    fn command(&mut self, line: &str) -> Result<Reply, SmtpError> {
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\r\n")?;
        self.writer.flush()?;
        let reply = Reply::parse(&mut self.reader)?;
        Ok(reply)
    }
}

/// Write `data` to `out` applying SMTP dot-transparency: any line that begins
/// with a dot is prefixed with an extra dot, and the content is CRLF-terminated
/// (normalized) as required by RFC 5321 §4.5.2.
fn write_dot_stuffed(out: &mut Vec<u8>, data: &[u8]) {
    let mut line_start = true;
    let mut i = 0;
    while i < data.len() {
        // Find the end of the current line (LF).
        let line_end = data[i..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| i + p + 1)
            .unwrap_or(data.len());

        // Normalize the line's line-ending to CRLF.
        let raw_line = &data[i..line_end];
        let (content, terminator_len) = if raw_line.ends_with(b"\r\n") {
            (&raw_line[..raw_line.len() - 2], 2usize)
        } else if raw_line.ends_with(b"\n") {
            (&raw_line[..raw_line.len() - 1], 1usize)
        } else {
            // No terminator (last line). Emit as-is; terminator added later.
            (raw_line, 0usize)
        };

        if line_start && !content.is_empty() && content[0] == b'.' {
            out.push(b'.');
        }
        out.extend_from_slice(content);
        // Emit CRLF for the line (skip if we'll add the final CRLF anyway and
        // this was the trailing line without a terminator).
        if terminator_len > 0 {
            out.extend_from_slice(b"\r\n");
        }
        line_start = true;
        i = line_end;
    }
    // Ensure the whole message ends with CRLF (the dot terminator adds one too).
    if !out.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
}
