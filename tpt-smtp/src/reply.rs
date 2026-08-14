// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SMTP reply model and wire (de)serialization (RFC 5321 §4.2).

use std::io::BufRead;

use crate::error::SmtpError;

/// An SMTP reply: a 3-digit code plus one or more text lines.
///
/// Per RFC 5321 §4.2, the code space is divided as:
///
/// - `2xy` — positive completion (success)
/// - `3xy` — positive intermediate (continue, e.g. `354` after `DATA`)
/// - `4xy` — transient negative (try again later)
/// - `5xy` — permanent negative (do not retry the same way)
///
/// A reply may carry multiple text lines. On the wire the first and any
/// continuation lines are prefixed with the code followed by a hyphen; the
/// final line is prefixed with the code followed by a space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The 3-digit reply code (100–599).
    pub code: u16,
    /// The text lines of the reply, in order. Always contains at least one.
    pub lines: Vec<String>,
}

impl std::fmt::Display for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.code, self.message())
    }
}

impl Reply {
    /// Construct a single-line reply.
    pub fn new(code: u16, text: impl Into<String>) -> Self {
        Self {
            code,
            lines: vec![text.into()],
        }
    }

    /// `220 Service ready`.
    pub fn service_ready(text: impl Into<String>) -> Self {
        Self::new(220, text)
    }

    /// `221 Service closing transmission channel`.
    pub fn closing() -> Self {
        Self::new(221, "Service closing transmission channel")
    }

    /// `250 OK`.
    pub fn ok() -> Self {
        Self::new(250, "OK")
    }

    /// `354 Start mail input; end with <CRLF>.<CRLF>`.
    pub fn start_mail_input() -> Self {
        Self::new(354, "Start mail input; end with <CRLF>.<CRLF>")
    }

    /// `500 Syntax error, command unrecognized`.
    pub fn syntax_error_command() -> Self {
        Self::new(500, "Syntax error, command unrecognized")
    }

    /// `501 Syntax error in parameters or arguments`.
    pub fn syntax_error_params() -> Self {
        Self::new(501, "Syntax error in parameters or arguments")
    }

    /// `502 Command not implemented`.
    pub fn not_implemented() -> Self {
        Self::new(502, "Command not implemented")
    }

    /// `503 Bad sequence of commands`.
    pub fn bad_sequence() -> Self {
        Self::new(503, "Bad sequence of commands")
    }

    /// `504 Command parameter not implemented`.
    pub fn param_not_implemented() -> Self {
        Self::new(504, "Command parameter not implemented")
    }

    /// `550 Requested action not taken: mailbox unavailable`.
    pub fn mailbox_unavailable(text: impl Into<String>) -> Self {
        Self::new(550, text)
    }

    /// True for `2xy`/`3xy` (the command may proceed or has succeeded).
    pub fn is_positive(&self) -> bool {
        (200..=399).contains(&self.code)
    }

    /// True for `2xy` (the action completed successfully).
    pub fn is_success(&self) -> bool {
        (200..=299).contains(&self.code)
    }

    /// The text of the first reply line.
    pub fn message(&self) -> &str {
        self.lines.first().map(|s| s.as_str()).unwrap_or("")
    }

    /// Serialize to wire format (CRLF-terminated lines).
    pub fn to_wire(&self) -> String {
        let mut out = String::new();
        let last = self.lines.len().saturating_sub(1);
        for (i, line) in self.lines.iter().enumerate() {
            let sep = if i == last { ' ' } else { '-' };
            out.push_str(&format!("{}{}{}\r\n", self.code, sep, line));
        }
        out
    }

    /// Read a (possibly multi-line) reply from `reader`.
    pub fn parse<R: BufRead>(reader: &mut R) -> Result<Reply, SmtpError> {
        let mut first = String::new();
        if reader.read_line(&mut first)? == 0 {
            return Err(SmtpError::ConnectionClosed);
        }
        let first = first.trim_end_matches(['\r', '\n']);
        let (code, rest) = Self::split_code(first)?;
        let sep = first.chars().nth(3);
        let mut lines = vec![rest.to_string()];

        // Continuation lines until the terminal line (code + space).
        if sep == Some('-') {
            loop {
                let mut buf = String::new();
                if reader.read_line(&mut buf)? == 0 {
                    break;
                }
                let line = buf.trim_end_matches(['\r', '\n']);
                let (c2, r2) = Self::split_code(line)?;
                if c2 != code {
                    // Defensive: a mismatched code ends the reply.
                    break;
                }
                lines.push(r2.to_string());
                if line.chars().nth(3) == Some(' ') {
                    break;
                }
            }
        }

        Ok(Reply { code, lines })
    }

    fn split_code(line: &str) -> Result<(u16, &str), SmtpError> {
        if line.len() < 3 {
            return Err(SmtpError::InvalidReply(line.to_string()));
        }
        let code = line[..3]
            .parse::<u16>()
            .map_err(|_| SmtpError::InvalidReply(line.to_string()))?;
        let rest = line[3..].strip_prefix([' ', '-']).unwrap_or("");
        Ok((code, rest))
    }
}
