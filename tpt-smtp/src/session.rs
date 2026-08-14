// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The RFC 5321 SMTP server session state machine, transport-agnostic.
//!
//! A [`Session`] is driven over any `BufRead + Write` (see [`Session::run`]),
//! which keeps it fully testable without a network. The TCP [`crate::server`]
//! wraps this for real sockets.

use std::io::{BufRead, Write};

use crate::backend::{DeliveryError, Envelope, MailDelivery};
use crate::codec::{parse_command, parse_path};
use crate::reply::Reply;

/// Maximum length of a single command line accepted from a client. RFC 5321
/// §4.5.3.1 recommends at least 512 octets for the command; we use a generous
/// bound and reject over-long lines.
const MAX_COMMAND_LEN: usize = 1024;

/// Maximum size of a message body the session will buffer (default 25 MiB).
/// Backends may enforce stricter limits during `MAIL FROM:` via `SIZE`.
const DEFAULT_MAX_MESSAGE: usize = 25 * 1024 * 1024;

/// SMTP session states (RFC 5321 §4.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Connected; awaiting `EHLO`/`HELO`.
    Greeted,
    /// `EHLO`/`HELO` done; awaiting `MAIL`.
    Initial,
    /// `MAIL` accepted; awaiting `RCPT`.
    Mail,
    /// At least one `RCPT` accepted; awaiting more `RCPT` or `DATA`.
    Rcpt,
    /// `DATA` seen; reading the message body until `<CRLF>.<CRLF>`.
    Data,
}

/// A single SMTP session for one connection.
pub struct Session {
    backend: std::sync::Arc<dyn MailDelivery>,
    state: State,
    /// The SMTP server's domain name (used in the greeting and `EHLO` reply).
    hostname: String,
    /// The client's announced identity from `EHLO`/`HELO`.
    client_name: Option<String>,
    /// `true` once the client issued `EHLO` (ESMTP extensions available).
    esmtp: bool,
    /// Reverse-path collected from `MAIL FROM:`.
    reverse_path: Option<String>,
    /// Forward-paths collected from `RCPT TO:`.
    forward_paths: Vec<String>,
    /// Optional negotiated extension hooks.
    extensions: Extensions,
    /// Per-session size limit (octets).
    max_message: usize,
    /// STARTTLS requested/available state (the session should refuse mail ops
    /// until TLS is established, if `required`).
    tls_active: bool,
}

/// Extension feature flags / hooks for the session.
#[derive(Debug, Clone, Default)]
pub struct Extensions {
    /// If `true`, advertise and allow `STARTTLS`.
    pub starttls: bool,
    /// If `true`, advertise and allow `AUTH` (the session emits a 503/504 if no
    /// mechanism callback is supplied).
    pub auth: bool,
    /// If `true`, require the session to negotiate TLS before `MAIL`.
    pub starttls_required: bool,
    /// If `true`, advertise the `SIZE` extension.
    pub size: bool,
}

impl Default for Session {
    fn default() -> Self {
        Self::new(std::sync::Arc::new(crate::memory::MemoryBackend::new()))
    }
}

impl Session {
    /// Create a session bound to `backend` with the given server `hostname`.
    pub fn with_hostname(backend: std::sync::Arc<dyn MailDelivery>, hostname: impl Into<String>) -> Self {
        Self {
            backend,
            state: State::Greeted,
            hostname: hostname.into(),
            client_name: None,
            esmtp: false,
            reverse_path: None,
            forward_paths: Vec::new(),
            extensions: Extensions::default(),
            max_message: DEFAULT_MAX_MESSAGE,
            tls_active: false,
        }
    }

    /// Create a session bound to `backend` using the host's name as advertised
    /// hostname.
    pub fn new(backend: std::sync::Arc<dyn MailDelivery>) -> Self {
        let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
        Self::with_hostname(backend, hostname)
    }

    /// Configure which ESMTP extensions are advertised/enabled.
    pub fn set_extensions(&mut self, extensions: Extensions) -> &mut Self {
        self.extensions = extensions;
        self
    }

    /// Set the maximum accepted message size in octets.
    pub fn set_max_message(&mut self, max: usize) -> &mut Self {
        self.max_message = max;
        self
    }

    /// Drive the session to completion over `reader`/`writer`. Sends the
    /// greeting, then processes commands until `QUIT` or EOF.
    pub fn run<R: BufRead, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let greeting = Reply::service_ready(format!("{} SMTP tpt-smtp ready", self.hostname));
        self.write_reply(writer, &greeting)?;
        self.state = State::Initial;

        let mut line = String::new();
        loop {
            line.clear();
            let n = reader.read_line(&mut line)?;
            if n == 0 {
                break; // EOF
            }
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                // A bare CRLF is ignored between commands (RFC 5321 §4.5.2).
                continue;
            }
            if trimmed.len() > MAX_COMMAND_LEN {
                self.write_reply(writer, &Reply::syntax_error_command())?;
                writer.flush()?;
                continue;
            }
            let quit = self.handle_line(trimmed, reader, writer)?;
            writer.flush()?;
            if quit {
                break;
            }
        }
        Ok(())
    }

    fn handle_line<R: BufRead, W: Write>(
        &mut self,
        line: &str,
        reader: &mut R,
        writer: &mut W,
    ) -> std::io::Result<bool> {
        let cmd = parse_command(line);
        let verb = &cmd.verb;
        let args = &cmd.args;

        // The only commands valid before HELO/EHLO are HELO, EHLO, and QUIT.
        if self.state == State::Initial
            && !matches!(verb.as_str(), "HELO" | "EHLO" | "QUIT")
        {
            self.write_reply(writer, &Reply::bad_sequence())?;
            return Ok(false);
        }

        match verb.as_str() {
            "HELO" => self.cmd_helo(args, writer),
            "EHLO" => self.cmd_ehlo(args, writer),
            "MAIL" => self.cmd_mail(args, writer),
            "RCPT" => self.cmd_rcpt(args, writer),
            "DATA" => self.cmd_data(args, reader, writer),
            "RSET" => self.cmd_rset(writer),
            "NOOP" => self.cmd_noop(writer),
            "QUIT" => self.cmd_quit(writer),
            "VRFY" => self.cmd_vrfy(args, writer),
            "EXPN" => self.cmd_expn(args, writer),
            "HELP" => self.cmd_help(writer),
            "STARTTLS" => self.cmd_starttls(args, writer),
            "AUTH" => self.cmd_auth(args, writer),
            _ => {
                self.write_reply(writer, &Reply::syntax_error_command())?;
                Ok(false)
            }
        }
    }

    fn cmd_helo<W: Write>(&mut self, args: &str, writer: &mut W) -> std::io::Result<bool> {
        if args.is_empty() {
            self.write_reply(writer, &Reply::syntax_error_params())?;
            return Ok(false);
        }
        self.client_name = Some(args.to_string());
        self.esmtp = false;
        self.state = State::Initial;
        self.write_reply(
            writer,
            &Reply::new(250, format!("{} greets {}", self.hostname, args)),
        )?;
        Ok(false)
    }

    fn cmd_ehlo<W: Write>(&mut self, args: &str, writer: &mut W) -> std::io::Result<bool> {
        if args.is_empty() {
            self.write_reply(writer, &Reply::syntax_error_params())?;
            return Ok(false);
        }
        self.client_name = Some(args.to_string());
        self.esmtp = true;
        self.state = State::Initial;

        let mut lines = vec![format!("{} greets {}", self.hostname, args)];
        if self.extensions.size {
            lines.push(format!("SIZE {}", self.max_message));
        }
        if self.extensions.starttls {
            lines.push("STARTTLS".to_string());
        }
        if self.extensions.auth {
            lines.push("AUTH PLAIN LOGIN".to_string());
        }
        lines.push("8BITMIME".to_string());
        self.write_reply(writer, &Reply::new(250, lines.join("\r\n")))?;
        Ok(false)
    }

    fn cmd_mail<W: Write>(&mut self, args: &str, writer: &mut W) -> std::io::Result<bool> {
        if self.state != State::Initial {
            self.write_reply(writer, &Reply::bad_sequence())?;
            return Ok(false);
        }
        if self.extensions.starttls_required && !self.tls_active {
            self.write_reply(writer, &Reply::bad_sequence())?;
            return Ok(false);
        }
        // Must be "FROM:".
        if !args.to_ascii_uppercase().starts_with("FROM:") {
            self.write_reply(writer, &Reply::syntax_error_params())?;
            return Ok(false);
        }
        let path = match parse_path(args) {
            Some(p) => p,
            None => {
                self.write_reply(writer, &Reply::syntax_error_params())?;
                return Ok(false);
            }
        };
        // Optional SIZE parameter.
        if let Some(size_val) = crate::codec::param_value(args, "SIZE") {
            if let Ok(size) = size_val.parse::<usize>() {
                if size > self.max_message {
                    self.write_reply(
                        writer,
                        &Reply::new(552, "Message exceeds fixed maximum message size"),
                    )?;
                    return Ok(false);
                }
            }
        }
        let from = if path.is_empty() { None } else { Some(path) };
        if let Err(e) = self.backend.accept_sender(from.as_deref()) {
            self.write_reply(writer, &delivery_to_reply(&e))?;
            return Ok(false);
        }
        self.reverse_path = from;
        self.forward_paths.clear();
        self.state = State::Mail;
        self.write_reply(writer, &Reply::ok())?;
        Ok(false)
    }

    fn cmd_rcpt<W: Write>(&mut self, args: &str, writer: &mut W) -> std::io::Result<bool> {
        if self.state != State::Mail && self.state != State::Rcpt {
            self.write_reply(writer, &Reply::bad_sequence())?;
            return Ok(false);
        }
        if !args.to_ascii_uppercase().starts_with("TO:") {
            self.write_reply(writer, &Reply::syntax_error_params())?;
            return Ok(false);
        }
        let path = match parse_path(args) {
            Some(p) => p,
            None => {
                self.write_reply(writer, &Reply::syntax_error_params())?;
                return Ok(false);
            }
        };
        if path.is_empty() {
            self.write_reply(writer, &Reply::syntax_error_params())?;
            return Ok(false);
        }
        if let Err(e) = self.backend.accept_recipient(&path) {
            self.write_reply(writer, &delivery_to_reply(&e))?;
            return Ok(false);
        }
        self.forward_paths.push(path);
        self.state = State::Rcpt;
        self.write_reply(writer, &Reply::ok())?;
        Ok(false)
    }

    fn cmd_data<R: BufRead, W: Write>(
        &mut self,
        _args: &str,
        reader: &mut R,
        writer: &mut W,
    ) -> std::io::Result<bool> {
        if self.state != State::Rcpt {
            self.write_reply(writer, &Reply::bad_sequence())?;
            return Ok(false);
        }
        self.state = State::Data;
        self.write_reply(writer, &Reply::start_mail_input())?;
        writer.flush()?;

        // Read the message body until a line that is exactly ".". Apply
        // transparency: a leading "." in a received line is removed.
        let mut body = Vec::with_capacity(1024);
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader.read_line(&mut line)?;
            if n == 0 {
                // EOF mid-message: treat as aborted.
                self.write_reply(writer, &Reply::new(451, "Transaction aborted: connection closed"))?;
                self.reset_transaction();
                return Ok(false);
            }
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed == "." {
                break;
            }
            // Undo transparency: strip one leading dot.
            let content = if let Some(stripped) = trimmed.strip_prefix('.') {
                stripped
            } else {
                trimmed
            };
            body.extend_from_slice(content.as_bytes());
            body.extend_from_slice(b"\r\n");
            if body.len() > self.max_message {
                // Discard remainder and reject.
                let mut discard = String::new();
                while reader.read_line(&mut discard)? > 0 {
                    if discard.trim_end_matches(['\r', '\n']) == "." {
                        break;
                    }
                    discard.clear();
                }
                self.write_reply(
                    writer,
                    &Reply::new(552, "Message exceeds fixed maximum message size"),
                )?;
                self.reset_transaction();
                return Ok(false);
            }
        }

        let envelope = Envelope::new(
            self.reverse_path.clone(),
            self.forward_paths.clone(),
            body,
        );
        let result = self.backend.deliver(&envelope);
        self.reset_transaction();
        match result {
            Ok(()) => {
                self.write_reply(writer, &Reply::new(250, "OK: queued as tpt-id"))?;
            }
            Err(e) => {
                self.write_reply(writer, &delivery_to_reply(&e))?;
            }
        }
        Ok(false)
    }

    fn cmd_rset<W: Write>(&mut self, writer: &mut W) -> std::io::Result<bool> {
        self.reset_transaction();
        self.write_reply(writer, &Reply::ok())?;
        Ok(false)
    }

    fn cmd_noop<W: Write>(&mut self, writer: &mut W) -> std::io::Result<bool> {
        self.write_reply(writer, &Reply::ok())?;
        Ok(false)
    }

    fn cmd_quit<W: Write>(&mut self, writer: &mut W) -> std::io::Result<bool> {
        self.write_reply(writer, &Reply::closing())?;
        Ok(true)
    }

    fn cmd_vrfy<W: Write>(&mut self, args: &str, writer: &mut W) -> std::io::Result<bool> {
        if args.is_empty() {
            self.write_reply(writer, &Reply::syntax_error_params())?;
            return Ok(false);
        }
        // RFC 5321 §3.5.2: servers may refuse VRFY; we report "cannot verify but
        // will accept" to avoid disclosing account info (252).
        self.write_reply(writer, &Reply::new(252, format!("Cannot VRFY user, but will accept {}", args)))?;
        Ok(false)
    }

    fn cmd_expn<W: Write>(&mut self, args: &str, writer: &mut W) -> std::io::Result<bool> {
        if args.is_empty() {
            self.write_reply(writer, &Reply::syntax_error_params())?;
            return Ok(false);
        }
        self.write_reply(writer, &Reply::new(252, format!("Cannot EXPN list, but will accept {}", args)))?;
        Ok(false)
    }

    fn cmd_help<W: Write>(&mut self, writer: &mut W) -> std::io::Result<bool> {
        let lines = [
            "Supported commands:",
            "HELO, EHLO, MAIL, RCPT, DATA, RSET, NOOP, QUIT, VRFY, EXPN, HELP",
        ];
        self.write_reply(writer, &Reply::new(250, lines.join("\r\n")))?;
        Ok(false)
    }

    fn cmd_starttls<W: Write>(&mut self, _args: &str, writer: &mut W) -> std::io::Result<bool> {
        if !self.extensions.starttls {
            self.write_reply(writer, &Reply::not_implemented())?;
            return Ok(false);
        }
        if self.state != State::Initial {
            self.write_reply(writer, &Reply::bad_sequence())?;
            return Ok(false);
        }
        // We cannot actually perform the TLS handshake here (transport
        // responsibility); we emit 220 and flag the session. Integrators wrap
        // the socket in TLS after this reply.
        self.tls_active = true;
        self.write_reply(writer, &Reply::new(220, "Ready to start TLS"))?;
        Ok(false)
    }

    fn cmd_auth<W: Write>(&mut self, _args: &str, writer: &mut W) -> std::io::Result<bool> {
        if !self.extensions.auth {
            self.write_reply(writer, &Reply::not_implemented())?;
            return Ok(false);
        }
        // No credentials callback is wired in this phase; report the parameter
        // as unimplemented to keep the session safe.
        self.write_reply(writer, &Reply::param_not_implemented())?;
        Ok(false)
    }

    fn reset_transaction(&mut self) {
        self.reverse_path = None;
        self.forward_paths.clear();
        self.state = State::Initial;
    }

    fn write_reply<W: Write>(&self, w: &mut W, reply: &Reply) -> std::io::Result<()> {
        w.write_all(reply.to_wire().as_bytes())?;
        Ok(())
    }
}

/// Map a [`DeliveryError`] onto the appropriate SMTP reply.
fn delivery_to_reply(e: &DeliveryError) -> Reply {
    match e {
        DeliveryError::NoSuchRecipient(r) => Reply::mailbox_unavailable(format!("No such recipient: {}", r)),
        DeliveryError::Rejected(r) => Reply::new(554, format!("Transaction failed: {}", r)),
        DeliveryError::Temporary(r) => Reply::new(451, r.clone()),
        DeliveryError::Other(r) => Reply::new(554, r.clone()),
    }
}
