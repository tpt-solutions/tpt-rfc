// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The RFC 4511 LDAP session: reads request messages, dispatches them to the
//! [`DirectoryBackend`], and writes response messages. Transport-agnostic so it
//! can be driven over any `Read + Write` for testing, or over a TCP stream by
//! the [`crate::server`].

use std::io::{Read, Write};
use std::sync::Arc;

use crate::backend::{DirectoryBackend, Modification};
use crate::ber::BerError;
use crate::protocol::{
    decode_request, entry_to_result, filter_matches, scope_match, AuthChoice, LdapRequest,
    LdapResponse, RequestOp, ResponseOp, ResultCode,
};

/// Maximum bytes accumulated while reading a single in-flight LDAP message.
const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// An LDAP session for a single connection.
pub struct Session {
    backend: Arc<dyn DirectoryBackend>,
}

impl Session {
    /// Create a new session bound to `backend`.
    pub fn new(backend: Arc<dyn DirectoryBackend>) -> Self {
        Self { backend }
    }

    /// Drive the session to completion over `reader`/`writer`. Reads LDAP
    /// messages until EOF, dispatching each and writing the corresponding
    /// response(s). `UnbindRequest` and `AbandonRequest` do not produce
    /// responses.
    pub fn run<R: Read, W: Write>(&mut self, reader: &mut R, writer: &mut W) -> std::io::Result<()> {
        let mut buf: Vec<u8> = Vec::new();
        while let Some(req) = read_message(reader, &mut buf)? {
            let close = self.handle_request(&req, writer)?;
            writer.flush()?;
            if close {
                break;
            }
        }
        Ok(())
    }

    /// Process one request, writing any responses. Returns `true` if the
    /// connection should be closed (unbind).
    fn handle_request<W: Write>(&self, req: &LdapRequest, writer: &mut W) -> std::io::Result<bool> {
        // Reject unrecognized critical controls up front (RFC 4511 §4.1.11).
        if req.controls.iter().any(|c| c.criticality) {
            return self
                .respond(
                    &req.op,
                    req.id,
                    ResultCode::UnavailableCriticalExtension,
                    "unsupported critical control",
                    writer,
                )
                .map(|_| false);
        }

        match &req.op {
            RequestOp::Bind(b) => self.handle_bind(&req.op, req.id, b, writer),
            RequestOp::Unbind => Ok(true),
            RequestOp::Search(s) => self.handle_search(req.id, s, writer),
            RequestOp::Compare(c) => self.handle_compare(&req.op, req.id, c, writer),
            RequestOp::Add(a) => self.handle_add(&req.op, req.id, a, writer),
            RequestOp::Delete(dn) => self.handle_delete(&req.op, req.id, dn, writer),
            RequestOp::Modify(m) => self.handle_modify(&req.op, req.id, m, writer),
            RequestOp::ModifyDn(d) => self.handle_modify_dn(&req.op, req.id, d, writer),
            RequestOp::Abandon(_) => Ok(false),
            RequestOp::Extended(_) => self
                .respond(
                    &req.op,
                    req.id,
                    ResultCode::UnwillingToPerform,
                    "no extended operations implemented",
                    writer,
                )
                .map(|_| false),
        }
    }

    fn handle_bind<W: Write>(
        &self,
        op: &RequestOp,
        id: i32,
        req: &crate::protocol::BindRequest,
        writer: &mut W,
    ) -> std::io::Result<bool> {
        if req.version < 2 {
            return self
                .respond(op, id, ResultCode::ProtocolError, "unsupported LDAP version", writer)
                .map(|_| false);
        }
        let result = match &req.auth {
            AuthChoice::Simple(pw) => self
                .backend
                .bind_simple(&req.name, pw)
                .map(|ok| {
                    if ok {
                        ResultCode::Success
                    } else {
                        ResultCode::InvalidCredentials
                    }
                })
                .map_err(|e| ResultCode::from_backend_error(&e)),
            AuthChoice::Sasl(sasl) => self
                .backend
                .bind_sasl(&req.name, &sasl)
                .map(|ok| {
                    if ok {
                        ResultCode::Success
                    } else {
                        ResultCode::InvalidCredentials
                    }
                })
                .map_err(|e| ResultCode::from_backend_error(&e)),
        };
        self.emit(op, id, result, "bind failed", writer).map(|_| false)
    }

    fn handle_search<W: Write>(
        &self,
        id: i32,
        req: &crate::protocol::SearchRequest,
        writer: &mut W,
    ) -> std::io::Result<bool> {
        let entries = match self.backend.entries() {
            Ok(e) => e,
            Err(e) => {
                let code = ResultCode::from_backend_error(&e);
                return self
                    .respond(
                        &RequestOp::Search(req.clone()),
                        id,
                        code,
                        "search failed",
                        writer,
                    )
                    .map(|_| false);
            }
        };

        let mut returned = 0i32;
        let size_limit = if req.size_limit > 0 {
            Some(req.size_limit)
        } else {
            None
        };

        let mut done_code = ResultCode::Success;
        let mut done_diag = String::new();
        for entry in entries.iter() {
            if !scope_match(req.scope, &req.base, &entry.dn) {
                continue;
            }
            if !filter_matches(&req.filter, entry) {
                continue;
            }
            if let Some(limit) = size_limit {
                if returned >= limit {
                    done_code = ResultCode::SizeLimitExceeded;
                    done_diag = "size limit exceeded".to_string();
                    break;
                }
            }
            let result = entry_to_result(entry, req.types_only, &req.attributes);
            let resp = LdapResponse {
                id,
                op: ResponseOp::SearchResultEntry(result),
                controls: Vec::new(),
            };
            writer.write_all(&resp.encode())?;
            returned += 1;
        }

        self.respond(&RequestOp::Search(req.clone()), id, done_code, &done_diag, writer)
            .map(|_| false)
    }

    fn handle_compare<W: Write>(
        &self,
        op: &RequestOp,
        id: i32,
        req: &crate::protocol::CompareRequest,
        writer: &mut W,
    ) -> std::io::Result<bool> {
        let result = self
            .backend
            .compare(&req.entry, &req.ava.attribute_desc, &req.ava.assertion_value)
            .map(|matched| {
                if matched {
                    ResultCode::CompareTrue
                } else {
                    ResultCode::CompareFalse
                }
            })
            .map_err(|e| ResultCode::from_backend_error(&e));
        self.emit(op, id, result, "compare failed", writer).map(|_| false)
    }

    fn handle_add<W: Write>(
        &self,
        op: &RequestOp,
        id: i32,
        req: &crate::protocol::AddRequest,
        writer: &mut W,
    ) -> std::io::Result<bool> {
        let result = self.backend.add(&req.entry).map(|_| ResultCode::Success).map_err(|e| ResultCode::from_backend_error(&e));
        self.emit(op, id, result, "add failed", writer).map(|_| false)
    }

    fn handle_delete<W: Write>(
        &self,
        op: &RequestOp,
        id: i32,
        dn: &str,
        writer: &mut W,
    ) -> std::io::Result<bool> {
        let result = self.backend.delete(dn).map(|_| ResultCode::Success).map_err(|e| ResultCode::from_backend_error(&e));
        self.emit(op, id, result, "delete failed", writer).map(|_| false)
    }

    fn handle_modify<W: Write>(
        &self,
        op: &RequestOp,
        id: i32,
        req: &crate::protocol::ModifyRequest,
        writer: &mut W,
    ) -> std::io::Result<bool> {
        let changes: Vec<Modification> = req.changes.clone();
        let result = self
            .backend
            .modify(&req.object, &changes)
            .map(|_| ResultCode::Success).map_err(|e| ResultCode::from_backend_error(&e));
        self.emit(op, id, result, "modify failed", writer).map(|_| false)
    }

    fn handle_modify_dn<W: Write>(
        &self,
        op: &RequestOp,
        id: i32,
        req: &crate::backend::ModifyDnRequest,
        writer: &mut W,
    ) -> std::io::Result<bool> {
        let result = self.backend.modify_dn(req).map(|_| ResultCode::Success).map_err(|e| ResultCode::from_backend_error(&e));
        self.emit(op, id, result, "modify DN failed", writer).map(|_| false)
    }

    /// Emit a result response for `op`, mapping `Ok`/`Err` result codes.
    fn emit<W: Write>(
        &self,
        op: &RequestOp,
        id: i32,
        result: Result<ResultCode, ResultCode>,
        diag: &str,
        writer: &mut W,
    ) -> std::io::Result<()> {
        match result {
            Ok(code) => self.respond(op, id, code, "", writer),
            Err(code) => self.respond(op, id, code, diag, writer),
        }
    }

    /// Emit a single result response (with the correct application tag for the
    /// originating operation) carrying `code` and `diag`.
    fn respond<W: Write>(
        &self,
        op: &RequestOp,
        id: i32,
        code: ResultCode,
        diag: &str,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let result = if code == ResultCode::Success {
            crate::protocol::LdapResult::success()
        } else {
            crate::protocol::LdapResult::error(code, diag)
        };
        let response_op = match op {
            RequestOp::Bind(_) => ResponseOp::Bind(result),
            RequestOp::Search(_) => ResponseOp::SearchResultDone(result),
            RequestOp::Compare(_) => ResponseOp::Compare(result),
            RequestOp::Add(_) => ResponseOp::Add(result),
            RequestOp::Delete(_) => ResponseOp::Delete(result),
            RequestOp::Modify(_) => ResponseOp::Modify(result),
            RequestOp::ModifyDn(_) => ResponseOp::ModifyDn(result),
            RequestOp::Extended(_) => ResponseOp::Extended(result),
            RequestOp::Unbind | RequestOp::Abandon(_) => {
                // These operations never produce a response.
                return Ok(());
            }
        };
        let resp = LdapResponse {
            id,
            op: response_op,
            controls: Vec::new(),
        };
        writer.write_all(&resp.encode())
    }
}

/// Read a single complete LDAP message from `reader`, accumulating into `buf`
/// until enough bytes are available. Returns `None` on clean EOF.
fn read_message<R: Read>(reader: &mut R, buf: &mut Vec<u8>) -> std::io::Result<Option<LdapRequest>> {
    loop {
        match decode_request(buf) {
            Ok((req, consumed)) => {
                buf.drain(..consumed);
                return Ok(Some(req));
            }
            Err(BerError::Truncated) => {
                let mut chunk = [0u8; 8192];
                let n = reader.read(&mut chunk)?;
                if n == 0 {
                    if buf.is_empty() {
                        return Ok(None);
                    }
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "truncated LDAP message",
                    ));
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > MAX_MESSAGE_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "LDAP message too large",
                    ));
                }
            }
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("BER decode error: {}", e),
                ));
            }
        }
    }
}
