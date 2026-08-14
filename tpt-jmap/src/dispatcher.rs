// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The JMAP method dispatcher (RFC 8620 §3). It owns a `MailStore`, validates
//! the request envelope, resolves result references, routes each method call to
//! the backend, and assembles the `Response`.

use std::cell::RefCell;
use std::collections::HashMap;

use serde_json::Value;

use crate::error::{MethodError, RequestError};
use crate::mail::store::MailStore;
use crate::reference::resolve_args;
use crate::session::Session;
use crate::types::{check_capabilities, Invocation, Request, Response};

/// Dispatches JMAP method calls against a `MailStore` backend.
pub struct Dispatcher {
    store: RefCell<Box<dyn MailStore>>,
    session: Session,
}

impl Dispatcher {
    /// Create a dispatcher with the default single-account session.
    pub fn new(store: impl MailStore + 'static) -> Self {
        Dispatcher {
            store: RefCell::new(Box::new(store)),
            session: Session::default_for("account1"),
        }
    }

    /// Create a dispatcher with an explicit session (e.g. to advertise custom
    /// capabilities or multiple accounts).
    pub fn with_session(store: impl MailStore + 'static, session: Session) -> Self {
        Dispatcher {
            store: RefCell::new(Box::new(store)),
            session,
        }
    }

    /// The session resource this server would advertise at its API endpoint.
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Process a raw JSON request value, returning the `Response`, or — on a
    /// request-level error (RFC 8620 §3.7) — the serialized error response.
    pub fn dispatch(&self, request: Value) -> Result<Response, Value> {
        let req = match Response::parse_request(request) {
            Ok(r) => r,
            Err(e) => return Err(e.to_response()),
        };
        if let Err(cap) = check_capabilities(&req.using, &Session::supported_capabilities()) {
            return Err(RequestError::UnknownCapability { capability: cap }.to_response());
        }
        Ok(self.dispatch_request(req))
    }

    fn dispatch_request(&self, req: Request) -> Response {
        let mut responses: HashMap<String, Value> = HashMap::new();
        let mut method_responses: Vec<Invocation> = Vec::new();

        for call in &req.method_calls {
            let resolved = match resolve_args(call, &responses) {
                Ok(v) => v,
                Err(e) => {
                    method_responses.push(Invocation::error(&call.client_id, &e));
                    continue;
                }
            };

            let account = resolved.get("accountId").and_then(|v| v.as_str());
            let result = match account {
                Some(acc) => self.route(acc, &call.name, &resolved),
                None => Err(MethodError::invalid_arguments(
                    "accountId is required",
                    vec!["accountId"],
                )),
            };

            let inv = match result {
                Ok(value) => Invocation {
                    name: call.name.clone(),
                    args: value,
                    client_id: call.client_id.clone(),
                },
                Err(e) => Invocation::error(&call.client_id, &e),
            };
            responses.insert(call.client_id.clone(), inv.args.clone());
            method_responses.push(inv);
        }

        Response {
            method_responses,
            session_state: self.session.state.clone(),
            created_ids: None,
        }
    }

    fn route(&self, account: &str, method: &str, args: &Value) -> Result<Value, MethodError> {
        if !self.store.borrow().account_exists(account) {
            return Err(MethodError::account_not_found(account));
        }
        let mut store = self.store.borrow_mut();
        match method {
            "Mailbox/get" => store.mailbox_get(account, args),
            "Mailbox/set" => store.mailbox_set(account, args),
            "Mailbox/query" => store.mailbox_query(account, args),
            "Mailbox/changes" => store.mailbox_changes(account, args),
            "Email/get" => store.email_get(account, args),
            "Email/query" => store.email_query(account, args),
            "Email/set" => store.email_set(account, args),
            "Email/changes" => store.email_changes(account, args),
            "Thread/get" => store.thread_get(account, args),
            "EmailSubmission/get" => store.email_submission_get(account, args),
            "EmailSubmission/set" => store.email_submission_set(account, args),
            "EmailSubmission/query" => store.email_submission_query(account, args),
            "EmailSubmission/changes" => store.email_submission_changes(account, args),
            _ => Err(MethodError::unknown_method(method)),
        }
    }
}
