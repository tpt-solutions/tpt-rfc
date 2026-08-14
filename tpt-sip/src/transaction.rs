// SPDX-License-Identifier: MIT OR Apache-2.0
//! SIP transaction layer (RFC 3261 §17).
//!
//! A *transaction* is a request issued by a client transaction user (TU)
//! or received by a server TU, together with all responses to that
//! request (for INVITE also the acknowledging ACK). The four state
//! machines below implement the client/server, INVITE/non-INVITE
//! behaviours exactly as specified in §17.1 and §17.2:
//!
//! - client INVITE:   Calling → Proceeding → Accepted | Completed → Terminated
//! - client non-INVITE: Trying → Proceeding → Completed → Terminated
//! - server INVITE:   Proceeding → Completed → Confirmed → Terminated
//! - server non-INVITE: Trying → Proceeding → Completed → Terminated
//!
//! The engine is transport-agnostic and timer-driven: callers feed it
//! [`TxEvent`]s (an outbound request/response, an inbound message, or a
//! fired timer) and act on the returned [`TxAction`]s (transmit a
//! message, start/stop a timer, deliver to the TU, or terminate).

use std::time::Duration;

use crate::error::SipError;
use crate::message::{Header, Message, RequestLine};
use crate::method::Method;

/// Whether the transaction runs over a reliable (e.g. TCP/TLS/SCTP) or
/// unreliable (e.g. UDP) transport. Reliable transports skip
/// retransmission timers and the ACK-wait states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportReliability {
    /// Unreliable transport (UDP) — retransmission and wait timers apply.
    Unreliable,
    /// Reliable transport (TCP/TLS) — no retransmission needed.
    Reliable,
}

/// The direction of the transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// A client transaction: originated the request.
    Client,
    /// A server transaction: received the request.
    Server,
}

/// Whether the transaction is for an INVITE (or ACK/CANCEL derived from
/// it) or another method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionKind {
    /// INVITE-class transaction (the only one with an ACK sub-flow).
    Invite,
    /// Any non-INVITE method (OPTIONS, REGISTER, BYE, …).
    NonInvite,
}

/// Timer durations and retransmission parameters (RFC 3261 §17). All
/// defaults follow the specification; tests may shorten them.
#[derive(Debug, Clone)]
pub struct TxTimers {
    /// T1: round-trip time estimate (default 500 ms).
    pub t1: Duration,
    /// T2: maximum retransmission interval (default 4 s).
    pub t2: Duration,
    /// T4: maximum duration a message can remain in the network (5 s).
    pub t4: Duration,
}

impl Default for TxTimers {
    fn default() -> Self {
        TxTimers {
            t1: Duration::from_millis(500),
            t2: Duration::from_secs(4),
            t4: Duration::from_secs(5),
        }
    }
}

impl TxTimers {
    fn timer_a(&self, count: u32) -> Duration {
        self.exponential(self.t1, count)
    }
    fn timer_b(&self) -> Duration {
        self.t1 * 64
    }
    fn timer_d(&self, reliable: bool) -> Duration {
        if reliable {
            Duration::ZERO
        } else {
            Duration::from_secs(32)
        }
    }
    fn timer_e(&self, count: u32) -> Duration {
        self.exponential(self.t1, count)
    }
    fn timer_f(&self) -> Duration {
        self.t1 * 64
    }
    fn timer_g(&self, count: u32) -> Duration {
        self.exponential(self.t1, count)
    }
    fn timer_h(&self) -> Duration {
        self.t1 * 64
    }
    fn timer_i(&self, reliable: bool) -> Duration {
        if reliable {
            Duration::ZERO
        } else {
            self.t4
        }
    }
    fn timer_j(&self, reliable: bool) -> Duration {
        if reliable {
            Duration::ZERO
        } else {
            self.t1 * 64
        }
    }
    fn timer_k(&self, reliable: bool) -> Duration {
        if reliable {
            Duration::ZERO
        } else {
            Duration::from_secs(4)
        }
    }
    fn timer_m(&self, reliable: bool) -> Duration {
        if reliable {
            Duration::ZERO
        } else {
            self.t1 * 64
        }
    }
    fn exponential(&self, base: Duration, count: u32) -> Duration {
        let factor = 1u64.checked_shl(count).unwrap_or(u64::MAX).min(64);
        let mut d = base * factor as u32;
        if d > self.t2 {
            d = self.t2;
        }
        d
    }
}

/// States of the transaction state machine. The variants are grouped by
/// the (role, kind) they belong to; see the module docs for the
/// transition graphs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxState {
    // client INVITE
    /// Initial state: INVITE sent, awaiting first response.
    Calling,
    /// INVITE sent, at least one provisional (1xx) received.
    ProceedingInvite,
    /// A 2xx was received; waiting for possible 2xx retransmissions.
    Accepted,
    /// A non-2xx was received; ACK sent, waiting Timer D.
    CompletedInvite,
    // client non-INVITE
    /// Initial state: request sent, awaiting first response.
    Trying,
    /// Response (provisional or final) received.
    Proceeding,
    /// Final response received; waiting Timer K.
    Completed,
    // server INVITE
    /// Received INVITE; awaiting a TU response.
    ProceedingServer,
    /// Final non-2xx sent; awaiting ACK.
    CompletedServer,
    /// ACK received; waiting Timer I.
    ConfirmedServer,
    // server non-INVITE
    /// Received request; awaiting a TU response.
    TryingServer,
    /// A provisional (1xx) response was sent; awaiting a final.
    ProceedingServerNonInvite,
    /// Final response sent; waiting Timer J.
    CompletedServerNonInvite,
    /// Terminal state.
    Terminated,
}

/// An event delivered to the transaction state machine.
#[derive(Debug, Clone)]
pub enum TxEvent {
    /// Client: the TU submits the request to send. Server: a request
    /// arrived from the network.
    Request(Message),
    /// Client: a response arrived from the network. Server: the TU submits
    /// a response to send.
    Response(Message),
    /// A timer fired. The string names match the RFC (A, B, D, E, F, G, H,
    /// I, J, K, M).
    Timer(&'static str),
}

/// An action the transaction requests of its driver.
#[derive(Debug, Clone)]
pub enum TxAction {
    /// Transmit this message on the transport.
    Transmit(Message),
    /// (Re)start the named timer with this duration.
    StartTimer(&'static str, Duration),
    /// Stop the named timer.
    StopTimer(&'static str),
    /// Deliver this message to the transaction user (TU).
    Deliver(Message),
    /// The transaction has reached its terminal state.
    Terminate,
}

/// A SIP transaction.
pub struct Transaction {
    /// Direction of the transaction.
    pub role: Role,
    /// INVITE-class or non-INVITE.
    pub kind: TransactionKind,
    /// The branch parameter — the transaction identifier (RFC 3261 §17).
    pub branch: String,
    /// The method of the original request.
    pub method: Method,
    /// Transport reliability (selects retransmission/wait behaviour).
    pub reliable: bool,
    /// Current state.
    pub state: TxState,
    timers: TxTimers,
    retransmit_count: u32,
    g_started: bool,
    original_request: Option<Message>,
    last_response: Option<Message>,
    last_ack: Option<Message>,
}

impl Transaction {
    fn build(
        role: Role,
        kind: TransactionKind,
        request: &Message,
        reliable: bool,
    ) -> Result<Transaction, SipError> {
        let branch = request
            .top_via()
            .and_then(|v| v.branch().map(|b| b.to_string()))
            .ok_or_else(|| SipError::Transaction("request has no Via branch".into()))?;
        let method = request
            .method()
            .ok_or_else(|| SipError::Transaction("request has no method".into()))?;
        let state = match (role, kind) {
            (Role::Client, TransactionKind::Invite) => TxState::Calling,
            (Role::Client, TransactionKind::NonInvite) => TxState::Trying,
            (Role::Server, TransactionKind::Invite) => TxState::ProceedingServer,
            (Role::Server, TransactionKind::NonInvite) => TxState::TryingServer,
        };
        Ok(Transaction {
            role,
            kind,
            branch,
            method,
            reliable,
            state,
            timers: TxTimers::default(),
            retransmit_count: 0,
            g_started: false,
            original_request: Some(request.clone()),
            last_response: None,
            last_ack: None,
        })
    }

    /// Create a client INVITE transaction and apply the initial request
    /// send. Returns the transaction plus the resulting actions (a
    /// `Transmit` and any timer starts).
    pub fn client_invite(
        request: &Message,
        reliable: bool,
    ) -> Result<(Transaction, Vec<TxAction>), SipError> {
        let mut tx = Self::build(Role::Client, TransactionKind::Invite, request, reliable)?;
        let actions = tx.on_event(TxEvent::Request(request.clone()));
        Ok((tx, actions))
    }

    /// Create a client non-INVITE transaction and apply the initial
    /// request send.
    pub fn client_non_invite(
        request: &Message,
        reliable: bool,
    ) -> Result<(Transaction, Vec<TxAction>), SipError> {
        let mut tx = Self::build(Role::Client, TransactionKind::NonInvite, request, reliable)?;
        let actions = tx.on_event(TxEvent::Request(request.clone()));
        Ok((tx, actions))
    }

    /// Create a server INVITE transaction seeded by the received request.
    pub fn server_invite(
        request: &Message,
        reliable: bool,
    ) -> Result<(Transaction, Vec<TxAction>), SipError> {
        let mut tx = Self::build(Role::Server, TransactionKind::Invite, request, reliable)?;
        let actions = tx.on_event(TxEvent::Request(request.clone()));
        Ok((tx, actions))
    }

    /// Create a server non-INVITE transaction seeded by the received
    /// request.
    pub fn server_non_invite(
        request: &Message,
        reliable: bool,
    ) -> Result<(Transaction, Vec<TxAction>), SipError> {
        let mut tx = Self::build(Role::Server, TransactionKind::NonInvite, request, reliable)?;
        let actions = tx.on_event(TxEvent::Request(request.clone()));
        Ok((tx, actions))
    }

    /// Override the timer configuration (e.g. for fast tests).
    pub fn set_timers(&mut self, timers: TxTimers) -> &mut Self {
        self.timers = timers;
        self
    }

    /// Whether the transaction has reached its terminal state.
    pub fn is_terminated(&self) -> bool {
        self.state == TxState::Terminated
    }

    /// Drive the state machine with an event, returning the resulting
    /// actions.
    pub fn on_event(&mut self, event: TxEvent) -> Vec<TxAction> {
        match (self.role, self.kind) {
            (Role::Client, TransactionKind::Invite) => self.client_invite_evt(event),
            (Role::Client, TransactionKind::NonInvite) => self.client_non_invite_evt(event),
            (Role::Server, TransactionKind::Invite) => self.server_invite_evt(event),
            (Role::Server, TransactionKind::NonInvite) => self.server_non_invite_evt(event),
        }
    }

    fn start_timer(&self, name: &'static str, dur: Duration, out: &mut Vec<TxAction>) {
        if !dur.is_zero() {
            out.push(TxAction::StartTimer(name, dur));
        }
    }

    // ---- client INVITE ----
    fn client_invite_evt(&mut self, event: TxEvent) -> Vec<TxAction> {
        let mut out = Vec::new();
        match (&self.state, event) {
            (TxState::Calling, TxEvent::Request(msg)) => {
                self.original_request = Some(msg.clone());
                out.push(TxAction::Transmit(msg));
                if !self.reliable {
                    self.start_timer("A", self.timers.timer_a(0), &mut out);
                }
                self.start_timer("B", self.timers.timer_b(), &mut out);
                self.state = TxState::ProceedingInvite;
            }
            (TxState::ProceedingInvite, TxEvent::Timer("A")) => {
                if let Some(req) = &self.original_request {
                    out.push(TxAction::Transmit(req.clone()));
                    self.retransmit_count += 1;
                    self.start_timer("A", self.timers.timer_a(self.retransmit_count), &mut out);
                }
            }
            (TxState::ProceedingInvite, TxEvent::Timer("B")) => {
                self.state = TxState::Terminated;
                out.push(TxAction::Terminate);
            }
            (TxState::ProceedingInvite, TxEvent::Response(msg)) => {
                let code = status_code(&msg);
                if (100..200).contains(&code) {
                    out.push(TxAction::Deliver(msg));
                } else if (200..300).contains(&code) {
                    out.push(TxAction::Deliver(msg));
                    self.start_timer("M", self.timers.timer_m(self.reliable), &mut out);
                    self.state = TxState::Accepted;
                } else {
                    if let Some(ack) = self.build_ack(&msg) {
                        out.push(TxAction::Transmit(ack));
                    }
                    out.push(TxAction::Deliver(msg));
                    if self.reliable {
                        self.state = TxState::Terminated;
                        out.push(TxAction::Terminate);
                    } else {
                        self.start_timer("D", self.timers.timer_d(self.reliable), &mut out);
                        self.state = TxState::CompletedInvite;
                    }
                }
            }
            (TxState::Accepted, TxEvent::Response(msg)) => {
                out.push(TxAction::Deliver(msg));
                self.start_timer("M", self.timers.timer_m(self.reliable), &mut out);
            }
            (TxState::Accepted, TxEvent::Timer("M")) => {
                self.state = TxState::Terminated;
                out.push(TxAction::Terminate);
            }
            (TxState::CompletedInvite, TxEvent::Response(_)) => {
                if let Some(ack) = &self.last_ack {
                    out.push(TxAction::Transmit(ack.clone()));
                }
            }
            (TxState::CompletedInvite, TxEvent::Timer("D")) => {
                self.state = TxState::Terminated;
                out.push(TxAction::Terminate);
            }
            _ => {}
        }
        out
    }

    // ---- client non-INVITE ----
    fn client_non_invite_evt(&mut self, event: TxEvent) -> Vec<TxAction> {
        let mut out = Vec::new();
        match (&self.state, event) {
            (TxState::Trying, TxEvent::Request(msg)) => {
                self.original_request = Some(msg.clone());
                out.push(TxAction::Transmit(msg));
                if !self.reliable {
                    self.start_timer("E", self.timers.timer_e(0), &mut out);
                }
                self.start_timer("F", self.timers.timer_f(), &mut out);
                self.state = TxState::Proceeding;
            }
            (TxState::Proceeding, TxEvent::Timer("E")) => {
                if let Some(req) = &self.original_request {
                    out.push(TxAction::Transmit(req.clone()));
                    self.retransmit_count += 1;
                    self.start_timer("E", self.timers.timer_e(self.retransmit_count), &mut out);
                }
            }
            (TxState::Proceeding, TxEvent::Timer("F")) => {
                self.state = TxState::Terminated;
                out.push(TxAction::Terminate);
            }
            (TxState::Proceeding, TxEvent::Response(msg)) => {
                out.push(TxAction::Deliver(msg));
                self.start_timer("K", self.timers.timer_k(self.reliable), &mut out);
                self.state = TxState::Completed;
            }
            (TxState::Completed, TxEvent::Timer("K")) => {
                self.state = TxState::Terminated;
                out.push(TxAction::Terminate);
            }
            _ => {}
        }
        out
    }

    // ---- server INVITE ----
    fn server_invite_evt(&mut self, event: TxEvent) -> Vec<TxAction> {
        let mut out = Vec::new();
        match (&self.state, event) {
            (TxState::ProceedingServer, TxEvent::Response(msg)) => {
                let code = status_code(&msg);
                self.last_response = Some(msg.clone());
                out.push(TxAction::Transmit(msg));
                if (100..200).contains(&code) {
                    if !self.g_started {
                        self.g_started = true;
                        if !self.reliable {
                            self.start_timer("G", self.timers.timer_g(0), &mut out);
                        }
                    }
                } else if (200..300).contains(&code) {
                    self.state = TxState::Terminated;
                    out.push(TxAction::Terminate);
                } else {
                    self.g_started = false;
                    out.push(TxAction::StopTimer("G"));
                    if self.reliable {
                        self.state = TxState::Terminated;
                        out.push(TxAction::Terminate);
                    } else {
                        self.start_timer("H", self.timers.timer_h(), &mut out);
                        self.state = TxState::CompletedServer;
                    }
                }
            }
            (TxState::ProceedingServer, TxEvent::Timer("G")) => {
                if let Some(resp) = &self.last_response {
                    out.push(TxAction::Transmit(resp.clone()));
                    self.retransmit_count += 1;
                    self.start_timer("G", self.timers.timer_g(self.retransmit_count), &mut out);
                }
            }
            (TxState::ProceedingServer, TxEvent::Request(_)) => {
                if let Some(resp) = &self.last_response {
                    out.push(TxAction::Transmit(resp.clone()));
                }
            }
            (TxState::CompletedServer, TxEvent::Request(msg)) => {
                if msg.method() == Some(Method::Ack) {
                    out.push(TxAction::Deliver(msg));
                    self.start_timer("I", self.timers.timer_i(self.reliable), &mut out);
                    self.state = TxState::ConfirmedServer;
                } else if let Some(resp) = &self.last_response {
                    out.push(TxAction::Transmit(resp.clone()));
                }
            }
            (TxState::CompletedServer, TxEvent::Timer("H")) => {
                self.state = TxState::Terminated;
                out.push(TxAction::Terminate);
            }
            (TxState::ConfirmedServer, TxEvent::Timer("I")) => {
                self.state = TxState::Terminated;
                out.push(TxAction::Terminate);
            }
            (TxState::ConfirmedServer, TxEvent::Request(_)) => {
                if let Some(resp) = &self.last_response {
                    out.push(TxAction::Transmit(resp.clone()));
                }
            }
            _ => {}
        }
        out
    }

    // ---- server non-INVITE ----
    fn server_non_invite_evt(&mut self, event: TxEvent) -> Vec<TxAction> {
        let mut out = Vec::new();
        match (&self.state, event) {
            (TxState::TryingServer, TxEvent::Response(msg)) => {
                let code = status_code(&msg);
                self.last_response = Some(msg.clone());
                out.push(TxAction::Transmit(msg));
                if (100..200).contains(&code) {
                    self.state = TxState::ProceedingServerNonInvite;
                } else if !self.reliable {
                    self.start_timer("J", self.timers.timer_j(self.reliable), &mut out);
                    self.state = TxState::CompletedServerNonInvite;
                } else {
                    self.state = TxState::Terminated;
                    out.push(TxAction::Terminate);
                }
            }
            (TxState::ProceedingServerNonInvite, TxEvent::Response(msg)) => {
                let code = status_code(&msg);
                self.last_response = Some(msg.clone());
                out.push(TxAction::Transmit(msg));
                if !(100..200).contains(&code) {
                    if !self.reliable {
                        self.start_timer("J", self.timers.timer_j(self.reliable), &mut out);
                    }
                    self.state = TxState::CompletedServerNonInvite;
                }
            }
            (
                TxState::ProceedingServerNonInvite | TxState::CompletedServerNonInvite,
                TxEvent::Request(_),
            ) => {
                if let Some(resp) = &self.last_response {
                    out.push(TxAction::Transmit(resp.clone()));
                }
            }
            (TxState::CompletedServerNonInvite, TxEvent::Timer("J")) => {
                self.state = TxState::Terminated;
                out.push(TxAction::Terminate);
            }
            _ => {}
        }
        out
    }

    /// Build the ACK sent by a client INVITE transaction upon receiving a
    /// non-2xx response (RFC 3261 §17.1.1.3).
    fn build_ack(&mut self, response: &Message) -> Option<Message> {
        let req = self.original_request.clone()?;
        let uri = req.request_line().map(|r| r.uri.clone())?;
        let mut via = String::new();
        let mut first = true;
        for v in response.via() {
            if !first {
                via.push_str(", ");
            }
            first = false;
            via.push_str(&v.to_string());
        }
        let from = response.from().map(|f| f.to_string())?;
        let to = response.to().map(|t| t.to_string())?;
        let call_id = response.call_id()?.to_string();
        let cseq = response.cseq().map(|c| c.seq)?;
        let ack = Message::request(
            RequestLine::new(Method::Ack, uri),
            vec![
                Header::new("Via", via),
                Header::new("Max-Forwards", "70".to_string()),
                Header::new("From", from),
                Header::new("To", to),
                Header::new("Call-ID", call_id),
                Header::new("CSeq", format!("{cseq} ACK")),
            ],
            Vec::new(),
        );
        self.last_ack = Some(ack.clone());
        Some(ack)
    }
}

fn status_code(msg: &Message) -> u16 {
    msg.status_line().map(|s| s.code).unwrap_or(0)
}
