// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The BGP peer finite-state machine (RFC 4271 §8). The FSM is
//! transport-agnostic: callers drive it by feeding events ([`FsmEvent`]) and
//! acting on the returned [`FsmAction`]s (open the TCP connection, send an
//! OPEN/KEEPALIVE/NOTIFICATION, (re)start a timer, …). Timer bookkeeping is
//! the caller's responsibility.

use crate::wire::Notification;

/// The six BGP peer states (RFC 4271 §8, Figure 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsmState {
    /// No resources allocated; the initial and final state.
    Idle,
    /// Waiting for the TCP connection to be completed (we initiated it).
    Connect,
    /// Waiting for a TCP connection to be completed (peer initiated it) or for
    /// a connect retry.
    Active,
    /// OPEN sent; awaiting the peer's OPEN.
    OpenSent,
    /// OPEN received and accepted; awaiting a KEEPALIVE (or UPDATE).
    OpenConfirm,
    /// Peering established; UPDATEs may flow.
    Established,
}

impl FsmState {
    /// The canonical state name (RFC 4271).
    pub fn name(self) -> &'static str {
        match self {
            FsmState::Idle => "Idle",
            FsmState::Connect => "Connect",
            FsmState::Active => "Active",
            FsmState::OpenSent => "OpenSent",
            FsmState::OpenConfirm => "OpenConfirm",
            FsmState::Established => "Established",
        }
    }

    /// True once the peer has reached the Established state.
    pub fn is_established(self) -> bool {
        self == FsmState::Established
    }
}

/// Events that drive the peer FSM (RFC 4271 §8.1, condensed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsmEvent {
    /// Administrative start (ManualStart / AutomaticStart).
    ManualStart,
    /// Administrative stop (ManualStop).
    ManualStop,
    /// The locally-initiated TCP connection succeeded.
    TcpConnectionValid,
    /// The locally-initiated TCP connection failed or was refused.
    TcpConnectionFailed,
    /// A passive (peer-initiated) TCP connection was accepted.
    TcpConnectionOpened,
    /// The TCP connection was closed.
    TcpClose,
    /// A syntactically and semantically valid OPEN was received. The remote
    /// BGP identifier is carried so collision detection (§6.8) can compare it
    /// against the local one.
    BgpOpenValid([u8; 4]),
    /// The received OPEN failed validation; the NOTIFICATION to send is
    /// attached.
    BgpOpenInvalid(Notification),
    /// A NOTIFICATION was received from the peer.
    NotificationReceived(Notification),
    /// A KEEPALIVE was received.
    KeepaliveReceived,
    /// The hold timer expired.
    HoldTimerExpired,
    /// The keepalive timer expired (it is the caller's job to send a
    /// KEEPALIVE and restart it).
    KeepaliveTimerExpired,
    /// The DelayOpen timer expired (optional DelayOpen mode).
    DelayOpenTimerExpired,
    /// The IdleHold timer expired.
    IdleHoldTimerExpired,
}

/// Actions the FSM requests of the caller in response to an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsmAction {
    /// Initiate (or re-initiate) the TCP connection to the peer.
    InitiateTcpConnection,
    /// Release/close the TCP connection.
    ReleaseTcpConnection,
    /// Send an OPEN message to the peer.
    SendOpen,
    /// Send a KEEPALIVE message to the peer.
    SendKeepalive,
    /// Send a NOTIFICATION message to the peer.
    SendNotification(Notification),
    /// Start the ConnectRetry timer.
    StartConnectRetryTimer,
    /// Start the Hold timer.
    StartHoldTimer,
    /// Start the Keepalive timer.
    StartKeepaliveTimer,
    /// Start the DelayOpen timer (optional mode).
    StartDelayOpenTimer,
    /// Start the IdleHold timer.
    StartIdleHoldTimer,
}

/// A BGP peer finite-state machine.
#[derive(Debug, Clone)]
pub struct Fsm {
    /// The current state.
    pub state: FsmState,
    /// The local BGP identifier, used for collision detection.
    pub local_bgp_id: [u8; 4],
    /// The remote BGP identifier learned from a received OPEN (used for
    /// collision detection, §6.8). `None` until an OPEN has been accepted.
    pub remote_bgp_id: Option<[u8; 4]>,
    /// Whether four-octet ASN semantics are in effect (affects nothing in the
    /// FSM itself but is tracked for caller convenience).
    pub as4: bool,
}

impl Fsm {
    /// Create a new FSM in the Idle state.
    pub fn new(local_bgp_id: [u8; 4]) -> Self {
        Fsm {
            state: FsmState::Idle,
            local_bgp_id,
            remote_bgp_id: None,
            as4: true,
        }
    }

    /// Feed an event to the FSM, transitioning state and returning the actions
    /// the caller must perform.
    pub fn on_event(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        let mut actions = Vec::new();
        let mut next = self.state;

        match (self.state, &event) {
            // ---- Idle -----------------------------------------------------
            (FsmState::Idle, FsmEvent::ManualStart) => {
                next = FsmState::Connect;
                actions.push(FsmAction::InitiateTcpConnection);
                actions.push(FsmAction::StartConnectRetryTimer);
                actions.push(FsmAction::StartDelayOpenTimer);
            }
            (FsmState::Idle, FsmEvent::IdleHoldTimerExpired) => {
                next = FsmState::Connect;
                actions.push(FsmAction::InitiateTcpConnection);
                actions.push(FsmAction::StartConnectRetryTimer);
                actions.push(FsmAction::StartDelayOpenTimer);
            }
            (FsmState::Idle, FsmEvent::ManualStop) => { /* remain Idle */ }

            // ---- Connect --------------------------------------------------
            (FsmState::Connect, FsmEvent::ManualStop) => {
                next = FsmState::Idle;
                actions.push(FsmAction::ReleaseTcpConnection);
                actions.push(FsmAction::StartIdleHoldTimer);
            }
            (FsmState::Connect, FsmEvent::TcpConnectionValid) => {
                next = FsmState::OpenSent;
                actions.push(FsmAction::SendOpen);
                actions.push(FsmAction::StartHoldTimer);
            }
            (FsmState::Connect, FsmEvent::TcpConnectionFailed) => {
                next = FsmState::Idle;
                actions.push(FsmAction::StartConnectRetryTimer);
                actions.push(FsmAction::StartIdleHoldTimer);
            }
            (FsmState::Connect, FsmEvent::TcpConnectionOpened) => {
                next = FsmState::OpenSent;
                actions.push(FsmAction::SendOpen);
                actions.push(FsmAction::StartHoldTimer);
            }
            (FsmState::Connect, FsmEvent::DelayOpenTimerExpired) => {
                next = FsmState::OpenSent;
                actions.push(FsmAction::SendOpen);
                actions.push(FsmAction::StartHoldTimer);
            }
            (FsmState::Connect, FsmEvent::BgpOpenInvalid(n)) => {
                next = FsmState::Idle;
                actions.push(FsmAction::SendNotification(n.clone()));
                actions.push(FsmAction::ReleaseTcpConnection);
                actions.push(FsmAction::StartIdleHoldTimer);
            }

            // ---- Active ---------------------------------------------------
            (FsmState::Active, FsmEvent::ManualStop) => {
                next = FsmState::Idle;
                actions.push(FsmAction::ReleaseTcpConnection);
                actions.push(FsmAction::StartIdleHoldTimer);
            }
            (FsmState::Active, FsmEvent::TcpConnectionValid)
            | (FsmState::Active, FsmEvent::TcpConnectionOpened) => {
                next = FsmState::OpenSent;
                actions.push(FsmAction::SendOpen);
                actions.push(FsmAction::StartHoldTimer);
            }
            (FsmState::Active, FsmEvent::TcpConnectionFailed) => {
                next = FsmState::Connect;
                actions.push(FsmAction::InitiateTcpConnection);
                actions.push(FsmAction::StartConnectRetryTimer);
                actions.push(FsmAction::StartDelayOpenTimer);
            }
            (FsmState::Active, FsmEvent::DelayOpenTimerExpired) => {
                next = FsmState::OpenSent;
                actions.push(FsmAction::SendOpen);
                actions.push(FsmAction::StartHoldTimer);
            }

            // ---- OpenSent -------------------------------------------------
            (FsmState::OpenSent, FsmEvent::ManualStop) => {
                next = FsmState::Idle;
                actions.push(FsmAction::SendNotification(Notification::cease()));
                actions.push(FsmAction::ReleaseTcpConnection);
                actions.push(FsmAction::StartIdleHoldTimer);
            }
            (FsmState::OpenSent, FsmEvent::TcpConnectionValid)
            | (FsmState::OpenSent, FsmEvent::TcpConnectionOpened) => {
                // A second connection arrives while we already have an OPEN
                // accepted elsewhere: resolve by BGP identifier (§6.8).
                if let Some(remote) = self.remote_bgp_id {
                    if self.local_bgp_id <= remote {
                        // We win — drop the new connection, keep our session.
                        actions.push(FsmAction::ReleaseTcpConnection);
                    } else {
                        // We are the higher-id speaker — close our session.
                        next = FsmState::Idle;
                        actions.push(FsmAction::ReleaseTcpConnection);
                        actions.push(FsmAction::StartIdleHoldTimer);
                    }
                } else {
                    actions.push(FsmAction::SendOpen);
                }
            }
            (FsmState::OpenSent, FsmEvent::BgpOpenValid(remote)) => {
                self.remote_bgp_id = Some(*remote);
                next = FsmState::OpenConfirm;
                actions.push(FsmAction::SendKeepalive);
                actions.push(FsmAction::StartKeepaliveTimer);
            }
            (FsmState::OpenSent, FsmEvent::BgpOpenInvalid(n))
            | (FsmState::OpenSent, FsmEvent::NotificationReceived(n)) => {
                next = FsmState::Idle;
                if let FsmEvent::BgpOpenInvalid(_) = &event {
                    actions.push(FsmAction::SendNotification(n.clone()));
                }
                actions.push(FsmAction::ReleaseTcpConnection);
                actions.push(FsmAction::StartIdleHoldTimer);
            }
            (FsmState::OpenSent, FsmEvent::HoldTimerExpired) => {
                next = FsmState::Idle;
                actions.push(FsmAction::SendNotification(Notification::new(
                    crate::wire::err_code::HOLD_TIMER_EXPIRED,
                    0,
                    Vec::new(),
                )));
                actions.push(FsmAction::ReleaseTcpConnection);
                actions.push(FsmAction::StartIdleHoldTimer);
            }
            (FsmState::OpenSent, FsmEvent::TcpClose) => {
                next = FsmState::Idle;
                actions.push(FsmAction::StartIdleHoldTimer);
            }

            // ---- OpenConfirm ----------------------------------------------
            (FsmState::OpenConfirm, FsmEvent::ManualStop) => {
                next = FsmState::Idle;
                actions.push(FsmAction::SendNotification(Notification::cease()));
                actions.push(FsmAction::ReleaseTcpConnection);
                actions.push(FsmAction::StartIdleHoldTimer);
            }
            (FsmState::OpenConfirm, FsmEvent::TcpConnectionValid)
            | (FsmState::OpenConfirm, FsmEvent::TcpConnectionOpened) => {
                // Duplicate connection (collision). The higher BGP id closes
                // its session (§6.8.2).
                if let Some(remote) = self.remote_bgp_id {
                    if self.local_bgp_id <= remote {
                        actions.push(FsmAction::ReleaseTcpConnection);
                    } else {
                        next = FsmState::Idle;
                        actions.push(FsmAction::SendNotification(Notification::cease()));
                        actions.push(FsmAction::ReleaseTcpConnection);
                        actions.push(FsmAction::StartIdleHoldTimer);
                    }
                }
            }
            (FsmState::OpenConfirm, FsmEvent::BgpOpenValid(_)) => {
                // A second OPEN on the same session is ignored.
            }
            (FsmState::OpenConfirm, FsmEvent::KeepaliveReceived) => {
                next = FsmState::Established;
                actions.push(FsmAction::StartHoldTimer);
            }
            (FsmState::OpenConfirm, FsmEvent::TcpClose)
            | (FsmState::OpenConfirm, FsmEvent::HoldTimerExpired)
            | (FsmState::OpenConfirm, FsmEvent::BgpOpenInvalid(_))
            | (FsmState::OpenConfirm, FsmEvent::NotificationReceived(_)) => {
                next = FsmState::Idle;
                if let FsmEvent::BgpOpenInvalid(n) = &event {
                    actions.push(FsmAction::SendNotification(n.clone()));
                }
                actions.push(FsmAction::ReleaseTcpConnection);
                actions.push(FsmAction::StartIdleHoldTimer);
            }

            // ---- Established ----------------------------------------------
            (FsmState::Established, FsmEvent::ManualStop) => {
                next = FsmState::Idle;
                actions.push(FsmAction::SendNotification(Notification::cease()));
                actions.push(FsmAction::ReleaseTcpConnection);
                actions.push(FsmAction::StartIdleHoldTimer);
            }
            (FsmState::Established, FsmEvent::KeepaliveReceived) => {
                next = FsmState::Established;
                actions.push(FsmAction::StartHoldTimer);
            }
            (FsmState::Established, FsmEvent::KeepaliveTimerExpired) => {
                actions.push(FsmAction::SendKeepalive);
                actions.push(FsmAction::StartKeepaliveTimer);
            }
            (FsmState::Established, FsmEvent::TcpClose)
            | (FsmState::Established, FsmEvent::HoldTimerExpired)
            | (FsmState::Established, FsmEvent::BgpOpenInvalid(_))
            | (FsmState::Established, FsmEvent::NotificationReceived(_)) => {
                next = FsmState::Idle;
                actions.push(FsmAction::SendNotification(Notification::cease()));
                actions.push(FsmAction::ReleaseTcpConnection);
                actions.push(FsmAction::StartIdleHoldTimer);
            }

            // Default: unhandled event in this state is a no-op.
            _ => {}
        }

        if next == FsmState::Idle {
            self.remote_bgp_id = None;
        }
        self.state = next;
        actions
    }
}
