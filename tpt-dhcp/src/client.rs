// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The RFC 2131 client finite-state machine.
//!
//! The client is driven event-by-event: call [`Client::start_discover`], feed
//! the server's reply to [`Client::receive_offer`] to get the REQUEST to send,
//! then feed the ACK to [`Client::receive_ack`] to transition to `Bound`.
//! Renewal, rebinding, and release are explicit client-initiated actions. This
//! keeps the FSM transport-agnostic and fully testable without a network.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::error::DhcpError;
use crate::message::{DhcpMessage, MessageOp};
use crate::options::{DhcpOption, MessageType};

/// Client FSM states (RFC 2131 §4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    /// No address; ready to send DISCOVER.
    Init,
    /// DISCOVER sent, waiting for OFFER(s).
    Selecting,
    /// REQUEST sent, waiting for ACK/NAK.
    Requesting,
    /// Address acquired and in use.
    Bound,
    /// Lease past T1; renewing with the leasing server (unicast).
    Renewing,
    /// Lease past T2; rebinding with any server (broadcast).
    Rebinding,
}

/// A lease as understood by the client.
#[derive(Debug, Clone)]
pub struct ClientLease {
    /// The address granted to this client.
    pub ip: Ipv4Addr,
    /// The server that granted the lease.
    pub server_id: Ipv4Addr,
    /// Total lease time in seconds.
    pub lease_time: u32,
    /// Renewal (T1) time in seconds.
    pub renewal_time: u32,
    /// Rebinding (T2) time in seconds.
    pub rebinding_time: u32,
    /// When the lease was obtained.
    pub obtained_at: Instant,
}

impl ClientLease {
    /// Whether the lease has fully expired relative to `now`.
    pub fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.obtained_at) >= Duration::from_secs(self.lease_time as u64)
    }

    /// Whether the client should begin renewing (past T1) relative to `now`.
    pub fn should_renew(&self, now: Instant) -> bool {
        now.duration_since(self.obtained_at) >= Duration::from_secs(self.renewal_time as u64)
    }

    /// Whether the client should begin rebinding (past T2) relative to `now`.
    pub fn should_rebind(&self, now: Instant) -> bool {
        now.duration_since(self.obtained_at) >= Duration::from_secs(self.rebinding_time as u64)
    }
}

/// A DHCP client.
pub struct Client {
    mac: [u8; 6],
    client_id: Option<Vec<u8>>,
    state: ClientState,
    xid: u32,
    next_xid: u32,
    offered: Option<Offer>,
    lease: Option<ClientLease>,
}

#[derive(Debug, Clone)]
struct Offer {
    ip: Ipv4Addr,
    server_id: Ipv4Addr,
    lease_time: u32,
    renewal_time: u32,
    rebinding_time: u32,
}

impl Client {
    /// Create a client with the given hardware (MAC) address.
    pub fn new(mac: [u8; 6]) -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x1234_5678);
        Self {
            mac,
            client_id: None,
            state: ClientState::Init,
            xid: 0,
            next_xid: (seed ^ 0x9E3779B9) as u32 | 1,
            offered: None,
            lease: None,
        }
    }

    /// Set a Client Identifier (option 61). When unset, the MAC is used as the
    /// client identity by the server.
    pub fn set_client_id(&mut self, id: Vec<u8>) {
        self.client_id = Some(id);
    }

    /// The client's current FSM state.
    pub fn state(&self) -> ClientState {
        self.state
    }

    /// The current lease, if bound.
    pub fn lease(&self) -> Option<&ClientLease> {
        self.lease.as_ref()
    }

    fn alloc_xid(&mut self) -> u32 {
        // A tiny xorshift keeps successive ids well-distributed without a
        // dependency; collisions are harmless for a single client session.
        let mut x = self.next_xid;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.next_xid = x | 1;
        x
    }

    /// Begin address acquisition: transition to `Selecting` and return the
    /// DISCOVER message to broadcast.
    pub fn start_discover(&mut self) -> DhcpMessage {
        self.xid = self.alloc_xid();
        self.offered = None;
        self.state = ClientState::Selecting;
        self.build_request(
            MessageType::Discover,
            true,
            false,
            false,
            Ipv4Addr::UNSPECIFIED,
        )
    }

    /// Feed a server message received while `Selecting`. If it is an OFFER
    /// matching this client's transaction, returns the REQUEST to send and
    /// transitions to `Requesting`; otherwise returns `None` (the message is
    /// ignored).
    pub fn receive_offer(&mut self, msg: &DhcpMessage) -> Option<DhcpMessage> {
        if self.state != ClientState::Selecting {
            return None;
        }
        if msg.message_type() != Some(MessageType::Offer) || msg.xid != self.xid {
            return None;
        }
        let ip = msg.yiaddr;
        let server_id = msg.server_identifier()?;
        if ip == Ipv4Addr::UNSPECIFIED {
            return None;
        }
        let lease_time = msg.lease_time().unwrap_or(3600);
        let renewal_time = msg
            .find_option(crate::options::CODE_RENEWAL_TIME)
            .and_then(|o| match o {
                DhcpOption::RenewalTime(v) => Some(*v),
                _ => None,
            })
            .unwrap_or(lease_time / 2);
        let rebinding_time = msg
            .find_option(crate::options::CODE_REBINDING_TIME)
            .and_then(|o| match o {
                DhcpOption::RebindingTime(v) => Some(*v),
                _ => None,
            })
            .unwrap_or(lease_time * 7 / 8);

        self.offered = Some(Offer {
            ip,
            server_id,
            lease_time,
            renewal_time,
            rebinding_time,
        });

        let request = self.build_request(
            MessageType::Request,
            true,
            true,
            true,
            Ipv4Addr::UNSPECIFIED,
        );
        self.state = ClientState::Requesting;
        Some(request)
    }

    /// Feed a server message received while `Requesting`, `Renewing`, or
    /// `Rebinding`. An ACK transitions to `Bound` (committing the lease); a NAK
    /// returns the client to `Init`. Messages that do not match the current
    /// transaction are rejected with [`DhcpError::UnexpectedMessage`].
    pub fn receive_ack(&mut self, msg: &DhcpMessage) -> Result<(), DhcpError> {
        if !matches!(
            self.state,
            ClientState::Requesting | ClientState::Renewing | ClientState::Rebinding
        ) {
            return Err(DhcpError::UnexpectedMessage);
        }
        if msg.xid != self.xid {
            return Err(DhcpError::UnexpectedMessage);
        }
        match msg.message_type() {
            Some(MessageType::Ack) => {
                let server_id = msg
                    .server_identifier()
                    .or_else(|| self.offered.as_ref().map(|o| o.server_id))
                    .or_else(|| self.lease.as_ref().map(|l| l.server_id))
                    .ok_or(DhcpError::UnexpectedMessage)?;
                let ip = if msg.yiaddr != Ipv4Addr::UNSPECIFIED {
                    msg.yiaddr
                } else {
                    self.lease
                        .as_ref()
                        .map(|l| l.ip)
                        .unwrap_or(Ipv4Addr::UNSPECIFIED)
                };
                let lease_time = msg
                    .lease_time()
                    .or(self.offered.as_ref().map(|o| o.lease_time))
                    .unwrap_or(3600);
                let renewal_time = msg
                    .find_option(crate::options::CODE_RENEWAL_TIME)
                    .and_then(|o| match o {
                        DhcpOption::RenewalTime(v) => Some(*v),
                        _ => None,
                    })
                    .or(self.offered.as_ref().map(|o| o.renewal_time))
                    .unwrap_or(lease_time / 2);
                let rebinding_time = msg
                    .find_option(crate::options::CODE_REBINDING_TIME)
                    .and_then(|o| match o {
                        DhcpOption::RebindingTime(v) => Some(*v),
                        _ => None,
                    })
                    .or(self.offered.as_ref().map(|o| o.rebinding_time))
                    .unwrap_or(lease_time * 7 / 8);

                self.lease = Some(ClientLease {
                    ip,
                    server_id,
                    lease_time,
                    renewal_time,
                    rebinding_time,
                    obtained_at: Instant::now(),
                });
                self.offered = None;
                self.state = ClientState::Bound;
                Ok(())
            }
            Some(MessageType::Nak) => {
                self.offered = None;
                self.lease = None;
                self.state = ClientState::Init;
                Ok(())
            }
            _ => Err(DhcpError::UnexpectedMessage),
        }
    }

    /// Begin renewal (past T1) while `Bound`: transition to `Renewing` and return
    /// the unicast REQUEST to send to the leasing server. Returns `None` if the
    /// client is not `Bound`.
    pub fn start_renew(&mut self) -> Option<DhcpMessage> {
        if self.state != ClientState::Bound {
            return None;
        }
        let lease = self.lease.clone()?;
        self.xid = self.alloc_xid();
        self.state = ClientState::Renewing;
        Some(self.build_request(MessageType::Request, false, true, false, lease.ip))
    }

    /// Begin rebinding (past T2) while `Bound`: transition to `Rebinding` and
    /// return the broadcast REQUEST to send. Returns `None` if not `Bound`.
    pub fn start_rebind(&mut self) -> Option<DhcpMessage> {
        if self.state != ClientState::Bound {
            return None;
        }
        let lease = self.lease.clone()?;
        self.xid = self.alloc_xid();
        self.state = ClientState::Rebinding;
        Some(self.build_request(MessageType::Request, true, false, false, lease.ip))
    }

    /// Release the current lease while `Bound`: returns the RELEASE message to
    /// send and transitions back to `Init`. Returns `None` if not `Bound`.
    pub fn release(&mut self) -> Option<DhcpMessage> {
        if self.state != ClientState::Bound {
            return None;
        }
        let lease = self.lease.clone()?;
        self.xid = self.alloc_xid();
        self.lease = None;
        self.state = ClientState::Init;
        Some(self.build_request(MessageType::Release, false, true, false, lease.ip))
    }

    fn build_request(
        &self,
        mtype: MessageType,
        broadcast: bool,
        include_server_id: bool,
        include_requested_ip: bool,
        ciaddr: Ipv4Addr,
    ) -> DhcpMessage {
        let mut msg = DhcpMessage::new();
        msg.op = MessageOp::BootRequest;
        msg.set_chaddr(&self.mac);
        msg.xid = self.xid;
        msg.flags = if broadcast { 0x8000 } else { 0 };
        msg.ciaddr = ciaddr;
        msg.set_option(DhcpOption::MessageType(mtype));
        if include_server_id {
            if let Some(offer) = &self.offered {
                msg.set_option(DhcpOption::ServerIdentifier(offer.server_id));
            } else if let Some(lease) = &self.lease {
                msg.set_option(DhcpOption::ServerIdentifier(lease.server_id));
            }
        }
        if include_requested_ip {
            if let Some(offer) = &self.offered {
                msg.set_option(DhcpOption::RequestedIpAddress(offer.ip));
            }
        }
        if let Some(id) = &self.client_id {
            msg.set_option(DhcpOption::ClientIdentifier(id.clone()));
        }
        msg.set_option(DhcpOption::ParameterRequestList(vec![
            crate::options::CODE_SUBNET_MASK,
            crate::options::CODE_ROUTER,
            crate::options::CODE_DOMAIN_NAME_SERVER,
            crate::options::CODE_DOMAIN_NAME,
            crate::options::CODE_HOST_NAME,
        ]));
        msg
    }
}
