// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The RFC 8415 client finite-state machine.
//!
//! The client is driven event-by-event: call [`Client::start_solicit`], feed the
//! server's reply to [`Client::receive_advertise`] to get the REQUEST to send,
//! then feed the REPLY to [`Client::receive_reply`] to transition to `Bound`.
//! Renewal, rebinding, release, decline, and stateless information-request are
//! explicit client-initiated actions. This keeps the FSM transport-agnostic and
//! fully testable without a network.

use std::net::Ipv6Addr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::error::Dhcpv6Error;
use crate::message::Dhcpv6Message;
use crate::options::{
    Dhcpv6Option, Duid, IaAddress, IaNa, MessageType, OPTION_DNS_SERVERS, OPTION_DOMAIN_SEARCH,
};

/// Client FSM states (RFC 8415 §7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    /// No configuration; ready to send SOLICIT.
    Init,
    /// SOLICIT sent, waiting for ADVERTISE(s).
    Selecting,
    /// REQUEST sent, waiting for REPLY/NoAddrsAvail.
    Requesting,
    /// Address acquired and in use.
    Bound,
    /// Lease past T1; renewing with the leasing server (unicast).
    Renewing,
    /// Lease past T2; rebinding with any server.
    Rebinding,
    /// RELEASE sent, waiting for the server's REPLY.
    Releasing,
    /// DECLINE sent, waiting for the server's REPLY.
    Declining,
}

/// A lease as understood by the client.
#[derive(Debug, Clone)]
pub struct ClientLease {
    /// The server that granted the lease.
    pub server_id: Duid,
    /// The IA identifier this lease is bound to.
    pub iaid: u32,
    /// Granted non-temporary/temporary addresses: (address, preferred, valid).
    pub addresses: Vec<(Ipv6Addr, u32, u32)>,
    /// Granted prefixes: (prefix, prefix-length, preferred, valid).
    pub prefixes: Vec<(Ipv6Addr, u8, u32, u32)>,
    /// Renewal (T1) time in seconds.
    pub t1: u32,
    /// Rebinding (T2) time in seconds.
    pub t2: u32,
    /// DNS recursive name servers returned by the server.
    pub dns_servers: Vec<Ipv6Addr>,
    /// Domain search list returned by the server.
    pub domain_search: Vec<String>,
    /// When the lease was obtained.
    pub obtained_at: Instant,
}

impl ClientLease {
    /// Whether the lease has fully expired relative to `now`.
    pub fn is_expired(&self, now: Instant) -> bool {
        let total: u32 = self
            .addresses
            .iter()
            .map(|(_, _, v)| *v)
            .chain(self.prefixes.iter().map(|(_, _, _, v)| *v))
            .max()
            .unwrap_or(0);
        now.duration_since(self.obtained_at) >= Duration::from_secs(total as u64)
    }

    /// Whether the client should begin renewing (past T1) relative to `now`.
    pub fn should_renew(&self, now: Instant) -> bool {
        now.duration_since(self.obtained_at) >= Duration::from_secs(self.t1 as u64)
    }

    /// Whether the client should begin rebinding (past T2) relative to `now`.
    pub fn should_rebind(&self, now: Instant) -> bool {
        now.duration_since(self.obtained_at) >= Duration::from_secs(self.t2 as u64)
    }
}

/// A DHCPv6 client.
pub struct Client {
    duid: Duid,
    iaid: u32,
    state: ClientState,
    xid: [u8; 3],
    next_xid: u32,
    selected_server: Option<Duid>,
    lease: Option<ClientLease>,
}

impl Client {
    /// Create a client with the given DUID, using IAID 1 for its Identity
    /// Association.
    pub fn new(duid: Duid) -> Self {
        Self::with_iaid(duid, 1)
    }

    /// Create a client with the given DUID and an explicit IAID.
    pub fn with_iaid(duid: Duid, iaid: u32) -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x1234_5678);
        Self {
            duid,
            iaid,
            state: ClientState::Init,
            xid: [0; 3],
            next_xid: (seed ^ 0x9E3779B9) as u32 | 1,
            selected_server: None,
            lease: None,
        }
    }

    /// The client's DUID.
    pub fn duid(&self) -> &Duid {
        &self.duid
    }

    /// The client's current FSM state.
    pub fn state(&self) -> ClientState {
        self.state
    }

    /// The current lease, if bound.
    pub fn lease(&self) -> Option<&ClientLease> {
        self.lease.as_ref()
    }

    fn alloc_xid(&mut self) -> [u8; 3] {
        let mut x = self.next_xid;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.next_xid = x | 1;
        [(x >> 16) as u8, (x >> 8) as u8, x as u8]
    }

    fn base_request(
        &self,
        mtype: MessageType,
        include_server_id: bool,
        include_ia: bool,
    ) -> Dhcpv6Message {
        let mut msg = Dhcpv6Message::new(mtype);
        msg.transaction_id = self.xid;
        msg.set_option(Dhcpv6Option::ClientId(self.duid.clone()));
        if include_server_id {
            if let Some(srv) = &self.selected_server {
                msg.set_option(Dhcpv6Option::ServerId(srv.clone()));
            } else if let Some(l) = &self.lease {
                msg.set_option(Dhcpv6Option::ServerId(l.server_id.clone()));
            }
        }
        msg.set_option(Dhcpv6Option::ElapsedTime(0));
        if include_ia {
            let options = if let Some(l) = &self.lease {
                let mut inner = Vec::new();
                for (addr, _, _) in &l.addresses {
                    inner.push(Dhcpv6Option::IaAddr(IaAddress {
                        address: *addr,
                        preferred_lifetime: 0,
                        valid_lifetime: 0,
                        options: Vec::new(),
                    }));
                }
                for (prefix, plen, _, _) in &l.prefixes {
                    inner.push(Dhcpv6Option::IaPrefix(crate::options::IaPrefix {
                        preferred_lifetime: 0,
                        valid_lifetime: 0,
                        prefix_length: *plen,
                        prefix: *prefix,
                        options: Vec::new(),
                    }));
                }
                inner
            } else {
                Vec::new()
            };
            msg.set_option(Dhcpv6Option::IaNa(IaNa {
                iaid: self.iaid,
                t1: 0,
                t2: 0,
                options,
            }));
        }
        msg.set_option(Dhcpv6Option::Oro(vec![
            OPTION_DNS_SERVERS,
            OPTION_DOMAIN_SEARCH,
        ]));
        msg
    }

    /// Begin address acquisition: transition to `Selecting` and return the SOLICIT
    /// message to multicast.
    pub fn start_solicit(&mut self) -> Dhcpv6Message {
        self.xid = self.alloc_xid();
        self.selected_server = None;
        self.lease = None;
        self.state = ClientState::Selecting;
        let mut msg = self.base_request(MessageType::Solicit, false, false);
        // SOLICIT carries the empty IA_NA so the server knows what to offer.
        msg.set_option(Dhcpv6Option::IaNa(IaNa {
            iaid: self.iaid,
            t1: 0,
            t2: 0,
            options: Vec::new(),
        }));
        msg
    }

    /// Request only stateless configuration (DNS etc.) via INFORMATION-REQUEST.
    /// Transitions to `Requesting` after a successful REPLY (no addresses are granted).
    pub fn information_request(&mut self) -> Dhcpv6Message {
        self.xid = self.alloc_xid();
        self.state = ClientState::Requesting;
        self.base_request(MessageType::InformationRequest, false, false)
    }

    /// Feed a server message received while `Selecting`. If it is an ADVERTISE
    /// matching this client's transaction, returns the REQUEST to send and
    /// transitions to `Requesting`; otherwise returns `None`.
    pub fn receive_advertise(&mut self, msg: &Dhcpv6Message) -> Option<Dhcpv6Message> {
        if self.state != ClientState::Selecting {
            return None;
        }
        if msg.msg_type != MessageType::Advertise || msg.transaction_id != self.xid {
            return None;
        }
        let server_id = msg.server_id()?.clone();

        // Choose the address the server offered for our IA.
        let mut requested: Vec<Dhcpv6Option> = Vec::new();
        for ia in msg.ia_nas() {
            if ia.iaid == self.iaid {
                for o in &ia.options {
                    if let Dhcpv6Option::IaAddr(a) = o {
                        requested.push(Dhcpv6Option::IaAddr(IaAddress {
                            address: a.address,
                            preferred_lifetime: 0,
                            valid_lifetime: 0,
                            options: Vec::new(),
                        }));
                    }
                }
            }
        }
        for ia in msg.ia_pds() {
            if ia.iaid == self.iaid {
                for o in &ia.options {
                    if let Dhcpv6Option::IaPrefix(p) = o {
                        requested.push(Dhcpv6Option::IaPrefix(crate::options::IaPrefix {
                            preferred_lifetime: 0,
                            valid_lifetime: 0,
                            prefix_length: p.prefix_length,
                            prefix: p.prefix,
                            options: Vec::new(),
                        }));
                    }
                }
            }
        }

        let mut request = self.base_request(MessageType::Request, true, false);
        request.set_option(Dhcpv6Option::ServerId(server_id.clone()));
        if !requested.is_empty() {
            request.set_option(Dhcpv6Option::IaNa(IaNa {
                iaid: self.iaid,
                t1: 0,
                t2: 0,
                options: requested,
            }));
        }
        self.selected_server = Some(server_id);
        self.state = ClientState::Requesting;
        Some(request)
    }

    /// Feed a server REPLY received while `Requesting`, `Renewing`, `Rebinding`,
    /// `Releasing`, or `Declining`. On success it commits the lease (or clears it
    /// for release) and transitions to `Bound`/`Init`. Messages that do not match
    /// the current transaction are rejected with [`Dhcpv6Error::UnexpectedMessage`].
    pub fn receive_reply(&mut self, msg: &Dhcpv6Message) -> Result<(), Dhcpv6Error> {
        let valid = matches!(
            self.state,
            ClientState::Requesting
                | ClientState::Renewing
                | ClientState::Rebinding
                | ClientState::Releasing
                | ClientState::Declining
        );
        if !valid {
            return Err(Dhcpv6Error::UnexpectedMessage);
        }
        if msg.msg_type != MessageType::Reply || msg.transaction_id != self.xid {
            return Err(Dhcpv6Error::UnexpectedMessage);
        }

        match self.state {
            ClientState::Releasing => {
                self.lease = None;
                self.state = ClientState::Init;
                return Ok(());
            }
            ClientState::Declining => {
                self.lease = None;
                self.state = ClientState::Init;
                return Ok(());
            }
            _ => {}
        }

        // A non-success status at the top level means the server refused.
        if let Some((code, _)) = msg.status_code() {
            if code != 0 {
                self.lease = None;
                self.state = ClientState::Init;
                return Ok(());
            }
        }

        let server_id = msg
            .server_id()
            .cloned()
            .or_else(|| self.selected_server.clone())
            .or_else(|| self.lease.as_ref().map(|l| l.server_id.clone()))
            .ok_or(Dhcpv6Error::UnexpectedMessage)?;

        let mut addresses = Vec::new();
        let mut prefixes = Vec::new();
        let mut t1 = 0u32;
        let mut t2 = 0u32;
        for ia in msg.ia_nas() {
            if ia.iaid == self.iaid {
                if ia.t1 != 0 {
                    t1 = ia.t1;
                }
                if ia.t2 != 0 {
                    t2 = ia.t2;
                }
                for o in &ia.options {
                    if let Dhcpv6Option::IaAddr(a) = o {
                        addresses.push((a.address, a.preferred_lifetime, a.valid_lifetime));
                    }
                }
            }
        }
        for ia in msg.ia_pds() {
            if ia.iaid == self.iaid {
                if ia.t1 != 0 {
                    t1 = ia.t1;
                }
                if ia.t2 != 0 {
                    t2 = ia.t2;
                }
                for o in &ia.options {
                    if let Dhcpv6Option::IaPrefix(p) = o {
                        prefixes.push((
                            p.prefix,
                            p.prefix_length,
                            p.preferred_lifetime,
                            p.valid_lifetime,
                        ));
                    }
                }
            }
        }

        let dns_servers = match msg.find_option(OPTION_DNS_SERVERS) {
            Some(Dhcpv6Option::DnsServers(s)) => s.clone(),
            _ => Vec::new(),
        };
        let domain_search = match msg.find_option(OPTION_DOMAIN_SEARCH) {
            Some(Dhcpv6Option::DomainSearch(d)) => d.clone(),
            _ => Vec::new(),
        };

        self.lease = Some(ClientLease {
            server_id,
            iaid: self.iaid,
            addresses,
            prefixes,
            t1,
            t2,
            dns_servers,
            domain_search,
            obtained_at: Instant::now(),
        });
        self.selected_server = None;
        self.state = ClientState::Bound;
        Ok(())
    }

    /// Begin renewal (past T1) while `Bound`: transition to `Renewing` and return
    /// the unicast REQUEST to send to the leasing server. Returns `None` if the
    /// client is not `Bound`.
    pub fn start_renew(&mut self) -> Option<Dhcpv6Message> {
        if self.state != ClientState::Bound {
            return None;
        }
        self.xid = self.alloc_xid();
        self.state = ClientState::Renewing;
        Some(self.base_request(MessageType::Request, false, true))
    }

    /// Begin rebinding (past T2) while `Bound`: transition to `Rebinding` and
    /// return the REQUEST to send to any server. Returns `None` if not `Bound`.
    pub fn start_rebind(&mut self) -> Option<Dhcpv6Message> {
        if self.state != ClientState::Bound {
            return None;
        }
        self.xid = self.alloc_xid();
        self.state = ClientState::Rebinding;
        Some(self.base_request(MessageType::Request, false, true))
    }

    /// Release the current lease while `Bound`: returns the RELEASE message to
    /// send and transitions to `Releasing`. Returns `None` if not `Bound`.
    pub fn release(&mut self) -> Option<Dhcpv6Message> {
        if self.state != ClientState::Bound {
            return None;
        }
        self.xid = self.alloc_xid();
        self.state = ClientState::Releasing;
        Some(self.base_request(MessageType::Release, true, true))
    }

    /// Report an address conflict while `Bound`: returns the DECLINE message to
    /// send and transitions to `Declining`. Returns `None` if not `Bound`.
    pub fn decline(&mut self) -> Option<Dhcpv6Message> {
        if self.state != ClientState::Bound {
            return None;
        }
        self.xid = self.alloc_xid();
        self.state = ClientState::Declining;
        Some(self.base_request(MessageType::Decline, true, true))
    }
}
