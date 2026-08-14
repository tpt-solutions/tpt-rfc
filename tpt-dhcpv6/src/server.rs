// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The RFC 8415 server finite-state machine, plus a minimal UDP listener.
//!
//! [`Server::process`] is transport-agnostic: hand it a decoded [`Dhcpv6Message`]
//! and it returns the reply to send (or `None` when no reply is needed — e.g. a
//! REQUEST aimed at a different server). [`Server::run`] wraps `process` in a UDP
//! socket for real use.

use std::net::UdpSocket;
use std::time::Instant;

use crate::error::Dhcpv6Error;
use crate::lease::{AcquireRequest, IaLease, LeaseStore};
use crate::options::IaKind;
use crate::memory::MemoryLeaseStore;
use crate::message::Dhcpv6Message;
use crate::options::{
    Dhcpv6Option, Duid, IaAddress, IaNa, IaPd, IaPrefix, IaTa, MessageType, StatusCode,
    OPTION_DNS_SERVERS, OPTION_DOMAIN_SEARCH, OPTION_IA_NA, OPTION_IA_PD, OPTION_IA_TA,
    STATUS_NO_ADDRS_AVAIL, STATUS_NO_BINDING, STATUS_NO_PREFIX_AVAIL,
    STATUS_NOT_ON_LINK, STATUS_SUCCESS,
};

/// A DHCPv6 server backed by a pluggable [`LeaseStore`].
pub struct Server<S: LeaseStore> {
    config: crate::memory::PoolConfig,
    store: S,
}

impl Server<MemoryLeaseStore> {
    /// Create a server using the reference in-memory lease store for `config`.
    pub fn new(config: crate::memory::PoolConfig) -> Self {
        Self::with_store(config.clone(), MemoryLeaseStore::new(config))
    }
}

impl<S: LeaseStore> Server<S> {
    /// Create a server using a caller-provided lease store and pool config.
    ///
    /// `config` tells the server its own DUID, the address/prefix pools, and the
    /// configuration options to advertise; `store` is the authority on resource
    /// allocation. They must describe the same pool to behave correctly.
    pub fn with_store(config: crate::memory::PoolConfig, store: S) -> Self {
        Self { config, store }
    }

    /// Borrow the server's pool configuration.
    pub fn config(&self) -> &crate::memory::PoolConfig {
        &self.config
    }

    /// Borrow the underlying lease store (for introspection/testing).
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Decode a packet, run the server FSM, and re-encode the reply.
    ///
    /// Returns `None` when the server has nothing to say (no reply, drop the
    /// packet). This is the right boundary for a custom transport: hand bytes in,
    /// get reply bytes out.
    pub fn process_bytes(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>, Dhcpv6Error> {
        let msg = Dhcpv6Message::from_bytes(packet)?;
        Ok(self.process(&msg)?.map(|r| r.to_bytes()))
    }

    /// Run the server FSM on a decoded message.
    pub fn process(&mut self, msg: &Dhcpv6Message) -> Result<Option<Dhcpv6Message>, Dhcpv6Error> {
        let client_id = match msg.client_id() {
            Some(d) => d.clone(),
            None => return Ok(None),
        };
        let now = Instant::now();

        match msg.msg_type {
            MessageType::Solicit => self.handle_solicit(msg, &client_id, now),
            MessageType::Request => self.handle_request(msg, &client_id, now),
            MessageType::Confirm => self.handle_confirm(msg, &client_id),
            MessageType::Renew => self.handle_renew_rebind(msg, &client_id, now),
            MessageType::Rebind => self.handle_renew_rebind(msg, &client_id, now),
            MessageType::Release => self.handle_release(msg, &client_id),
            MessageType::Decline => self.handle_decline(msg, &client_id),
            MessageType::InformationRequest => Ok(Some(self.handle_information_request(msg))),
            _ => Ok(None),
        }
    }

    fn wants(&self, msg: &Dhcpv6Message, code: u16) -> bool {
        match msg.oro() {
            None => true,
            Some(list) => list.contains(&code),
        }
    }

    fn handle_solicit(
        &mut self,
        msg: &Dhcpv6Message,
        client_id: &Duid,
        now: Instant,
    ) -> Result<Option<Dhcpv6Message>, Dhcpv6Error> {
        let reply_kind = if msg.rapid_commit() {
            MessageType::Reply
        } else {
            MessageType::Advertise
        };
        let mut reply = self.base_reply(reply_kind, msg);

        for ia in msg.ia_nas() {
            let req = AcquireRequest {
                client_id: client_id.clone(),
                iaid: ia.iaid,
                kind: IaKind::Na,
                requested_address: None,
                requested_prefix: None,
                now,
            };
            match self.store.acquire(req) {
                Ok(lease) => reply.set_option(Self::build_ia_na(&lease)),
                Err(_) => reply.set_option(Self::ia_status(ia.iaid, OPTION_IA_NA, STATUS_NO_ADDRS_AVAIL)),
            }
        }
        for ia in msg.ia_tas() {
            let req = AcquireRequest {
                client_id: client_id.clone(),
                iaid: ia.iaid,
                kind: IaKind::Ta,
                requested_address: None,
                requested_prefix: None,
                now,
            };
            match self.store.acquire(req) {
                Ok(lease) => reply.set_option(Self::build_ia_ta(&lease)),
                Err(_) => reply.set_option(Self::ia_status(ia.iaid, OPTION_IA_TA, STATUS_NO_ADDRS_AVAIL)),
            }
        }
        for ia in msg.ia_pds() {
            let req = AcquireRequest {
                client_id: client_id.clone(),
                iaid: ia.iaid,
                kind: IaKind::Pd,
                requested_address: None,
                requested_prefix: None,
                now,
            };
            match self.store.acquire(req) {
                Ok(lease) => reply.set_option(Self::build_ia_pd(&lease)),
                Err(_) => reply.set_option(Self::ia_status(ia.iaid, OPTION_IA_PD, STATUS_NO_PREFIX_AVAIL)),
            }
        }

        self.add_config_options(&mut reply, msg);
        Ok(Some(reply))
    }

    fn handle_request(
        &mut self,
        msg: &Dhcpv6Message,
        client_id: &Duid,
        now: Instant,
    ) -> Result<Option<Dhcpv6Message>, Dhcpv6Error> {
        // A server identifier means the client is selecting a specific server;
        // ignore requests not aimed at us.
        if let Some(sid) = msg.server_id() {
            if sid != &self.config.server_duid {
                return Ok(None);
            }
        }

        let mut reply = self.base_reply(MessageType::Reply, msg);
        let mut any = false;

        for ia in msg.ia_nas() {
            any = true;
            match self.store.confirm(client_id, ia.iaid, IaKind::Na, now) {
                Ok(lease) => reply.set_option(Self::build_ia_na(&lease)),
                Err(_) => reply.set_option(Self::ia_status(ia.iaid, OPTION_IA_NA, STATUS_NO_BINDING)),
            }
        }
        for ia in msg.ia_tas() {
            any = true;
            match self.store.confirm(client_id, ia.iaid, IaKind::Ta, now) {
                Ok(lease) => reply.set_option(Self::build_ia_ta(&lease)),
                Err(_) => reply.set_option(Self::ia_status(ia.iaid, OPTION_IA_TA, STATUS_NO_BINDING)),
            }
        }
        for ia in msg.ia_pds() {
            any = true;
            match self.store.confirm(client_id, ia.iaid, IaKind::Pd, now) {
                Ok(lease) => reply.set_option(Self::build_ia_pd(&lease)),
                Err(_) => reply.set_option(Self::ia_status(ia.iaid, OPTION_IA_PD, STATUS_NO_PREFIX_AVAIL)),
            }
        }

        // A REQUEST with no IA options is not meaningful; reply with nothing.
        if !any {
            return Ok(None);
        }

        self.add_config_options(&mut reply, msg);
        Ok(Some(reply))
    }

    fn handle_confirm(
        &self,
        msg: &Dhcpv6Message,
        client_id: &Duid,
    ) -> Result<Option<Dhcpv6Message>, Dhcpv6Error> {
        // On-link check: if we hold a binding for any of the client's IAs, the
        // addresses are still on-link.
        let mut on_link = false;
        for ia in msg.ia_nas() {
            if self.store.lease_for(client_id, ia.iaid, IaKind::Na).is_some() {
                on_link = true;
            }
        }
        for ia in msg.ia_pds() {
            if self.store.lease_for(client_id, ia.iaid, IaKind::Pd).is_some() {
                on_link = true;
            }
        }
        let mut reply = self.base_reply(MessageType::Reply, msg);
        let code = if on_link { STATUS_SUCCESS } else { STATUS_NOT_ON_LINK };
        reply.set_option(Dhcpv6Option::StatusCode(StatusCode {
            code,
            message: String::new(),
        }));
        Ok(Some(reply))
    }

    fn handle_renew_rebind(
        &mut self,
        msg: &Dhcpv6Message,
        client_id: &Duid,
        now: Instant,
    ) -> Result<Option<Dhcpv6Message>, Dhcpv6Error> {
        let mut reply = self.base_reply(MessageType::Reply, msg);
        let mut any = false;
        for ia in msg.ia_nas() {
            any = true;
            match self.store.confirm(client_id, ia.iaid, IaKind::Na, now) {
                Ok(lease) => reply.set_option(Self::build_ia_na(&lease)),
                Err(_) => reply.set_option(Self::ia_status(ia.iaid, OPTION_IA_NA, STATUS_NO_BINDING)),
            }
        }
        for ia in msg.ia_pds() {
            any = true;
            match self.store.confirm(client_id, ia.iaid, IaKind::Pd, now) {
                Ok(lease) => reply.set_option(Self::build_ia_pd(&lease)),
                Err(_) => reply.set_option(Self::ia_status(ia.iaid, OPTION_IA_PD, STATUS_NO_PREFIX_AVAIL)),
            }
        }
        if !any {
            return Ok(None);
        }
        self.add_config_options(&mut reply, msg);
        Ok(Some(reply))
    }

    fn handle_release(
        &mut self,
        msg: &Dhcpv6Message,
        client_id: &Duid,
    ) -> Result<Option<Dhcpv6Message>, Dhcpv6Error> {
        let mut released = false;
        for ia in msg.ia_nas() {
            if self.store.release(client_id, ia.iaid, IaKind::Na).is_ok() {
                released = true;
            }
        }
        for ia in msg.ia_tas() {
            if self.store.release(client_id, ia.iaid, IaKind::Ta).is_ok() {
                released = true;
            }
        }
        for ia in msg.ia_pds() {
            if self.store.release(client_id, ia.iaid, IaKind::Pd).is_ok() {
                released = true;
            }
        }
        let mut reply = self.base_reply(MessageType::Reply, msg);
        let code = if released { STATUS_SUCCESS } else { STATUS_NO_BINDING };
        reply.set_option(Dhcpv6Option::StatusCode(StatusCode {
            code,
            message: String::new(),
        }));
        Ok(Some(reply))
    }

    fn handle_decline(
        &mut self,
        msg: &Dhcpv6Message,
        client_id: &Duid,
    ) -> Result<Option<Dhcpv6Message>, Dhcpv6Error> {
        for ia in msg.ia_nas() {
            let _ = self.store.decline(client_id, ia.iaid, IaKind::Na);
        }
        for ia in msg.ia_tas() {
            let _ = self.store.decline(client_id, ia.iaid, IaKind::Ta);
        }
        for ia in msg.ia_pds() {
            let _ = self.store.decline(client_id, ia.iaid, IaKind::Pd);
        }
        let mut reply = self.base_reply(MessageType::Reply, msg);
        reply.set_option(Dhcpv6Option::StatusCode(StatusCode {
            code: STATUS_SUCCESS,
            message: String::new(),
        }));
        Ok(Some(reply))
    }

    fn handle_information_request(&self, msg: &Dhcpv6Message) -> Dhcpv6Message {
        let mut reply = self.base_reply(MessageType::Reply, msg);
        self.add_config_options(&mut reply, msg);
        reply
    }

    fn add_config_options(&self, reply: &mut Dhcpv6Message, msg: &Dhcpv6Message) {
        if !self.config.dns_servers.is_empty() && self.wants(msg, OPTION_DNS_SERVERS) {
            reply.set_option(Dhcpv6Option::DnsServers(self.config.dns_servers.clone()));
        }
        if !self.config.domain_search.is_empty() && self.wants(msg, OPTION_DOMAIN_SEARCH) {
            reply.set_option(Dhcpv6Option::DomainSearch(
                self.config.domain_search.clone(),
            ));
        }
    }

    fn base_reply(&self, kind: MessageType, req: &Dhcpv6Message) -> Dhcpv6Message {
        let mut reply = Dhcpv6Message::new(kind);
        reply.transaction_id = req.transaction_id;
        reply.set_option(Dhcpv6Option::ServerId(self.config.server_duid.clone()));
        reply
    }

    fn build_ia_na(lease: &IaLease) -> Dhcpv6Option {
        Dhcpv6Option::IaNa(IaNa {
            iaid: lease.iaid,
            t1: secs(lease.t1),
            t2: secs(lease.t2),
            options: lease
                .addresses
                .iter()
                .map(|a| {
                    Dhcpv6Option::IaAddr(IaAddress {
                        address: a.address,
                        preferred_lifetime: secs(a.preferred_lifetime),
                        valid_lifetime: secs(a.valid_lifetime),
                        options: Vec::new(),
                    })
                })
                .collect(),
        })
    }

    fn build_ia_ta(lease: &IaLease) -> Dhcpv6Option {
        Dhcpv6Option::IaTa(IaTa {
            iaid: lease.iaid,
            options: lease
                .addresses
                .iter()
                .map(|a| {
                    Dhcpv6Option::IaAddr(IaAddress {
                        address: a.address,
                        preferred_lifetime: secs(a.preferred_lifetime),
                        valid_lifetime: secs(a.valid_lifetime),
                        options: Vec::new(),
                    })
                })
                .collect(),
        })
    }

    fn build_ia_pd(lease: &IaLease) -> Dhcpv6Option {
        Dhcpv6Option::IaPd(IaPd {
            iaid: lease.iaid,
            t1: secs(lease.t1),
            t2: secs(lease.t2),
            options: lease
                .prefixes
                .iter()
                .map(|p| {
                    Dhcpv6Option::IaPrefix(IaPrefix {
                        preferred_lifetime: secs(p.preferred_lifetime),
                        valid_lifetime: secs(p.valid_lifetime),
                        prefix_length: p.prefix_length,
                        prefix: p.prefix,
                        options: Vec::new(),
                    })
                })
                .collect(),
        })
    }

    fn ia_status(iaid: u32, ia_code: u16, status: u16) -> Dhcpv6Option {
        let inner = Dhcpv6Option::StatusCode(StatusCode {
            code: status,
            message: String::new(),
        });
        match ia_code {
            OPTION_IA_NA => Dhcpv6Option::IaNa(IaNa {
                iaid,
                t1: 0,
                t2: 0,
                options: vec![inner],
            }),
            OPTION_IA_TA => Dhcpv6Option::IaTa(IaTa {
                iaid,
                options: vec![inner],
            }),
            OPTION_IA_PD => Dhcpv6Option::IaPd(IaPd {
                iaid,
                t1: 0,
                t2: 0,
                options: vec![inner],
            }),
            _ => Dhcpv6Option::StatusCode(StatusCode {
                code: status,
                message: String::new(),
            }),
        }
    }

    /// Bind a UDP socket and serve forever, replying to each received packet.
    ///
    /// The socket is bound to `bind_addr` (typically `[::]:547`) with
    /// `IPV6_V6ONLY` left at the system default. Replies are sent to the source
    /// address of each datagram.
    pub fn run(&mut self, bind_addr: &str) -> std::io::Result<()> {
        let socket = UdpSocket::bind(bind_addr)?;
        let mut buf = [0u8; 1500];
        loop {
            let (n, src) = socket.recv_from(&mut buf)?;
            match self.process_bytes(&buf[..n]) {
                Ok(Some(p)) => {
                    let _ = socket.send_to(&p, src);
                }
                Ok(None) => continue,
                Err(e) => {
                    eprintln!("dhcpv6: dropping packet: {}", e);
                    continue;
                }
            }
        }
    }
}

fn secs(d: std::time::Duration) -> u32 {
    d.as_secs().min(u32::MAX as u64) as u32
}
