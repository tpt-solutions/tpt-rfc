// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The RFC 2131 server finite-state machine, plus a minimal UDP listener.
//!
//! [`Server::process`] is transport-agnostic: hand it a decoded
//! [`DhcpMessage`] and it returns the reply to send (or `None` when no reply is
//! needed — e.g. a RELEASE, or a REQUEST aimed at a different server).
//! [`Server::run`] wraps `process` in a UDP socket for real use.

use std::net::{Ipv4Addr, UdpSocket};
use std::time::Instant;

use crate::error::DhcpError;
use crate::lease::{AcquireRequest, Lease, LeaseStore};
use crate::memory::MemoryLeaseStore;
use crate::message::{DhcpMessage, MessageOp};
use crate::options::{
    DhcpOption, MessageType, CODE_DOMAIN_NAME, CODE_DOMAIN_NAME_SERVER, CODE_LEASE_TIME,
    CODE_MESSAGE_TYPE, CODE_PARAMETER_REQUEST_LIST, CODE_REBINDING_TIME, CODE_RENEWAL_TIME,
    CODE_ROUTER, CODE_SERVER_IDENTIFIER, CODE_SUBNET_MASK, LEASE_TIME_INFINITY,
};

/// A DHCP server backed by a pluggable [`LeaseStore`].
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
    /// `config` tells the server its own IP, the subnet mask, and the
    /// configuration options to advertise; `store` is the authority on address
    /// allocation. They must describe the same pool to behave correctly.
    pub fn with_store(config: crate::memory::PoolConfig, store: S) -> Self {
        Self { config, store }
    }

    /// Borrow the server's pool configuration.
    pub fn config(&self) -> &crate::memory::PoolConfig {
        &self.config
    }

    /// Decode a packet, run the server FSM, and re-encode the reply.
    ///
    /// Returns `None` when the server has nothing to say (no reply, drop the
    /// packet). This is the right boundary for a custom transport: hand bytes
    /// in, get reply bytes out.
    pub fn process_bytes(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>, DhcpError> {
        let msg = DhcpMessage::from_bytes(packet)?;
        Ok(self.process(&msg)?.map(|r| r.to_bytes()))
    }

    /// Run the server FSM on a decoded message.
    pub fn process(&mut self, msg: &DhcpMessage) -> Result<Option<DhcpMessage>, DhcpError> {
        let client_id = msg
            .client_identifier()
            .map(|b| b.to_vec())
            .unwrap_or_else(|| msg.mac().to_vec());
        let now = Instant::now();

        match msg.message_type() {
            Some(MessageType::Discover) => {
                let req_ip = msg.requested_ip().unwrap_or(Ipv4Addr::UNSPECIFIED);
                let lease = self.store.acquire(AcquireRequest {
                    client_id,
                    mac: msg.mac().to_vec(),
                    requested_ip: req_ip,
                    now,
                })?;
                Ok(Some(self.build_reply(
                    MessageType::Offer,
                    msg,
                    Some(&lease),
                )))
            }
            Some(MessageType::Request) => {
                // A server identifier means the client is selecting a specific
                // server; ignore requests not aimed at us.
                if let Some(sid) = msg.server_identifier() {
                    if sid != self.config.server_ip {
                        return Ok(None);
                    }
                }
                let ip = msg.requested_ip().unwrap_or(msg.ciaddr);
                if ip == Ipv4Addr::UNSPECIFIED {
                    return Ok(None);
                }
                match self.store.confirm(ip, &client_id, now) {
                    Ok(lease) => Ok(Some(self.build_reply(MessageType::Ack, msg, Some(&lease)))),
                    Err(_) => Ok(Some(self.build_reply(MessageType::Nak, msg, None))),
                }
            }
            Some(MessageType::Decline) => {
                let ip = msg.requested_ip().unwrap_or(msg.ciaddr);
                let _ = self.store.decline(ip);
                Ok(None)
            }
            Some(MessageType::Release) => {
                let _ = self.store.release(msg.ciaddr);
                Ok(None)
            }
            Some(MessageType::Inform) => Ok(Some(self.build_reply(MessageType::Ack, msg, None))),
            _ => Ok(None),
        }
    }

    /// Build a reply to `req`, filling in the fixed header and the appropriate
    /// options for `kind`. `lease` is `Some` for OFFER/ACK that grant an
    /// address and `None` for NAK/INFORM.
    fn build_reply(
        &self,
        kind: MessageType,
        req: &DhcpMessage,
        lease: Option<&Lease>,
    ) -> DhcpMessage {
        let mut reply = DhcpMessage::new();
        reply.op = MessageOp::BootReply;
        reply.htype = req.htype;
        reply.hlen = req.hlen;
        reply.hops = req.hops;
        reply.xid = req.xid;
        reply.flags = req.flags;
        reply.giaddr = req.giaddr;
        reply.chaddr = req.chaddr;
        reply.siaddr = self.config.server_ip;
        // The client only receives yiaddr when it does not already hold an
        // address (SELECTING); in RENEWING/REBINDING/INIT-REBOOT it keeps its
        // current address (RFC 2131 §4.3.2).
        if let Some(l) = lease {
            if req.ciaddr == Ipv4Addr::UNSPECIFIED {
                reply.yiaddr = l.ip;
            }
        }

        reply.set_option(DhcpOption::MessageType(kind));

        let prl: Option<Vec<u8>> =
            req.find_option(CODE_PARAMETER_REQUEST_LIST)
                .and_then(|o| match o {
                    DhcpOption::ParameterRequestList(v) => Some(v.clone()),
                    _ => None,
                });

        // Mandatory options are always included; others only when requested.
        let wanted = |code: u8| -> bool {
            match &prl {
                None => true,
                Some(list) => {
                    list.contains(&code)
                        || matches!(
                            code,
                            CODE_MESSAGE_TYPE
                                | CODE_SERVER_IDENTIFIER
                                | CODE_SUBNET_MASK
                                | CODE_PARAMETER_REQUEST_LIST
                        )
                }
            }
        };

        if let Some(l) = lease {
            if wanted(CODE_RENEWAL_TIME) {
                reply.set_option(DhcpOption::RenewalTime(
                    l.t1.as_secs().min(u64::from(LEASE_TIME_INFINITY)) as u32,
                ));
            }
            if wanted(CODE_REBINDING_TIME) {
                reply.set_option(DhcpOption::RebindingTime(
                    l.t2.as_secs().min(u64::from(LEASE_TIME_INFINITY)) as u32,
                ));
            }
        }
        if wanted(CODE_SERVER_IDENTIFIER) {
            reply.set_option(DhcpOption::ServerIdentifier(self.config.server_ip));
        }
        if lease.is_some() && wanted(CODE_LEASE_TIME) {
            let secs = lease
                .map(|l| {
                    l.lease_duration
                        .as_secs()
                        .min(u64::from(LEASE_TIME_INFINITY)) as u32
                })
                .unwrap_or(0);
            reply.set_option(DhcpOption::LeaseTime(secs));
        }
        if self.config.subnet_mask != Ipv4Addr::UNSPECIFIED && wanted(CODE_SUBNET_MASK) {
            reply.set_option(DhcpOption::SubnetMask(self.config.subnet_mask));
        }
        if !self.config.routers.is_empty() && wanted(CODE_ROUTER) {
            reply.set_option(DhcpOption::Router(self.config.routers.clone()));
        }
        if !self.config.domain_name_servers.is_empty() && wanted(CODE_DOMAIN_NAME_SERVER) {
            reply.set_option(DhcpOption::DomainNameServer(
                self.config.domain_name_servers.clone(),
            ));
        }
        if let Some(domain) = &self.config.domain_name {
            if wanted(CODE_DOMAIN_NAME) {
                reply.set_option(DhcpOption::DomainName(domain.clone()));
            }
        }
        reply
    }

    /// Bind a UDP socket and serve forever, replying to each received packet.
    ///
    /// The socket is bound to `bind_addr` (typically `0.0.0.0:67`) with
    /// broadcast enabled. Replies are sent to the relay agent when `giaddr` is
    /// set, otherwise broadcast (when the client set the broadcast flag or does
    /// not yet have an address) or unicast to the granted address.
    pub fn run(&mut self, bind_addr: &str) -> std::io::Result<()> {
        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_broadcast(true)?;
        let mut buf = [0u8; 1500];
        loop {
            let (n, _src) = socket.recv_from(&mut buf)?;
            let packet = match self.process_bytes(&buf[..n]) {
                Ok(Some(p)) => p,
                Ok(None) => continue,
                Err(e) => {
                    eprintln!("dhcp: dropping packet: {}", e);
                    continue;
                }
            };
            let reply = match DhcpMessage::from_bytes(&packet) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("dhcp: internal encode error: {}", e);
                    continue;
                }
            };
            let dest = if reply.giaddr != Ipv4Addr::UNSPECIFIED {
                (reply.giaddr, 67)
            } else if reply.flags & 0x8000 != 0 || reply.yiaddr == Ipv4Addr::UNSPECIFIED {
                (Ipv4Addr::new(255, 255, 255, 255), 68)
            } else {
                (reply.yiaddr, 68)
            };
            let _ = socket.send_to(&packet, dest);
        }
    }

    /// Borrow the underlying lease store (for introspection/testing).
    pub fn store(&self) -> &S {
        &self.store
    }
}
