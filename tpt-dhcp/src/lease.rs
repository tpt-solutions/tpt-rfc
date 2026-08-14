// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pluggable lease storage for the DHCP server.
//!
//! The server owns the protocol state machine; the [`LeaseStore`] trait decides
//! how addresses are allocated, tracked, and expired. Implement it against your
//! own store (database, file, distributed lock) or use the reference
//! [`crate::memory::MemoryLeaseStore`].

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::error::LeaseError;

/// Fraction of the lease duration used as the renewal (T1) time by default.
pub const DEFAULT_T1_FRACTION: f64 = 0.5;
/// Fraction of the lease duration used as the rebinding (T2) time by default.
pub const DEFAULT_T2_FRACTION: f64 = 0.875;

/// A granted lease: an address bound to a client for a limited time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// The address granted to the client.
    pub ip: Ipv4Addr,
    /// Stable client identity (option 61 if present, else the MAC).
    pub client_id: Vec<u8>,
    /// The client's hardware (MAC) address.
    pub mac: Vec<u8>,
    /// Total lease duration.
    pub lease_duration: Duration,
    /// Renewal (T1) time remaining at grant.
    pub t1: Duration,
    /// Rebinding (T2) time remaining at grant.
    pub t2: Duration,
    /// Absolute expiry instant.
    pub expires_at: Instant,
}

impl Lease {
    /// Whether this lease has expired relative to `now`.
    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

/// Inputs to a lease allocation request.
#[derive(Debug, Clone)]
pub struct AcquireRequest {
    /// Stable client identity (option 61 if present, else the MAC).
    pub client_id: Vec<u8>,
    /// The client's hardware (MAC) address.
    pub mac: Vec<u8>,
    /// A specific address the client would prefer (0.0.0.0 means "any").
    pub requested_ip: Ipv4Addr,
    /// The instant the request is being made.
    pub now: Instant,
}

/// Backend trait a DHCP server uses to allocate and track leases.
///
/// Implementors must be `Send + Sync` so a single backend instance can serve
/// many packets behind an `Arc`. All methods take `&mut self`: the server is
/// single-threaded per socket, so the backend need not provide internal
/// locking.
pub trait LeaseStore: Send + Sync {
    /// Allocate a lease for `req`.
    ///
    /// If `req.requested_ip` is set and free (and in the pool), it is honoured;
    /// otherwise the next free address is chosen. The returned lease's
    /// `expires_at` is computed from `req.now` and the pool's lease duration.
    fn acquire(&mut self, req: AcquireRequest) -> Result<Lease, LeaseError>;

    /// Confirm/extend the lease for `ip` belonging to `client_id`.
    ///
    /// Used when the server turns a REQUEST into an ACK (SELECTING, INIT-REBOOT,
    /// RENEWING, REBINDING). The lease lifetime is reset to `now + duration`.
    fn confirm(
        &mut self,
        ip: Ipv4Addr,
        client_id: &[u8],
        now: Instant,
    ) -> Result<Lease, LeaseError>;

    /// Release the lease for `ip` (client sent DHCPRELEASE).
    fn release(&mut self, ip: Ipv4Addr) -> Result<(), LeaseError>;

    /// Mark `ip` as declined (client detected a conflict, DHCPDECLINE).
    ///
    /// Declined addresses are removed from the active pool and held out of
    /// allocation for a probation period.
    fn decline(&mut self, ip: Ipv4Addr) -> Result<(), LeaseError>;

    /// Return a snapshot of the lease for `ip`, if one is currently active.
    fn lease_for(&self, ip: Ipv4Addr) -> Option<Lease>;
}
