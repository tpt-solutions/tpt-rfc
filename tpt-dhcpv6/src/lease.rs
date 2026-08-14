// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pluggable lease storage for the DHCPv6 server.
//!
//! The server owns the protocol state machine; the [`LeaseStore`] trait decides
//! how Identity Associations (addresses, prefixes) are allocated, tracked, and
//! expired. Implement it against your own store (database, file, distributed
//! lock) or use the reference [`crate::memory::MemoryLeaseStore`].

use std::time::{Duration, Instant};

use crate::error::LeaseError;
use crate::options::{Duid, IaKind};

/// Fraction of the lease duration used as the renewal (T1) time by default.
pub const DEFAULT_T1_FRACTION: f64 = 0.5;
/// Fraction of the lease duration used as the rebinding (T2) time by default.
pub const DEFAULT_T2_FRACTION: f64 = 0.8;

/// The kind of resource a single IA address lease entry grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IaAddressLease {
    /// The granted IPv6 address.
    pub address: std::net::Ipv6Addr,
    /// Preferred lifetime in seconds.
    pub preferred_lifetime: Duration,
    /// Valid lifetime in seconds.
    pub valid_lifetime: Duration,
}

/// The kind of resource a single IA prefix lease entry grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IaPrefixLease {
    /// The delegated prefix base address.
    pub prefix: std::net::Ipv6Addr,
    /// Prefix length in bits.
    pub prefix_length: u8,
    /// Preferred lifetime in seconds.
    pub preferred_lifetime: Duration,
    /// Valid lifetime in seconds.
    pub valid_lifetime: Duration,
}

/// A granted Identity Association: a set of addresses (IA_NA/IA_TA) or prefixes
/// (IA_PD) bound to a client for a limited time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IaLease {
    /// The IA identifier the client chose.
    pub iaid: u32,
    /// Whether this is a non-temporary/temporary address IA or a prefix IA.
    pub kind: IaKind,
    /// Stable client identity (its DUID).
    pub client_id: Duid,
    /// Granted addresses (IA_NA/IA_TA). Empty for IA_PD.
    pub addresses: Vec<IaAddressLease>,
    /// Granted prefixes (IA_PD). Empty for IA_NA/IA_TA.
    pub prefixes: Vec<IaPrefixLease>,
    /// Renewal (T1) time remaining at grant.
    pub t1: Duration,
    /// Rebinding (T2) time remaining at grant.
    pub t2: Duration,
    /// Absolute expiry instant.
    pub expires_at: Instant,
}

impl IaLease {
    /// Whether this lease has expired relative to `now`.
    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

/// Inputs to a lease allocation request.
#[derive(Debug, Clone)]
pub struct AcquireRequest {
    /// Stable client identity (its DUID).
    pub client_id: Duid,
    /// The client-chosen IA identifier.
    pub iaid: u32,
    /// The kind of IA being requested.
    pub kind: IaKind,
    /// A specific address the client would prefer (IA_NA/IA_TA only).
    pub requested_address: Option<std::net::Ipv6Addr>,
    /// A specific (prefix, length) the client would prefer (IA_PD only).
    pub requested_prefix: Option<(std::net::Ipv6Addr, u8)>,
    /// The instant the request is being made.
    pub now: Instant,
}

/// Backend trait a DHCPv6 server uses to allocate and track leases.
///
/// Implementors must be `Send + Sync` so a single backend instance can serve
/// many packets behind an `Arc`. All methods take `&mut self`: the server is
/// single-threaded per socket, so the backend need not provide internal
/// locking.
pub trait LeaseStore: Send + Sync {
    /// Allocate a new IA for `req`.
    ///
    /// If `req.requested_address`/`req.requested_prefix` is set and free (and in
    /// the pool), it is honoured; otherwise the next free resource is chosen.
    /// The returned lease's `expires_at` is computed from `req.now` and the
    /// pool's lease duration.
    fn acquire(&mut self, req: AcquireRequest) -> Result<IaLease, LeaseError>;

    /// Confirm/extend the IA for `(client_id, iaid, kind)`.
    ///
    /// Used when the server turns a REQUEST/RENEW/REBIND into a REPLY. The lease
    /// lifetime is reset to `now + duration`.
    fn confirm(
        &mut self,
        client_id: &Duid,
        iaid: u32,
        kind: IaKind,
        now: Instant,
    ) -> Result<IaLease, LeaseError>;

    /// Release the IA for `(client_id, iaid, kind)` (client sent RELEASE).
    fn release(
        &mut self,
        client_id: &Duid,
        iaid: u32,
        kind: IaKind,
    ) -> Result<(), LeaseError>;

    /// Mark the IA for `(client_id, iaid, kind)` as declined (client sent
    /// DECLINE).
    ///
    /// Declined resources are removed from the active pool and held out of
    /// allocation for a probation period.
    fn decline(
        &mut self,
        client_id: &Duid,
        iaid: u32,
        kind: IaKind,
    ) -> Result<(), LeaseError>;

    /// Return a snapshot of the IA for `(client_id, iaid, kind)`, if active.
    fn lease_for(&self, client_id: &Duid, iaid: u32, kind: IaKind) -> Option<IaLease>;
}
