// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reference in-memory lease backend, useful for tests, examples, and small
//! deployments that do not need durable storage.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::error::LeaseError;
use crate::lease::{AcquireRequest, Lease, LeaseStore, DEFAULT_T1_FRACTION, DEFAULT_T2_FRACTION};

/// Configuration for a managed address pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// The server's own IP; also used as the Server Identifier option.
    pub server_ip: Ipv4Addr,
    /// Subnet mask advertised to clients.
    pub subnet_mask: Ipv4Addr,
    /// First allocatable address (inclusive).
    pub pool_start: Ipv4Addr,
    /// Last allocatable address (inclusive).
    pub pool_end: Ipv4Addr,
    /// Default lease duration offered to clients.
    pub lease_duration: Duration,
    /// Default routers advertised to clients.
    pub routers: Vec<Ipv4Addr>,
    /// DNS servers advertised to clients.
    pub domain_name_servers: Vec<Ipv4Addr>,
    /// Domain name advertised to clients.
    pub domain_name: Option<String>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            server_ip: Ipv4Addr::new(192, 168, 1, 1),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            pool_start: Ipv4Addr::new(192, 168, 1, 10),
            pool_end: Ipv4Addr::new(192, 168, 1, 200),
            lease_duration: Duration::from_secs(3600),
            routers: vec![Ipv4Addr::new(192, 168, 1, 1)],
            domain_name_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
            domain_name: Some("example.local".to_string()),
        }
    }
}

/// A simple in-memory [`LeaseStore`].
///
/// Addresses are allocated from the configured pool first-come, with a specific
/// requested address honoured when free. Expired leases and declined addresses
/// are pruned lazily as allocations happen.
pub struct MemoryLeaseStore {
    config: PoolConfig,
    leases: HashMap<Ipv4Addr, Lease>,
    declined: HashMap<Ipv4Addr, Instant>,
}

impl MemoryLeaseStore {
    /// Create a store managing `config`'s pool.
    pub fn new(config: PoolConfig) -> Self {
        Self {
            config,
            leases: HashMap::new(),
            declined: HashMap::new(),
        }
    }

    /// Borrow the pool configuration.
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    fn in_pool(&self, ip: Ipv4Addr) -> bool {
        let s: u32 = self.config.pool_start.into();
        let e: u32 = self.config.pool_end.into();
        let n: u32 = ip.into();
        n >= s && n <= e
    }

    fn is_declined(&self, ip: Ipv4Addr, now: Instant) -> bool {
        match self.declined.get(&ip) {
            Some(expiry) if *expiry > now => true,
            Some(_) => false,
            None => false,
        }
    }

    fn prune(&mut self, now: Instant) {
        self.leases.retain(|_, l| !l.is_expired(now));
        self.declined.retain(|_, expiry| *expiry > now);
    }

    fn make_lease(&self, ip: Ipv4Addr, client_id: Vec<u8>, mac: Vec<u8>, now: Instant) -> Lease {
        let dur = self.config.lease_duration;
        let t1 = dur.mul_f64(DEFAULT_T1_FRACTION);
        let t2 = dur.mul_f64(DEFAULT_T2_FRACTION);
        Lease {
            ip,
            client_id,
            mac,
            lease_duration: dur,
            t1,
            t2,
            expires_at: now + dur,
        }
    }
}

impl LeaseStore for MemoryLeaseStore {
    fn acquire(&mut self, req: AcquireRequest) -> Result<Lease, LeaseError> {
        let now = req.now;
        self.prune(now);

        // Candidate: an explicit request that is free or already ours.
        let mut chosen: Option<Ipv4Addr> = None;
        if req.requested_ip != Ipv4Addr::UNSPECIFIED && self.in_pool(req.requested_ip) {
            let taken = self.leases.get(&req.requested_ip);
            let free = match taken {
                None => !self.is_declined(req.requested_ip, now),
                Some(l) => l.client_id == req.client_id,
            };
            if free {
                chosen = Some(req.requested_ip);
            }
        }

        // Otherwise scan the pool for the first available address.
        if chosen.is_none() {
            let s: u32 = self.config.pool_start.into();
            let e: u32 = self.config.pool_end.into();
            for n in s..=e {
                let ip = Ipv4Addr::from(n);
                let taken = self.leases.get(&ip);
                let free = match taken {
                    None => !self.is_declined(ip, now),
                    Some(l) => l.client_id == req.client_id,
                };
                if free {
                    chosen = Some(ip);
                    break;
                }
            }
        }

        let ip = chosen.ok_or(LeaseError::PoolExhausted)?;
        let lease = self.make_lease(ip, req.client_id, req.mac, now);
        self.leases.insert(ip, lease.clone());
        Ok(lease)
    }

    fn confirm(
        &mut self,
        ip: Ipv4Addr,
        client_id: &[u8],
        now: Instant,
    ) -> Result<Lease, LeaseError> {
        let lease = self.leases.get(&ip).ok_or(LeaseError::NoLease(ip))?;
        if lease.client_id != client_id {
            return Err(LeaseError::ClientMismatch(ip));
        }
        let renewed = self.make_lease(ip, client_id.to_vec(), lease.mac.clone(), now);
        self.leases.insert(ip, renewed.clone());
        Ok(renewed)
    }

    fn release(&mut self, ip: Ipv4Addr) -> Result<(), LeaseError> {
        self.leases.remove(&ip);
        Ok(())
    }

    fn decline(&mut self, ip: Ipv4Addr) -> Result<(), LeaseError> {
        self.leases.remove(&ip);
        // Hold the address out of the pool for one lease duration as probation.
        let probation = Instant::now() + self.config.lease_duration;
        self.declined.insert(ip, probation);
        Ok(())
    }

    fn lease_for(&self, ip: Ipv4Addr) -> Option<Lease> {
        self.leases.get(&ip).cloned()
    }
}
