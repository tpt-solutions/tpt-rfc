// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reference in-memory lease backend, useful for tests, examples, and small
//! deployments that do not need durable storage.

use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

use crate::error::LeaseError;
use crate::lease::{
    AcquireRequest, IaAddressLease, IaLease, IaPrefixLease, LeaseStore, DEFAULT_T1_FRACTION,
    DEFAULT_T2_FRACTION,
};
use crate::options::{Duid, IaKind};

/// Configuration for a managed address/prefix pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// The server's own DUID; used as the Server Identifier option.
    pub server_duid: Duid,
    /// First allocatable non-temporary address (inclusive).
    pub address_pool_start: Ipv6Addr,
    /// Last allocatable non-temporary address (inclusive).
    pub address_pool_end: Ipv6Addr,
    /// First allocatable prefix base (inclusive, aligned to `pd_prefix_length`).
    pub pd_pool_start: Ipv6Addr,
    /// Last allocatable prefix base (inclusive).
    pub pd_pool_end: Ipv6Addr,
    /// Delegated prefix length (e.g. 64 for a /64).
    pub pd_prefix_length: u8,
    /// Default lease duration offered to clients.
    pub lease_duration: Duration,
    /// DNS recursive name servers advertised to clients.
    pub dns_servers: Vec<Ipv6Addr>,
    /// Domain search list advertised to clients.
    pub domain_search: Vec<String>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            server_duid: Duid::Ll {
                hardware_type: crate::options::HARDWARE_ETHERNET,
                link_layer: vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            },
            address_pool_start: Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x10),
            address_pool_end: Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0xff),
            pd_pool_start: Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 0),
            pd_pool_end: Ipv6Addr::new(0x2001, 0xdb8, 2, 0xffff, 0, 0, 0, 0),
            pd_prefix_length: 64,
            lease_duration: Duration::from_secs(3600),
            dns_servers: vec![Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x53)],
            domain_search: vec!["example.local".to_string()],
        }
    }
}

type LeaseKey = (Duid, u32, IaKind);

/// A simple in-memory [`LeaseStore`].
///
/// Addresses are allocated from the configured address pool and prefixes from the
/// configured prefix pool, first-come, with a specific requested resource
/// honoured when free. Expired leases and declined resources are pruned lazily as
/// allocations happen.
pub struct MemoryLeaseStore {
    config: PoolConfig,
    leases: HashMap<LeaseKey, IaLease>,
    declined_addrs: HashMap<Ipv6Addr, Instant>,
    declined_prefixes: HashMap<(Ipv6Addr, u8), Instant>,
}

impl MemoryLeaseStore {
    /// Create a store managing `config`'s pools.
    pub fn new(config: PoolConfig) -> Self {
        Self {
            config,
            leases: HashMap::new(),
            declined_addrs: HashMap::new(),
            declined_prefixes: HashMap::new(),
        }
    }

    /// Borrow the pool configuration.
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    fn in_addr_pool(&self, n: u128) -> bool {
        n >= u128::from(self.config.address_pool_start)
            && n <= u128::from(self.config.address_pool_end)
    }

    fn in_pd_pool(&self, n: u128) -> bool {
        n >= u128::from(self.config.pd_pool_start) && n <= u128::from(self.config.pd_pool_end)
    }

    fn pick_address(
        &self,
        requested: Option<Ipv6Addr>,
        now: Instant,
    ) -> Result<Ipv6Addr, LeaseError> {
        let used: HashSet<u128> = self
            .leases
            .values()
            .flat_map(|l| l.addresses.iter().map(|a| u128::from(a.address)))
            .collect();
        let declined: HashSet<u128> = self
            .declined_addrs
            .iter()
            .filter(|(_, exp)| **exp > now)
            .map(|(ip, _)| u128::from(*ip))
            .collect();

        if let Some(req) = requested {
            let n = u128::from(req);
            if !self.in_addr_pool(n) {
                return Err(LeaseError::OutOfPool(req));
            }
            if used.contains(&n) || declined.contains(&n) {
                return Err(LeaseError::AddressInUse(req));
            }
            return Ok(req);
        }

        let start = u128::from(self.config.address_pool_start);
        let end = u128::from(self.config.address_pool_end);
        let mut n = start;
        while n <= end {
            if !used.contains(&n) && !declined.contains(&n) {
                return Ok(Ipv6Addr::from(n));
            }
            n = n.wrapping_add(1);
        }
        Err(LeaseError::PoolExhausted)
    }

    fn pick_prefix(
        &self,
        requested: Option<(Ipv6Addr, u8)>,
        now: Instant,
    ) -> Result<(Ipv6Addr, u8), LeaseError> {
        let plen = self.config.pd_prefix_length;
        let step = prefix_step(plen);
        let used: HashSet<u128> = self
            .leases
            .values()
            .flat_map(|l| {
                l.prefixes
                    .iter()
                    .map(|p| align_prefix(u128::from(p.prefix), plen))
            })
            .collect();
        let declined: HashSet<u128> = self
            .declined_prefixes
            .iter()
            .filter(|(_, exp)| **exp > now)
            .map(|((p, _), _)| align_prefix(u128::from(*p), plen))
            .collect();

        if let Some((req_prefix, req_plen)) = requested {
            let n = align_prefix(u128::from(req_prefix), plen);
            if !self.in_pd_pool(n) {
                return Err(LeaseError::OutOfPool(req_prefix));
            }
            if used.contains(&n) || declined.contains(&n) {
                return Err(LeaseError::AddressInUse(req_prefix));
            }
            return Ok((Ipv6Addr::from(n), req_plen.min(plen)));
        }

        let mut n = align_prefix(u128::from(self.config.pd_pool_start), plen);
        let end = u128::from(self.config.pd_pool_end);
        while n <= end {
            if !used.contains(&n) && !declined.contains(&n) {
                return Ok((Ipv6Addr::from(n), plen));
            }
            n = n.wrapping_add(step);
        }
        Err(LeaseError::PoolExhausted)
    }

    fn prune(&mut self, now: Instant) {
        self.leases.retain(|_, l| !l.is_expired(now));
        self.declined_addrs.retain(|_, exp| *exp > now);
        self.declined_prefixes.retain(|_, exp| *exp > now);
    }

    fn make_address_lease(
        &self,
        client_id: Duid,
        iaid: u32,
        kind: IaKind,
        addr: Ipv6Addr,
        now: Instant,
    ) -> IaLease {
        let dur = self.config.lease_duration;
        let addr_lease = IaAddressLease {
            address: addr,
            preferred_lifetime: dur,
            valid_lifetime: dur,
        };
        make_ia_lease(
            client_id,
            iaid,
            kind,
            vec![addr_lease],
            Vec::new(),
            now,
            dur,
        )
    }

    fn make_prefix_lease(
        &self,
        client_id: Duid,
        iaid: u32,
        prefix: Ipv6Addr,
        plen: u8,
        now: Instant,
    ) -> IaLease {
        let dur = self.config.lease_duration;
        let prefix_lease = IaPrefixLease {
            prefix,
            prefix_length: plen,
            preferred_lifetime: dur,
            valid_lifetime: dur,
        };
        make_ia_lease(
            client_id,
            iaid,
            IaKind::Pd,
            Vec::new(),
            vec![prefix_lease],
            now,
            dur,
        )
    }

    fn refresh(&self, lease: &IaLease, now: Instant) -> IaLease {
        let dur = self.config.lease_duration;
        let mut renewed = lease.clone();
        renewed.t1 = dur.mul_f64(DEFAULT_T1_FRACTION);
        renewed.t2 = dur.mul_f64(DEFAULT_T2_FRACTION);
        renewed.expires_at = now + dur;
        renewed
    }
}

fn prefix_step(plen: u8) -> u128 {
    if plen >= 128 {
        0
    } else {
        1u128 << (128 - plen)
    }
}

fn align_prefix(n: u128, plen: u8) -> u128 {
    if plen == 0 {
        0
    } else {
        n & (!0u128 << (128 - plen))
    }
}

fn make_ia_lease(
    client_id: Duid,
    iaid: u32,
    kind: IaKind,
    addresses: Vec<IaAddressLease>,
    prefixes: Vec<IaPrefixLease>,
    now: Instant,
    dur: Duration,
) -> IaLease {
    let t1 = dur.mul_f64(DEFAULT_T1_FRACTION);
    let t2 = dur.mul_f64(DEFAULT_T2_FRACTION);
    IaLease {
        iaid,
        kind,
        client_id,
        addresses,
        prefixes,
        t1,
        t2,
        expires_at: now + dur,
    }
}

impl LeaseStore for MemoryLeaseStore {
    fn acquire(&mut self, req: AcquireRequest) -> Result<IaLease, LeaseError> {
        let now = req.now;
        self.prune(now);
        let key: LeaseKey = (req.client_id.clone(), req.iaid, req.kind);

        // Reuse an existing active lease for the same (client, IA) instead of
        // handing out a second resource.
        if let Some(existing) = self.leases.get(&key) {
            let renewed = self.refresh(existing, now);
            self.leases.insert(key, renewed.clone());
            return Ok(renewed);
        }

        match req.kind {
            IaKind::Na | IaKind::Ta => {
                let addr = self.pick_address(req.requested_address, now)?;
                let lease = self.make_address_lease(req.client_id, req.iaid, req.kind, addr, now);
                self.leases.insert(key, lease.clone());
                Ok(lease)
            }
            IaKind::Pd => {
                let (prefix, plen) = self.pick_prefix(req.requested_prefix, now)?;
                let lease = self.make_prefix_lease(req.client_id, req.iaid, prefix, plen, now);
                self.leases.insert(key, lease.clone());
                Ok(lease)
            }
        }
    }

    fn confirm(
        &mut self,
        client_id: &Duid,
        iaid: u32,
        kind: IaKind,
        now: Instant,
    ) -> Result<IaLease, LeaseError> {
        let key: LeaseKey = (client_id.clone(), iaid, kind);
        let lease = self.leases.get(&key).ok_or(LeaseError::NoLease)?;
        let renewed = self.refresh(lease, now);
        self.leases.insert(key, renewed.clone());
        Ok(renewed)
    }

    fn release(&mut self, client_id: &Duid, iaid: u32, kind: IaKind) -> Result<(), LeaseError> {
        let key: LeaseKey = (client_id.clone(), iaid, kind);
        self.leases.remove(&key);
        Ok(())
    }

    fn decline(&mut self, client_id: &Duid, iaid: u32, kind: IaKind) -> Result<(), LeaseError> {
        let key: LeaseKey = (client_id.clone(), iaid, kind);
        let lease = self.leases.remove(&key).ok_or(LeaseError::NoLease)?;
        let probation = Instant::now() + self.config.lease_duration;
        for a in &lease.addresses {
            self.declined_addrs.insert(a.address, probation);
        }
        for p in &lease.prefixes {
            self.declined_prefixes
                .insert((p.prefix, p.prefix_length), probation);
        }
        Ok(())
    }

    fn lease_for(&self, client_id: &Duid, iaid: u32, kind: IaKind) -> Option<IaLease> {
        self.leases.get(&(client_id.clone(), iaid, kind)).cloned()
    }
}
