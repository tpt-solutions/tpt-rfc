// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Routing Information Base (Adj-RIB-In + Loc-RIB) and a pluggable
//! decision process. The decision process follows RFC 4271 §9.1.2.1; callers
//! may supply their own by implementing [`DecisionProcess`], and route
//! import/export filtering is delegated to a pluggable [`Policy`].

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::attributes::{Aggregator, AsPath, NextHop, Origin, Prefix};

/// Where a route was learned from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteSource {
    /// The address/identifier of the peer that advertised the route.
    pub peer: [u8; 4],
    /// Whether the route was learned over an iBGP (internal) session rather
    /// than eBGP.
    pub is_ibgp: bool,
}

/// A route held in the RIB: a prefix plus the path attributes needed by the
/// decision process and forwarding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// The destination prefix.
    pub prefix: Prefix,
    /// ORIGIN attribute.
    pub origin: Option<Origin>,
    /// AS_PATH attribute.
    pub as_path: AsPath,
    /// NEXT_HOP attribute (the next-hop used to forward; for IPv6 this is in
    /// the MP_REACH_NLRI, but the IPv4 form is carried here for convenience).
    pub next_hop: Option<NextHop>,
    /// MULTI_EXIT_DISC attribute.
    pub med: Option<u32>,
    /// LOCAL_PREF attribute (iBGP only).
    pub local_pref: Option<u32>,
    /// AGGREGATOR attribute.
    pub aggregator: Option<Aggregator>,
    /// COMMUNITY attribute values.
    pub communities: Vec<u32>,
    /// Provenance of the route.
    pub source: RouteSource,
}

impl Route {
    /// Construct a route from its prefix and source, with all attributes empty.
    pub fn new(prefix: Prefix, source: RouteSource) -> Route {
        Route {
            prefix,
            origin: None,
            as_path: AsPath::default(),
            next_hop: None,
            med: None,
            local_pref: None,
            aggregator: None,
            communities: Vec::new(),
            source,
        }
    }
}

/// The BGP route-selection algorithm. Implementors compare a candidate route
/// against the current best and indicate which is preferred.
pub trait DecisionProcess {
    /// Returns `Ordering::Greater` if `candidate` is strictly preferred over
    /// `current_best` (which may be `None` when no best route exists yet).
    fn compare(&self, current_best: Option<&Route>, candidate: &Route) -> Ordering;
}

/// The reference decision process implementing RFC 4271 §9.1.2.1.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultDecision;

impl DecisionProcess for DefaultDecision {
    fn compare(&self, current_best: Option<&Route>, candidate: &Route) -> Ordering {
        let cur = match current_best {
            None => return Ordering::Greater,
            Some(c) => c,
        };

        // (a) Highest LOCAL_PREF.
        let lp_cur = cur.local_pref.unwrap_or(0);
        let lp_can = candidate.local_pref.unwrap_or(0);
        if lp_cur != lp_can {
            return lp_cur.cmp(&lp_can).reverse();
        }

        // (b) Shortest AS_PATH (in terms of AS_SEQUENCE segments).
        let ap_cur = cur.as_path.path_length();
        let ap_can = candidate.as_path.path_length();
        if ap_cur != ap_can {
            return ap_cur.cmp(&ap_can);
        }

        // (c) Lowest ORIGIN value (IGP < EGP < INCOMPLETE).
        let o_cur = cur.origin.map(|o| o.to_u8()).unwrap_or(3);
        let o_can = candidate.origin.map(|o| o.to_u8()).unwrap_or(3);
        if o_cur != o_can {
            return o_cur.cmp(&o_can);
        }

        // (d) LOWEST_MULTI_EXIT_DISC, compared only among routes from the same
        // neighbouring AS (the first AS in the AS_PATH).
        let na_cur = cur.as_path.first_asn();
        let na_can = candidate.as_path.first_asn();
        if na_cur == na_can {
            let m_cur = cur.med.unwrap_or(0);
            let m_can = candidate.med.unwrap_or(0);
            if m_cur != m_can {
                return m_cur.cmp(&m_can);
            }
        }

        // (e) Prefer eBGP over iBGP.
        if cur.source.is_ibgp != candidate.source.is_ibgp {
            return if candidate.source.is_ibgp {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }

        // (f)/(g) Lowest BGP identifier (peer) of the advertising speaker.
        cur.source.peer.cmp(&candidate.source.peer)
    }
}

/// A route import/export policy. The policy may inspect and mutate the route
/// and then decide whether to accept or reject it.
pub trait Policy {
    /// Apply the policy to a route. Returning `false` rejects the route (it is
    /// not installed / not advertised); returning `true` accepts it (mutations
    /// made to `route` are kept).
    fn apply(&self, route: &mut Route) -> bool;
}

/// A routing information base: the Adj-RIB-In (all routes received, per peer)
/// and the Loc-RIB (the single best route per prefix), with a pluggable
/// decision process.
#[derive(Debug, Clone)]
pub struct Rib<D: DecisionProcess> {
    /// All received routes, per prefix (Adj-RIB-In).
    adj: BTreeMap<Prefix, Vec<Route>>,
    /// The currently-selected best route per prefix (Loc-RIB).
    loc: BTreeMap<Prefix, Route>,
    /// The decision process used to rank routes.
    decision: D,
}

impl<D: DecisionProcess> Rib<D> {
    /// Create an empty RIB using the given decision process.
    pub fn new(decision: D) -> Self {
        Rib {
            adj: BTreeMap::new(),
            loc: BTreeMap::new(),
            decision,
        }
    }

    /// The decision process in use.
    pub fn decision(&self) -> &D {
        &self.decision
    }

    /// Insert a route into the Adj-RIB-In and, if it is now the best for its
    /// prefix, update the Loc-RIB.
    pub fn insert(&mut self, route: Route) {
        let prefix = route.prefix;
        let entry = self.adj.entry(prefix).or_default();
        // Replace an identical route from the same peer if present.
        if let Some(slot) = entry.iter_mut().find(|r| {
            r.source.peer == route.source.peer && r.source.is_ibgp == route.source.is_ibgp
        }) {
            *slot = route.clone();
        } else {
            entry.push(route.clone());
        }
        self.recompute(prefix);
    }

    /// Withdraw all routes for `prefix` learned from `peer` (Adj-RIB-In
    /// withdrawal), recomputing the Loc-RIB entry. Returns true if a Loc-RIB
    /// entry was removed or changed.
    pub fn withdraw(&mut self, prefix: Prefix, peer: [u8; 4]) -> bool {
        if let Some(entry) = self.adj.get_mut(&prefix) {
            entry.retain(|r| r.source.peer != peer);
            if entry.is_empty() {
                self.adj.remove(&prefix);
            }
        }
        let before = self.loc.get(&prefix).map(|r| r.source.peer);
        self.recompute(prefix);
        let after = self.loc.get(&prefix).map(|r| r.source.peer);
        before != after || before.is_some()
    }

    fn recompute(&mut self, prefix: Prefix) {
        let mut best: Option<Route> = None;
        if let Some(routes) = self.adj.get(&prefix) {
            for r in routes {
                if self.decision.compare(best.as_ref(), r) == Ordering::Greater {
                    best = Some(r.clone());
                }
            }
        }
        match best {
            Some(b) => {
                self.loc.insert(prefix, b);
            }
            None => {
                self.loc.remove(&prefix);
            }
        }
    }

    /// The best (Loc-RIB) route for `prefix`, if any.
    pub fn best(&self, prefix: &Prefix) -> Option<&Route> {
        self.loc.get(prefix)
    }

    /// Iterate over the best (Loc-RIB) routes.
    pub fn iter_best(&self) -> impl Iterator<Item = (&Prefix, &Route)> {
        self.loc.iter()
    }

    /// The number of prefixes in the Loc-RIB.
    pub fn len(&self) -> usize {
        self.loc.len()
    }

    /// Whether the Loc-RIB is empty.
    pub fn is_empty(&self) -> bool {
        self.loc.is_empty()
    }

    /// Insert a route, first passing it through `policy`. Returns `true` if the
    /// route was accepted and installed.
    pub fn insert_with_policy<P: Policy>(&mut self, mut route: Route, policy: &P) -> bool {
        if policy.apply(&mut route) {
            self.insert(route);
            true
        } else {
            false
        }
    }
}
