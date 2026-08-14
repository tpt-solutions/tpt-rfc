// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Intra-area shortest-path-first calculation (RFC 2328 §16) over the Router
//! and Network LSAs of an area, implemented as Dijkstra's algorithm. The result
//! is a routing table giving, for every reachable destination, the first-hop
//! router (next hop) and the accumulated cost.

use std::collections::{BinaryHeap, HashMap, HashSet};

use crate::error::OspfError;
use crate::lsa::{Ip4, NetworkLsa, RouterLsa};

/// A node in the SPF tree: either a router (keyed by its Router Id) or a
/// broadcast network (keyed by the DR's interface address == the Network-LSA
/// Link State Id).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Node {
    Router(Ip4),
    Network(Ip4),
}

/// A computed route to a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// The destination: a Router Id for router routes, or a network address for
    /// stub routes.
    pub destination: Ip4,
    /// The first-hop Router Id on the path to `destination`.
    pub next_hop: Ip4,
    /// The total path cost.
    pub cost: u32,
}

/// A leaf (stub) network route learned from a router's stub links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StubRoute {
    /// The network address of the stub.
    pub network: Ip4,
    /// The address mask of the stub.
    pub mask: Ip4,
    /// The first-hop Router Id toward the stub.
    pub next_hop: Ip4,
    /// The total path cost to the stub.
    pub cost: u32,
}

/// The result of an SPF calculation: router routes, stub routes, and the
/// order in which routers were added to the tree.
#[derive(Debug, Clone)]
pub struct RoutingTable {
    router_routes: HashMap<Ip4, Route>,
    stub_routes: Vec<StubRoute>,
    tree_order: Vec<Ip4>,
}

impl RoutingTable {
    /// The route to a destination router, if reachable.
    pub fn route_to(&self, router: Ip4) -> Option<&Route> {
        self.router_routes.get(&router)
    }

    /// The first-hop Router Id toward `router`, if reachable.
    pub fn next_hop(&self, router: Ip4) -> Option<Ip4> {
        self.router_routes.get(&router).map(|r| r.next_hop)
    }

    /// The accumulated cost to a destination router, if reachable.
    pub fn cost_to(&self, router: Ip4) -> Option<u32> {
        self.router_routes.get(&router).map(|r| r.cost)
    }

    /// All stub (leaf) network routes.
    pub fn stub_routes(&self) -> &[StubRoute] {
        &self.stub_routes
    }

    /// The order in which routers were added to the shortest-path tree (the
    /// "tree order" of RFC 2328 §16).
    pub fn tree_order(&self) -> &[Ip4] {
        &self.tree_order
    }

    /// All router routes.
    pub fn router_routes(&self) -> impl Iterator<Item = &Route> {
        self.router_routes.values()
    }
}

/// A builder that accumulates the LSAs of an area and computes the shortest-path
/// tree from a chosen root router.
#[derive(Debug, Clone, Default)]
pub struct Spf {
    root: Option<Ip4>,
    routers: HashMap<Ip4, RouterLsa>,
    networks: HashMap<Ip4, NetworkLsa>,
}

impl Spf {
    /// Create an SPF builder rooted at `root_router_id`.
    pub fn new(root: Ip4) -> Self {
        Self {
            root: Some(root),
            routers: HashMap::new(),
            networks: HashMap::new(),
        }
    }

    /// Add a Router-LSA to the area topology.
    pub fn add_router_lsa(&mut self, lsa: RouterLsa) -> &mut Self {
        self.routers.insert(lsa.header.advertising_router, lsa);
        self
    }

    /// Add a Network-LSA to the area topology.
    pub fn add_network_lsa(&mut self, lsa: NetworkLsa) -> &mut Self {
        self.networks.insert(lsa.header.link_state_id, lsa);
        self
    }

    /// Run Dijkstra's shortest-path-first algorithm from the configured root and
    /// return the resulting routing table.
    pub fn calculate(&self) -> Result<RoutingTable, OspfError> {
        let root = self.root.ok_or(OspfError::SpfRootMissing([0; 4]))?;
        if !self.routers.contains_key(&root) {
            return Err(OspfError::SpfRootMissing(root));
        }

        let mut dist: HashMap<Node, u32> = HashMap::new();
        let mut next_hop: HashMap<Node, Ip4> = HashMap::new();
        let mut in_tree: HashSet<Node> = HashSet::new();
        let mut tree_order: Vec<Ip4> = Vec::new();
        let mut stub_routes: Vec<StubRoute> = Vec::new();

        // Min-heap of candidates keyed by distance.
        let mut heap: BinaryHeap<(std::cmp::Reverse<(u32, u8)>, Node)> = BinaryHeap::new();

        dist.insert(Node::Router(root), 0);
        next_hop.insert(Node::Router(root), root);
        heap.push((std::cmp::Reverse((0u32, 0u8)), Node::Router(root)));

        while let Some((std::cmp::Reverse((d, _)), node)) = heap.pop() {
            if in_tree.contains(&node) {
                continue;
            }
            in_tree.insert(node);

            match node {
                Node::Router(r) => {
                    tree_order.push(r);
                    let Some(rl) = self.routers.get(&r) else {
                        continue;
                    };
                    for link in &rl.links {
                        let link_cost = d + link.metric as u32;
                        match link.link_type {
                            // Point-to-point: neighbor is a router.
                            1 => {
                                let v = Node::Router(link.link_id);
                                if !in_tree.contains(&v)
                                    && link_cost < *dist.get(&v).unwrap_or(&u32::MAX)
                                {
                                    dist.insert(v, link_cost);
                                    let nh = if r == root {
                                        link.link_id
                                    } else {
                                        next_hop[&node]
                                    };
                                    next_hop.insert(v, nh);
                                    heap.push((std::cmp::Reverse((link_cost, 0)), v));
                                }
                            }
                            // Transit: link points to a broadcast network.
                            2 => {
                                let v = Node::Network(link.link_id);
                                if !in_tree.contains(&v)
                                    && link_cost < *dist.get(&v).unwrap_or(&u32::MAX)
                                {
                                    dist.insert(v, link_cost);
                                    let nh = next_hop[&node];
                                    next_hop.insert(v, nh);
                                    heap.push((std::cmp::Reverse((link_cost, 1)), v));
                                }
                            }
                            // Stub: a leaf network route.
                            3 => {
                                stub_routes.push(StubRoute {
                                    network: link.link_id,
                                    mask: link.link_data,
                                    next_hop: next_hop[&node],
                                    cost: link_cost,
                                });
                            }
                            // Virtual link: out of scope for intra-area SPF.
                            4 => {}
                            _ => {}
                        }
                    }
                }
                Node::Network(n) => {
                    let Some(nl) = self.networks.get(&n) else {
                        continue;
                    };
                    // The cost to each attached router equals the cost to reach
                    // the network itself (the network link has no added metric).
                    for ar in &nl.attached_routers {
                        let v = Node::Router(*ar);
                        if !in_tree.contains(&v) && d < *dist.get(&v).unwrap_or(&u32::MAX) {
                            dist.insert(v, d);
                            let nh = next_hop[&node];
                            next_hop.insert(v, nh);
                            heap.push((std::cmp::Reverse((d, 0)), v));
                        }
                    }
                }
            }
        }

        let mut router_routes = HashMap::new();
        for (node, route) in next_hop {
            if let Node::Router(r) = node {
                router_routes.insert(
                    r,
                    Route {
                        destination: r,
                        next_hop: route,
                        cost: *dist.get(&node).unwrap_or(&0),
                    },
                );
            }
        }

        Ok(RoutingTable {
            router_routes,
            stub_routes,
            tree_order,
        })
    }
}
