// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The OSPF neighbor finite-state machine (RFC 2328 §10.4, Figure 11): the
//! states Down → Attempt → Init → 2-Way → ExStart → Exchange → Loading → Full,
//! with the events that drive transitions and a `NeighborTable` to track the
//! adjacency state of every discovered peer.

use std::collections::HashMap;

use crate::lsa::Ip4;
use crate::wire::DbdPacket;

/// OSPF neighbor state (RFC 2328 §10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborState {
    /// No recent information about the neighbor.
    Down,
    /// NBMA only: hello packets have not yet been heard.
    Attempt,
    /// Hello received, but bidirectional communication not yet established.
    Init,
    /// Communication is bidirectional (each router sees the other in its Hello).
    TwoWay,
    /// Negotiating the master/slave role for Database Description exchange.
    ExStart,
    /// Database Description packets are being exchanged.
    Exchange,
    /// Link State Request packets are being sent for missing LSAs.
    Loading,
    /// The neighbor's link-state database is fully synchronized.
    Full,
}

impl NeighborState {
    /// True once adjacency (database synchronization) is fully established.
    pub fn is_adjacent(self) -> bool {
        self == NeighborState::Full
    }

    /// The canonical state name, used in diagnostics.
    pub fn name(self) -> &'static str {
        match self {
            NeighborState::Down => "Down",
            NeighborState::Attempt => "Attempt",
            NeighborState::Init => "Init",
            NeighborState::TwoWay => "2-Way",
            NeighborState::ExStart => "ExStart",
            NeighborState::Exchange => "Exchange",
            NeighborState::Loading => "Loading",
            NeighborState::Full => "Full",
        }
    }
}

/// Events that drive the neighbor state machine (RFC 2328 §10.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborEvent {
    /// A Hello packet was received from this neighbor.
    HelloReceived,
    /// An active attempt to bring up the adjacency was initiated (NBMA only).
    Start,
    /// Bidirectional communication was detected. `adjacency_eligible` is true
    /// when an adjacency should be formed with this neighbor (i.e. one of the
    /// two routers is the DR or BDR on the link).
    TwoWayReceived {
        /// Whether an adjacency should be established with this neighbor.
        adjacency_eligible: bool,
    },
    /// Master/slave negotiation completed; DD sequence numbers agreed.
    NegotiationDone,
    /// Database Description exchange finished. `ls_requests_pending` is true if
    /// there are still LSAs to request from the neighbor.
    ExchangeDone {
        /// Whether Link State Requests remain to be sent.
        ls_requests_pending: bool,
    },
    /// All requested LSAs have been received and acknowledged.
    LoadingDone,
    /// A received LSA is newer than expected (sequence mismatch during
    /// synchronization): re-start the exchange.
    SeqNumberMismatch,
    /// A Link State Request cited an LSA that could not be found: re-start.
    BadLinkStateRequest,
    /// The neighbor no longer lists us in its Hello (communication one-way).
    OneWayReceived,
    /// The inactivity timer fired (no Hello within RouterDeadInterval).
    InactivityTimer,
    /// The neighbor was administratively removed.
    KillNeighbor,
    /// The underlying link went down.
    LinkDown,
}

/// A single tracked neighbor and its synchronization context.
#[derive(Debug, Clone)]
pub struct Neighbor {
    /// The neighbor's Router Id.
    pub router_id: Ip4,
    /// Current FSM state.
    pub state: NeighborState,
    /// Whether this router is the master (true) or slave (false) for the DBD
    /// exchange.
    pub master: bool,
    /// The negotiated DD sequence number.
    pub dd_sequence: u32,
    /// The last Database Description packet seen from this neighbor, if any.
    pub last_dd: Option<DbdPacket>,
    /// The set of LSA keys still to be requested during Loading.
    pub pending_requests: Vec<crate::lsa::LsaKey>,
}

impl Neighbor {
    /// Create a new neighbor in the Down state.
    pub fn new(router_id: Ip4) -> Self {
        Self {
            router_id,
            state: NeighborState::Down,
            master: false,
            dd_sequence: 0,
            last_dd: None,
            pending_requests: Vec::new(),
        }
    }

    /// Apply `event`, returning the new state and mutating the synchronization
    /// context as required.
    pub fn on_event(&mut self, event: NeighborEvent) -> NeighborState {
        let next = transition(self.state, event);
        if next != self.state {
            if next == NeighborState::ExStart {
                // Entering ExStart (re)initialises the exchange context.
                self.master = false;
                self.dd_sequence = 0;
                self.last_dd = None;
            }
            self.state = next;
        }
        self.state
    }
}

/// The core transition function: given a current state and an event, return the
/// next state (RFC 2328 Figure 11).
pub fn transition(state: NeighborState, event: NeighborEvent) -> NeighborState {
    use NeighborEvent::*;
    use NeighborState::*;
    match (state, event) {
        (Down, Start) => Attempt,
        (Down, HelloReceived) => Init,
        (Down, _) => Down,

        (Attempt, HelloReceived) => Init,
        (Attempt, KillNeighbor | LinkDown) => Down,
        (Attempt, _) => Attempt,

        (Init, HelloReceived) => Init,
        (Init, TwoWayReceived { adjacency_eligible }) => {
            if adjacency_eligible {
                ExStart
            } else {
                TwoWay
            }
        }
        (Init, InactivityTimer | KillNeighbor | LinkDown) => Down,
        (Init, _) => Init,

        (TwoWay, HelloReceived) => TwoWay,
        (TwoWay, OneWayReceived) => Init,
        (
            TwoWay,
            TwoWayReceived {
                adjacency_eligible: false,
            },
        ) => TwoWay,
        (
            TwoWay,
            TwoWayReceived {
                adjacency_eligible: true,
            },
        ) => ExStart,
        (TwoWay, InactivityTimer | KillNeighbor | LinkDown) => Down,
        (TwoWay, _) => TwoWay,

        (ExStart, HelloReceived) => ExStart,
        (ExStart, OneWayReceived) => Init,
        (
            ExStart,
            TwoWayReceived {
                adjacency_eligible: false,
            },
        ) => TwoWay,
        (ExStart, NegotiationDone) => Exchange,
        (ExStart, InactivityTimer | KillNeighbor | LinkDown) => Down,
        (ExStart, _) => ExStart,

        (Exchange, HelloReceived) => Exchange,
        (Exchange, OneWayReceived) => Init,
        (
            Exchange,
            TwoWayReceived {
                adjacency_eligible: false,
            },
        ) => TwoWay,
        (Exchange, NegotiationDone) => Exchange,
        (
            Exchange,
            ExchangeDone {
                ls_requests_pending: true,
            },
        ) => Loading,
        (
            Exchange,
            ExchangeDone {
                ls_requests_pending: false,
            },
        ) => Full,
        (Exchange, InactivityTimer | KillNeighbor | LinkDown) => Down,
        (Exchange, _) => Exchange,

        (Loading, HelloReceived) => Loading,
        (Loading, OneWayReceived) => Init,
        (
            Loading,
            TwoWayReceived {
                adjacency_eligible: false,
            },
        ) => TwoWay,
        (Loading, ExchangeDone { .. }) => Full,
        (Loading, SeqNumberMismatch | BadLinkStateRequest) => ExStart,
        (Loading, InactivityTimer | KillNeighbor | LinkDown) => Down,
        (Loading, _) => Loading,

        (Full, HelloReceived) => Full,
        (Full, OneWayReceived) => Init,
        (
            Full,
            TwoWayReceived {
                adjacency_eligible: false,
            },
        ) => TwoWay,
        (Full, SeqNumberMismatch | BadLinkStateRequest) => ExStart,
        (Full, ExchangeDone { .. }) => Full,
        (Full, InactivityTimer | KillNeighbor | LinkDown) => Down,
        (Full, _) => Full,
    }
}

/// A table of neighbors discovered on an interface, keyed by Router Id.
#[derive(Debug, Clone, Default)]
pub struct NeighborTable {
    neighbors: HashMap<Ip4, Neighbor>,
}

impl NeighborTable {
    /// Create an empty table.
    pub fn new() -> Self {
        Self {
            neighbors: HashMap::new(),
        }
    }

    /// The number of tracked neighbors.
    pub fn len(&self) -> usize {
        self.neighbors.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.neighbors.is_empty()
    }

    /// Get a neighbor by Router Id.
    pub fn get(&self, router_id: &Ip4) -> Option<&Neighbor> {
        self.neighbors.get(router_id)
    }

    /// Get a mutable neighbor by Router Id.
    pub fn get_mut(&mut self, router_id: &Ip4) -> Option<&mut Neighbor> {
        self.neighbors.get_mut(router_id)
    }

    /// Ensure a neighbor exists (creating it in Down if new) and apply `event`.
    /// Returns the resulting state.
    pub fn process(&mut self, router_id: Ip4, event: NeighborEvent) -> NeighborState {
        let n = self
            .neighbors
            .entry(router_id)
            .or_insert_with(|| Neighbor::new(router_id));
        n.on_event(event)
    }

    /// Iterate over all tracked neighbors.
    pub fn iter(&self) -> impl Iterator<Item = &Neighbor> {
        self.neighbors.values()
    }
}
