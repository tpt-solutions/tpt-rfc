// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The link-state database (LSDB) and the flooding acceptance logic of
//! RFC 2328 §13: deciding whether an incoming LSA is newer than the locally
//! held copy, and therefore whether it should be installed and flooded onward.

use std::collections::HashMap;

use crate::lsa::{Lsa, LsaHeader, LsaKey, MAX_AGE};

/// The relative recency of two LSAs, per the sequence-number comparison rules of
/// RFC 2328 §13 (modular sequence arithmetic, MaxAge, and checksum tie-breaks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsaOrdering {
    /// `a` is older than `b`.
    Older,
    /// `a` and `b` are identical instances (same sequence, age, and checksum).
    Equal,
    /// `a` is newer than `b`.
    Newer,
}

/// Compare two LSA headers for recency.
pub fn compare_lsa(a: &LsaHeader, b: &LsaHeader) -> LsaOrdering {
    if a.sequence_number == b.sequence_number {
        // Same sequence number: resolve by MaxAge and then by checksum.
        if a.age == MAX_AGE && b.age != MAX_AGE {
            return LsaOrdering::Newer;
        }
        if b.age == MAX_AGE && a.age != MAX_AGE {
            return LsaOrdering::Older;
        }
        if a.checksum == b.checksum {
            return LsaOrdering::Equal;
        }
        return if a.checksum > b.checksum {
            LsaOrdering::Newer
        } else {
            LsaOrdering::Older
        };
    }
    let d = seq_diff(a.sequence_number, b.sequence_number);
    if d > 0 {
        LsaOrdering::Newer
    } else {
        LsaOrdering::Older
    }
}

/// Signed difference of two sequence numbers, accounting for the wraparound at
/// `MAX_SEQUENCE + 1`.
fn seq_diff(a: u32, b: u32) -> i64 {
    let mut d = a as i64 - b as i64;
    if d > 0x4000_0000 {
        d -= 0x8000_0000;
    } else if d < -0x4000_0000 {
        d += 0x8000_0000;
    }
    d
}

/// The action a router should take after receiving an LSA, per the receive
/// procedure of §13.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveAction {
    /// The LSA is new or newer: install it into the database and flood it out
    /// the other interfaces.
    InstallAndFlood,
    /// An identical copy is already present: just acknowledge (do not flood).
    Duplicate,
    /// The LSA is older than the database copy: send it back to the sender.
    Reject,
}

/// The link-state database: a map from LSA key to the newest LSA instance held.
#[derive(Debug, Clone, Default)]
pub struct LinkStateDatabase {
    lsas: HashMap<LsaKey, Lsa>,
}

impl LinkStateDatabase {
    /// Create an empty database.
    pub fn new() -> Self {
        Self {
            lsas: HashMap::new(),
        }
    }

    /// The number of LSAs currently held.
    pub fn len(&self) -> usize {
        self.lsas.len()
    }

    /// Whether the database is empty.
    pub fn is_empty(&self) -> bool {
        self.lsas.is_empty()
    }

    /// Look up the LSA with `key`, if present.
    pub fn get(&self, key: &LsaKey) -> Option<&Lsa> {
        self.lsas.get(key)
    }

    /// Iterate over all held LSAs.
    pub fn iter(&self) -> impl Iterator<Item = &Lsa> {
        self.lsas.values()
    }

    /// Unconditionally install an LSA, replacing any prior copy with the same
    /// key. Returns the previous copy, if any.
    pub fn insert(&mut self, lsa: Lsa) -> Option<Lsa> {
        let key = lsa.key();
        self.lsas.insert(key, lsa)
    }

    /// Apply the §13 receive procedure to an incoming LSA and mutate the
    /// database accordingly. The returned [`ReceiveAction`] tells the caller
    /// whether to flood the LSA outward (InstallAndFlood), acknowledge it
    /// (Duplicate), or send it back to the sender (Reject).
    pub fn receive(&mut self, lsa: Lsa) -> ReceiveAction {
        let key = lsa.key();
        match self.lsas.get(&key) {
            None => {
                let prev = self.lsas.insert(key, lsa);
                debug_assert!(prev.is_none());
                ReceiveAction::InstallAndFlood
            }
            Some(existing) => match compare_lsa(lsa.header(), existing.header()) {
                LsaOrdering::Equal => ReceiveAction::Duplicate,
                LsaOrdering::Newer => {
                    self.lsas.insert(key, lsa);
                    ReceiveAction::InstallAndFlood
                }
                LsaOrdering::Older => ReceiveAction::Reject,
            },
        }
    }
}

/// Helper to build the canonical key of a header.
pub fn key_of(h: &LsaHeader) -> LsaKey {
    h.key()
}
