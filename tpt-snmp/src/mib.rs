// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pluggable MIB / OID handler trait and a simple in-memory backend.

use std::collections::BTreeMap;

use crate::error::SnmpError;
use crate::oid::ObjectIdentifier;
use crate::value::{SnmpValue, VarBind};

/// A handler that resolves OIDs to values for `Get`/`GetNext`/`Set` processing.
///
/// Implement this trait (or use [`InMemoryMib`]) to back an [`crate::Agent`]
/// with your own directory of managed objects.
pub trait MibHandler {
    /// Resolve a single OID to its current binding, or `None` if it is not
    /// present.
    fn get(&self, oid: &ObjectIdentifier) -> Option<VarBind>;

    /// Resolve the lexically-next OID greater than `oid`, for `GetNext`.
    fn get_next(&self, oid: &ObjectIdentifier) -> Option<VarBind>;

    /// Apply a `Set`. Return an error to abort the whole request.
    fn set(&mut self, vb: &VarBind) -> Result<(), SnmpError>;
}

/// A reference in-memory MIB backed by a sorted map of OID → value.
#[derive(Debug, Clone, Default)]
pub struct InMemoryMib {
    map: BTreeMap<ObjectIdentifier, SnmpValue>,
}

impl InMemoryMib {
    /// Create an empty MIB.
    pub fn new() -> Self {
        InMemoryMib {
            map: BTreeMap::new(),
        }
    }

    /// Insert/replace an object.
    pub fn insert(&mut self, oid: ObjectIdentifier, value: SnmpValue) {
        self.map.insert(oid, value);
    }

    /// Number of objects currently stored.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the MIB is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl MibHandler for InMemoryMib {
    fn get(&self, oid: &ObjectIdentifier) -> Option<VarBind> {
        self.map
            .get(oid)
            .map(|v| VarBind::new(oid.clone(), v.clone()))
    }

    fn get_next(&self, oid: &ObjectIdentifier) -> Option<VarBind> {
        self.map
            .range(oid.clone()..)
            .find(|(k, _)| *k > oid)
            .map(|(k, v)| VarBind::new(k.clone(), v.clone()))
    }

    fn set(&mut self, vb: &VarBind) -> Result<(), SnmpError> {
        self.map.insert(vb.oid.clone(), vb.value.clone());
        Ok(())
    }
}
