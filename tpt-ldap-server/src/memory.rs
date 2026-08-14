// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reference in-memory directory backend, useful for tests, examples, and small
//! deployments that do not need durable storage.

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::backend::{
    Attribute, BackendError, DirectoryBackend, Entry, Modification, ModificationOp, ModifyDnRequest,
};

/// A simple in-memory [`DirectoryBackend`].
///
/// Entries are keyed by case-insensitive DN. `bind_simple` checks the entry's
/// `userPassword` attribute with a constant-time comparison against the supplied
/// bytes (plaintext; no `{SSHA}`/hash schemes are interpreted by the reference
/// backend). For real deployments implement [`DirectoryBackend`] against your
/// own store.
pub struct MemoryBackend {
    entries: Mutex<BTreeMap<String, Entry>>,
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryBackend {
    /// Create an empty in-memory backend.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
        }
    }

    /// Insert (or replace) an entry.
    pub fn add_entry(&self, entry: Entry) -> Result<(), BackendError> {
        self.add(&entry)
    }
}

fn norm(dn: &str) -> String {
    dn.to_ascii_lowercase()
}

impl DirectoryBackend for MemoryBackend {
    fn bind_simple(&self, dn: &str, password: &[u8]) -> Result<bool, BackendError> {
        let entries = self.entries.lock().expect("backend lock poisoned");
        match entries.get(&norm(dn)) {
            Some(entry) => match entry.attribute("userPassword") {
                Some(attr) => Ok(attr.values.iter().any(|v| constant_time_eq(v, password))),
                None => Ok(false),
            },
            None => Ok(false),
        }
    }

    fn bind_sasl(
        &self,
        dn: &str,
        sasl: &crate::backend::SaslCredentials,
    ) -> Result<bool, BackendError> {
        // The reference backend does not implement any SASL mechanism.
        let _ = (dn, sasl);
        Err(BackendError::Unsupported)
    }

    fn entries(&self) -> Result<Vec<Entry>, BackendError> {
        let entries = self.entries.lock().expect("backend lock poisoned");
        Ok(entries.values().cloned().collect())
    }

    fn compare(&self, dn: &str, attribute: &str, value: &[u8]) -> Result<bool, BackendError> {
        let entries = self.entries.lock().expect("backend lock poisoned");
        match entries.get(&norm(dn)) {
            Some(entry) => match entry.attribute(attribute) {
                Some(attr) => Ok(attr.values.iter().any(|v| *v == value)),
                None => Ok(false),
            },
            None => Err(BackendError::NotFound),
        }
    }

    fn add(&self, entry: &Entry) -> Result<(), BackendError> {
        let mut entries = self.entries.lock().expect("backend lock poisoned");
        if entries.contains_key(&norm(&entry.dn)) {
            return Err(BackendError::EntryAlreadyExists);
        }
        entries.insert(norm(&entry.dn), entry.clone());
        Ok(())
    }

    fn delete(&self, dn: &str) -> Result<(), BackendError> {
        let mut entries = self.entries.lock().expect("backend lock poisoned");
        if entries.remove(&norm(dn)).is_none() {
            return Err(BackendError::NotFound);
        }
        Ok(())
    }

    fn modify(&self, dn: &str, changes: &[Modification]) -> Result<(), BackendError> {
        let mut entries = self.entries.lock().expect("backend lock poisoned");
        let key = norm(dn);
        let entry = entries.get_mut(&key).ok_or(BackendError::NotFound)?;
        for change in changes {
            let attr = entry
                .attributes
                .iter_mut()
                .find(|a| a.name.eq_ignore_ascii_case(&change.name));
            match change.op {
                ModificationOp::Add => {
                    if let Some(a) = attr {
                        for v in &change.values {
                            if a.values.iter().any(|existing| existing == v) {
                                return Err(BackendError::AttributeOrValueExists);
                            }
                        }
                        a.values.extend_from_slice(&change.values);
                    } else {
                        entry
                            .attributes
                            .push(Attribute::new(change.name.clone(), change.values.clone()));
                    }
                }
                ModificationOp::Delete => {
                    let a = attr.ok_or(BackendError::NoSuchAttribute)?;
                    if change.values.is_empty() {
                        entry
                            .attributes
                            .retain(|x| x.name.eq_ignore_ascii_case(&change.name));
                    } else {
                        let before = a.values.len();
                        a.values.retain(|v| !change.values.iter().any(|c| c == v));
                        if a.values.len() == before {
                            return Err(BackendError::NoSuchAttribute);
                        }
                        if a.values.is_empty() {
                            entry
                                .attributes
                                .retain(|x| x.name.eq_ignore_ascii_case(&change.name));
                        }
                    }
                }
                ModificationOp::Replace => {
                    if change.values.is_empty() {
                        entry
                            .attributes
                            .retain(|x| x.name.eq_ignore_ascii_case(&change.name));
                    } else if let Some(a) = attr {
                        a.values = change.values.clone();
                    } else {
                        entry
                            .attributes
                            .push(Attribute::new(change.name.clone(), change.values.clone()));
                    }
                }
            }
        }
        Ok(())
    }

    fn modify_dn(&self, req: &ModifyDnRequest) -> Result<(), BackendError> {
        let mut entries = self.entries.lock().expect("backend lock poisoned");
        let key = norm(&req.dn);
        if !entries.contains_key(&key) {
            return Err(BackendError::NotFound);
        }
        let (new_rdn_name, new_rdn_value) =
            parse_rdn(&req.new_rdn).ok_or_else(|| BackendError::Other("invalid new RDN".into()))?;
        let superior = match &req.new_superior {
            Some(s) => s.clone(),
            None => crate::protocol::dn_parent(&req.dn)
                .ok_or_else(|| BackendError::Other("cannot derive new superior".into()))?,
        };
        let new_dn = format!("{},{}", req.new_rdn, superior);
        let new_key = norm(&new_dn);
        if new_key != key && entries.contains_key(&new_key) {
            return Err(BackendError::EntryAlreadyExists);
        }

        let (old_rdn_name, old_rdn_value) = parse_rdn(&req.dn).unwrap_or_default();

        let entry = entries.get_mut(&key).unwrap();
        entry.dn = new_dn.clone();

        // Ensure the new RDN attribute carries the new value.
        upsert_value(&mut entry.attributes, &new_rdn_name, &new_rdn_value);

        // If deleting the old RDN, drop its attribute value (unless it is the
        // same attribute/value we just ensured).
        if req.delete_old_rdn && (old_rdn_name != new_rdn_name || old_rdn_value != new_rdn_value) {
            remove_value(&mut entry.attributes, &old_rdn_name, &old_rdn_value);
        }

        let moved = entries.remove(&key).unwrap();
        entries.insert(new_key, moved);
        Ok(())
    }
}

/// Insert `value` into attribute `name` if not already present.
fn upsert_value(attrs: &mut Vec<Attribute>, name: &str, value: &[u8]) {
    if let Some(a) = attrs.iter_mut().find(|a| a.name.eq_ignore_ascii_case(name)) {
        if !a.values.iter().any(|v| v == value) {
            a.values.push(value.to_vec());
        }
    } else {
        attrs.push(Attribute::new(name, vec![value.to_vec()]));
    }
}

/// Remove `value` from attribute `name` (and drop the attribute if emptied).
fn remove_value(attrs: &mut Vec<Attribute>, name: &str, value: &[u8]) {
    if let Some(a) = attrs.iter_mut().find(|a| a.name.eq_ignore_ascii_case(name)) {
        a.values.retain(|v| v != value);
    }
    attrs.retain(|a| !a.name.eq_ignore_ascii_case(name) || !a.values.is_empty());
}

/// Parse the attribute name and value from an RDN component like `cn=alice`.
fn parse_rdn(rdn: &str) -> Option<(String, Vec<u8>)> {
    let eq = rdn.find('=')?;
    let name = rdn[..eq].trim().to_string();
    let value = rdn[eq + 1..].trim().as_bytes().to_vec();
    Some((name, value))
}

/// Length-independent equality check on secret material (bind passwords).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
