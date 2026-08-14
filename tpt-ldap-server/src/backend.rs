// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The pluggable directory backend trait and the data types the server uses to
//! describe entries and modifications.
//!
//! A server only ever needs to authenticate bind requests and to read/write
//! entries, so the backend trait is intentionally small. The session layer owns
//! connection state, search scope handling, and search-filter evaluation; the
//! backend just stores durable directory state.

pub use crate::error::BackendError;

/// A single attribute of a directory entry: a type plus zero or more values.
///
/// LDAP attribute values are opaque octets; binary attributes (e.g.
/// `userCertificate`) are carried verbatim. Forcing values to `Vec<u8>` keeps
/// this crate free of any string-encoding assumptions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// The attribute description (type), e.g. `cn` or `objectClass`.
    pub name: String,
    /// The attribute's values (a SET; order is not significant in LDAP).
    pub values: Vec<Vec<u8>>,
}

impl Attribute {
    /// Create an attribute from a name and a list of byte-string values.
    pub fn new(name: impl Into<String>, values: Vec<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            values,
        }
    }
}

/// A directory entry: a distinguished name plus its attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The entry's distinguished name, e.g. `cn=alice,dc=example,dc=com`.
    pub dn: String,
    /// The entry's attributes.
    pub attributes: Vec<Attribute>,
}

impl Entry {
    /// Create an entry from a DN and a list of attributes.
    pub fn new(dn: impl Into<String>, attributes: Vec<Attribute>) -> Self {
        Self {
            dn: dn.into(),
            attributes,
        }
    }

    /// Look up an attribute by (case-insensitive) name.
    pub fn attribute(&self, name: &str) -> Option<&Attribute> {
        self.attributes
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case(name))
    }
}

/// SASL bind credentials carried inside a `BindRequest` (RFC 4511 §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaslCredentials {
    /// The SASL mechanism name (e.g. `PLAIN`, `EXTERNAL`).
    pub mechanism: String,
    /// The optional SASL credentials octet string.
    pub credentials: Vec<u8>,
}

/// The kind of modification in a `ModifyRequest` (RFC 4511 §4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModificationOp {
    /// Add the values to the attribute (creating it if absent).
    Add,
    /// Delete the values from the attribute (or all values if `values` is empty).
    Delete,
    /// Replace the attribute's values with `values` (deleting it if empty).
    Replace,
}

/// A single change in a `ModifyRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Modification {
    /// The operation to perform.
    pub op: ModificationOp,
    /// The attribute being modified.
    pub name: String,
    /// The values involved (interpretation depends on `op`).
    pub values: Vec<Vec<u8>>,
}

/// Backend trait an LDAP server uses to authenticate binds and read/write
/// directory entries.
///
/// Implementors must be `Send + Sync` so a single backend instance can serve
/// many connections behind an `Arc`.
pub trait DirectoryBackend: Send + Sync {
    /// Check a simple (name + password) bind. Return `Ok(true)` if the
    /// credentials are accepted, `Ok(false)` to send `invalidCredentials`.
    fn bind_simple(&self, dn: &str, password: &[u8]) -> Result<bool, BackendError>;

    /// Check a SASL bind. The default implementation reports `Unsupported`,
    /// which the session maps to `authMethodNotSupported`. Override this to
    /// support specific mechanisms.
    fn bind_sasl(&self, dn: &str, sasl: &SaslCredentials) -> Result<bool, BackendError> {
        let _ = (dn, sasl);
        Err(BackendError::Unsupported)
    }

    /// Return every entry in the directory. The session applies search scope
    /// (base / single-level / whole-subtree) and filter evaluation on top of
    /// this, so a backend may return the full set without optimizing either.
    fn entries(&self) -> Result<Vec<Entry>, BackendError>;

    /// Compare `dn`'s `attribute` to `value`, returning `true` for a match.
    fn compare(&self, dn: &str, attribute: &str, value: &[u8]) -> Result<bool, BackendError>;

    /// Add a new entry. Return `Err(EntryExists)` if it already exists.
    fn add(&self, entry: &Entry) -> Result<(), BackendError>;

    /// Delete the entry named by `dn`. Return `Err(NotFound)` if absent.
    fn delete(&self, dn: &str) -> Result<(), BackendError>;

    /// Apply a list of modifications to the entry named by `dn`.
    fn modify(&self, dn: &str, changes: &[Modification]) -> Result<(), BackendError>;

    /// Rename/move the entry named by `dn` per a `ModifyDNRequest`.
    fn modify_dn(&self, req: &ModifyDnRequest) -> Result<(), BackendError>;
}

/// The rename parameters of a `ModifyDNRequest` (RFC 4511 §4.9), copied from the
/// decoded protocol message so the backend does not depend on the codec layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifyDnRequest {
    /// The DN of the entry to rename.
    pub dn: String,
    /// The new relative distinguished name (RDN).
    pub new_rdn: String,
    /// Whether the old RDN attribute value should be removed from the entry.
    pub delete_old_rdn: bool,
    /// The new superior entry's DN, if the entry is being moved.
    pub new_superior: Option<String>,
}
