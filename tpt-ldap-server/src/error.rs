// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Error types for the LDAP server.

use thiserror::Error;

/// Errors surfaced by a [`crate::backend::DirectoryBackend`] implementation.
///
/// The session layer maps these onto LDAP `resultCode` values (see
/// `crate::protocol::ResultCode`). They are not used for ordinary
/// protocol-level rejections (e.g. a malformed message), which are handled
/// inline as `protocolError`.
#[derive(Debug, Error)]
pub enum BackendError {
    /// Credentials were rejected (simple bind). Maps to `invalidCredentials`.
    #[error("authentication failed")]
    AuthenticationFailed,

    /// A referenced entry does not exist. Maps to `noSuchObject`.
    #[error("no such object")]
    NotFound,

    /// An entry being added already exists. Maps to `entryAlreadyExists`.
    #[error("entry already exists")]
    EntryAlreadyExists,

    /// A referenced attribute does not exist. Maps to `noSuchAttribute`.
    #[error("no such attribute")]
    NoSuchAttribute,

    /// An attribute value to add already exists. Maps to
    /// `attributeOrValueExists`.
    #[error("attribute or value exists")]
    AttributeOrValueExists,

    /// The backend refused the operation for authorization reasons. Maps to
    /// `insufficientAccessRights`.
    #[error("insufficient access rights")]
    InsufficientAccess,

    /// A schema/value constraint was violated. Maps to `constraintViolation`.
    #[error("constraint violation")]
    ConstraintViolation,

    /// The requested operation is not supported (e.g. a SASL mechanism the
    /// backend does not implement). Maps to `authMethodNotSupported` /
    /// `unavailableCriticalExtension` depending on context.
    #[error("operation not supported")]
    Unsupported,

    /// Any other backend-specific failure.
    #[error("{0}")]
    Other(String),
}
