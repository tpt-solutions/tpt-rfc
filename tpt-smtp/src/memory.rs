// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reference in-memory mail storage / relay backend, useful for tests,
//! examples, and small deployments that do not need durable storage.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::backend::{DeliveryError, Envelope, MailDelivery};

/// A thread-safe in-memory [`MailDelivery`] backend.
///
/// Every accepted message is stored keyed by each of its recipients, so the
/// backend doubles as a simple mailbox store. Use [`MemoryBackend::messages_for`]
/// to retrieve the messages queued for a recipient (e.g. in a test or a
/// retrieval example).
pub struct MemoryBackend {
    /// recipient lowercased -> list of raw message bytes.
    mailboxes: Mutex<HashMap<String, Vec<Vec<u8>>>>,
    /// Optional allow-list of accepted recipient domains / addresses. When
    /// empty, all recipients are accepted (open relay for testing only).
    allowed: Mutex<Vec<String>>,
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryBackend {
    /// Create an empty backend that accepts any recipient.
    pub fn new() -> Self {
        Self {
            mailboxes: Mutex::new(HashMap::new()),
            allowed: Mutex::new(Vec::new()),
        }
    }

    /// Restrict accepted recipients to the given addresses/domains. A value
    /// containing an `@` matches a full address (case-insensitive); otherwise it
    /// matches any recipient whose domain equals it.
    pub fn set_allowed_recipients(&self, recipients: Vec<String>) {
        *self.allowed.lock().expect("backend lock poisoned") = recipients;
    }

    /// Return a copy of all messages stored for `recipient`.
    pub fn messages_for(&self, recipient: &str) -> Vec<Vec<u8>> {
        let map = self.mailboxes.lock().expect("backend lock poisoned");
        map.get(&recipient.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default()
    }

    /// Total number of messages stored across all recipients.
    pub fn total_stored(&self) -> usize {
        let map = self.mailboxes.lock().expect("backend lock poisoned");
        map.values().map(|v| v.len()).sum()
    }

    fn recipient_allowed(&self, recipient: &str) -> bool {
        let allowed = self.allowed.lock().expect("backend lock poisoned");
        if allowed.is_empty() {
            return true;
        }
        let recipient = recipient.to_ascii_lowercase();
        allowed.iter().any(|a| {
            let a = a.to_ascii_lowercase();
            if let Some(domain) = a.strip_prefix('@') {
                recipient.ends_with(&format!("@{}", domain))
            } else {
                recipient == a
            }
        })
    }
}

impl MailDelivery for MemoryBackend {
    fn accept_recipient(&self, recipient: &str) -> Result<(), DeliveryError> {
        if self.recipient_allowed(recipient) {
            Ok(())
        } else {
            Err(DeliveryError::NoSuchRecipient(recipient.to_string()))
        }
    }

    fn deliver(&self, envelope: &Envelope) -> Result<(), DeliveryError> {
        if envelope.recipients.is_empty() {
            return Err(DeliveryError::Rejected("no recipients".to_string()));
        }
        let mut map = self.mailboxes.lock().expect("backend lock poisoned");
        for rcpt in &envelope.recipients {
            map.entry(rcpt.to_ascii_lowercase())
                .or_default()
                .push(envelope.message.clone());
        }
        Ok(())
    }
}
