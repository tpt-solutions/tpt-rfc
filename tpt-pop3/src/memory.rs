// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reference in-memory mailbox backend, useful for tests, examples, and small
//! deployments that do not need durable storage.

use std::collections::HashMap;
use std::sync::Mutex;

use md5::{Digest, Md5};

use crate::backend::{BackendError, MailboxBackend, MailboxMessage};

#[derive(Default)]
struct Account {
    password: String,
    messages: Vec<MailboxMessage>,
}

/// A simple in-memory [`MailboxBackend`].
///
/// Each user owns a password and a list of messages. Credentials are checked
/// with constant-time comparison, and `APOP` is supported by computing
/// `md5(timestamp + password)`. Deletions are applied during
/// [`MemoryBackend::expunge`].
///
/// This backend is provided mainly as a reference and for testing; for real
/// deployments implement [`MailboxBackend`] against your own store.
pub struct MemoryBackend {
    accounts: Mutex<HashMap<String, Account>>,
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
            accounts: Mutex::new(HashMap::new()),
        }
    }

    /// Add (or replace) a user with the given password and mailbox contents.
    /// Each message is assigned a stable `UIDL` of the form `<user>:<index>`.
    pub fn add_user(&self, user: &str, password: &str, messages: Vec<Vec<u8>>) {
        let messages = messages
            .into_iter()
            .enumerate()
            .map(|(i, content)| MailboxMessage::new(format!("{}:{}", user, i), content))
            .collect();
        let mut accounts = self.accounts.lock().expect("backend lock poisoned");
        accounts.insert(
            user.to_string(),
            Account {
                password: password.to_string(),
                messages,
            },
        );
    }

    fn apop_digest(&self, user: &str, timestamp: &str) -> Option<String> {
        let accounts = self.accounts.lock().expect("backend lock poisoned");
        let account = accounts.get(user)?;
        let mut hasher = Md5::new();
        hasher.update(timestamp.as_bytes());
        hasher.update(account.password.as_bytes());
        let digest = hasher.finalize();
        Some(hex::encode(digest))
    }
}

impl MailboxBackend for MemoryBackend {
    fn authenticate(&self, user: &str, pass: &str) -> Result<bool, BackendError> {
        let accounts = self.accounts.lock().expect("backend lock poisoned");
        match accounts.get(user) {
            Some(account) => Ok(constant_time_eq(
                account.password.as_bytes(),
                pass.as_bytes(),
            )),
            None => Ok(false),
        }
    }

    fn authenticate_apop(
        &self,
        user: &str,
        timestamp: &str,
        digest: &str,
    ) -> Result<bool, BackendError> {
        match self.apop_digest(user, timestamp) {
            Some(expected) => {
                let expected = expected.to_ascii_lowercase();
                let provided = digest.to_ascii_lowercase();
                Ok(constant_time_eq(expected.as_bytes(), provided.as_bytes()))
            }
            None => Ok(false),
        }
    }

    fn messages(&self, user: &str) -> Result<Vec<MailboxMessage>, BackendError> {
        let accounts = self.accounts.lock().expect("backend lock poisoned");
        match accounts.get(user) {
            Some(account) => Ok(account.messages.clone()),
            None => Ok(Vec::new()),
        }
    }

    fn expunge(&self, user: &str, uids: &[String]) -> Result<(), BackendError> {
        let mut accounts = self.accounts.lock().expect("backend lock poisoned");
        if let Some(account) = accounts.get_mut(user) {
            account.messages.retain(|m| !uids.contains(&m.uid));
        }
        Ok(())
    }
}

/// Length-independent, branch-minimised equality check on secret material.
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
