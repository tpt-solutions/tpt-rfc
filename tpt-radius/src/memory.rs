// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reference in-memory [`AuthBackend`] for tests and examples.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::server::{AuthBackend, AuthDecision, AuthRequest};

/// A simple in-memory user store keyed by username, holding the expected PAP
/// password. Intended for testing and examples; production backends should
/// implement [`AuthBackend`] against a real data source.
pub struct MemoryBackend {
    users: Mutex<HashMap<String, String>>,
}

impl MemoryBackend {
    /// Create an empty backend.
    pub fn new() -> MemoryBackend {
        MemoryBackend {
            users: Mutex::new(HashMap::new()),
        }
    }

    /// Register (or replace) a user's password.
    pub fn add_user(&self, username: &str, password: &str) {
        self.users
            .lock()
            .expect("memory backend mutex poisoned")
            .insert(username.to_string(), password.to_string());
    }
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthBackend for MemoryBackend {
    fn authenticate(&self, request: &AuthRequest<'_>) -> AuthDecision {
        let user = match request.username {
            Some(u) => u,
            None => {
                return AuthDecision::Reject {
                    message: Some("missing User-Name".into()),
                }
            }
        };
        let pw = match &request.password {
            Some(p) => p,
            None => {
                return AuthDecision::Reject {
                    message: Some("missing User-Password".into()),
                }
            }
        };
        let store = self.users.lock().expect("memory backend mutex poisoned");
        match store.get(user) {
            Some(expected) if expected.as_bytes() == pw.as_slice() => AuthDecision::Accept {
                attributes: Vec::new(),
            },
            _ => AuthDecision::Reject {
                message: Some("invalid credentials".into()),
            },
        }
    }
}
