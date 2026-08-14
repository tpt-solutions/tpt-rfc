// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The JMAP Session resource and capability objects (RFC 8620 §2, §4;
//! RFC 8621 §1.2).

use serde::{Deserialize, Serialize};

use crate::types::capability;

/// The `urn:ietf:params:jmap:core` capability object (RFC 8620 §4).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoreCapability {
    pub max_size_upload: u64,
    pub max_concurrent_upload: u32,
    pub max_size_request: u64,
    pub max_concurrent_requests: u32,
    pub max_calls_in_request: u32,
    pub max_objects_in_get: u32,
    pub max_objects_in_set: u32,
    pub collation_algorithms: Vec<String>,
}

impl Default for CoreCapability {
    fn default() -> Self {
        CoreCapability {
            max_size_upload: 35 * 1024 * 1024,
            max_concurrent_upload: 4,
            max_size_request: 10 * 1024 * 1024,
            max_concurrent_requests: 4,
            max_calls_in_request: 32,
            max_objects_in_get: 1000,
            max_objects_in_set: 1000,
            collation_algorithms: vec!["i;unicode-casemap".to_owned()],
        }
    }
}

/// The `urn:ietf:params:jmap:mail` capability object (RFC 8621 §1.2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MailCapability {
    pub max_mailboxes_per_email: u32,
    pub max_mailbox_depth: Option<u32>,
    pub max_size_mailbox_name: u32,
    pub max_delayed_send: u32,
    pub message_list_cache_ttl: u32,
}

impl Default for MailCapability {
    fn default() -> Self {
        MailCapability {
            max_mailboxes_per_email: 10_000,
            max_mailbox_depth: None,
            max_size_mailbox_name: 490,
            max_delayed_send: 0,
            message_list_cache_ttl: 0,
        }
    }
}

/// A single account entry in the session resource (RFC 8620 §2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub account_id: String,
    pub name: String,
    #[serde(default)]
    pub is_primary: bool,
    #[serde(default)]
    pub is_read_only: bool,
    #[serde(default)]
    pub has_data_for: Vec<String>,
}

/// The JMAP Session resource (RFC 8620 §2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub username: String,
    pub accounts: Vec<Account>,
    pub primary_accounts: std::collections::HashMap<String, String>,
    pub api_url: String,
    pub download_url: String,
    pub upload_url: String,
    pub event_source_url: String,
    pub state: String,
    pub capabilities: std::collections::HashMap<String, Capability>,
}

/// The server's capability objects, keyed by URN.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Capability {
    #[serde(flatten)]
    pub core: CoreCapability,
    #[serde(flatten)]
    pub mail: MailCapability,
}

impl Session {
    /// The capability URNs this crate supports.
    pub fn supported_capabilities() -> Vec<&'static str> {
        vec![capability::CORE, capability::MAIL]
    }

    /// Build a session for a single primary account with default capabilities.
    pub fn default_for<A: Into<String>>(account_id: A) -> Self {
        let account_id = account_id.into();
        let mut primary_accounts = std::collections::HashMap::new();
        primary_accounts.insert(capability::CORE.to_owned(), account_id.clone());
        primary_accounts.insert(capability::MAIL.to_owned(), account_id.clone());
        Session {
            username: account_id.clone(),
            accounts: vec![Account {
                account_id: account_id.clone(),
                name: account_id.clone(),
                is_primary: true,
                is_read_only: false,
                has_data_for: vec![capability::MAIL.to_owned()],
            }],
            primary_accounts,
            api_url: "https://api.example/jmap".to_owned(),
            download_url: "https://api.example/jmap/download/{accountId}/{blobId}/{name}"
                .to_owned(),
            upload_url: "https://api.example/jmap/upload/{accountId}".to_owned(),
            event_source_url: "https://api.example/jmap/event/{types}".to_owned(),
            state: "static".to_owned(),
            capabilities: {
                let mut m = std::collections::HashMap::new();
                m.insert(capability::CORE.to_owned(), Capability::default());
                m
            },
        }
    }
}
