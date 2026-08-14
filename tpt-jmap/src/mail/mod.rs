// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! JMAP Mail data-model objects (RFC 8621).

pub mod store;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::types::Id;

/// An RFC 5322 address (`{ name?, email }`, RFC 8621 §4.1.1).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EmailAddress {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub email: String,
}

/// A header of an Email (`{ name, value }`, RFC 8621 §4.1.2).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EmailHeader {
    pub name: String,
    pub value: String,
}

/// The rights a user has on a Mailbox (RFC 8621 §3.1.1).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailboxRights {
    pub may_read_items: bool,
    pub may_add_items: bool,
    pub may_remove_items: bool,
    pub may_create_child: bool,
    pub may_rename: bool,
    pub may_delete: bool,
    pub may_submit: bool,
}

/// A Mailbox object (RFC 8621 §3.1).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mailbox {
    pub id: Id,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<Id>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default)]
    pub sort_order: f64,
    #[serde(default)]
    pub total_emails: u64,
    #[serde(default)]
    pub unread_emails: u64,
    #[serde(default)]
    pub total_threads: u64,
    #[serde(default)]
    pub unread_threads: u64,
    pub my_rights: MailboxRights,
    pub is_subscribed: bool,
}

impl Mailbox {
    /// Build a new top-level mailbox with default rights.
    pub fn new<S: Into<String>>(id: Id, name: S) -> Self {
        Mailbox {
            id,
            name: name.into(),
            parent_id: None,
            role: None,
            sort_order: 0.0,
            total_emails: 0,
            unread_emails: 0,
            total_threads: 0,
            unread_threads: 0,
            my_rights: MailboxRights {
                may_read_items: true,
                may_add_items: true,
                may_remove_items: true,
                may_create_child: true,
                may_rename: true,
                may_delete: true,
                may_submit: true,
            },
            is_subscribed: true,
        }
    }
}

/// An Email object (RFC 8621 §4.1). A focused, internally-consistent subset of
/// the full property set sufficient for `/get` and `/query`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Email {
    pub id: Id,
    pub blob_id: Id,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<Id>,
    pub mailbox_ids: Map<String, Value>,
    pub keywords: Map<String, Value>,
    pub size: u64,
    pub received_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<Vec<EmailAddress>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<EmailAddress>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cc: Option<Vec<EmailAddress>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bcc: Option<Vec<EmailAddress>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<Vec<EmailAddress>>,
    #[serde(default)]
    pub has_attachment: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<EmailHeader>,
}

/// A Thread object (RFC 8621 §5.1): a group of emails.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Thread {
    pub id: Id,
    pub email_ids: Vec<Id>,
}

/// An EmailSubmission object (RFC 8621 §7.1).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailSubmission {
    pub id: Id,
    pub identity_id: Id,
    pub email_id: Id,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<Id>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub send_at: Option<String>,
    #[serde(default = "default_undo_status")]
    pub undo_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_status: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipients: Option<Vec<EmailAddress>>,
}

fn default_undo_status() -> String {
    "final".to_owned()
}

/// Keep only the requested top-level `properties` of a serialized object. If
/// `properties` is `None`, the value is returned unchanged. Nested property
/// paths (e.g. `"myRights/mayReadItems"`) are not expanded; the RFC's
/// top-level property selection is what most clients rely on.
pub(crate) fn select_properties(mut value: Value, properties: &Option<Vec<String>>) -> Value {
    let Some(properties) = properties else {
        return value;
    };
    if let Value::Object(map) = &mut value {
        let allowed: std::collections::HashSet<&String> = properties.iter().collect();
        map.retain(|k, _| allowed.contains(k));
    }
    value
}
