// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pluggable mail-storage backend trait (RFC 8621) plus shared argument/result
//! helpers. The `Dispatcher` routes method calls to these operations; users can
//! provide their own `MailStore` implementation, or use `MemoryMailStore`.

pub mod memory;

use serde::Serialize;
use serde_json::Value;

pub use memory::MemoryMailStore;

use crate::error::MethodError;
use crate::types::Id;

/// Reusable parsed form of a `* /get` argument object (RFC 8620 §5.1).
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetArgs {
    #[serde(default)]
    pub ids: Option<Vec<Id>>,
    #[serde(default)]
    pub properties: Option<Vec<String>>,
}

/// Reusable parsed form of a `* /set` argument object (RFC 8620 §5.3).
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetArgs {
    #[serde(default)]
    pub if_in_state: Option<String>,
    #[serde(default)]
    pub create: Option<serde_json::Map<String, Value>>,
    #[serde(default)]
    pub update: Option<std::collections::HashMap<String, Value>>,
    #[serde(default)]
    pub destroy: Option<Vec<Id>>,
}

/// Reusable parsed form of a `* /query` argument object (RFC 8620 §5.5).
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryArgs {
    #[serde(default)]
    pub filter: Option<Value>,
    #[serde(default)]
    pub sort: Option<Vec<Value>>,
    #[serde(default)]
    pub position: i64,
    #[serde(default)]
    pub anchor: Option<String>,
    #[serde(default)]
    pub anchor_offset: i64,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub calculate_total: bool,
}

/// Reusable parsed form of a `* /changes` argument object (RFC 8620 §5.6).
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangesArgs {
    pub since_state: String,
    #[serde(default)]
    pub max_changes: Option<u32>,
}

/// Standard `* /get` result (RFC 8620 §5.1).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetResult {
    pub account_id: String,
    pub state: String,
    pub list: Vec<Value>,
    pub not_found: Vec<Id>,
}

/// Standard `* /set` result (RFC 8620 §5.3).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetResult {
    pub account_id: String,
    pub old_state: String,
    pub new_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<std::collections::HashMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<Vec<Id>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destroyed: Option<Vec<Id>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_created: Option<std::collections::HashMap<String, MethodError>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_updated: Option<std::collections::HashMap<Id, MethodError>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_destroyed: Option<std::collections::HashMap<Id, MethodError>>,
}

/// Standard `* /query` result (RFC 8620 §5.5).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryResult {
    pub account_id: String,
    pub query_state: String,
    pub can_calculate_changes: bool,
    pub position: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    pub ids: Vec<Id>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collapse_threads: Option<bool>,
}

/// Standard `* /changes` result (RFC 8620 §5.6).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangesResult {
    pub account_id: String,
    pub old_state: String,
    pub new_state: String,
    pub has_more_changes: bool,
    pub created: Vec<Id>,
    pub updated: Vec<Id>,
    pub destroyed: Vec<Id>,
}

/// The pluggable storage backend. `get`/`query`/`changes` are read-only;
/// `set` mutates and may return an `invalidArguments`/`serverFail` error.
pub trait MailStore {
    /// Whether the store serves the given account.
    fn account_exists(&self, account_id: &str) -> bool;
    /// Opaque, monotonically-changing state string for the account.
    fn state(&self, account_id: &str) -> String;

    fn mailbox_get(&self, account_id: &str, args: &Value) -> Result<Value, MethodError>;
    fn mailbox_set(&mut self, account_id: &str, args: &Value) -> Result<Value, MethodError>;
    fn mailbox_query(&self, account_id: &str, args: &Value) -> Result<Value, MethodError>;
    fn mailbox_changes(&self, account_id: &str, args: &Value) -> Result<Value, MethodError>;

    fn email_get(&self, account_id: &str, args: &Value) -> Result<Value, MethodError>;
    fn email_query(&self, account_id: &str, args: &Value) -> Result<Value, MethodError>;
    fn email_set(&mut self, account_id: &str, args: &Value) -> Result<Value, MethodError>;
    fn email_changes(&self, account_id: &str, args: &Value) -> Result<Value, MethodError>;

    fn thread_get(&self, account_id: &str, args: &Value) -> Result<Value, MethodError>;

    fn email_submission_get(&self, account_id: &str, args: &Value) -> Result<Value, MethodError>;
    fn email_submission_set(
        &mut self,
        account_id: &str,
        args: &Value,
    ) -> Result<Value, MethodError>;
    fn email_submission_query(&self, account_id: &str, args: &Value) -> Result<Value, MethodError>;
    fn email_submission_changes(
        &self,
        account_id: &str,
        args: &Value,
    ) -> Result<Value, MethodError>;
}
