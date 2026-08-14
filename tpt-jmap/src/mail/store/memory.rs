// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! In-memory reference `MailStore` implementation, for tests and examples.

use std::collections::{BTreeMap, HashMap};

use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use super::{
    ChangesArgs, ChangesResult, GetArgs, GetResult, MailStore, QueryArgs, QueryResult, SetArgs,
    SetResult,
};
use crate::error::MethodError;
use crate::mail::{select_properties, Email, EmailSubmission, Mailbox, Thread};
use crate::types::Id;

#[derive(Default, Clone)]
struct ChangeSet {
    created: Vec<Id>,
    updated: Vec<Id>,
    destroyed: Vec<Id>,
}

#[derive(Default)]
struct AccountData {
    revision: u64,
    mailboxes: BTreeMap<Id, Mailbox>,
    emails: BTreeMap<Id, Email>,
    threads: BTreeMap<Id, Thread>,
    submissions: BTreeMap<Id, EmailSubmission>,
    next: u64,
    change_log: BTreeMap<u64, ChangeSet>,
}

impl AccountData {
    fn alloc(&mut self, prefix: char) -> Id {
        self.next += 1;
        Id(format!("{prefix}{}", self.next))
    }

    fn record_change(&mut self, cs: ChangeSet) {
        if cs.created.is_empty() && cs.updated.is_empty() && cs.destroyed.is_empty() {
            return;
        }
        self.revision += 1;
        self.change_log.insert(self.revision, cs);
    }
}

/// A simple in-memory `MailStore`. Suitable for tests, examples, and as a
/// reference for implementing a real backend. It does **not** perform actual
/// SMTP delivery for `EmailSubmission` (submissions are recorded with
/// `undoStatus: "pending"`; callers may cancel them).
pub struct MemoryMailStore {
    accounts: HashMap<String, AccountData>,
}

impl Default for MemoryMailStore {
    fn default() -> Self {
        let mut s = MemoryMailStore {
            accounts: HashMap::new(),
        };
        s.accounts
            .insert("account1".to_owned(), AccountData::default());
        s
    }
}

impl MemoryMailStore {
    /// Create a store with a default `account1` account.
    pub fn new() -> Self {
        let mut s = MemoryMailStore {
            accounts: HashMap::new(),
        };
        s.accounts
            .insert("account1".to_owned(), AccountData::default());
        s
    }

    /// Register (or replace) an account.
    pub fn add_account<S: Into<String>>(&mut self, id: S) {
        self.accounts.insert(id.into(), AccountData::default());
    }

    /// Insert a pre-built mailbox (test/example seeding). Returns its id.
    pub fn seed_mailbox(&mut self, mailbox: Mailbox) -> Id {
        let id = mailbox.id.clone();
        self.accounts
            .get_mut("account1")
            .expect("default account")
            .mailboxes
            .insert(id.clone(), mailbox);
        id
    }

    /// Insert a pre-built email (test/example seeding). Returns its id.
    pub fn seed_email(&mut self, email: Email) -> Id {
        let id = email.id.clone();
        self.accounts
            .get_mut("account1")
            .expect("default account")
            .emails
            .insert(id.clone(), email);
        id
    }

    fn account(&self, id: &str) -> &AccountData {
        self.accounts
            .get(id)
            .expect("account must exist (checked by dispatcher)")
    }

    fn account_mut(&mut self, id: &str) -> &mut AccountData {
        self.accounts
            .get_mut(id)
            .expect("account must exist (checked by dispatcher)")
    }

    /// Aggregate change-log entries with revision > `since`.
    fn collect_changes(&self, data: &AccountData, since: u64) -> (Vec<Id>, Vec<Id>, Vec<Id>) {
        let mut created = Vec::new();
        let mut updated = Vec::new();
        let mut destroyed = Vec::new();
        for (rev, cs) in data.change_log.range((since + 1)..) {
            let _ = rev;
            created.extend(cs.created.iter().cloned());
            updated.extend(cs.updated.iter().cloned());
            destroyed.extend(cs.destroyed.iter().cloned());
        }
        (created, updated, destroyed)
    }
}

impl MailStore for MemoryMailStore {
    fn account_exists(&self, account_id: &str) -> bool {
        self.accounts.contains_key(account_id)
    }

    fn state(&self, account_id: &str) -> String {
        self.account(account_id).revision.to_string()
    }

    // ---- Mailbox -----------------------------------------------------------

    fn mailbox_get(&self, account_id: &str, args: &Value) -> Result<Value, MethodError> {
        let ga: GetArgs = parse_args(args)?;
        let data = self.account(account_id);
        let (list, not_found) = match &ga.ids {
            Some(ids) => {
                let mut list = Vec::new();
                let mut nf = Vec::new();
                for id in ids {
                    if let Some(m) = data.mailboxes.get(id) {
                        list.push(m);
                    } else {
                        nf.push(id.clone());
                    }
                }
                (list, nf)
            }
            None => (data.mailboxes.values().collect(), Vec::new()),
        };
        let list: Vec<Value> = list
            .iter()
            .map(|m| select_properties(serde_json::to_value(m).unwrap(), &ga.properties))
            .collect();
        let result = GetResult {
            account_id: account_id.to_owned(),
            state: data.revision.to_string(),
            list,
            not_found,
        };
        to_value(result)
    }

    fn mailbox_set(&mut self, account_id: &str, args: &Value) -> Result<Value, MethodError> {
        let sa: SetArgs = parse_args(args)?;
        let data = self.account_mut(account_id);
        if let Some(s) = &sa.if_in_state {
            if *s != data.revision.to_string() {
                return Err(MethodError::invalid_arguments(
                    "ifInState does not match current state",
                    vec!["ifInState"],
                ));
            }
        }
        let old = data.revision.to_string();

        let mut created = HashMap::new();
        let mut not_created = HashMap::new();
        let mut updated = Vec::new();
        let mut not_updated = HashMap::new();
        let mut destroyed = Vec::new();
        let mut not_destroyed = HashMap::new();
        let mut change = ChangeSet::default();

        if let Some(create) = &sa.create {
            for (cid, val) in create {
                let base = json!({
                    "id": data.alloc('M'),
                    "name": "",
                    "myRights": {
                        "mayReadItems": true, "mayAddItems": true, "mayRemoveItems": true,
                        "mayCreateChild": true, "mayRename": true, "mayDelete": true, "maySubmit": true
                    },
                    "isSubscribed": true,
                    "sortOrder": 0.0,
                });
                match merge_and_parse::<Mailbox>(base, val) {
                    Ok(m) if m.name.trim().is_empty() => {
                        not_created.insert(
                            cid.clone(),
                            MethodError::invalid_arguments("name is required", vec!["name"]),
                        );
                    }
                    Ok(m) => {
                        let id = m.id.clone();
                        data.mailboxes.insert(id.clone(), m.clone());
                        change.created.push(id.clone());
                        created.insert(cid.clone(), serde_json::to_value(&m).unwrap());
                    }
                    Err(e) => {
                        not_created.insert(cid.clone(), e);
                    }
                }
            }
        }

        if let Some(update) = &sa.update {
            for (id, patch) in update {
                let id = Id::new(id);
                match data.mailboxes.get(&id) {
                    Some(m) => {
                        let base = serde_json::to_value(m).unwrap();
                        match merge_and_parse::<Mailbox>(base, patch) {
                            Ok(mut m) => {
                                m.id = id.clone();
                                data.mailboxes.insert(id.clone(), m);
                                updated.push(id.clone());
                                change.updated.push(id.clone());
                            }
                            Err(e) => {
                                not_updated.insert(id.clone(), e);
                            }
                        }
                    }
                    None => {
                        not_updated.insert(id.clone(), MethodError::not_found());
                    }
                }
            }
        }

        if let Some(destroy) = &sa.destroy {
            for id in destroy {
                if data.mailboxes.remove(id).is_some() {
                    destroyed.push(id.clone());
                    change.destroyed.push(id.clone());
                } else {
                    not_destroyed.insert(id.clone(), MethodError::not_found());
                }
            }
        }

        data.record_change(change);
        let result = SetResult {
            account_id: account_id.to_owned(),
            old_state: old,
            new_state: data.revision.to_string(),
            created: if created.is_empty() {
                None
            } else {
                Some(created)
            },
            updated: if updated.is_empty() {
                None
            } else {
                Some(updated)
            },
            destroyed: if destroyed.is_empty() {
                None
            } else {
                Some(destroyed)
            },
            not_created: if not_created.is_empty() {
                None
            } else {
                Some(not_created)
            },
            not_updated: if not_updated.is_empty() {
                None
            } else {
                Some(not_updated)
            },
            not_destroyed: if not_destroyed.is_empty() {
                None
            } else {
                Some(not_destroyed)
            },
        };
        to_value(result)
    }

    fn mailbox_query(&self, account_id: &str, args: &Value) -> Result<Value, MethodError> {
        let qa: QueryArgs = parse_args(args)?;
        let data = self.account(account_id);
        let mut items: Vec<&Mailbox> = data.mailboxes.values().collect();
        if let Some(filter) = &qa.filter {
            items.retain(|m| mailbox_matches(m, filter));
        }
        mailbox_sort(&mut items, &qa.sort);
        let (ids, total, position) = apply_query(&items, &qa, |m| m.id.clone());
        let result = QueryResult {
            account_id: account_id.to_owned(),
            query_state: data.revision.to_string(),
            can_calculate_changes: true,
            position,
            total: if qa.calculate_total {
                Some(total)
            } else {
                None
            },
            ids,
            collapse_threads: None,
        };
        to_value(result)
    }

    fn mailbox_changes(&self, account_id: &str, args: &Value) -> Result<Value, MethodError> {
        changes_result(self, account_id, args)
    }

    // ---- Email -------------------------------------------------------------

    fn email_get(&self, account_id: &str, args: &Value) -> Result<Value, MethodError> {
        let ga: GetArgs = parse_args(args)?;
        let data = self.account(account_id);
        let (list, not_found) = match &ga.ids {
            Some(ids) => {
                let mut list = Vec::new();
                let mut nf = Vec::new();
                for id in ids {
                    if let Some(e) = data.emails.get(id) {
                        list.push(e);
                    } else {
                        nf.push(id.clone());
                    }
                }
                (list, nf)
            }
            None => (data.emails.values().collect(), Vec::new()),
        };
        let list: Vec<Value> = list
            .iter()
            .map(|e| select_properties(serde_json::to_value(e).unwrap(), &ga.properties))
            .collect();
        let result = GetResult {
            account_id: account_id.to_owned(),
            state: data.revision.to_string(),
            list,
            not_found,
        };
        to_value(result)
    }

    fn email_query(&self, account_id: &str, args: &Value) -> Result<Value, MethodError> {
        let qa: QueryArgs = parse_args(args)?;
        let data = self.account(account_id);
        let mut items: Vec<&Email> = data.emails.values().collect();
        if let Some(filter) = &qa.filter {
            items.retain(|e| email_matches(e, filter));
        }
        email_sort(&mut items, &qa.sort);
        let (ids, total, position) = apply_query(&items, &qa, |e| e.id.clone());
        let result = QueryResult {
            account_id: account_id.to_owned(),
            query_state: data.revision.to_string(),
            can_calculate_changes: true,
            position,
            total: if qa.calculate_total {
                Some(total)
            } else {
                None
            },
            ids,
            collapse_threads: None,
        };
        to_value(result)
    }

    fn email_set(&mut self, account_id: &str, args: &Value) -> Result<Value, MethodError> {
        let sa: SetArgs = parse_args(args)?;
        let data = self.account_mut(account_id);
        if let Some(s) = &sa.if_in_state {
            if *s != data.revision.to_string() {
                return Err(MethodError::invalid_arguments(
                    "ifInState does not match current state",
                    vec!["ifInState"],
                ));
            }
        }
        let old = data.revision.to_string();
        let mut created = HashMap::new();
        let mut not_created = HashMap::new();
        let mut updated = Vec::new();
        let mut not_updated = HashMap::new();
        let mut destroyed = Vec::new();
        let mut not_destroyed = HashMap::new();
        let mut change = ChangeSet::default();

        if let Some(create) = &sa.create {
            for (cid, val) in create {
                let base = json!({
                    "id": data.alloc('E'),
                    "blobId": data.alloc('B'),
                    "mailboxIds": {},
                    "keywords": {},
                    "size": 0,
                    "receivedAt": now_rfc3339(),
                });
                match merge_and_parse::<Email>(base, val) {
                    Ok(e) if e.mailbox_ids.is_empty() => {
                        not_created.insert(
                            cid.clone(),
                            MethodError::invalid_arguments(
                                "at least one mailboxId is required",
                                vec!["mailboxIds"],
                            ),
                        );
                    }
                    Ok(e) => {
                        let id = e.id.clone();
                        data.emails.insert(id.clone(), e.clone());
                        change.created.push(id.clone());
                        created.insert(cid.clone(), serde_json::to_value(&e).unwrap());
                    }
                    Err(e) => {
                        not_created.insert(cid.clone(), e);
                    }
                }
            }
        }

        if let Some(update) = &sa.update {
            for (id, patch) in update {
                let id = Id::new(id);
                match data.emails.get(&id) {
                    Some(e) => {
                        let base = serde_json::to_value(e).unwrap();
                        match merge_and_parse::<Email>(base, patch) {
                            Ok(e) => {
                                data.emails.insert(id.clone(), e);
                                updated.push(id.clone());
                                change.updated.push(id.clone());
                            }
                            Err(e) => {
                                not_updated.insert(id.clone(), e);
                            }
                        }
                    }
                    None => {
                        not_updated.insert(id.clone(), MethodError::not_found());
                    }
                }
            }
        }

        if let Some(destroy) = &sa.destroy {
            for id in destroy {
                // Remove the email from any threads and submissions too.
                if data.emails.remove(id).is_some() {
                    destroyed.push(id.clone());
                    change.destroyed.push(id.clone());
                } else {
                    not_destroyed.insert(id.clone(), MethodError::not_found());
                }
            }
        }

        data.record_change(change);
        let result = SetResult {
            account_id: account_id.to_owned(),
            old_state: old,
            new_state: data.revision.to_string(),
            created: if created.is_empty() {
                None
            } else {
                Some(created)
            },
            updated: if updated.is_empty() {
                None
            } else {
                Some(updated)
            },
            destroyed: if destroyed.is_empty() {
                None
            } else {
                Some(destroyed)
            },
            not_created: if not_created.is_empty() {
                None
            } else {
                Some(not_created)
            },
            not_updated: if not_updated.is_empty() {
                None
            } else {
                Some(not_updated)
            },
            not_destroyed: if not_destroyed.is_empty() {
                None
            } else {
                Some(not_destroyed)
            },
        };
        to_value(result)
    }

    fn email_changes(&self, account_id: &str, args: &Value) -> Result<Value, MethodError> {
        changes_result(self, account_id, args)
    }

    // ---- Thread ------------------------------------------------------------

    fn thread_get(&self, account_id: &str, args: &Value) -> Result<Value, MethodError> {
        let ga: GetArgs = parse_args(args)?;
        let data = self.account(account_id);
        let (list, not_found) = match &ga.ids {
            Some(ids) => {
                let mut list = Vec::new();
                let mut nf = Vec::new();
                for id in ids {
                    if let Some(t) = data.threads.get(id) {
                        list.push(t);
                    } else {
                        nf.push(id.clone());
                    }
                }
                (list, nf)
            }
            None => (data.threads.values().collect(), Vec::new()),
        };
        let list: Vec<Value> = list
            .iter()
            .map(|t| select_properties(serde_json::to_value(t).unwrap(), &ga.properties))
            .collect();
        let result = GetResult {
            account_id: account_id.to_owned(),
            state: data.revision.to_string(),
            list,
            not_found,
        };
        to_value(result)
    }

    // ---- EmailSubmission ---------------------------------------------------

    fn email_submission_get(&self, account_id: &str, args: &Value) -> Result<Value, MethodError> {
        let ga: GetArgs = parse_args(args)?;
        let data = self.account(account_id);
        let (list, not_found) = match &ga.ids {
            Some(ids) => {
                let mut list = Vec::new();
                let mut nf = Vec::new();
                for id in ids {
                    if let Some(s) = data.submissions.get(id) {
                        list.push(s);
                    } else {
                        nf.push(id.clone());
                    }
                }
                (list, nf)
            }
            None => (data.submissions.values().collect(), Vec::new()),
        };
        let list: Vec<Value> = list
            .iter()
            .map(|s| select_properties(serde_json::to_value(s).unwrap(), &ga.properties))
            .collect();
        let result = GetResult {
            account_id: account_id.to_owned(),
            state: data.revision.to_string(),
            list,
            not_found,
        };
        to_value(result)
    }

    fn email_submission_set(
        &mut self,
        account_id: &str,
        args: &Value,
    ) -> Result<Value, MethodError> {
        let sa: SetArgs = parse_args(args)?;
        let data = self.account_mut(account_id);
        if let Some(s) = &sa.if_in_state {
            if *s != data.revision.to_string() {
                return Err(MethodError::invalid_arguments(
                    "ifInState does not match current state",
                    vec!["ifInState"],
                ));
            }
        }
        let old = data.revision.to_string();
        let mut created = HashMap::new();
        let mut not_created = HashMap::new();
        let mut updated = Vec::new();
        let mut not_updated = HashMap::new();
        let mut destroyed = Vec::new();
        let mut not_destroyed = HashMap::new();
        let mut change = ChangeSet::default();

        if let Some(create) = &sa.create {
            for (cid, val) in create {
                let base = json!({
                    "id": data.alloc('S'),
                    "identityId": "",
                    "emailId": "",
                    "undoStatus": "pending",
                    "sendAt": now_rfc3339(),
                });
                match merge_and_parse::<EmailSubmission>(base, val) {
                    Ok(s)
                        if s.identity_id.as_str().is_empty() || s.email_id.as_str().is_empty() =>
                    {
                        not_created.insert(
                            cid.clone(),
                            MethodError::invalid_arguments(
                                "identityId and emailId are required",
                                vec!["identityId", "emailId"],
                            ),
                        );
                    }
                    Ok(s) => {
                        if !data.emails.contains_key(&s.email_id) {
                            not_created.insert(
                                cid.clone(),
                                MethodError::invalid_arguments(
                                    "emailId does not reference an existing email",
                                    vec!["emailId"],
                                ),
                            );
                            continue;
                        }
                        let id = s.id.clone();
                        // Preserve the email's thread if not explicitly set.
                        let mut sub = s;
                        if sub.thread_id.is_none() {
                            sub.thread_id = data
                                .emails
                                .get(&sub.email_id)
                                .and_then(|e| e.thread_id.clone());
                        }
                        data.submissions.insert(id.clone(), sub.clone());
                        change.created.push(id.clone());
                        created.insert(cid.clone(), serde_json::to_value(&sub).unwrap());
                    }
                    Err(e) => {
                        not_created.insert(cid.clone(), e);
                    }
                }
            }
        }

        if let Some(update) = &sa.update {
            for (id, patch) in update {
                let id = Id::new(id);
                match data.submissions.get(&id) {
                    Some(orig) => {
                        let prev_status = orig.undo_status.clone();
                        let base = serde_json::to_value(orig).unwrap();
                        match merge_and_parse::<EmailSubmission>(base, patch) {
                            Ok(mut s) => {
                                // Only cancellation is honoured by the reference
                                // backend (RFC 8621 §7.3): undoStatus may move
                                // from "pending" to "canceled".
                                if let Some(req) = patch.get("undoStatus") {
                                    if req.as_str() == Some("canceled") && prev_status != "pending"
                                    {
                                        not_updated.insert(
                                            id.clone(),
                                            MethodError::invalid_arguments(
                                                "can only cancel a pending submission",
                                                vec!["undoStatus"],
                                            ),
                                        );
                                        continue;
                                    }
                                }
                                s.id = id.clone();
                                data.submissions.insert(id.clone(), s);
                                updated.push(id.clone());
                                change.updated.push(id.clone());
                            }
                            Err(e) => {
                                not_updated.insert(id.clone(), e);
                            }
                        }
                    }
                    None => {
                        not_updated.insert(id.clone(), MethodError::not_found());
                    }
                }
            }
        }

        if let Some(destroy) = &sa.destroy {
            for id in destroy {
                if data.submissions.remove(id).is_some() {
                    destroyed.push(id.clone());
                    change.destroyed.push(id.clone());
                } else {
                    not_destroyed.insert(id.clone(), MethodError::not_found());
                }
            }
        }

        data.record_change(change);
        let result = SetResult {
            account_id: account_id.to_owned(),
            old_state: old,
            new_state: data.revision.to_string(),
            created: if created.is_empty() {
                None
            } else {
                Some(created)
            },
            updated: if updated.is_empty() {
                None
            } else {
                Some(updated)
            },
            destroyed: if destroyed.is_empty() {
                None
            } else {
                Some(destroyed)
            },
            not_created: if not_created.is_empty() {
                None
            } else {
                Some(not_created)
            },
            not_updated: if not_updated.is_empty() {
                None
            } else {
                Some(not_updated)
            },
            not_destroyed: if not_destroyed.is_empty() {
                None
            } else {
                Some(not_destroyed)
            },
        };
        to_value(result)
    }

    fn email_submission_query(&self, account_id: &str, args: &Value) -> Result<Value, MethodError> {
        let qa: QueryArgs = parse_args(args)?;
        let data = self.account(account_id);
        let mut items: Vec<&EmailSubmission> = data.submissions.values().collect();
        if let Some(filter) = &qa.filter {
            items.retain(|s| submission_matches(s, filter));
        }
        submission_sort(&mut items, &qa.sort);
        let (ids, total, position) = apply_query(&items, &qa, |s| s.id.clone());
        let result = QueryResult {
            account_id: account_id.to_owned(),
            query_state: data.revision.to_string(),
            can_calculate_changes: true,
            position,
            total: if qa.calculate_total {
                Some(total)
            } else {
                None
            },
            ids,
            collapse_threads: None,
        };
        to_value(result)
    }

    fn email_submission_changes(
        &self,
        account_id: &str,
        args: &Value,
    ) -> Result<Value, MethodError> {
        changes_result(self, account_id, args)
    }
}

// ---------------------------------------------------------------------------
// Argument/result helpers
// ---------------------------------------------------------------------------

fn parse_args<T: DeserializeOwned>(args: &Value) -> Result<T, MethodError> {
    serde_json::from_value(args.clone())
        .map_err(|e| MethodError::invalid_arguments(&e.to_string(), vec![]))
}

fn to_value<T: serde::Serialize>(v: T) -> Result<Value, MethodError> {
    serde_json::to_value(v).map_err(|e| MethodError::server_fail(&e.to_string()))
}

/// Merge `patch` (a JSON object) over `base` (a JSON object), then deserialize
/// to `T`. Unknown keys are tolerated by serde (deny_unknown_fields is off),
/// so this is a forgiving patch apply.
fn merge_and_parse<T: DeserializeOwned>(mut base: Value, patch: &Value) -> Result<T, MethodError> {
    if let (Value::Object(b), Value::Object(p)) = (&mut base, patch) {
        for (k, v) in p {
            b.insert(k.clone(), v.clone());
        }
    }
    serde_json::from_value(base).map_err(|e| MethodError::invalid_arguments(&e.to_string(), vec![]))
}

fn changes_result(
    store: &MemoryMailStore,
    account_id: &str,
    args: &Value,
) -> Result<Value, MethodError> {
    let ca: ChangesArgs = parse_args(args)?;
    let data = store.account(account_id);
    let since: u64 = ca.since_state.parse().unwrap_or(0);
    let (created, updated, destroyed) = store.collect_changes(data, since);
    let result = ChangesResult {
        account_id: account_id.to_owned(),
        old_state: ca.since_state.clone(),
        new_state: data.revision.to_string(),
        has_more_changes: false,
        created,
        updated,
        destroyed,
    };
    to_value(result)
}

/// Apply position/limit and return the selected ids plus the total count and
/// the clamped position used.
fn apply_query<T>(items: &[T], qa: &QueryArgs, id_of: impl Fn(&T) -> Id) -> (Vec<Id>, u64, u64) {
    let total = items.len() as u64;
    let position = qa.position.max(0) as usize;
    let ids: Vec<Id> = match qa.limit {
        Some(l) => items
            .iter()
            .skip(position)
            .take(l as usize)
            .map(&id_of)
            .collect(),
        None => items.iter().skip(position).map(&id_of).collect(),
    };
    (ids, total, position as u64)
}

// ---------------------------------------------------------------------------
// Filtering / sorting (a pragmatic subset of RFC 8620 §5.5 / RFC 8621)
// ---------------------------------------------------------------------------

fn mailbox_matches(m: &Mailbox, filter: &Value) -> bool {
    let f = match filter.as_object() {
        Some(f) => f,
        None => return true,
    };
    for (k, v) in f {
        match k.as_str() {
            "name" => {
                if let Some(s) = v.as_str() {
                    if !eq_casemap(&m.name, s) {
                        return false;
                    }
                }
            }
            "parentId" => {
                if m.parent_id.as_ref().map(|p| p.as_str()) != v.as_str() {
                    return false;
                }
            }
            "role" => {
                if m.role.as_deref() != v.as_str() {
                    return false;
                }
            }
            "hasAnyRole" => {
                if v.as_bool() == Some(true) && m.role.is_none() {
                    return false;
                }
                if v.as_bool() == Some(false) && m.role.is_some() {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

fn email_matches(e: &Email, filter: &Value) -> bool {
    let f = match filter.as_object() {
        Some(f) => f,
        None => return true,
    };
    for (k, v) in f {
        match k.as_str() {
            "inMailbox" => {
                if let Some(id) = v.as_str() {
                    if !e.mailbox_ids.contains_key(id) {
                        return false;
                    }
                }
            }
            "subject" => {
                if let Some(s) = v.as_str() {
                    if !contains_casemap(e.subject.as_deref().unwrap_or(""), s) {
                        return false;
                    }
                }
            }
            "hasKeyword" => {
                if let Some(kw) = v.as_str() {
                    if !e.keywords.contains_key(kw) {
                        return false;
                    }
                }
            }
            "hasAttachment" => {
                if v.as_bool() == Some(true) && !e.has_attachment {
                    return false;
                }
                if v.as_bool() == Some(false) && e.has_attachment {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

fn submission_matches(s: &EmailSubmission, filter: &Value) -> bool {
    let f = match filter.as_object() {
        Some(f) => f,
        None => return true,
    };
    for (k, v) in f {
        match k.as_str() {
            "emailId" => {
                if s.email_id.as_str() != v.as_str().unwrap_or("") {
                    return false;
                }
            }
            "identityId" => {
                if s.identity_id.as_str() != v.as_str().unwrap_or("") {
                    return false;
                }
            }
            "undoStatus" if s.undo_status != v.as_str().unwrap_or("") => return false,
            _ => {}
        }
    }
    true
}

fn mailbox_sort(items: &mut Vec<&Mailbox>, sort: &Option<Vec<Value>>) {
    let (prop, asc) = sort_property(sort, "sortOrder");
    items.sort_by(|a, b| {
        let ord = match prop.as_str() {
            "name" => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            "sortOrder" => a
                .sort_order
                .partial_cmp(&b.sort_order)
                .unwrap_or(std::cmp::Ordering::Equal),
            _ => a.id.cmp(&b.id),
        };
        if asc {
            ord
        } else {
            ord.reverse()
        }
    });
}

fn email_sort(items: &mut Vec<&Email>, sort: &Option<Vec<Value>>) {
    let (prop, asc) = sort_property(sort, "receivedAt");
    items.sort_by(|a, b| {
        let ord = match prop.as_str() {
            "subject" => a.subject.cmp(&b.subject),
            "id" => a.id.cmp(&b.id),
            _ => a.received_at.cmp(&b.received_at),
        };
        if asc {
            ord
        } else {
            ord.reverse()
        }
    });
}

fn submission_sort(items: &mut Vec<&EmailSubmission>, sort: &Option<Vec<Value>>) {
    let (prop, asc) = sort_property(sort, "sendAt");
    items.sort_by(|a, b| {
        let ord = match prop.as_str() {
            "id" => a.id.cmp(&b.id),
            _ => a.send_at.cmp(&b.send_at),
        };
        if asc {
            ord
        } else {
            ord.reverse()
        }
    });
}

fn sort_property(sort: &Option<Vec<Value>>, default: &str) -> (String, bool) {
    if let Some(list) = sort {
        if let Some(first) = list.first() {
            if let Some(obj) = first.as_object() {
                let prop = obj
                    .get("property")
                    .and_then(|v| v.as_str())
                    .unwrap_or(default)
                    .to_owned();
                let asc = obj
                    .get("isAscending")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                return (prop, asc);
            }
        }
    }
    (default.to_owned(), true)
}

// ---------------------------------------------------------------------------
// Small string helpers (i;unicode-casemap is case-insensitive equality)
// ---------------------------------------------------------------------------

fn eq_casemap(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn contains_casemap(hay: &str, needle: &str) -> bool {
    hay.to_lowercase().contains(&needle.to_lowercase())
}

/// Current UTC time as an RFC 3339 / ISO 8601 timestamp, computed without
/// external date crates.
fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, mo, d) = civil_from_days((secs / 86400) + 719_163);
    let (h, mi, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Days-from-civil (Howard Hinnant) → (year, month, day).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
