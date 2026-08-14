// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Mail data model operations against `MemoryMailStore` (RFC 8621).

use serde_json::{json, Map, Value};
use tpt_jmap::{Dispatcher, Email, Id, Mailbox, MemoryMailStore};

fn dispatch(store: MemoryMailStore, req: Value) -> Value {
    let d = Dispatcher::new(store);
    match d.dispatch(req) {
        Ok(resp) => serde_json::to_value(resp).unwrap(),
        Err(err) => err,
    }
}

fn seeded_store() -> MemoryMailStore {
    let mut store = MemoryMailStore::new();
    let mut inbox = Mailbox::new(Id::new("M1"), "Inbox");
    inbox.role = Some("inbox".to_owned());
    inbox.sort_order = 1.0;
    store.seed_mailbox(inbox);

    let mut archive = Mailbox::new(Id::new("M2"), "Archive");
    archive.role = Some("archive".to_owned());
    archive.sort_order = 2.0;
    store.seed_mailbox(archive);

    let known = Mailbox::new(Id::new("MK"), "Known");
    store.seed_mailbox(known);
    let email = Email {
        id: Id::new("E1"),
        blob_id: Id::new("B1"),
        thread_id: Some(Id::new("T1")),
        mailbox_ids: {
            let mut m = Map::new();
            m.insert("M1".to_owned(), Value::Bool(true));
            m
        },
        keywords: Map::new(),
        size: 42,
        received_at: "2026-01-01T00:00:00Z".to_owned(),
        subject: Some("Hello".to_owned()),
        from: None,
        to: None,
        cc: None,
        bcc: None,
        reply_to: None,
        has_attachment: false,
        preview: None,
        headers: vec![],
    };
    store.seed_email(email);
    store
}

#[test]
fn mailbox_get_by_id() {
    let store = seeded_store();
    let resp = dispatch(
        store,
        json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            "methodCalls": [["Mailbox/get", {"accountId": "account1", "ids": ["M1"]}, "a1"]]
        }),
    );
    let list = &resp["methodResponses"][0][1]["list"];
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["id"], "M1");
    assert_eq!(list[0]["name"], "Inbox");
    assert_eq!(list[0]["role"], "inbox");
}

#[test]
fn mailbox_get_property_filter() {
    let store = seeded_store();
    let resp = dispatch(
        store,
        json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            "methodCalls": [["Mailbox/get", {"accountId": "account1", "properties": ["id", "name"]}, "a1"]]
        }),
    );
    let list = &resp["methodResponses"][0][1]["list"];
    assert_eq!(list.as_array().unwrap().len(), 3);
    assert!(list[0].get("role").is_none());
    assert!(list[0].get("name").is_some());
}

#[test]
fn mailbox_query_filter_and_sort() {
    let store = seeded_store();
    let resp = dispatch(
        store,
        json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            "methodCalls": [["Mailbox/query", {
                "accountId": "account1",
                "filter": { "name": "archive" },
                "sort": [{"property": "name", "isAscending": true}]
            }, "q1"]]
        }),
    );
    let ids = &resp["methodResponses"][0][1]["ids"];
    assert_eq!(ids, &json!(["M2"]));
}

#[test]
fn mailbox_set_create_update_destroy() {
    // All steps in one request: create, rename (via result reference to the
    // created id), read back, then destroy. State persists across method calls
    // within a single request.
    let store = seeded_store();
    let resp = dispatch(
        store,
        json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            "methodCalls": [
                ["Mailbox/set", {
                    "accountId": "account1",
                    "create": { "c1": { "name": "Draft" } }
                }, "s1"],
                ["Mailbox/set", {
                    "accountId": "account1",
                    "update": { "#s1/created/c1/id": { "name": "Renamed" } }
                }, "u1"],
                ["Mailbox/get", {
                    "accountId": "account1",
                    "ids": ["#s1/created/c1/id"]
                }, "g1"],
                ["Mailbox/set", {
                    "accountId": "account1",
                    "destroy": ["#s1/created/c1/id"]
                }, "d1"]
            ]
        }),
    );
    let created = &resp["methodResponses"][0][1]["created"]["c1"];
    assert_eq!(created["name"], "Draft");
    assert_eq!(resp["methodResponses"][1][1]["updated"][0], created["id"]);
    assert_eq!(resp["methodResponses"][2][1]["list"][0]["name"], "Renamed");
    assert_eq!(resp["methodResponses"][3][1]["destroyed"][0], created["id"]);
}

#[test]
fn mailbox_changes_since_state() {
    // Create then query changes within one request (state persists).
    let store = seeded_store();
    let resp = dispatch(
        store,
        json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            "methodCalls": [
                ["Mailbox/set", {
                    "accountId": "account1",
                    "create": { "c1": { "name": "X" } }
                }, "s1"],
                ["Mailbox/changes", {
                    "accountId": "account1",
                    "sinceState": "0"
                }, "c1"]
            ]
        }),
    );
    let new_state = resp["methodResponses"][0][1]["newState"]
        .as_str()
        .unwrap()
        .to_owned();
    let ch = &resp["methodResponses"][1][1];
    assert!(!ch["created"].as_array().unwrap().is_empty());
    assert_eq!(ch["newState"], new_state);
}

#[test]
fn email_get_and_query() {
    let store = seeded_store();
    let resp = dispatch(
        store,
        json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            "methodCalls": [
                ["Email/get", {"accountId": "account1", "ids": ["E1"]}, "g1"],
                ["Email/query", {"accountId": "account1", "filter": { "inMailbox": "M1" }, "calculateTotal": true}, "q1"]
            ]
        }),
    );
    assert_eq!(resp["methodResponses"][0][1]["list"][0]["subject"], "Hello");
    assert_eq!(resp["methodResponses"][1][1]["ids"], json!(["E1"]));
    assert_eq!(resp["methodResponses"][1][1]["total"], 1);
}

#[test]
fn thread_get_not_found_when_absent() {
    let store = seeded_store();
    let resp = dispatch(
        store,
        json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            "methodCalls": [["Thread/get", {"accountId": "account1", "ids": ["T1"]}, "t1"]]
        }),
    );
    assert_eq!(resp["methodResponses"][0][1]["notFound"][0], "T1");
}

#[test]
fn email_submission_create_then_cancel() {
    // Single request: create a submission, then cancel it via a result
    // reference to the freshly created id (RFC 8620 §3.4).
    let store = seeded_store();
    let resp = dispatch(
        store,
        json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            "methodCalls": [
                ["EmailSubmission/set", {
                    "accountId": "account1",
                    "create": { "1": { "identityId": "I1", "emailId": "E1" } }
                }, "s1"],
                ["EmailSubmission/set", {
                    "accountId": "account1",
                    "update": { "#s1/created/1/id": { "undoStatus": "canceled" } }
                }, "s2"],
                ["EmailSubmission/get", {
                    "accountId": "account1",
                    "ids": ["#s1/created/1/id"]
                }, "g1"]
            ]
        }),
    );
    let create = &resp["methodResponses"][0][1]["created"]["1"];
    assert_eq!(create["undoStatus"], "pending");
    let sub_id = create["id"].as_str().unwrap().to_owned();

    let cancel = &resp["methodResponses"][1][1];
    assert_eq!(cancel["updated"][0], sub_id);
    // Read back within the same request to confirm the cancellation persisted.
    assert_eq!(
        resp["methodResponses"][2][1]["list"][0]["undoStatus"],
        "canceled"
    );
}
