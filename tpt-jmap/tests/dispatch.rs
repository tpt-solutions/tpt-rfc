// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Core dispatch, result references, and error handling (RFC 8620 §3).

use tpt_jmap::{Dispatcher, MemoryMailStore};

fn dispatch_json(store: MemoryMailStore, req: serde_json::Value) -> serde_json::Value {
    let d = Dispatcher::new(store);
    match d.dispatch(req) {
        Ok(resp) => serde_json::to_value(resp).unwrap(),
        Err(err) => err,
    }
}

#[test]
fn not_request_when_method_calls_empty() {
    let store = MemoryMailStore::new();
    let req = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core"],
        "methodCalls": []
    });
    let err = dispatch_json(store, req);
    assert_eq!(err["methodResponses"][0][0], "error");
    assert_eq!(err["methodResponses"][0][1]["type"], "notRequest");
}

#[test]
fn not_json() {
    let store = MemoryMailStore::new();
    let err = dispatch_json(store, serde_json::json!(123));
    assert_eq!(err["methodResponses"][0][1]["type"], "notJSON");
}

#[test]
fn unknown_capability() {
    let store = MemoryMailStore::new();
    let req = serde_json::json!({
        "using": ["urn:ietf:params:jmap:does-not-exist"],
        "methodCalls": [["Mailbox/get", {"accountId": "account1"}, "a1"]]
    });
    let err = dispatch_json(store, req);
    assert_eq!(err["methodResponses"][0][1]["type"], "unknownCapability");
}

#[test]
fn unknown_method_is_a_method_error() {
    let store = MemoryMailStore::new();
    let req = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core"],
        "methodCalls": [["Frobnicate/do", {"accountId": "account1"}, "a1"]]
    });
    let resp = dispatch_json(store, req);
    assert_eq!(resp["methodResponses"][0][0], "error");
    assert_eq!(resp["methodResponses"][0][1]["type"], "unknownMethod");
}

#[test]
fn account_not_found() {
    let store = MemoryMailStore::new();
    let req = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core"],
        "methodCalls": [["Mailbox/get", {"accountId": "nope"}, "a1"]]
    });
    let resp = dispatch_json(store, req);
    assert_eq!(resp["methodResponses"][0][1]["type"], "accountNotFound");
}

#[test]
fn result_reference_resolution() {
    // Mirrors RFC 8620 §3.4.1: an Email references a just-created Mailbox id.
    let store = MemoryMailStore::new();
    let req = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [
            ["Mailbox/set", {
                "accountId": "account1",
                "create": { "1": { "name": "A new mailbox" } }
            }, "MailboxSet1"],
            ["Email/set", {
                "accountId": "account1",
                "create": {
                    "#1": {
                        "mailboxIds": { "1": "#MailboxSet1/created/1/id" },
                        "subject": "A new email"
                    }
                }
            }, "EmailSet1"]
        ]
    });
    let resp = dispatch_json(store, req);

    let mailbox_created = &resp["methodResponses"][0][1]["created"]["1"];
    assert_eq!(mailbox_created["name"], "A new mailbox");
    let new_mailbox_id = mailbox_created["id"].as_str().unwrap();

    let email_created = &resp["methodResponses"][1][1]["created"]["#1"];
    assert_eq!(
        email_created["mailboxIds"]["1"],
        serde_json::json!(new_mailbox_id)
    );
    assert_eq!(email_created["subject"], "A new email");
}

#[test]
fn invalid_result_reference_is_reported() {
    let store = MemoryMailStore::new();
    let req = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [
            ["Email/set", {
                "accountId": "account1",
                "create": { "1": { "mailboxIds": { "1": "#NoSuchCall/created/1/id" }, "subject": "x" } }
            }, "e1"]
        ]
    });
    let resp = dispatch_json(store, req);
    assert_eq!(resp["methodResponses"][0][0], "error");
    assert_eq!(
        resp["methodResponses"][0][1]["type"],
        "invalidResultReference"
    );
}

#[test]
fn invalid_arguments_reported_in_not_created() {
    let store = MemoryMailStore::new();
    let req = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [
            ["Email/set", {
                "accountId": "account1",
                "create": { "1": { "subject": "x" } }  // missing mailboxIds
            }, "e1"]
        ]
    });
    let resp = dispatch_json(store, req);
    assert_eq!(
        resp["methodResponses"][0][1]["notCreated"]["1"]["type"],
        "invalidArguments"
    );
}
