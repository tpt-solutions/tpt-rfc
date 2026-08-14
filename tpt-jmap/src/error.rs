// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! JMAP error model (RFC 8620 §3.5–§3.7).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A method-level error (RFC 8620 §3.5). Serializes to the standard error
/// object `{ "type": …, "status": …, "detail": …, … }`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MethodError {
    /// The machine-readable error type (e.g. `"invalidArguments"`).
    #[serde(rename = "type")]
    pub type_: String,
    /// The HTTP status code associated with the error, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// For `invalidArguments`: the argument properties that were invalid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<Vec<String>>,
    /// For `invalidResultReference`: the offending reference string.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "reference")]
    pub reference: Option<String>,
}

impl MethodError {
    /// `unknownMethod` — the method name is not recognised (RFC 8620 §3.6).
    pub fn unknown_method(name: &str) -> Self {
        MethodError {
            type_: "unknownMethod".to_owned(),
            status: Some(400),
            detail: Some(format!("Unknown method: {name}")),
            properties: None,
            reference: None,
        }
    }

    /// `invalidArguments` — one or more arguments were invalid (RFC 8620 §3.6).
    pub fn invalid_arguments(detail: &str, properties: Vec<&str>) -> Self {
        MethodError {
            type_: "invalidArguments".to_owned(),
            status: Some(400),
            detail: Some(detail.to_owned()),
            properties: Some(properties.into_iter().map(|s| s.to_owned()).collect()),
            reference: None,
        }
    }

    /// `invalidResultReference` — a result reference could not be resolved
    /// (RFC 8620 §3.6).
    pub fn invalid_result_reference(reference: &str, detail: &str) -> Self {
        MethodError {
            type_: "invalidResultReference".to_owned(),
            status: Some(400),
            detail: Some(detail.to_owned()),
            properties: None,
            reference: Some(reference.to_owned()),
        }
    }

    /// `accountNotFound` (RFC 8620 §3.6).
    pub fn account_not_found(account_id: &str) -> Self {
        MethodError {
            type_: "accountNotFound".to_owned(),
            status: Some(400),
            detail: Some(format!("No such account: {account_id}")),
            properties: None,
            reference: None,
        }
    }

    /// `forbidden` (RFC 8620 §3.6).
    pub fn forbidden(detail: &str) -> Self {
        MethodError {
            type_: "forbidden".to_owned(),
            status: Some(403),
            detail: Some(detail.to_owned()),
            properties: None,
            reference: None,
        }
    }

    /// `notFound` — the requested ids were not found (RFC 8621).
    pub fn not_found() -> Self {
        MethodError {
            type_: "notFound".to_owned(),
            status: Some(404),
            detail: Some("Some requested ids were not found".to_owned()),
            properties: None,
            reference: None,
        }
    }

    /// `serverFail` (RFC 8620 §3.6).
    pub fn server_fail(detail: &str) -> Self {
        MethodError {
            type_: "serverFail".to_owned(),
            status: Some(500),
            detail: Some(detail.to_owned()),
            properties: None,
            reference: None,
        }
    }
}

/// A request-level error (RFC 8620 §3.7), returned as a top-level error
/// response rather than inside `methodResponses`.
#[derive(Clone, Debug, Serialize)]
pub enum RequestError {
    /// The request body was not valid JSON.
    NotJSON,
    /// The JSON was valid but did not conform to the Request structure.
    NotRequest { detail: String },
    /// A capability in `using` is not supported by the server.
    UnknownCapability { capability: String },
}

impl RequestError {
    /// Render the request-level error as a full JMAP response JSON value
    /// (RFC 8620 §3.7: the `methodResponses` array contains a single
    /// `["error", {…}, "#0"]` invocation, plus a `sessionState`).
    pub fn to_response(&self) -> Value {
        let (type_, status, detail) = match self {
            RequestError::NotJSON => (
                "notJSON",
                400u16,
                "The request did not parse as JSON".to_owned(),
            ),
            RequestError::NotRequest { detail } => (
                "notRequest",
                400u16,
                format!("The request was not a valid Request object: {detail}"),
            ),
            RequestError::UnknownCapability { capability } => (
                "unknownCapability",
                400u16,
                format!("Unsupported capability: {capability}"),
            ),
        };
        let args = serde_json::json!({
            "type": type_,
            "status": status,
            "detail": detail,
        });
        serde_json::json!({
            "methodResponses": [["error", args, "#0"]],
            "sessionState": "",
        })
    }
}
