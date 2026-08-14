// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Core JMAP data types and the request/response envelope (RFC 8620 §1.2, §3.2,
//! §3.3).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::RequestError;

/// A JMAP object/account identifier (RFC 8620 §1.2: "Id — a String of any
/// characters except those prohibited by the type").
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Id(pub String);

impl Id {
    /// Construct an id from any string-like value.
    pub fn new<S: Into<String>>(s: S) -> Self {
        Id(s.into())
    }

    /// The id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for Id {
    fn from(s: &str) -> Self {
        Id(s.to_owned())
    }
}

impl From<String> for Id {
    fn from(s: String) -> Self {
        Id(s)
    }
}

impl From<u64> for Id {
    fn from(n: u64) -> Self {
        Id(n.to_string())
    }
}

/// A single method invocation: the 3-tuple `[methodName, args, clientId]`
/// (RFC 8620 §3.2). `args` is the method-specific argument object.
#[derive(Clone, Debug)]
pub struct Invocation {
    /// The method name, e.g. `"Mailbox/get"`.
    pub name: String,
    /// The method arguments as a JSON object.
    pub args: Value,
    /// The client-supplied identifier for correlating the response.
    pub client_id: String,
}

impl Invocation {
    /// Build a successful method response invocation. `args` must serialize to
    /// a JSON object.
    pub fn result<S: Into<String>>(name: S, client_id: S, args: &impl Serialize) -> Self {
        Invocation {
            name: name.into(),
            args: serde_json::to_value(args).expect("method result must be serializable"),
            client_id: client_id.into(),
        }
    }

    /// Build an error method response invocation (RFC 8620 §3.5).
    pub fn error(client_id: &str, err: &crate::error::MethodError) -> Self {
        Invocation {
            name: "error".to_owned(),
            args: serde_json::to_value(err).expect("error must be serializable"),
            client_id: client_id.to_owned(),
        }
    }
}

impl Serialize for Invocation {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(3))?;
        seq.serialize_element(&self.name)?;
        seq.serialize_element(&self.args)?;
        seq.serialize_element(&self.client_id)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Invocation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = <[Value; 3]>::deserialize(deserializer)?;
        let name = raw[0]
            .as_str()
            .ok_or_else(|| serde::de::Error::custom("method name must be a string"))?
            .to_owned();
        let client_id = raw[2]
            .as_str()
            .ok_or_else(|| serde::de::Error::custom("client id must be a string"))?
            .to_owned();
        Ok(Invocation {
            name,
            args: raw[1].clone(),
            client_id,
        })
    }
}

/// A JMAP Request object (RFC 8620 §3.2).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Request {
    /// The capability URNs required for every method in `method_calls`.
    #[serde(default)]
    pub using: Vec<String>,
    /// The ordered list of method calls to perform.
    #[serde(default, rename = "methodCalls")]
    pub method_calls: Vec<Invocation>,
    /// Maps client-generated creation ids to server-assigned ids (RFC 8620 §3.2).
    #[serde(
        default,
        rename = "createdIds",
        skip_serializing_if = "Option::is_none"
    )]
    pub created_ids: Option<Map<String, Value>>,
    /// Opaque blob passed through from a previous response (RFC 8620 §3.2).
    #[serde(
        default,
        rename = "secondaryDevices",
        skip_serializing_if = "Option::is_none"
    )]
    pub secondary_devices: Option<Value>,
}

/// A JMAP Response object (RFC 8620 §3.3).
#[derive(Clone, Debug, Serialize)]
pub struct Response {
    /// Ordered method responses, matching `method_calls` order.
    #[serde(rename = "methodResponses")]
    pub method_responses: Vec<Invocation>,
    /// Opaque server state string.
    #[serde(rename = "sessionState")]
    pub session_state: String,
    /// Optional createdIds map returned to the client.
    #[serde(rename = "createdIds", skip_serializing_if = "Option::is_none")]
    pub created_ids: Option<Map<String, Value>>,
}

impl Response {
    /// Parse a JSON request value into a `Request`, returning a
    /// request-level error (RFC 8620 §3.7) when malformed.
    pub fn parse_request(value: Value) -> std::result::Result<Request, RequestError> {
        match value {
            Value::Object(_) => serde_json::from_value(value.clone())
                .map_err(|e| RequestError::NotRequest {
                    detail: e.to_string(),
                })
                .and_then(|req: Request| {
                    if req.method_calls.is_empty() {
                        Err(RequestError::NotRequest {
                            detail: "methodCalls must not be empty".to_owned(),
                        })
                    } else {
                        Ok(req)
                    }
                }),
            _ => Err(RequestError::NotJSON),
        }
    }
}

/// Well-known JMAP capability URNs.
pub mod capability {
    /// JMAP core (RFC 8620 §4).
    pub const CORE: &str = "urn:ietf:params:jmap:core";
    /// JMAP Mail (RFC 8621 §1.2).
    pub const MAIL: &str = "urn:ietf:params:jmap:mail";
}

/// Require that every capability in `using` is supported by the server.
pub(crate) fn check_capabilities(
    using: &[String],
    supported: &[&str],
) -> std::result::Result<(), String> {
    for cap in using {
        if !supported.contains(&cap.as_str()) {
            return Err(cap.clone());
        }
    }
    Ok(())
}
