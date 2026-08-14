// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! NETCONF message model (RFC 6241): capability exchange, `<rpc>`, `<rpc-reply>`,
//! the standard operations, and `<rpc-error>`.
//!
//! The model is intentionally small: only the operations this crate's server
//! implements are first-class. Any operation the server does not recognise is
//! carried through as [`Operation::Other`] so callers can inspect it.

use crate::error::{NetconfError, Result};
use crate::xml::{parse_root, Xml};

/// The NETCONF base namespace (RFC 6241 §3.1).
pub const NETCONF_BASE_NS_1_0: &str = "urn:ietf:params:xml:ns:netconf:base:1.0";
/// The NETCONF 1.1 base namespace (RFC 6241 §3.1, announced via capability).
pub const NETCONF_BASE_NS_1_1: &str = "urn:ietf:params:xml:ns:netconf:base:1.1";

/// A NETCONF datastore identifier (RFC 6241 §4.1 / §8.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DatastoreName {
    /// The running configuration.
    Running,
    /// The startup configuration.
    Startup,
    /// The candidate configuration.
    Candidate,
    /// A configuration accessed by URL.
    Url(String),
}

impl DatastoreName {
    /// Parse a datastore from a `<source>`/`<target>`/`<config-source>` element.
    pub fn from_target_element(el: &Xml) -> Result<DatastoreName> {
        if let Some(child) = el.children.first() {
            return DatastoreName::from_local_name(child.local_name(), child.text_content());
        }
        // Some servers place a <url> child with text content.
        if let Some(url) = el.child_named("url") {
            return Ok(DatastoreName::Url(url.text_content().to_string()));
        }
        Err(NetconfError::UnknownDatastore(el.name.clone()))
    }

    fn from_local_name(name: &str, text: &str) -> Result<DatastoreName> {
        match name {
            "running" => Ok(DatastoreName::Running),
            "startup" => Ok(DatastoreName::Startup),
            "candidate" => Ok(DatastoreName::Candidate),
            "url" => Ok(DatastoreName::Url(text.to_string())),
            other => Err(NetconfError::UnknownDatastore(other.to_string())),
        }
    }

    /// Render this datastore as the inner element of a `<source>`/`<target>`.
    pub fn to_target_element(&self, parent: &str) -> Xml {
        let mut el = Xml::new(parent);
        match self {
            DatastoreName::Running => el.children.push(Xml::new("running")),
            DatastoreName::Startup => el.children.push(Xml::new("startup")),
            DatastoreName::Candidate => el.children.push(Xml::new("candidate")),
            DatastoreName::Url(u) => el.children.push(Xml::new("url").text(u.clone())),
        }
        el
    }
}

/// The default-operation mode of an `<edit-config>` (RFC 6241 §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditDefaultOp {
    /// Merge (default): create/merge with existing.
    Merge,
    /// Replace the entire target with the config.
    Replace,
    /// Create only; error if the node already exists.
    Create,
    /// Delete the nodes named in the config.
    Delete,
    /// Do nothing (used to change operation of a subtree).
    None,
}

impl EditDefaultOp {
    fn from_str(s: &str) -> EditDefaultOp {
        match s {
            "replace" => EditDefaultOp::Replace,
            "create" => EditDefaultOp::Create,
            "delete" => EditDefaultOp::Delete,
            "none" => EditDefaultOp::None,
            _ => EditDefaultOp::Merge,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            EditDefaultOp::Merge => "merge",
            EditDefaultOp::Replace => "replace",
            EditDefaultOp::Create => "create",
            EditDefaultOp::Delete => "delete",
            EditDefaultOp::None => "none",
        }
    }
}

/// A NETCONF operation carried inside an `<rpc>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    /// `<get-config>`
    GetConfig {
        /// The source datastore.
        source: DatastoreName,
    },
    /// `<get>`
    Get {
        /// Optional subtree filter element (the `<filter>` body).
        filter: Option<Xml>,
    },
    /// `<edit-config>`
    EditConfig {
        /// The target datastore.
        target: DatastoreName,
        /// Default operation mode.
        default_op: EditDefaultOp,
        /// The `<config>` element (raw config subtree).
        config: Xml,
    },
    /// `<copy-config>`
    CopyConfig {
        /// The target datastore.
        target: DatastoreName,
        /// The source datastore.
        source: DatastoreName,
    },
    /// `<delete-config>`
    DeleteConfig {
        /// The target datastore.
        target: DatastoreName,
    },
    /// `<lock>`
    Lock {
        /// The target datastore.
        target: DatastoreName,
    },
    /// `<unlock>`
    Unlock {
        /// The target datastore.
        target: DatastoreName,
    },
    /// `<close-session>`
    CloseSession,
    /// `<kill-session>`
    KillSession {
        /// The session id to kill.
        session_id: u32,
    },
    /// `<discard-changes>`
    DiscardChanges,
    /// An operation this server does not model explicitly.
    Other {
        /// The operation element (carried verbatim).
        element: Xml,
    },
}

/// A parsed NETCONF `<rpc>` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rpc {
    /// The `message-id` attribute (RFC 6241 §4.1).
    pub message_id: String,
    /// The operation to perform.
    pub operation: Operation,
}

/// A NETCONF `<rpc-error>` (RFC 6241 §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError {
    /// `error-type` (transport/protocol/rpc/application).
    pub error_type: String,
    /// `error-tag` (e.g. `operation-failed`, `invalid-value`).
    pub error_tag: String,
    /// `error-severity` (`error` or `warning`).
    pub error_severity: String,
    /// `error-message` (human-readable, optional).
    pub error_message: Option<String>,
    /// `error-app-tag` (optional).
    pub error_app_tag: Option<String>,
    /// `error-path` (optional).
    pub error_path: Option<String>,
    /// `error-info` element (optional).
    pub error_info: Option<Xml>,
}

impl RpcError {
    /// Build a generic application-level error.
    pub fn application(tag: &str, message: impl Into<String>) -> RpcError {
        RpcError {
            error_type: "application".into(),
            error_tag: tag.into(),
            error_severity: "error".into(),
            error_message: Some(message.into()),
            error_app_tag: None,
            error_path: None,
            error_info: None,
        }
    }

    /// Convert into an [`RpcReply`] carrying this error.
    pub fn into_reply(self, message_id: &str) -> RpcReply {
        RpcReply {
            message_id: message_id.to_string(),
            result: ReplyResult::Error(self),
        }
    }
}

/// The payload of a `<rpc-reply>` (RFC 6241 §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyResult {
    /// `<ok/>`
    Ok,
    /// `<data>...</data>`
    Data(Xml),
    /// `<rpc-error>`
    Error(RpcError),
}

/// A parsed NETCONF `<rpc-reply>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcReply {
    /// The `message-id` (echoed from the request).
    pub message_id: String,
    /// The result payload.
    pub result: ReplyResult,
}

/// A NETCONF `<hello>` message (RFC 6241 §8.1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Hello {
    /// Announced capabilities.
    pub capabilities: Vec<String>,
    /// Server-assigned session id (server side only).
    pub session_id: Option<u32>,
}

impl Hello {
    /// The mandatory base:1.0 capability.
    pub fn base_1_0_capability() -> String {
        NETCONF_BASE_NS_1_0.to_string()
    }

    /// Build a server `<hello>` advertising the standard capabilities.
    pub fn server_default(session_id: u32) -> Hello {
        Hello {
            capabilities: vec![
                NETCONF_BASE_NS_1_0.to_string(),
                NETCONF_BASE_NS_1_1.to_string(),
                "urn:ietf:params:netconf:capability:writable-running:1.0".to_string(),
                "urn:ietf:params:netconf:capability:url:1.0".to_string(),
            ],
            session_id: Some(session_id),
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a `<hello>` message from an XML document string.
pub fn parse_hello(input: &str) -> Result<Hello> {
    let root = parse_root(input)?;
    if root.local_name() != "hello" {
        return Err(NetconfError::CapabilityExchange(format!(
            "expected <hello>, got <{}>",
            root.name
        )));
    }
    let mut hello = Hello::default();
    if let Some(caps) = root.child_named("capabilities") {
        for cap in caps.children_named("capability") {
            hello.capabilities.push(cap.text_content().to_string());
        }
    }
    if let Some(sid) = root.child_named("session-id") {
        hello.session_id = sid.text_content().trim().parse().ok();
    }
    Ok(hello)
}

/// Parse an `<rpc>` request from an XML document string.
pub fn parse_rpc(input: &str) -> Result<Rpc> {
    let root = parse_root(input)?;
    if root.local_name() != "rpc" {
        return Err(NetconfError::Rpc(format!(
            "expected <rpc>, got <{}>",
            root.name
        )));
    }
    let message_id = root
        .attribute("message-id")
        .ok_or(NetconfError::MissingMessageId)?
        .to_string();
    let op_el = root
        .children
        .first()
        .ok_or_else(|| NetconfError::Rpc("empty <rpc> with no operation".into()))?;
    let operation = parse_operation(op_el)?;
    Ok(Rpc {
        message_id,
        operation,
    })
}

fn parse_operation(el: &Xml) -> Result<Operation> {
    match el.local_name() {
        "get-config" => {
            let source = el
                .child_named("source")
                .ok_or_else(|| NetconfError::Rpc("<get-config> missing <source>".into()))?;
            Ok(Operation::GetConfig {
                source: DatastoreName::from_target_element(source)?,
            })
        }
        "get" => {
            let filter = el.child_named("filter").cloned();
            Ok(Operation::Get { filter })
        }
        "edit-config" => {
            let target = el
                .child_named("target")
                .ok_or_else(|| NetconfError::Rpc("<edit-config> missing <target>".into()))?;
            let config = el
                .child_named("config")
                .cloned()
                .ok_or_else(|| NetconfError::Rpc("<edit-config> missing <config>".into()))?;
            let default_op = el
                .child_named("default-operation")
                .map(|e| EditDefaultOp::from_str(e.text_content().trim()))
                .unwrap_or(EditDefaultOp::Merge);
            Ok(Operation::EditConfig {
                target: DatastoreName::from_target_element(target)?,
                default_op,
                config,
            })
        }
        "copy-config" => {
            let target = el
                .child_named("target")
                .ok_or_else(|| NetconfError::Rpc("<copy-config> missing <target>".into()))?;
            let source = el
                .child_named("source")
                .ok_or_else(|| NetconfError::Rpc("<copy-config> missing <source>".into()))?;
            Ok(Operation::CopyConfig {
                target: DatastoreName::from_target_element(target)?,
                source: DatastoreName::from_target_element(source)?,
            })
        }
        "delete-config" => {
            let target = el
                .child_named("target")
                .ok_or_else(|| NetconfError::Rpc("<delete-config> missing <target>".into()))?;
            Ok(Operation::DeleteConfig {
                target: DatastoreName::from_target_element(target)?,
            })
        }
        "lock" => {
            let target = el
                .child_named("target")
                .ok_or_else(|| NetconfError::Rpc("<lock> missing <target>".into()))?;
            Ok(Operation::Lock {
                target: DatastoreName::from_target_element(target)?,
            })
        }
        "unlock" => {
            let target = el
                .child_named("target")
                .ok_or_else(|| NetconfError::Rpc("<unlock> missing <target>".into()))?;
            Ok(Operation::Unlock {
                target: DatastoreName::from_target_element(target)?,
            })
        }
        "close-session" => Ok(Operation::CloseSession),
        "kill-session" => {
            let sid = el
                .child_named("session-id")
                .ok_or_else(|| NetconfError::Rpc("<kill-session> missing <session-id>".into()))?;
            let session_id = sid
                .text_content()
                .trim()
                .parse()
                .map_err(|_| NetconfError::Rpc("bad session-id".into()))?;
            Ok(Operation::KillSession { session_id })
        }
        "discard-changes" => Ok(Operation::DiscardChanges),
        _ => Ok(Operation::Other {
            element: el.clone(),
        }),
    }
}

/// Parse a `<rpc-reply>` from an XML document string.
pub fn parse_rpc_reply(input: &str) -> Result<RpcReply> {
    let root = parse_root(input)?;
    if root.local_name() != "rpc-reply" {
        return Err(NetconfError::Rpc(format!(
            "expected <rpc-reply>, got <{}>",
            root.name
        )));
    }
    let message_id = root
        .attribute("message-id")
        .ok_or(NetconfError::MissingMessageId)?
        .to_string();
    let result = if root.child_named("ok").is_some() {
        ReplyResult::Ok
    } else if let Some(data) = root.child_named("data") {
        ReplyResult::Data(data.clone())
    } else if let Some(err) = root.child_named("rpc-error") {
        ReplyResult::Error(parse_rpc_error(err))
    } else {
        return Err(NetconfError::Rpc(
            "<rpc-reply> without <ok>/<data>/<rpc-error>".into(),
        ));
    };
    Ok(RpcReply { message_id, result })
}

fn parse_rpc_error(el: &Xml) -> RpcError {
    RpcError {
        error_type: el
            .child_named("error-type")
            .map(|e| e.text_content().trim().to_string())
            .unwrap_or_else(|| "application".into()),
        error_tag: el
            .child_named("error-tag")
            .map(|e| e.text_content().trim().to_string())
            .unwrap_or_else(|| "operation-failed".into()),
        error_severity: el
            .child_named("error-severity")
            .map(|e| e.text_content().trim().to_string())
            .unwrap_or_else(|| "error".into()),
        error_message: el
            .child_named("error-message")
            .map(|e| e.text_content().to_string()),
        error_app_tag: el
            .child_named("error-app-tag")
            .map(|e| e.text_content().to_string()),
        error_path: el
            .child_named("error-path")
            .map(|e| e.text_content().to_string()),
        error_info: el.child_named("error-info").cloned(),
    }
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/// Serialize a `<hello>` message to a framed XML document.
pub fn hello_to_xml(hello: &Hello) -> Xml {
    let mut root = Xml::new("hello").attr("xmlns", NETCONF_BASE_NS_1_0);
    let mut caps = Xml::new("capabilities");
    for c in &hello.capabilities {
        caps.children.push(Xml::new("capability").text(c.clone()));
    }
    root.children.push(caps);
    if let Some(sid) = hello.session_id {
        root.children
            .push(Xml::new("session-id").text(sid.to_string()));
    }
    root
}

/// Serialize an [`Rpc`] to an `<rpc>` element.
pub fn rpc_to_xml(rpc: &Rpc) -> Xml {
    let mut root = Xml::new("rpc")
        .attr("message-id", rpc.message_id.clone())
        .attr("xmlns", NETCONF_BASE_NS_1_0);
    root.children.push(operation_to_xml(&rpc.operation));
    root
}

fn operation_to_xml(op: &Operation) -> Xml {
    match op {
        Operation::GetConfig { source } => {
            Xml::new("get-config").child(source.to_target_element("source"))
        }
        Operation::Get { filter } => match filter {
            Some(f) => Xml::new("get").child(f.clone()),
            None => Xml::new("get"),
        },
        Operation::EditConfig {
            target,
            default_op,
            config,
        } => {
            let mut el = Xml::new("edit-config");
            el.children.push(target.to_target_element("target"));
            el.children
                .push(Xml::new("default-operation").text(default_op.as_str().to_string()));
            el.children.push(config.clone());
            el
        }
        Operation::CopyConfig { target, source } => {
            let mut el = Xml::new("copy-config");
            el.children.push(target.to_target_element("target"));
            el.children.push(source.to_target_element("source"));
            el
        }
        Operation::DeleteConfig { target } => {
            Xml::new("delete-config").child(target.to_target_element("target"))
        }
        Operation::Lock { target } => Xml::new("lock").child(target.to_target_element("target")),
        Operation::Unlock { target } => {
            Xml::new("unlock").child(target.to_target_element("target"))
        }
        Operation::CloseSession => Xml::new("close-session"),
        Operation::KillSession { session_id } => {
            Xml::new("kill-session").child(Xml::new("session-id").text(session_id.to_string()))
        }
        Operation::DiscardChanges => Xml::new("discard-changes"),
        Operation::Other { element } => element.clone(),
    }
}

/// Serialize an [`RpcReply`] to an `<rpc-reply>` element.
pub fn rpc_reply_to_xml(reply: &RpcReply) -> Xml {
    let mut root = Xml::new("rpc-reply")
        .attr("message-id", reply.message_id.clone())
        .attr("xmlns", NETCONF_BASE_NS_1_0);
    match &reply.result {
        ReplyResult::Ok => root.children.push(Xml::new("ok")),
        ReplyResult::Data(data) => root.children.push(data.clone()),
        ReplyResult::Error(err) => root.children.push(rpc_error_to_xml(err)),
    }
    root
}

fn rpc_error_to_xml(err: &RpcError) -> Xml {
    let mut el = Xml::new("rpc-error");
    el.children
        .push(Xml::new("error-type").text(err.error_type.clone()));
    el.children
        .push(Xml::new("error-tag").text(err.error_tag.clone()));
    el.children
        .push(Xml::new("error-severity").text(err.error_severity.clone()));
    if let Some(m) = &err.error_message {
        el.children.push(Xml::new("error-message").text(m.clone()));
    }
    if let Some(t) = &err.error_app_tag {
        el.children.push(Xml::new("error-app-tag").text(t.clone()));
    }
    if let Some(p) = &err.error_path {
        el.children.push(Xml::new("error-path").text(p.clone()));
    }
    if let Some(info) = &err.error_info {
        el.children.push(info.clone());
    }
    el
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::to_string;

    #[test]
    fn hello_round_trips() {
        let h = Hello::server_default(42);
        let xml = to_string(&hello_to_xml(&h));
        let back = parse_hello(&xml).unwrap();
        assert_eq!(back.session_id, Some(42));
        assert!(back.capabilities.contains(&NETCONF_BASE_NS_1_0.to_string()));
    }

    #[test]
    fn get_config_rpc_round_trips() {
        let rpc = Rpc {
            message_id: "101".into(),
            operation: Operation::GetConfig {
                source: DatastoreName::Running,
            },
        };
        let xml = to_string(&rpc_to_xml(&rpc));
        let back = parse_rpc(&xml).unwrap();
        assert_eq!(back.message_id, "101");
        assert_eq!(
            back.operation,
            Operation::GetConfig {
                source: DatastoreName::Running
            }
        );
    }

    #[test]
    fn edit_config_rpc_round_trips() {
        let cfg = Xml::new("config").child(Xml::new("interface").text("eth0"));
        let rpc = Rpc {
            message_id: "7".into(),
            operation: Operation::EditConfig {
                target: DatastoreName::Candidate,
                default_op: EditDefaultOp::Replace,
                config: cfg,
            },
        };
        let xml = to_string(&rpc_to_xml(&rpc));
        let back = parse_rpc(&xml).unwrap();
        assert_eq!(back.operation, rpc.operation);
    }

    #[test]
    fn rpc_reply_ok_and_error() {
        let ok = RpcReply {
            message_id: "1".into(),
            result: ReplyResult::Ok,
        };
        let xml = to_string(&rpc_reply_to_xml(&ok));
        let back = parse_rpc_reply(&xml).unwrap();
        assert_eq!(back.result, ReplyResult::Ok);

        let err = RpcError::application("invalid-value", "bad leaf");
        let reply = err.into_reply("1");
        let xml = to_string(&rpc_reply_to_xml(&reply));
        let back = parse_rpc_reply(&xml).unwrap();
        match back.result {
            ReplyResult::Error(e) => assert_eq!(e.error_tag, "invalid-value"),
            _ => panic!("expected error"),
        }
    }

    #[test]
    fn rpc_reply_data_round_trips() {
        let data = Xml::new("data").child(Xml::new("interfaces"));
        let reply = RpcReply {
            message_id: "5".into(),
            result: ReplyResult::Data(data),
        };
        let xml = to_string(&rpc_reply_to_xml(&reply));
        let back = parse_rpc_reply(&xml).unwrap();
        match back.result {
            ReplyResult::Data(d) => assert_eq!(d.local_name(), "data"),
            _ => panic!("expected data"),
        }
    }
}
