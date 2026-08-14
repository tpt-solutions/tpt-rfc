// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! NETCONF server side: the pluggable [`Datastore`] backend, a reference
//! in-memory datastore, RPC dispatch, and the over-SSH serve loop (RFC 6242).

use std::collections::{HashMap, HashSet};

use tpt_ssh::connection::{
    encode_channel_close, encode_channel_data, encode_channel_eof, encode_channel_success,
    encode_open_confirm, parse_channel_message, ChannelMessage, DEFAULT_MAX_PACKET, DEFAULT_WINDOW,
};
use tpt_ssh::session::EncryptedConn;

use crate::error::{NetconfError, Result};
use crate::framing::encode_message;
use crate::message::{
    rpc_reply_to_xml, DatastoreName, EditDefaultOp, Hello, Operation, ReplyResult, Rpc, RpcError,
    RpcReply,
};
use crate::xml::{parse_root, to_string, Xml};

/// A pluggable configuration/state backend for the NETCONF server.
///
/// Implementations decide how datastores are stored and what operations they
/// support. The reference [`InMemoryDatastore`] is provided for tests and
/// examples; production servers plug in their own (e.g. backed by a YANG-modeled
/// tree or a real device).
pub trait Datastore {
    /// Return the current content of `source` as a `<data>` element.
    fn get_config(&mut self, source: DatastoreName) -> Result<Xml>;

    /// Return the running state as a `<data>` element (filtered if a subtree
    /// `filter` is supplied; filtering is the backend's responsibility).
    fn get(&mut self, filter: Option<&Xml>) -> Result<Xml>;

    /// Apply an `<edit-config>` to `target`.
    fn edit_config(
        &mut self,
        target: DatastoreName,
        default_op: EditDefaultOp,
        config: &Xml,
    ) -> Result<()>;

    /// Copy the content of `source` to `target`.
    fn copy_config(&mut self, target: DatastoreName, source: DatastoreName) -> Result<()>;

    /// Delete the content of `target`.
    fn delete_config(&mut self, target: DatastoreName) -> Result<()>;

    /// Acquire a lock on `target`.
    fn lock(&mut self, target: DatastoreName) -> Result<()>;

    /// Release a lock on `target`.
    fn unlock(&mut self, target: DatastoreName) -> Result<()>;

    /// Signal that the session is closing.
    fn close_session(&mut self) -> Result<()>;
}

/// A reference in-memory datastore holding `running`/`startup`/`candidate`
/// config trees and a set of held locks.
///
/// The `<edit-config>` engine here is intentionally simple (top-level
/// node merge/replace/create/delete by element name); a production backend
/// should implement the full per-node operation semantics of RFC 6241 §7.2.
#[derive(Debug, Default)]
pub struct InMemoryDatastore {
    stores: HashMap<DatastoreName, Xml>,
    locked: HashSet<DatastoreName>,
}

impl InMemoryDatastore {
    /// Create an empty datastore (running present but empty).
    pub fn new() -> InMemoryDatastore {
        let mut stores = HashMap::new();
        stores.insert(DatastoreName::Running, Xml::new("config"));
        InMemoryDatastore {
            stores,
            locked: HashSet::new(),
        }
    }

    /// Seed a datastore with a `<config>`-rooted tree (children are the config
    /// nodes). Useful for examples and tests.
    pub fn seed(&mut self, name: DatastoreName, children: Vec<Xml>) {
        let mut cfg = Xml::new("config");
        cfg.children = children;
        self.stores.insert(name, cfg);
    }

    fn data_element(store: &Xml) -> Xml {
        let mut data = Xml::new("data");
        data.children = store.children.clone();
        data
    }
}

impl Datastore for InMemoryDatastore {
    fn get_config(&mut self, source: DatastoreName) -> Result<Xml> {
        match self.stores.get(&source) {
            Some(s) => Ok(Self::data_element(s)),
            None => Err(NetconfError::UnknownDatastore(format!("{source:?}"))),
        }
    }

    fn get(&mut self, _filter: Option<&Xml>) -> Result<Xml> {
        // Subtree filtering (RFC 6241 §6) is out of scope for the reference
        // backend; the whole running datastore is returned.
        Ok(Self::data_element(
            self.stores.get(&DatastoreName::Running).unwrap(),
        ))
    }

    fn edit_config(
        &mut self,
        target: DatastoreName,
        default_op: EditDefaultOp,
        config: &Xml,
    ) -> Result<()> {
        if self.locked.contains(&target) {
            return Err(NetconfError::Rpc(
                "datastore is locked by another session".into(),
            ));
        }
        let store = self
            .stores
            .get_mut(&target)
            .ok_or_else(|| NetconfError::UnknownDatastore(format!("{target:?}")))?;
        match default_op {
            EditDefaultOp::Replace => {
                store.children = config.children.clone();
            }
            EditDefaultOp::Merge | EditDefaultOp::Create | EditDefaultOp::Delete => {
                for incoming in &config.children {
                    let local = incoming.local_name().to_string();
                    let existing = store.children.iter().position(|c| c.local_name() == local);
                    match default_op {
                        EditDefaultOp::Merge => {
                            if let Some(pos) = existing {
                                store.children[pos] = incoming.clone();
                            } else {
                                store.children.push(incoming.clone());
                            }
                        }
                        EditDefaultOp::Create => {
                            if existing.is_some() {
                                return Err(NetconfError::Rpc(format!(
                                    "create failed: node <{local}> already exists"
                                )));
                            }
                            store.children.push(incoming.clone());
                        }
                        EditDefaultOp::Delete => {
                            if let Some(pos) = existing {
                                store.children.remove(pos);
                            }
                        }
                        _ => unreachable!(),
                    }
                }
            }
            EditDefaultOp::None => {}
        }
        Ok(())
    }

    fn copy_config(&mut self, target: DatastoreName, source: DatastoreName) -> Result<()> {
        let src = self
            .stores
            .get(&source)
            .ok_or_else(|| NetconfError::UnknownDatastore(format!("{source:?}")))?
            .clone();
        if self.locked.contains(&target) {
            return Err(NetconfError::Rpc("datastore is locked".into()));
        }
        self.stores.insert(target, src);
        Ok(())
    }

    fn delete_config(&mut self, target: DatastoreName) -> Result<()> {
        match target {
            DatastoreName::Running => {
                return Err(NetconfError::Rpc(
                    "<delete-config> of the running datastore is not permitted".into(),
                ));
            }
            DatastoreName::Url(_) => {
                return Err(NetconfError::Rpc(
                    "<delete-config> of a URL datastore is not supported".into(),
                ));
            }
            _ => {}
        }
        if self.locked.contains(&target) {
            return Err(NetconfError::Rpc("datastore is locked".into()));
        }
        self.stores.insert(target, Xml::new("config"));
        Ok(())
    }

    fn lock(&mut self, target: DatastoreName) -> Result<()> {
        if self.locked.contains(&target) {
            return Err(NetconfError::Rpc(format!(
                "lock-denied: <{target:?}> already locked"
            )));
        }
        self.locked.insert(target);
        Ok(())
    }

    fn unlock(&mut self, target: DatastoreName) -> Result<()> {
        self.locked.remove(&target);
        Ok(())
    }

    fn close_session(&mut self) -> Result<()> {
        self.locked.clear();
        Ok(())
    }
}

/// Dispatch a parsed [`Rpc`] against the datastore, producing an [`RpcReply`].
pub fn dispatch<S: Datastore>(rpc: &Rpc, store: &mut S) -> Result<RpcReply> {
    let mid = rpc.message_id.clone();
    let result = match &rpc.operation {
        Operation::GetConfig { source } => match store.get_config(source.clone()) {
            Ok(data) => ReplyResult::Data(data),
            Err(e) => return Ok(error_to_reply(e, &mid)),
        },
        Operation::Get { filter } => match store.get(filter.as_ref()) {
            Ok(data) => ReplyResult::Data(data),
            Err(e) => return Ok(error_to_reply(e, &mid)),
        },
        Operation::EditConfig {
            target,
            default_op,
            config,
        } => match store.edit_config(target.clone(), *default_op, config) {
            Ok(()) => ReplyResult::Ok,
            Err(e) => return Ok(error_to_reply(e, &mid)),
        },
        Operation::CopyConfig { target, source } => {
            match store.copy_config(target.clone(), source.clone()) {
                Ok(()) => ReplyResult::Ok,
                Err(e) => return Ok(error_to_reply(e, &mid)),
            }
        }
        Operation::DeleteConfig { target } => match store.delete_config(target.clone()) {
            Ok(()) => ReplyResult::Ok,
            Err(e) => return Ok(error_to_reply(e, &mid)),
        },
        Operation::Lock { target } => match store.lock(target.clone()) {
            Ok(()) => ReplyResult::Ok,
            Err(e) => return Ok(error_to_reply(e, &mid)),
        },
        Operation::Unlock { target } => match store.unlock(target.clone()) {
            Ok(()) => ReplyResult::Ok,
            Err(e) => return Ok(error_to_reply(e, &mid)),
        },
        Operation::CloseSession => match store.close_session() {
            Ok(()) => ReplyResult::Ok,
            Err(e) => return Ok(error_to_reply(e, &mid)),
        },
        Operation::KillSession { .. } => {
            return Ok(error_to_reply(
                NetconfError::Rpc("<kill-session> is not supported by this server".into()),
                &mid,
            ));
        }
        Operation::DiscardChanges => {
            return Ok(error_to_reply(
                NetconfError::Rpc("<discard-changes> requires a candidate datastore".into()),
                &mid,
            ));
        }
        Operation::Other { element } => {
            return Ok(error_to_reply(
                NetconfError::Rpc(format!(
                    "operation <{}> is not supported",
                    element.local_name()
                )),
                &mid,
            ));
        }
    };
    Ok(RpcReply {
        message_id: mid,
        result,
    })
}

fn error_to_reply(e: NetconfError, mid: &str) -> RpcReply {
    let (error_type, tag, message) = match &e {
        NetconfError::UnknownDatastore(d) => (
            "protocol",
            "invalid-value",
            format!("unknown datastore: {d}"),
        ),
        NetconfError::XmlParse(_) => ("rpc", "malformed-message", e.to_string()),
        NetconfError::MissingMessageId => ("rpc", "missing-attribute", e.to_string()),
        NetconfError::Rpc(m) => ("application", "operation-failed", m.clone()),
        other => ("application", "operation-failed", other.to_string()),
    };
    RpcError {
        error_type: error_type.into(),
        error_tag: tag.into(),
        error_severity: "error".into(),
        error_message: Some(message),
        error_app_tag: None,
        error_path: None,
        error_info: None,
    }
    .into_reply(mid)
}

/// Serve a single NETCONF session over the given SSH connection's `netconf`
/// subsystem (RFC 6242).
///
/// `pump` moves this endpoint's pending bytes to the peer and pulls the peer's
/// bytes in; `session_id` is advertised in the server `<hello>`. The function
/// returns once the client closes the session (e.g. via `<close-session>` or
/// SSH EOF/close).
pub fn serve_ssh_session<F, S>(
    conn: &mut EncryptedConn,
    pump: &mut F,
    store: &mut S,
    session_id: u32,
) -> Result<()>
where
    F: FnMut(&mut EncryptedConn),
    S: Datastore,
{
    let mut decoder = crate::framing::FrameDecoder::new();
    let mut channel: Option<u32> = None;

    // Phase 1: channel open + subsystem request.
    loop {
        pump(conn);
        let payload = match conn.recv()? {
            Some(p) => p,
            None => continue,
        };
        match parse_channel_message(&payload)? {
            ChannelMessage::OpenSession { sender, .. } => {
                channel = Some(sender);
                conn.send(&encode_open_confirm(
                    sender,
                    0,
                    DEFAULT_WINDOW,
                    DEFAULT_MAX_PACKET,
                ));
                pump(conn);
            }
            ChannelMessage::Request {
                recipient,
                kind,
                want_reply,
                subsystem: Some(name),
                ..
            } if kind == "subsystem" && name == "netconf" => {
                if want_reply {
                    conn.send(&encode_channel_success(recipient));
                }
                pump(conn);
                break;
            }
            ChannelMessage::Close { .. } => return Ok(()),
            _ => {}
        }
    }
    let channel = channel.ok_or(NetconfError::TransportClosed)?;

    // Phase 2: capability exchange — send server hello, read client hello.
    let hello = Hello::server_default(session_id);
    let framed = encode_message(&to_string(&crate::message::hello_to_xml(&hello)));
    conn.send(&encode_channel_data(channel, &framed));
    pump(conn);

    let client_hello = read_next_message(conn, pump, &mut decoder, channel)?
        .ok_or_else(|| NetconfError::CapabilityExchange("client closed before <hello>".into()))?;
    let hello = crate::message::parse_hello(&client_hello)
        .map_err(|e| NetconfError::CapabilityExchange(e.to_string()))?;
    if !hello.capabilities.iter().any(|c| {
        c == crate::message::NETCONF_BASE_NS_1_0 || c == crate::message::NETCONF_BASE_NS_1_1
    }) {
        return Err(NetconfError::CapabilityExchange(
            "client did not advertise a NETCONF base capability".into(),
        ));
    }

    // Phase 3: RPC dispatch loop.
    loop {
        let payload = match conn.recv()? {
            Some(p) => p,
            None => {
                pump(conn);
                continue;
            }
        };
        match parse_channel_message(&payload)? {
            ChannelMessage::Data { recipient, data } if recipient == channel => {
                let messages = decoder.push(&data)?;
                for msg in messages {
                    let close = handle_message(conn, pump, channel, store, &msg)?;
                    if close {
                        conn.send(&encode_channel_eof(channel));
                        conn.send(&encode_channel_close(channel));
                        pump(conn);
                        return Ok(());
                    }
                }
            }
            ChannelMessage::Eof { recipient } if recipient == channel => {
                conn.send(&encode_channel_close(recipient));
                pump(conn);
                return Ok(());
            }
            ChannelMessage::Close { recipient } if recipient == channel => {
                return Ok(());
            }
            _ => {}
        }
    }
}

/// Returns `true` if the session should terminate after handling this message.
fn handle_message<F, S>(
    conn: &mut EncryptedConn,
    pump: &mut F,
    channel: u32,
    store: &mut S,
    msg: &str,
) -> Result<bool>
where
    F: FnMut(&mut EncryptedConn),
    S: Datastore,
{
    // A late <hello> (or any non-rpc) is ignored once capability exchange is done.
    let root = match parse_root(msg) {
        Ok(r) => r,
        Err(_) => return Ok(false),
    };
    if root.local_name() != "rpc" {
        return Ok(false);
    }
    let rpc = match crate::message::parse_rpc(msg) {
        Ok(r) => r,
        Err(e) => {
            // Cannot echo message-id without parsing; send a best-effort error.
            let reply = RpcReply {
                message_id: "0".into(),
                result: ReplyResult::Error(RpcError {
                    error_type: "rpc".into(),
                    error_tag: "malformed-message".into(),
                    error_severity: "error".into(),
                    error_message: Some(e.to_string()),
                    error_app_tag: None,
                    error_path: None,
                    error_info: None,
                }),
            };
            let framed = encode_message(&to_string(&rpc_reply_to_xml(&reply)));
            conn.send(&encode_channel_data(channel, &framed));
            pump(conn);
            return Ok(false);
        }
    };
    let close = matches!(rpc.operation, Operation::CloseSession);
    let reply = dispatch(&rpc, store)?;
    let framed = encode_message(&to_string(&rpc_reply_to_xml(&reply)));
    conn.send(&encode_channel_data(channel, &framed));
    pump(conn);
    Ok(close)
}

/// Read the next complete NETCONF message from the SSH channel, or `None` if
/// the peer ended the session.
fn read_next_message<F: FnMut(&mut EncryptedConn)>(
    conn: &mut EncryptedConn,
    pump: &mut F,
    decoder: &mut crate::framing::FrameDecoder,
    channel: u32,
) -> Result<Option<String>> {
    loop {
        pump(conn);
        let payload = match conn.recv()? {
            Some(p) => p,
            None => continue,
        };
        match parse_channel_message(&payload)? {
            ChannelMessage::Data { recipient, data } if recipient == channel => {
                if let Some(msg) = decoder.push(&data)?.into_iter().next() {
                    return Ok(Some(msg));
                }
            }
            ChannelMessage::Eof { recipient } if recipient == channel => return Ok(None),
            ChannelMessage::Close { recipient } if recipient == channel => return Ok(None),
            _ => {}
        }
    }
}
