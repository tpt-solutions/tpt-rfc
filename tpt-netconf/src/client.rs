// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A minimal NETCONF client over the SSH `netconf` subsystem (RFC 6242).
//!
//! This is provided primarily for integration testing and examples; the phase's
//! primary deliverable is the server. The client mirrors the server's
//! transport model: it owns the framing and capability exchange and exposes a
//! single `rpc(...)` call.

use tpt_ssh::connection::{
    encode_channel_close, encode_channel_data, encode_channel_eof, encode_open_session,
    encode_request_subsystem, parse_channel_message, ChannelMessage, DEFAULT_MAX_PACKET,
    DEFAULT_WINDOW,
};
use tpt_ssh::session::EncryptedConn;

use crate::error::{NetconfError, Result};
use crate::framing::encode_message;
use crate::message::{
    hello_to_xml, parse_hello, parse_rpc_reply, rpc_to_xml, Hello, Operation, Rpc, RpcReply,
};
use crate::xml::to_string;

/// A NETCONF client session bound to one SSH `netconf` subsystem.
pub struct NetconfSshClient {
    channel: u32,
    next_id: u32,
    decoder: crate::framing::FrameDecoder,
}

impl NetconfSshClient {
    /// Open a session channel, request the `netconf` subsystem, and perform the
    /// `<hello>` capability exchange.
    pub fn connect<F>(conn: &mut EncryptedConn, pump: &mut F) -> Result<NetconfSshClient>
    where
        F: FnMut(&mut EncryptedConn),
    {
        conn.send(&encode_open_session(0, DEFAULT_WINDOW, DEFAULT_MAX_PACKET));
        pump(conn);
        let channel = loop {
            pump(conn);
            match conn.recv()? {
                Some(payload) => match parse_channel_message(&payload)? {
                    ChannelMessage::OpenConfirm { recipient, .. } => break recipient,
                    ChannelMessage::OpenFailure { reason, desc, .. } => {
                        return Err(NetconfError::CapabilityExchange(format!(
                            "channel open failed: {reason} {desc}"
                        )));
                    }
                    _ => {}
                },
                None => continue,
            }
        };

        conn.send(&encode_request_subsystem(channel, "netconf", true));
        pump(conn);
        loop {
            pump(conn);
            match conn.recv()? {
                Some(payload) => match parse_channel_message(&payload)? {
                    ChannelMessage::Success { recipient } if recipient == channel => break,
                    ChannelMessage::Failure { recipient } if recipient == channel => {
                        return Err(NetconfError::CapabilityExchange(
                            "server rejected the netconf subsystem request".into(),
                        ));
                    }
                    _ => {}
                },
                None => continue,
            }
        }

        let mut client = NetconfSshClient {
            channel,
            next_id: 1,
            decoder: crate::framing::FrameDecoder::new(),
        };
        let hello = client.read_message(conn, pump)?.ok_or_else(|| {
            NetconfError::CapabilityExchange("server closed before <hello>".into())
        })?;
        let h = parse_hello(&hello).map_err(|e| NetconfError::CapabilityExchange(e.to_string()))?;
        if !h.capabilities.iter().any(|c| {
            c == crate::message::NETCONF_BASE_NS_1_0 || c == crate::message::NETCONF_BASE_NS_1_1
        }) {
            return Err(NetconfError::CapabilityExchange(
                "server did not advertise a NETCONF base capability".into(),
            ));
        }

        // Send our own <hello> (RFC 6241 §8.1 requires both peers to exchange
        // capabilities before any <rpc>).
        let client_hello = Hello {
            capabilities: vec![crate::message::NETCONF_BASE_NS_1_0.to_string()],
            session_id: None,
        };
        let framed = encode_message(&to_string(&hello_to_xml(&client_hello)));
        conn.send(&encode_channel_data(client.channel, &framed));
        pump(conn);

        Ok(client)
    }

    /// Send a single RPC operation and return the matching `<rpc-reply>`.
    pub fn rpc<F>(
        &mut self,
        conn: &mut EncryptedConn,
        pump: &mut F,
        operation: Operation,
    ) -> Result<RpcReply>
    where
        F: FnMut(&mut EncryptedConn),
    {
        let id = self.next_id;
        self.next_id += 1;
        let rpc = Rpc {
            message_id: id.to_string(),
            operation,
        };
        let framed = encode_message(&to_string(&rpc_to_xml(&rpc)));
        conn.send(&encode_channel_data(self.channel, &framed));
        pump(conn);

        let expected = id.to_string();
        loop {
            let msg = self
                .read_message(conn, pump)?
                .ok_or(NetconfError::TransportClosed)?;
            if let Ok(reply) = parse_rpc_reply(&msg) {
                if reply.message_id == expected {
                    return Ok(reply);
                }
            }
            // Otherwise keep reading (a stray message from the server).
        }
    }

    /// Send `<close-session>` and close the SSH channel cleanly.
    pub fn close<F>(&mut self, conn: &mut EncryptedConn, pump: &mut F) -> Result<()>
    where
        F: FnMut(&mut EncryptedConn),
    {
        let _ = self.rpc(conn, pump, Operation::CloseSession)?;
        conn.send(&encode_channel_eof(self.channel));
        conn.send(&encode_channel_close(self.channel));
        pump(conn);
        Ok(())
    }

    /// Read the next complete NETCONF message from the channel, or `None` if the
    /// peer ended the session.
    fn read_message<F>(&mut self, conn: &mut EncryptedConn, pump: &mut F) -> Result<Option<String>>
    where
        F: FnMut(&mut EncryptedConn),
    {
        loop {
            pump(conn);
            match conn.recv()? {
                Some(payload) => match parse_channel_message(&payload)? {
                    ChannelMessage::Data { recipient, data } if recipient == self.channel => {
                        if let Some(msg) = self.decoder.push(&data)?.into_iter().next() {
                            return Ok(Some(msg));
                        }
                    }
                    ChannelMessage::Eof { recipient } if recipient == self.channel => {
                        return Ok(None)
                    }
                    ChannelMessage::Close { recipient } if recipient == self.channel => {
                        return Ok(None)
                    }
                    _ => {}
                },
                None => continue,
            }
        }
    }
}

/// Build a server `<hello>` XML string (convenience for examples/logging).
pub fn server_hello_string(session_id: u32) -> String {
    to_string(&hello_to_xml(&crate::message::Hello::server_default(
        session_id,
    )))
}
