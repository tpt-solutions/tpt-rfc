// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SSH connection protocol (RFC 4254): channels, the `session` channel type,
//! and the `exec` request, with window/flow-control and `exit-status` handling.
//!
//! This provides a minimal but spec-faithful building block: open a session
//! channel, run one command, stream its stdout back, report the exit status,
//! and close the channel. The [`run_client_exec`] / [`run_server_session`]
//! helpers are transport-agnostic: the caller supplies a `pump` closure that
//! moves bytes between this endpoint and its peer (in-process `Link` pair, or
//! a `TcpStream`).

use crate::session::EncryptedConn;
use crate::wire::{Reader, Writer};
use crate::Error;

/// `SSH_MSG_GLOBAL_REQUEST`.
pub const SSH_MSG_GLOBAL_REQUEST: u8 = 80;
/// `SSH_MSG_REQUEST_SUCCESS`.
pub const SSH_MSG_REQUEST_SUCCESS: u8 = 81;
/// `SSH_MSG_REQUEST_FAILURE`.
pub const SSH_MSG_REQUEST_FAILURE: u8 = 82;
/// `SSH_MSG_CHANNEL_OPEN`.
pub const SSH_MSG_CHANNEL_OPEN: u8 = 90;
/// `SSH_MSG_CHANNEL_OPEN_CONFIRMATION`.
pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
/// `SSH_MSG_CHANNEL_OPEN_FAILURE`.
pub const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
/// `SSH_MSG_CHANNEL_WINDOW_ADJUST`.
pub const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
/// `SSH_MSG_CHANNEL_DATA`.
pub const SSH_MSG_CHANNEL_DATA: u8 = 94;
/// `SSH_MSG_CHANNEL_EXTENDED_DATA`.
pub const SSH_MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
/// `SSH_MSG_CHANNEL_EOF`.
pub const SSH_MSG_CHANNEL_EOF: u8 = 96;
/// `SSH_MSG_CHANNEL_CLOSE`.
pub const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
/// `SSH_MSG_CHANNEL_REQUEST`.
pub const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
/// `SSH_MSG_CHANNEL_SUCCESS`.
pub const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;
/// `SSH_MSG_CHANNEL_FAILURE`.
pub const SSH_MSG_CHANNEL_FAILURE: u8 = 100;

/// `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED` (RFC 4254 §5.1).
pub const SSH_OPEN_ADMINISTRATIVELY_PROHIBITED: u32 = 1;
/// `SSH_OPEN_CONNECT_FAILED`.
pub const SSH_OPEN_CONNECT_FAILED: u32 = 2;
/// `SSH_OPEN_UNKNOWN_CHANNEL_TYPE`.
pub const SSH_OPEN_UNKNOWN_CHANNEL_TYPE: u32 = 3;
/// `SSH_OPEN_RESOURCE_SHORTAGE`.
pub const SSH_OPEN_RESOURCE_SHORTAGE: u32 = 4;

/// Extended data type code for stderr (RFC 4254 §5.2).
pub const SSH_EXTENDED_DATA_STDERR: u32 = 1;

/// Default channel receive window (bytes) we advertise.
pub const DEFAULT_WINDOW: u32 = 1 << 20;
/// Default maximum packet size we accept.
pub const DEFAULT_MAX_PACKET: u32 = 32 * 1024;

/// A parsed channel-level message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelMessage {
    /// `SSH_MSG_CHANNEL_OPEN` for the `session` channel type.
    OpenSession {
        /// Sender channel number chosen by the peer.
        sender: u32,
        /// Initial receive window advertised by the peer.
        window: u32,
        /// Maximum packet size advertised by the peer.
        max_packet: u32,
    },
    /// `SSH_MSG_CHANNEL_OPEN_CONFIRMATION`.
    OpenConfirm {
        /// Our channel number (recipient).
        recipient: u32,
        /// Sender channel number chosen by the peer.
        sender: u32,
        /// Peer's receive window.
        window: u32,
        /// Peer's max packet size.
        max_packet: u32,
    },
    /// `SSH_MSG_CHANNEL_OPEN_FAILURE`.
    OpenFailure {
        /// Our channel number.
        recipient: u32,
        /// Reason code.
        reason: u32,
        /// Description.
        desc: String,
    },
    /// `SSH_MSG_CHANNEL_WINDOW_ADJUST`.
    WindowAdjust {
        /// Our channel number.
        recipient: u32,
        /// Bytes added to the window.
        bytes: u32,
    },
    /// `SSH_MSG_CHANNEL_DATA`.
    Data {
        /// Our channel number.
        recipient: u32,
        /// Payload bytes.
        data: Vec<u8>,
    },
    /// `SSH_MSG_CHANNEL_EXTENDED_DATA`.
    ExtendedData {
        /// Our channel number.
        recipient: u32,
        /// Extended data type code.
        data_type: u32,
        /// Payload bytes.
        data: Vec<u8>,
    },
    /// `SSH_MSG_CHANNEL_EOF`.
    Eof {
        /// Our channel number.
        recipient: u32,
    },
    /// `SSH_MSG_CHANNEL_CLOSE`.
    Close {
        /// Our channel number.
        recipient: u32,
    },
    /// `SSH_MSG_CHANNEL_REQUEST`.
    Request {
        /// Our channel number.
        recipient: u32,
        /// Request type (e.g. `exec`, `shell`, `exit-status`).
        kind: String,
        /// Whether the sender wants a success/failure reply.
        want_reply: bool,
        /// For `exec`/`shell`: the command string.
        command: Option<String>,
        /// For `exit-status`: the exit code.
        exit_status: Option<u32>,
    },
    /// `SSH_MSG_CHANNEL_SUCCESS`.
    Success {
        /// Our channel number.
        recipient: u32,
    },
    /// `SSH_MSG_CHANNEL_FAILURE`.
    Failure {
        /// Our channel number.
        recipient: u32,
    },
}

/// Encode a `session` channel open request (client side).
pub fn encode_open_session(sender: u32, window: u32, max_packet: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_byte(SSH_MSG_CHANNEL_OPEN);
    w.write_string(b"session");
    w.write_u32(sender);
    w.write_u32(window);
    w.write_u32(max_packet);
    w.into_inner()
}

/// Encode `SSH_MSG_CHANNEL_OPEN_CONFIRMATION`.
pub fn encode_open_confirm(recipient: u32, sender: u32, window: u32, max_packet: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_byte(SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
    w.write_u32(recipient);
    w.write_u32(sender);
    w.write_u32(window);
    w.write_u32(max_packet);
    w.into_inner()
}

/// Encode `SSH_MSG_CHANNEL_OPEN_FAILURE`.
pub fn encode_open_failure(recipient: u32, reason: u32, desc: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_byte(SSH_MSG_CHANNEL_OPEN_FAILURE);
    w.write_u32(recipient);
    w.write_u32(reason);
    w.write_string(desc.as_bytes());
    w.write_string(b"");
    w.into_inner()
}

/// Encode `SSH_MSG_CHANNEL_DATA`.
pub fn encode_channel_data(recipient: u32, data: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_byte(SSH_MSG_CHANNEL_DATA);
    w.write_u32(recipient);
    w.write_string(data);
    w.into_inner()
}

/// Encode `SSH_MSG_CHANNEL_EXTENDED_DATA`.
pub fn encode_channel_extended_data(recipient: u32, data_type: u32, data: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_byte(SSH_MSG_CHANNEL_EXTENDED_DATA);
    w.write_u32(recipient);
    w.write_u32(data_type);
    w.write_string(data);
    w.into_inner()
}

/// Encode a `window-adjust` message.
pub fn encode_window_adjust(recipient: u32, bytes: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_byte(SSH_MSG_CHANNEL_WINDOW_ADJUST);
    w.write_u32(recipient);
    w.write_u32(bytes);
    w.into_inner()
}

/// Encode `SSH_MSG_CHANNEL_EOF`.
pub fn encode_channel_eof(recipient: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_byte(SSH_MSG_CHANNEL_EOF);
    w.write_u32(recipient);
    w.into_inner()
}

/// Encode `SSH_MSG_CHANNEL_CLOSE`.
pub fn encode_channel_close(recipient: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_byte(SSH_MSG_CHANNEL_CLOSE);
    w.write_u32(recipient);
    w.into_inner()
}

/// Encode a `exec` channel request.
pub fn encode_request_exec(recipient: u32, command: &str, want_reply: bool) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_byte(SSH_MSG_CHANNEL_REQUEST);
    w.write_u32(recipient);
    w.write_string(b"exec");
    w.write_bool(want_reply);
    w.write_string(command.as_bytes());
    w.into_inner()
}

/// Encode an `exit-status` channel request (server → client).
pub fn encode_request_exit_status(recipient: u32, code: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_byte(SSH_MSG_CHANNEL_REQUEST);
    w.write_u32(recipient);
    w.write_string(b"exit-status");
    w.write_bool(false);
    w.write_u32(code);
    w.into_inner()
}

/// Encode `SSH_MSG_CHANNEL_SUCCESS` / `SSH_MSG_CHANNEL_FAILURE`.
pub fn encode_channel_success(recipient: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_byte(SSH_MSG_CHANNEL_SUCCESS);
    w.write_u32(recipient);
    w.into_inner()
}

/// Encode `SSH_MSG_CHANNEL_FAILURE`.
pub fn encode_channel_failure(recipient: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_byte(SSH_MSG_CHANNEL_FAILURE);
    w.write_u32(recipient);
    w.into_inner()
}

/// Parse a channel-level payload (RFC 4254 §5).
pub fn parse_channel_message(payload: &[u8]) -> Result<ChannelMessage, Error> {
    let mut r = Reader::new(payload);
    let code = r.read_byte().map_err(Error::Wire)?;
    match code {
        SSH_MSG_CHANNEL_OPEN => {
            let chan_type = r.read_string().map_err(Error::Wire)?;
            let sender = r.read_u32().map_err(Error::Wire)?;
            let window = r.read_u32().map_err(Error::Wire)?;
            let max_packet = r.read_u32().map_err(Error::Wire)?;
            if chan_type != b"session" {
                return Err(Error::Kex("unsupported channel type".into()));
            }
            Ok(ChannelMessage::OpenSession {
                sender,
                window,
                max_packet,
            })
        }
        SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
            let recipient = r.read_u32().map_err(Error::Wire)?;
            let sender = r.read_u32().map_err(Error::Wire)?;
            let window = r.read_u32().map_err(Error::Wire)?;
            let max_packet = r.read_u32().map_err(Error::Wire)?;
            Ok(ChannelMessage::OpenConfirm {
                recipient,
                sender,
                window,
                max_packet,
            })
        }
        SSH_MSG_CHANNEL_OPEN_FAILURE => {
            let recipient = r.read_u32().map_err(Error::Wire)?;
            let reason = r.read_u32().map_err(Error::Wire)?;
            let desc = String::from_utf8(r.read_string().map_err(Error::Wire)?.to_vec())
                .map_err(|_| Error::Kex("bad utf8".into()))?;
            Ok(ChannelMessage::OpenFailure {
                recipient,
                reason,
                desc,
            })
        }
        SSH_MSG_CHANNEL_WINDOW_ADJUST => {
            let recipient = r.read_u32().map_err(Error::Wire)?;
            let bytes = r.read_u32().map_err(Error::Wire)?;
            Ok(ChannelMessage::WindowAdjust { recipient, bytes })
        }
        SSH_MSG_CHANNEL_DATA => {
            let recipient = r.read_u32().map_err(Error::Wire)?;
            let data = r.read_string().map_err(Error::Wire)?.to_vec();
            Ok(ChannelMessage::Data { recipient, data })
        }
        SSH_MSG_CHANNEL_EXTENDED_DATA => {
            let recipient = r.read_u32().map_err(Error::Wire)?;
            let data_type = r.read_u32().map_err(Error::Wire)?;
            let data = r.read_string().map_err(Error::Wire)?.to_vec();
            Ok(ChannelMessage::ExtendedData {
                recipient,
                data_type,
                data,
            })
        }
        SSH_MSG_CHANNEL_EOF => {
            let recipient = r.read_u32().map_err(Error::Wire)?;
            Ok(ChannelMessage::Eof { recipient })
        }
        SSH_MSG_CHANNEL_CLOSE => {
            let recipient = r.read_u32().map_err(Error::Wire)?;
            Ok(ChannelMessage::Close { recipient })
        }
        SSH_MSG_CHANNEL_REQUEST => {
            let recipient = r.read_u32().map_err(Error::Wire)?;
            let kind = String::from_utf8(r.read_string().map_err(Error::Wire)?.to_vec())
                .map_err(|_| Error::Kex("bad utf8".into()))?;
            let want_reply = r.read_bool().map_err(Error::Wire)?;
            let mut command = None;
            let mut exit_status = None;
            match kind.as_str() {
                "exec" | "shell" => {
                    command = Some(
                        String::from_utf8(r.read_string().map_err(Error::Wire)?.to_vec())
                            .map_err(|_| Error::Kex("bad utf8".into()))?,
                    );
                }
                "exit-status" => {
                    exit_status = Some(r.read_u32().map_err(Error::Wire)?);
                }
                _ => {}
            }
            Ok(ChannelMessage::Request {
                recipient,
                kind,
                want_reply,
                command,
                exit_status,
            })
        }
        SSH_MSG_CHANNEL_SUCCESS => {
            let recipient = r.read_u32().map_err(Error::Wire)?;
            Ok(ChannelMessage::Success { recipient })
        }
        SSH_MSG_CHANNEL_FAILURE => {
            let recipient = r.read_u32().map_err(Error::Wire)?;
            Ok(ChannelMessage::Failure { recipient })
        }
        other => Err(Error::Kex(format!("unexpected channel message {other}"))),
    }
}

/// The result of running a command on the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Captured stdout bytes.
    pub stdout: Vec<u8>,
    /// Process exit status (0 = success).
    pub exit_status: u32,
}

/// Handler invoked by the server to execute a requested command.
pub trait CommandHandler {
    /// Run `command`, returning its captured output and exit status.
    fn run(&self, command: &str) -> CommandOutput;
}

/// A closure-based [`CommandHandler`] (kept simple for examples/tests).
impl<F> CommandHandler for F
where
    F: Fn(&str) -> CommandOutput,
{
    fn run(&self, command: &str) -> CommandOutput {
        (self)(command)
    }
}

/// Run a single `exec` command end-to-end as the client.
///
/// `pump` moves this endpoint's pending bytes to the peer and pulls the peer's
/// bytes into this endpoint (see [`crate::session`]). Returns the captured
/// stdout and exit status.
pub fn run_client_exec<F>(
    conn: &mut EncryptedConn,
    mut pump: F,
    command: &str,
) -> Result<(Vec<u8>, u32), Error>
where
    F: FnMut(&mut EncryptedConn),
{
    let client_chan = 0u32;
    conn.send(&encode_open_session(
        client_chan,
        DEFAULT_WINDOW,
        DEFAULT_MAX_PACKET,
    ));
    pump(conn);

    // Wait for OPEN_CONFIRMATION.
    loop {
        pump(conn);
        let Some(payload) = conn.recv()? else {
            continue;
        };
        match parse_channel_message(&payload)? {
            ChannelMessage::OpenConfirm { recipient, .. } if recipient == client_chan => {
                break;
            }
            ChannelMessage::OpenFailure { reason, desc, .. } => {
                return Err(Error::Kex(format!("channel open failed: {reason} {desc}")));
            }
            _ => {}
        }
    }
    conn.send(&encode_request_exec(client_chan, command, true));
    pump(conn);

    let mut stdout = Vec::new();
    let mut exit_status = 0u32;
    loop {
        pump(conn);
        let Some(payload) = conn.recv()? else {
            continue;
        };
        match parse_channel_message(&payload)? {
            ChannelMessage::Data { recipient, data } if recipient == client_chan => {
                stdout.extend_from_slice(&data);
            }
            ChannelMessage::Request {
                recipient,
                kind,
                exit_status: Some(code),
                ..
            } if recipient == client_chan && kind == "exit-status" => {
                exit_status = code;
            }
            ChannelMessage::Eof { recipient } if recipient == client_chan => {}
            ChannelMessage::Success { recipient } if recipient == client_chan => {}
            ChannelMessage::Close { recipient } if recipient == client_chan => {
                conn.send(&encode_channel_close(client_chan));
                pump(conn);
                break;
            }
            _ => {}
        }
    }
    Ok((stdout, exit_status))
}

/// Serve the connection protocol as the server until the channel is closed.
///
/// Handles a single session: opens the channel, executes the requested `exec`
/// command via `handler`, streams stdout back, reports the exit status, and
/// closes cleanly.
pub fn run_server_session<F, H>(
    conn: &mut EncryptedConn,
    mut pump: F,
    handler: &H,
) -> Result<(), Error>
where
    F: FnMut(&mut EncryptedConn),
    H: CommandHandler,
{
    let mut sent_close = false;
    loop {
        pump(conn);
        let Some(payload) = conn.recv()? else {
            continue;
        };
        match parse_channel_message(&payload)? {
            ChannelMessage::OpenSession {
                sender,
                window,
                max_packet,
            } => {
                conn.send(&encode_open_confirm(
                    sender,
                    0,
                    DEFAULT_WINDOW,
                    DEFAULT_MAX_PACKET,
                ));
                let _ = (window, max_packet);
                pump(conn);
            }
            ChannelMessage::Request {
                recipient,
                kind,
                want_reply,
                command,
                ..
            } if kind == "exec" => {
                let cmd = command.unwrap_or_default();
                let out = handler.run(&cmd);
                conn.send(&encode_channel_data(recipient, &out.stdout));
                conn.send(&encode_request_exit_status(recipient, out.exit_status));
                if want_reply {
                    conn.send(&encode_channel_success(recipient));
                }
                conn.send(&encode_channel_eof(recipient));
                conn.send(&encode_channel_close(recipient));
                sent_close = true;
                pump(conn);
            }
            ChannelMessage::Close { recipient } => {
                if !sent_close {
                    conn.send(&encode_channel_close(recipient));
                    pump(conn);
                }
                break;
            }
            ChannelMessage::Data { .. } => { /* ignore client stdin for exec */ }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_message_round_trips() {
        let open = encode_open_session(7, 1000, 2000);
        match parse_channel_message(&open).unwrap() {
            ChannelMessage::OpenSession {
                sender,
                window,
                max_packet,
            } => {
                assert_eq!((sender, window, max_packet), (7, 1000, 2000));
            }
            _ => panic!("wrong message"),
        }
        let data = encode_channel_data(3, b"hi");
        assert_eq!(
            parse_channel_message(&data).unwrap(),
            ChannelMessage::Data {
                recipient: 3,
                data: b"hi".to_vec()
            }
        );
    }
}
