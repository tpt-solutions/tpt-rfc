// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SSH user authentication protocol (RFC 4252).
//!
//! Implements the wire encoding/decoding and request/response logic for the
//! `none`, `password`, and `publickey` methods, plus banner handling. The
//! transport is provided by [`crate::session::EncryptedConn`]; this module
//! only understands the authentication message payloads.

use crate::host_key::HostKey;
use crate::wire::{Reader, Writer};
use crate::Error;

/// `SSH_MSG_USERAUTH_REQUEST`.
pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
/// `SSH_MSG_USERAUTH_FAILURE`.
pub const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
/// `SSH_MSG_USERAUTH_SUCCESS`.
pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
/// `SSH_MSG_USERAUTH_BANNER`.
pub const SSH_MSG_USERAUTH_BANNER: u8 = 53;
/// `SSH_MSG_USERAUTH_PK_OK` (public key query response).
pub const SSH_MSG_USERAUTH_PK_OK: u8 = 60;

/// The SSH user-auth service name.
pub const SERVICE_SSH_USERAUTH: &str = "ssh-userauth";

/// The result of an authentication exchange as seen by the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResult {
    /// Authentication succeeded.
    Success,
    /// Authentication failed; `allowed` lists the methods the server still
    /// accepts, `partial` indicates more steps are required.
    Failure {
        /// Methods still available (SSH name-list).
        allowed: Vec<String>,
        /// Whether this was only a partial success.
        partial: bool,
    },
    /// A public-key proof query succeeded; the client may now send a signed
    /// request. `alg`/`blob` echo the key the server accepted.
    PkOk {
        /// Public-key algorithm (e.g. `ssh-ed25519`).
        alg: String,
        /// Public-key blob.
        blob: Vec<u8>,
    },
    /// A human-readable banner pushed by the server.
    Banner {
        /// Banner text.
        message: String,
    },
}

/// Credential checker used by the server side to authorize a connection.
pub trait Authenticator {
    /// Authorize the `none` method for `user`.
    fn check_none(&self, user: &str) -> bool {
        let _ = user;
        false
    }
    /// Authorize `password` for `user`.
    fn check_password(&self, user: &str, password: &str) -> bool {
        let _ = (user, password);
        false
    }
    /// Whether `user` may authenticate with the given public key (used on the
    /// unsigned `publickey` query that precedes a signed request).
    fn check_pubkey(&self, user: &str, alg: &str, blob: &[u8]) -> bool {
        let _ = (user, alg, blob);
        false
    }
    /// Verify a public-key signature over `data` for `user`.
    fn verify_pubkey(&self, user: &str, alg: &str, blob: &[u8], sig: &[u8], data: &[u8]) -> bool {
        let _ = (user, alg, blob, sig, data);
        false
    }
}

/// Encode a `none` method authentication request.
pub fn encode_request_none(user: &str, service: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_byte(SSH_MSG_USERAUTH_REQUEST);
    w.write_string(user.as_bytes());
    w.write_string(service.as_bytes());
    w.write_string(b"none");
    w.into_inner()
}

/// Encode a `password` method authentication request.
pub fn encode_request_password(user: &str, service: &str, password: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_byte(SSH_MSG_USERAUTH_REQUEST);
    w.write_string(user.as_bytes());
    w.write_string(service.as_bytes());
    w.write_string(b"password");
    w.write_bool(false); // no password change
    w.write_string(password.as_bytes());
    w.into_inner()
}

/// The signed blob `session_id || SSH_MSG_USERAUTH_REQUEST || user || service
/// || "publickey" || TRUE || alg || blob` that the client signs for the
/// `publickey` method (RFC 4252 §7).
pub fn publickey_signature_data(
    session_id: &[u8],
    user: &str,
    service: &str,
    alg: &str,
    blob: &[u8],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_string(session_id);
    w.write_byte(SSH_MSG_USERAUTH_REQUEST);
    w.write_string(user.as_bytes());
    w.write_string(service.as_bytes());
    w.write_string(b"publickey");
    w.write_bool(true);
    w.write_string(alg.as_bytes());
    w.write_string(blob);
    w.into_inner()
}

/// Encode a `publickey` authentication request. When `signature` is `None`
/// this is the unsigned query that expects `SSH_MSG_USERAUTH_PK_OK` back;
/// when `Some`, `signature` is the SSH signature blob (`string(alg) ||
/// string(sig)`) over [`publickey_signature_data`].
pub fn encode_request_publickey(
    user: &str,
    service: &str,
    alg: &str,
    blob: &[u8],
    signature: Option<&[u8]>,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_byte(SSH_MSG_USERAUTH_REQUEST);
    w.write_string(user.as_bytes());
    w.write_string(service.as_bytes());
    w.write_string(b"publickey");
    w.write_bool(signature.is_some());
    w.write_string(alg.as_bytes());
    w.write_string(blob);
    if let Some(sig) = signature {
        w.write_string(sig);
    }
    w.into_inner()
}

/// Encode a `SSH_MSG_USERAUTH_BANNER` message from the server.
pub fn encode_banner(message: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_byte(SSH_MSG_USERAUTH_BANNER);
    w.write_string(message.as_bytes());
    w.write_string(b""); // language tag (empty)
    w.into_inner()
}

/// Parse an authentication response payload (client side).
pub fn parse_response(payload: &[u8]) -> Result<AuthResult, Error> {
    let mut r = Reader::new(payload);
    let code = r.read_byte().map_err(Error::Wire)?;
    match code {
        SSH_MSG_USERAUTH_SUCCESS => Ok(AuthResult::Success),
        SSH_MSG_USERAUTH_FAILURE => {
            let names = r.read_name_list().map_err(Error::Wire)?;
            let partial = r.read_bool().map_err(Error::Wire)?;
            let allowed = names
                .into_iter()
                .map(|b| {
                    String::from_utf8(b.to_vec()).map_err(|_| Error::HostKey("bad utf8".into()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(AuthResult::Failure { allowed, partial })
        }
        SSH_MSG_USERAUTH_PK_OK => {
            let alg = String::from_utf8(r.read_string().map_err(Error::Wire)?.to_vec())
                .map_err(|_| Error::HostKey("bad utf8".into()))?;
            let blob = r.read_string().map_err(Error::Wire)?.to_vec();
            Ok(AuthResult::PkOk { alg, blob })
        }
        SSH_MSG_USERAUTH_BANNER => {
            let message = String::from_utf8(r.read_string().map_err(Error::Wire)?.to_vec())
                .map_err(|_| Error::HostKey("bad utf8".into()))?;
            Ok(AuthResult::Banner { message })
        }
        other => Err(Error::HostKey(format!("unexpected auth message {other}"))),
    }
}

/// Process an incoming `SSH_MSG_USERAUTH_REQUEST` on the server side and return
/// the response payload to send back. Returns `None` for an unsupported
/// message code (the caller should treat that as a protocol error).
pub fn server_handle(
    payload: &[u8],
    session_id: &[u8],
    auth: &dyn Authenticator,
) -> Option<Vec<u8>> {
    let mut r = Reader::new(payload);
    let code = r.read_byte().ok()?;
    if code != SSH_MSG_USERAUTH_REQUEST {
        return None;
    }
    let user = String::from_utf8(r.read_string().ok()?.to_vec()).ok()?;
    let service = String::from_utf8(r.read_string().ok()?.to_vec()).ok()?;
    let method = String::from_utf8(r.read_string().ok()?.to_vec()).ok()?;

    let allowed: Vec<String> = vec!["password".into(), "publickey".into()];

    let fail = {
        let mut w = Writer::new();
        w.write_byte(SSH_MSG_USERAUTH_FAILURE);
        w.write_name_list(allowed.iter().map(|s| s.as_bytes()));
        w.write_bool(false);
        w.into_inner()
    };

    if service != SERVICE_SSH_USERAUTH {
        return Some(fail);
    }

    match method.as_str() {
        "none" => {
            if auth.check_none(&user) {
                let mut w = Writer::new();
                w.write_byte(SSH_MSG_USERAUTH_SUCCESS);
                Some(w.into_inner())
            } else {
                Some(fail)
            }
        }
        "password" => {
            let _change = r.read_bool().ok()?;
            let password = String::from_utf8(r.read_string().ok()?.to_vec()).ok()?;
            if auth.check_password(&user, &password) {
                let mut w = Writer::new();
                w.write_byte(SSH_MSG_USERAUTH_SUCCESS);
                Some(w.into_inner())
            } else {
                Some(fail)
            }
        }
        "publickey" => {
            let has_sig = r.read_bool().ok()?;
            let alg = String::from_utf8(r.read_string().ok()?.to_vec()).ok()?;
            let blob = r.read_string().ok()?.to_vec();
            if !has_sig {
                if auth.check_pubkey(&user, &alg, &blob) {
                    let mut w = Writer::new();
                    w.write_byte(SSH_MSG_USERAUTH_PK_OK);
                    w.write_string(alg.as_bytes());
                    w.write_string(&blob);
                    Some(w.into_inner())
                } else {
                    Some(fail)
                }
            } else {
                let sig = r.read_string().ok()?.to_vec();
                let data = publickey_signature_data(session_id, &user, &service, &alg, &blob);
                // Reuse the Ed25519 host-key verifier over the client key blob.
                let ok = if alg == "ssh-ed25519" {
                    HostKey::verify(&blob, &sig, &data).unwrap_or(false)
                        && auth.verify_pubkey(&user, &alg, &blob, &sig, &data)
                } else {
                    false
                };
                if ok {
                    let mut w = Writer::new();
                    w.write_byte(SSH_MSG_USERAUTH_SUCCESS);
                    Some(w.into_inner())
                } else {
                    Some(fail)
                }
            }
        }
        _ => Some(fail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedAuth {
        user: &'static str,
        password: &'static str,
        key: Vec<u8>,
    }

    impl Authenticator for FixedAuth {
        fn check_password(&self, user: &str, password: &str) -> bool {
            user == self.user && password == self.password
        }
        fn check_pubkey(&self, user: &str, _alg: &str, blob: &[u8]) -> bool {
            user == self.user && *blob == self.key[..]
        }
        fn verify_pubkey(
            &self,
            user: &str,
            _alg: &str,
            blob: &[u8],
            _sig: &[u8],
            _data: &[u8],
        ) -> bool {
            user == self.user && *blob == self.key[..]
        }
    }

    #[test]
    fn password_round_trip() {
        let auth = FixedAuth {
            user: "alice",
            password: "secret",
            key: Vec::new(),
        };
        let req = encode_request_password("alice", SERVICE_SSH_USERAUTH, "secret");
        let resp = server_handle(&req, b"session-id", &auth).unwrap();
        assert_eq!(parse_response(&resp).unwrap(), AuthResult::Success);

        let bad = encode_request_password("alice", SERVICE_SSH_USERAUTH, "wrong");
        let resp = server_handle(&bad, b"session-id", &auth).unwrap();
        assert_eq!(
            parse_response(&resp).unwrap(),
            AuthResult::Failure {
                allowed: vec!["password".into(), "publickey".into()],
                partial: false
            }
        );
    }

    #[test]
    fn publickey_query_then_unsupported_signature() {
        let auth = FixedAuth {
            user: "bob",
            password: "",
            key: vec![1, 2, 3],
        };
        // Unsigned query: key matches -> PK_OK.
        let q =
            encode_request_publickey("bob", SERVICE_SSH_USERAUTH, "ssh-ed25519", &[1, 2, 3], None);
        let resp = server_handle(&q, b"sid", &auth).unwrap();
        assert_eq!(
            parse_response(&resp).unwrap(),
            AuthResult::PkOk {
                alg: "ssh-ed25519".into(),
                blob: vec![1, 2, 3]
            }
        );
        // Signed request with an unverifiable signature -> failure.
        let s = encode_request_publickey(
            "bob",
            SERVICE_SSH_USERAUTH,
            "ssh-ed25519",
            &[1, 2, 3],
            Some(&[9, 9, 9]),
        );
        let resp = server_handle(&s, b"sid", &auth).unwrap();
        assert_eq!(
            parse_response(&resp).unwrap(),
            AuthResult::Failure {
                allowed: vec!["password".into(), "publickey".into()],
                partial: false
            }
        );
    }
}
