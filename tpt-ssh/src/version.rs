// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SSH protocol version exchange (RFC 4253 §4.2).
//!
//! Before any binary packet is sent, each side transmits an identification
//! string of the form `SSH-2.0-<softwareversion>[ <comments>]`, terminated by
//! CR LF. Both strings (without the line endings) feed directly into the key
//! exchange hash.

use thiserror::Error;

/// Maximum length, in bytes, of a single identification line (RFC 4253 §4.2).
pub const MAX_IDENTIFICATION_LEN: usize = 255;

/// The fixed protocol prefix.
pub const SSH_IDENT_PREFIX: &str = "SSH-2.0-";

/// Errors raised during version negotiation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VersionError {
    /// The identification line exceeded [`MAX_IDENTIFICATION_LEN`].
    #[error("identification line too long")]
    TooLong,
    /// The line did not begin with `SSH-2.0-`.
    #[error("unsupported or missing SSH protocol version")]
    UnsupportedProtocol,
    /// The software version component was empty.
    #[error("empty software version")]
    EmptySoftwareVersion,
    /// The identification contained invalid UTF-8.
    #[error("identification is not valid UTF-8")]
    InvalidUtf8,
}

/// A parsed SSH identification string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identification {
    /// The `<softwareversion>` component (e.g. `OpenSSH_9.9`).
    pub software_version: String,
    /// Optional `<comments>` component.
    pub comments: Option<String>,
}

impl Identification {
    /// Build an identification from a software version (no comments).
    pub fn new(software_version: impl Into<String>) -> Self {
        Self {
            software_version: software_version.into(),
            comments: None,
        }
    }

    /// Attach a comments component.
    pub fn with_comments(mut self, comments: impl Into<String>) -> Self {
        self.comments = Some(comments.into());
        self
    }

    /// Serialize as `SSH-2.0-<software>[ <comments>]\r\n`.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut s = String::new();
        s.push_str(SSH_IDENT_PREFIX);
        s.push_str(&self.software_version);
        if let Some(c) = &self.comments {
            s.push(' ');
            s.push_str(c);
        }
        let mut out = s.into_bytes();
        out.push(b'\r');
        out.push(b'\n');
        out
    }

    /// Parse a received identification line.
    ///
    /// Leading lines not starting with `SSH-` are tolerated by RFC 4253 (a
    /// server may emit banners); callers typically scan for the first line
    /// that starts with `SSH-` and pass just that line here.
    pub fn parse(line: &[u8]) -> Result<Self, VersionError> {
        // Strip a single trailing CR LF or LF.
        let line = match line {
            l if l.ends_with(b"\r\n") => &l[..l.len() - 2],
            l if l.ends_with(b"\n") => &l[..l.len() - 1],
            l => l,
        };
        if line.len() > MAX_IDENTIFICATION_LEN {
            return Err(VersionError::TooLong);
        }
        if !line.starts_with(SSH_IDENT_PREFIX.as_bytes()) {
            return Err(VersionError::UnsupportedProtocol);
        }
        let rest = &line[SSH_IDENT_PREFIX.len()..];
        let (sw, comments) = match rest.iter().position(|&b| b == b' ') {
            Some(i) => (rest[..i].to_vec(), Some(rest[i + 1..].to_vec())),
            None => (rest.to_vec(), None),
        };
        if sw.is_empty() {
            return Err(VersionError::EmptySoftwareVersion);
        }
        Ok(Identification {
            software_version: String::from_utf8(sw).map_err(|_| VersionError::InvalidUtf8)?,
            comments: comments
                .map(|c| String::from_utf8(c).map_err(|_| VersionError::InvalidUtf8))
                .transpose()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_round_trip() {
        let id = Identification::new("tpt-ssh_0.1").with_comments("clean-room");
        let wire = id.to_wire();
        assert_eq!(wire, b"SSH-2.0-tpt-ssh_0.1 clean-room\r\n");

        let parsed = Identification::parse(&wire).unwrap();
        assert_eq!(parsed.software_version, "tpt-ssh_0.1");
        assert_eq!(parsed.comments.as_deref(), Some("clean-room"));
    }

    #[test]
    fn parse_without_comments_and_lf_only() {
        let parsed = Identification::parse(b"SSH-2.0-OpenSSH_9.9\n").unwrap();
        assert_eq!(parsed.software_version, "OpenSSH_9.9");
        assert_eq!(parsed.comments, None);
    }

    #[test]
    fn reject_non_ssh_and_empty() {
        assert_eq!(
            Identification::parse(b"SSH-1.99-fails\r\n"),
            Err(VersionError::UnsupportedProtocol)
        );
        assert_eq!(
            Identification::parse(b"SSH-2.0-\r\n"),
            Err(VersionError::EmptySoftwareVersion)
        );
    }
}
