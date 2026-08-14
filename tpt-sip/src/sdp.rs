// SPDX-License-Identifier: MIT OR Apache-2.0
//! Minimal SDP (Session Description Protocol, RFC 8866) support, enough
//! to carry offer/answer bodies with `application/sdp` (RFC 3261 §5 and
//! RFC 3264). This is a building block: bring your own SDP negotiation,
//! but parse and serialise the common lines so SIP bodies round-trip.

use crate::error::{Result, SipError};

/// A parsed SDP session description.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Sdp {
    /// `v=` protocol version (must be 0).
    pub version: u32,
    /// `o=` origin: `<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>`.
    pub origin: String,
    /// `s=` session name.
    pub session_name: String,
    /// `c=` connection data, if present.
    pub connection: Option<String>,
    /// `t=` timing (default `0 0`).
    pub timing: String,
    /// `a=` session-level attributes.
    pub attributes: Vec<String>,
    /// `m=` media descriptions.
    pub media: Vec<Media>,
}

/// A single `m=` media description with its `a=` attributes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Media {
    /// Media type (`audio`, `video`, `application`, …).
    pub media: String,
    /// Transport port.
    pub port: u32,
    /// Transport protocol (`RTP/AVP`, `UDP/TLS/RTP/SAVPF`, …).
    pub proto: String,
    /// Media formats / payload type numbers.
    pub formats: Vec<String>,
    /// `a=` media-level attributes.
    pub attributes: Vec<String>,
}

impl Sdp {
    /// Parse an SDP description from text.
    pub fn parse(text: &str) -> Result<Sdp> {
        let mut sdp = Sdp::default();
        let mut current: Option<Media> = None;
        let mut seen_v = false;

        for raw_line in text.lines() {
            let line = raw_line.trim_end();
            if line.is_empty() {
                continue;
            }
            let (typ, val) = line
                .split_once('=')
                .ok_or_else(|| SipError::InvalidMessage(format!("bad SDP line: {line}")))?;
            match typ {
                "v" => {
                    sdp.version = val
                        .parse()
                        .map_err(|_| SipError::InvalidMessage(format!("bad SDP version: {val}")))?;
                    seen_v = true;
                }
                "o" => sdp.origin = val.to_string(),
                "s" => sdp.session_name = val.to_string(),
                "c" => sdp.connection = Some(val.to_string()),
                "t" => sdp.timing = val.to_string(),
                "a" => {
                    if let Some(m) = current.as_mut() {
                        m.attributes.push(val.to_string());
                    } else {
                        sdp.attributes.push(val.to_string());
                    }
                }
                "m" => {
                    if let Some(m) = current.take() {
                        sdp.media.push(m);
                    }
                    let mut parts = val.split_whitespace();
                    let media = parts
                        .next()
                        .ok_or_else(|| SipError::InvalidMessage("SDP m= missing type".into()))?
                        .to_string();
                    let port = parts
                        .next()
                        .ok_or_else(|| SipError::InvalidMessage("SDP m= missing port".into()))?
                        .parse()
                        .map_err(|_| SipError::InvalidMessage("SDP m= bad port".into()))?;
                    let proto = parts
                        .next()
                        .ok_or_else(|| SipError::InvalidMessage("SDP m= missing proto".into()))?
                        .to_string();
                    let formats: Vec<String> = parts.map(|s| s.to_string()).collect();
                    current = Some(Media {
                        media,
                        port,
                        proto,
                        formats,
                        attributes: Vec::new(),
                    });
                }
                _ => {}
            }
        }
        if let Some(m) = current.take() {
            sdp.media.push(m);
        }

        if !seen_v {
            return Err(SipError::InvalidMessage("SDP missing v= line".into()));
        }
        Ok(sdp)
    }

    /// Serialise back to canonical SDP text.
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("v={}\r\n", self.version));
        s.push_str(&format!("o={}\r\n", self.origin));
        s.push_str(&format!("s={}\r\n", self.session_name));
        if let Some(c) = &self.connection {
            s.push_str(&format!("c={c}\r\n"));
        }
        s.push_str(&format!(
            "t={}\r\n",
            if self.timing.is_empty() {
                "0 0"
            } else {
                &self.timing
            }
        ));
        for a in &self.attributes {
            s.push_str(&format!("a={a}\r\n"));
        }
        for m in &self.media {
            s.push_str(&format!(
                "m={} {} {} {}\r\n",
                m.media,
                m.port,
                m.proto,
                m.formats.join(" ")
            ));
            for a in &m.attributes {
                s.push_str(&format!("a={a}\r\n"));
            }
        }
        s
    }
}

impl std::fmt::Display for Sdp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_text())
    }
}

/// Construct a minimal audio offer (`audio` on `port`, RTP/AVP, with the
/// given payload types and `rtpmap` attributes).
pub fn audio_offer(origin: &str, port: u32, payloads: &[u32], codecs: &[&str]) -> Sdp {
    let mut sdp = Sdp {
        version: 0,
        origin: origin.to_string(),
        session_name: "tpt-sip".to_string(),
        connection: Some("IN IP4 0.0.0.0".to_string()),
        timing: "0 0".to_string(),
        attributes: vec!["sendrecv".to_string()],
        media: Vec::new(),
    };
    let formats: Vec<String> = payloads.iter().map(|p| p.to_string()).collect();
    let attributes: Vec<String> = codecs
        .iter()
        .enumerate()
        .map(|(i, c)| format!("rtpmap:{} {}", payloads[i], c))
        .collect();
    sdp.media.push(Media {
        media: "audio".to_string(),
        port,
        proto: "RTP/AVP".to_string(),
        formats,
        attributes,
    });
    sdp
}
