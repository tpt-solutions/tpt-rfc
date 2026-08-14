// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Low-level SMTP command-line parsing helpers (RFC 5321 §4.1.1).

/// The result of splitting a command line into its verb and the remainder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    /// The verb, upper-cased (e.g. `MAIL`, `EHLO`).
    pub verb: String,
    /// The argument text after the verb, trimmed. Empty if the line was only a
    /// verb.
    pub args: String,
}

/// Split a single command line into a [`Command`].
///
/// The verb is the maximal case-insensitive run of alphabetic characters at the
/// start of the line (`HELO`, `EHLO`, `MAIL`, `RSET`, ...). Everything after the
/// first whitespace is the argument text.
pub fn parse_command(line: &str) -> Command {
    let line = line.trim_end_matches(['\r', '\n']);
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len()
        && (bytes[i].is_ascii_alphabetic() || bytes[i] == b'-')
        && !bytes[i].is_ascii_whitespace()
    {
        // Verbs may contain a hyphen only right after letters (not trailing).
        if bytes[i] == b'-' && (i == 0 || !bytes[i - 1].is_ascii_alphabetic()) {
            break;
        }
        i += 1;
    }
    if i == 0 {
        return Command {
            verb: String::new(),
            args: String::new(),
        };
    }
    let (verb, rest) = line.split_at(i);
    let args = rest.trim().to_string();
    Command {
        verb: verb.to_ascii_uppercase(),
        args,
    }
}

/// Extract a path from a `MAIL FROM:` / `RCPT TO:` argument.
///
/// Per RFC 5321 §4.1.1.3, the path is enclosed in angle brackets, e.g.
/// `MAIL FROM:<alice@example.com>` or `RCPT TO:<>`. Returns the inner content
/// (empty string for `<>`). If no brackets are present, the whole argument
/// (after any `FROM:`/`TO:` keyword) is returned as a best-effort fallback.
pub fn parse_path(args: &str) -> Option<String> {
    let args = args.trim();
    // Strip a leading "FROM:"/"TO:" keyword if present.
    let args = strip_keyword(args);
    if let Some(start) = args.find('<') {
        let after = &args[start + 1..];
        if let Some(end) = after.find('>') {
            return Some(after[..end].to_string());
        }
        return None;
    }
    if args.is_empty() {
        None
    } else {
        Some(args.to_string())
    }
}

fn strip_keyword(args: &str) -> &str {
    let lower = args.to_ascii_lowercase();
    for kw in ["from:", "to:"] {
        if lower.starts_with(kw) {
            return &args[kw.len()..];
        }
    }
    args
}

/// Extract the leading `KEYWORD=value` parameter (e.g. `SIZE=1234`) from a
/// command argument, returning `(keyword, value, rest)`. `rest` is the remaining
/// argument text after the parameter (trimmed), or empty.
pub fn take_param(args: &str) -> Option<(String, String, String)> {
    let args = args.trim_start();
    let end = args.find([' ', '\t']);
    let (first, rest) = match end {
        Some(e) => (&args[..e], &args[e..]),
        None => (args, ""),
    };
    if let Some((k, v)) = first.split_once('=') {
        Some((
            k.trim().to_ascii_uppercase(),
            v.trim().to_string(),
            rest.trim().to_string(),
        ))
    } else {
        None
    }
}

/// Find the value of a named parameter (`KEY=value`) anywhere in a command
/// argument string, regardless of position. `key` is matched case-insensitively.
/// Returns `None` if the parameter is absent or has no `=value`.
pub fn param_value(args: &str, key: &str) -> Option<String> {
    let key = key.to_ascii_uppercase();
    for token in args.split_whitespace() {
        if let Some((k, v)) = token.split_once('=') {
            if k.trim().to_ascii_uppercase() == key {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}
