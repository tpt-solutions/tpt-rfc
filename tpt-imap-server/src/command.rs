// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Parsing of IMAP arguments (sequence sets, flag lists, FETCH/STORE/SEARCH
//! criteria) and rendering of message-derived data (dates, envelopes,
//! bodystructures). These helpers are protocol-level only; they do not touch
//! the store.

use std::collections::HashSet;

use crate::error::{ImapError, Result};
use crate::proto::Token;
use crate::types::*;

/// A parsed sequence set as a list of inclusive `(start, end)` ranges.
/// `end == u32::MAX` means "through the last element" (`*`).
pub type RangeSet = Vec<(u32, u32)>;

/// Parse a single token (typically an atom like `1:3`, `1,2,3`, `*`, `1:*`)
/// into a [`RangeSet`].
pub fn parse_seqset(tok: &Token) -> Result<RangeSet> {
    let s = match tok {
        Token::Atom(s) => s.as_str(),
        _ => return Err(ImapError::InvalidArguments),
    };
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (a, b) = match part.split_once(':') {
            Some((a, b)) => (parse_seq_num(a)?, parse_seq_num(b)?),
            None => {
                let n = parse_seq_num(part)?;
                (n, n)
            }
        };
        out.push((a, b));
    }
    if out.is_empty() {
        return Err(ImapError::InvalidArguments);
    }
    Ok(out)
}

fn parse_seq_num(s: &str) -> Result<u32> {
    if s == "*" {
        Ok(u32::MAX)
    } else {
        s.parse::<u32>().map_err(|_| ImapError::InvalidArguments)
    }
}

/// Resolve a [`RangeSet`] of sequence numbers against a mailbox of `count`
/// messages, returning ascending 1-based sequence numbers.
pub fn resolve_sequence(set: &RangeSet, count: u32) -> Vec<u32> {
    let mut out = Vec::new();
    for &(a, b) in set {
        let start = if a == u32::MAX { count } else { a };
        let end = if b == u32::MAX { count } else { b };
        if start == 0 || end == 0 || count == 0 {
            continue;
        }
        let (lo, hi) = if start <= end { (start, end) } else { (end, start) };
        for n in lo..=hi.min(count) {
            out.push(n);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Resolve a [`RangeSet`] of UIDs against the store's ordered UID list,
/// returning the matching UIDs in ascending order.
pub fn resolve_uid(set: &RangeSet, uids: &[u32]) -> Vec<u32> {
    let mut out = Vec::new();
    for uid in uids {
        if in_set(set, *uid) {
            out.push(*uid);
        }
    }
    out
}

/// Is `value` contained in the range set (with `*` meaning "max")?
pub fn in_set(set: &RangeSet, value: u32) -> bool {
    for &(a, b) in set {
        let start = if a == u32::MAX { u32::MAX } else { a };
        let end = if b == u32::MAX { u32::MAX } else { b };
        let (lo, hi) = if start <= end {
            (start, end)
        } else {
            (end, start)
        };
        if value >= lo && value <= hi {
            return true;
        }
    }
    false
}

/// A FETCH section specifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Section {
    /// Whole message (`BODY[]` / `RFC822`).
    Whole,
    /// Header portion (`BODY[HEADER]` / `RFC822.HEADER`).
    Header,
    /// Body text portion (`BODY[TEXT]`).
    Text,
    /// Selected header fields (`BODY[HEADER.FIELDS (...)]`).
    HeaderFields(Vec<String>),
}

/// A single FETCH data item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchItem {
    Flags,
    Uid,
    InternalDate,
    Size,
    Envelope,
    BodyStructure,
    BodyStructureSimple,
    Body {
        peek: bool,
        section: Section,
    },
}

/// Parse a FETCH command's arguments: the leading sequence set and the item
/// list (which may be a macro, a parenthesized list, or bare atoms).
pub fn parse_fetch(args: &[Token]) -> Result<(RangeSet, Vec<FetchItem>)> {
    if args.is_empty() {
        return Err(ImapError::InvalidArguments);
    }
    let set = parse_seqset(&args[0])?;
    let items = parse_fetch_items(&args[1..])?;
    Ok((set, items))
}

fn parse_fetch_items(args: &[Token]) -> Result<Vec<FetchItem>> {
    if args.is_empty() {
        return Err(ImapError::InvalidArguments);
    }
    // Single macro token.
    if args.len() == 1 {
        if let Token::Atom(s) = &args[0] {
            return Ok(expand_macro(s));
        }
    }
    // Parenthesized list.
    if matches!(args.first(), Some(Token::LParen)) {
        if !matches!(args.last(), Some(Token::RParen)) {
            return Err(ImapError::InvalidArguments);
        }
        return parse_item_slice(&args[1..args.len() - 1]);
    }
    parse_item_slice(args)
}

fn expand_macro(s: &str) -> Vec<FetchItem> {
    match s.to_ascii_uppercase().as_str() {
        "ALL" => vec![
            FetchItem::Flags,
            FetchItem::InternalDate,
            FetchItem::Size,
            FetchItem::Envelope,
            FetchItem::BodyStructureSimple,
        ],
        "FAST" => vec![FetchItem::Flags, FetchItem::InternalDate, FetchItem::Size],
        "FULL" => vec![
            FetchItem::Flags,
            FetchItem::InternalDate,
            FetchItem::Size,
            FetchItem::Envelope,
            FetchItem::BodyStructure,
            FetchItem::Uid,
        ],
        _ => vec![],
    }
}

fn parse_item_slice(tokens: &[Token]) -> Result<Vec<FetchItem>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let (item, ni) = parse_one_item(tokens, i)?;
        out.push(item);
        i = ni;
    }
    if out.is_empty() {
        return Err(ImapError::InvalidArguments);
    }
    Ok(out)
}

fn parse_one_item(tokens: &[Token], i: usize) -> Result<(FetchItem, usize)> {
    let tok = tokens.get(i).ok_or(ImapError::InvalidArguments)?;
    let upper = match tok {
        Token::Atom(s) => s.to_ascii_uppercase(),
        _ => return Err(ImapError::InvalidArguments),
    };
    let next = i + 1;
    let (item, consumed) = match upper.as_str() {
        "FLAGS" => (FetchItem::Flags, next),
        "UID" => (FetchItem::Uid, next),
        "INTERNALDATE" => (FetchItem::InternalDate, next),
        "RFC822.SIZE" => (FetchItem::Size, next),
        "RFC822" => (FetchItem::Body { peek: false, section: Section::Whole }, next),
        "RFC822.HEADER" => (FetchItem::Body { peek: true, section: Section::Header }, next),
        "ENVELOPE" => (FetchItem::Envelope, next),
        "BODYSTRUCTURE" => (FetchItem::BodyStructure, next),
        "BODY" if matches!(tokens.get(next), Some(Token::LBracket)) => {
            let (section, ni) = parse_section(tokens, next)?;
            (FetchItem::Body { peek: false, section }, ni)
        }
        "BODY" => (FetchItem::BodyStructureSimple, next),
        s if s.starts_with("BODY") && matches!(tokens.get(next), Some(Token::LBracket)) => {
            let peek = s == "BODY.PEEK";
            let (section, ni) = parse_section(tokens, next)?;
            (FetchItem::Body { peek, section }, ni)
        }
        s if s.starts_with("BODY") => return Err(ImapError::InvalidArguments),
        _ => return Err(ImapError::InvalidArguments),
    };
    Ok((item, consumed))
}

fn parse_section(tokens: &[Token], lbracket: usize) -> Result<(Section, usize)> {
    // tokens[lbracket] == LBracket
    if !matches!(tokens.get(lbracket), Some(Token::LBracket)) {
        return Err(ImapError::InvalidArguments);
    }
    let inner = lbracket + 1;
    let first = tokens.get(inner);
    let section = match first {
        Some(Token::RBracket) => Section::Whole,
        Some(Token::Atom(a)) => {
            let au = a.to_ascii_uppercase();
            match au.as_str() {
                "HEADER" => {
                    if matches!(tokens.get(inner + 1), Some(Token::LParen)) {
                        // HEADER.FIELDS ( ... )
                        let fields = collect_fields(tokens, inner + 2)?;
                        Section::HeaderFields(fields)
                    } else {
                        Section::Header
                    }
                }
                "HEADER.FIELDS" => {
                    let fields = collect_fields(tokens, inner + 1)?;
                    Section::HeaderFields(fields)
                }
                "TEXT" => Section::Text,
                _ => Section::Whole,
            }
        }
        _ => Section::Whole,
    };
    // find closing RBracket after inner
    let mut j = inner;
    while j < tokens.len() && !matches!(tokens.get(j), Some(Token::RBracket)) {
        j += 1;
    }
    if !matches!(tokens.get(j), Some(Token::RBracket)) {
        return Err(ImapError::InvalidArguments);
    }
    Ok((section, j + 1))
}

fn collect_fields(tokens: &[Token], start: usize) -> Result<Vec<String>> {
    if !matches!(tokens.get(start), Some(Token::LParen)) {
        return Err(ImapError::InvalidArguments);
    }
    let mut out = Vec::new();
    let mut i = start + 1;
    while i < tokens.len() {
        match &tokens[i] {
            Token::RParen => return Ok(out),
            Token::Atom(s) | Token::Quoted(s) => out.push(s.clone()),
            _ => return Err(ImapError::InvalidArguments),
        }
        i += 1;
    }
    Err(ImapError::InvalidArguments)
}

/// Parse a STORE command: sequence set, flag operation (with optional
/// `.SILENT`), and the flag list.
pub fn parse_store(args: &[Token]) -> Result<(RangeSet, FlagOp, bool, Vec<Flag>)> {
    if args.len() < 3 {
        return Err(ImapError::InvalidArguments);
    }
    let set = parse_seqset(&args[0])?;
    let op_str = match &args[1] {
        Token::Atom(s) => s.to_ascii_uppercase(),
        _ => return Err(ImapError::InvalidArguments),
    };
    let (op, silent) = if let Some(rest) = op_str.strip_suffix(".SILENT") {
        let base = rest.to_string();
        (flag_op(&base)?, true)
    } else {
        (flag_op(&op_str)?, false)
    };
    let flags = collect_flags(&args[2..])?;
    Ok((set, op, silent, flags))
}

fn flag_op(s: &str) -> Result<FlagOp> {
    match s {
        "FLAGS" => Ok(FlagOp::Replace),
        "+FLAGS" => Ok(FlagOp::Add),
        "-FLAGS" => Ok(FlagOp::Remove),
        _ => Err(ImapError::InvalidArguments),
    }
}

/// Collect a flag list given as a parenthesized group or as bare atoms.
pub fn collect_flags(tokens: &[Token]) -> Result<Vec<Flag>> {
    let mut out = Vec::new();
    if matches!(tokens.first(), Some(Token::LParen)) {
        if !matches!(tokens.last(), Some(Token::RParen)) {
            return Err(ImapError::InvalidArguments);
        }
        for t in &tokens[1..tokens.len() - 1] {
            out.push(flag_from_token(t)?);
        }
    } else {
        for t in tokens {
            out.push(flag_from_token(t)?);
        }
    }
    Ok(out)
}

fn flag_from_token(t: &Token) -> Result<Flag> {
    let s = match t {
        Token::Atom(s) | Token::Quoted(s) => s.as_str(),
        _ => return Err(ImapError::InvalidArguments),
    };
    s.parse::<Flag>().map_err(|_| ImapError::InvalidArguments)
}

/// A single SEARCH criterion.
#[derive(Debug, Clone)]
pub enum SearchCriterion {
    All,
    SeqSet(RangeSet),
    UidSet(RangeSet),
    Flag(SystemFlag),
    UnFlag(SystemFlag),
    Smaller(u32),
    Larger(u32),
    Text(String),
    Subject(String),
    From(String),
    To(String),
    Or(Box<SearchCriterion>, Box<SearchCriterion>),
    Not(Box<SearchCriterion>),
}

/// Parse SEARCH criteria. When `uid_mode` is set, a bare sequence set or the
/// `UID` keyword is interpreted against UIDs.
pub fn parse_search(args: &[Token], uid_mode: bool) -> Result<Vec<SearchCriterion>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let (c, ni) = parse_one_search(args, i, uid_mode)?;
        out.push(c);
        i = ni;
    }
    if out.is_empty() {
        return Err(ImapError::InvalidArguments);
    }
    Ok(out)
}

fn parse_one_search(
    args: &[Token],
    i: usize,
    uid_mode: bool,
) -> Result<(SearchCriterion, usize)> {
    let tok = args.get(i).ok_or(ImapError::InvalidArguments)?;
    let s = match tok {
        Token::Atom(s) => s.clone(),
        _ => return Err(ImapError::InvalidArguments),
    };
    let upper = s.to_ascii_uppercase();
    let next = i + 1;
    let crit = match upper.as_str() {
        "ALL" => SearchCriterion::All,
        "UID" => {
            let set = parse_seqset(args.get(next).ok_or(ImapError::InvalidArguments)?)?;
            SearchCriterion::UidSet(set)
        }
        "SEEN" => SearchCriterion::Flag(SystemFlag::Seen),
        "UNSEEN" => SearchCriterion::UnFlag(SystemFlag::Seen),
        "ANSWERED" => SearchCriterion::Flag(SystemFlag::Answered),
        "UNANSWERED" => SearchCriterion::UnFlag(SystemFlag::Answered),
        "FLAGGED" => SearchCriterion::Flag(SystemFlag::Flagged),
        "UNFLAGGED" => SearchCriterion::UnFlag(SystemFlag::Flagged),
        "DELETED" => SearchCriterion::Flag(SystemFlag::Deleted),
        "UNDELETED" => SearchCriterion::UnFlag(SystemFlag::Deleted),
        "DRAFT" => SearchCriterion::Flag(SystemFlag::Draft),
        "UNDRAFT" => SearchCriterion::UnFlag(SystemFlag::Draft),
        "NEW" => SearchCriterion::UnFlag(SystemFlag::Seen),
        "OLD" => SearchCriterion::Flag(SystemFlag::Seen),
        "SMALLER" => {
            let n = num_arg(args.get(next))?;
            SearchCriterion::Smaller(n)
        }
        "LARGER" => {
            let n = num_arg(args.get(next))?;
            SearchCriterion::Larger(n)
        }
        "SUBJECT" => SearchCriterion::Subject(str_arg(args.get(next))?),
        "TEXT" => SearchCriterion::Text(str_arg(args.get(next))?),
        "FROM" => SearchCriterion::From(str_arg(args.get(next))?),
        "TO" => SearchCriterion::To(str_arg(args.get(next))?),
        "NOT" => {
            let (inner, ni) = parse_one_search(args, next, uid_mode)?;
            return Ok((SearchCriterion::Not(Box::new(inner)), ni));
        }
        "OR" => {
            let (a, i2) = parse_one_search(args, next, uid_mode)?;
            let (b, i3) = parse_one_search(args, i2, uid_mode)?;
            return Ok((
                SearchCriterion::Or(Box::new(a), Box::new(b)),
                i3,
            ));
        }
        _ => {
            // Bare sequence set.
            let set = parse_seqset(tok)?;
            if uid_mode {
                SearchCriterion::UidSet(set)
            } else {
                SearchCriterion::SeqSet(set)
            }
        }
    };
    let consumed = match upper.as_str() {
        "UID" | "SMALLER" | "LARGER" | "SUBJECT" | "TEXT" | "FROM" | "TO" => next + 1,
        _ => next,
    };
    Ok((crit, consumed))
}

fn num_arg(t: Option<&Token>) -> Result<u32> {
    match t {
        Some(Token::Atom(s)) => s.parse::<u32>().map_err(|_| ImapError::InvalidArguments),
        _ => Err(ImapError::InvalidArguments),
    }
}

fn str_arg(t: Option<&Token>) -> Result<String> {
    match t {
        Some(Token::Atom(s)) | Some(Token::Quoted(s)) => Ok(s.clone()),
        _ => Err(ImapError::InvalidArguments),
    }
}

/// Parse the parenthesized STATUS item list from the tokens following the
/// mailbox name.
pub fn parse_status_items(args: &[Token]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    if matches!(args.first(), Some(Token::LParen)) {
        if !matches!(args.last(), Some(Token::RParen)) {
            return Err(ImapError::InvalidArguments);
        }
        for t in &args[1..args.len() - 1] {
            if let Token::Atom(s) = t {
                out.push(s.to_ascii_uppercase());
            }
        }
    } else {
        for t in args {
            if let Token::Atom(s) = t {
                out.push(s.to_ascii_uppercase());
            }
        }
    }
    Ok(out)
}

/// Quote a string for IMAP output if it contains atom-specials or is empty.
pub fn quote_if_needed(s: &str) -> String {
    let needs = s.is_empty()
        || s.bytes().any(|c| {
            matches!(
                c,
                b'(' | b')' | b'{' | b' ' | b'%' | b'*' | b'"' | b'\\' | 0x7f..=0xff | 0x00..=0x1f
            )
        });
    if needs {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        s.to_string()
    }
}

/// Trim leading/trailing ASCII whitespace from a byte slice.
pub fn trim_bytes(b: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = b.len();
    while start < end && b[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && b[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &b[start..end]
}

/// Render an internal date (Unix seconds) in IMAP `INTERNALDATE` format,
/// assuming UTC (e.g. `17-Jul-1996 02:44:25 +0000`).
pub fn format_internal_date(secs: i64) -> String {
    let days = secs / 86400;
    let rem = secs % 86400;
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;
    let (y, mo, d, _) = civil_from_days(days);
    let mon = MONTHS[(mo - 1) as usize];
    format!(
        "{d:02}-{mon}-{y:04} {hour:02}:{minute:02}:{second:02} +0000",
        d = d,
        mon = mon,
        y = y,
        hour = hour,
        minute = minute,
        second = second
    )
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Howard Hinnant's `days -> (year, month, day)` civil-date algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, doy)
}

/// Split an RFC 822 message into `(headers, body)` at the first blank line.
pub fn split_message(data: &[u8]) -> (&[u8], &[u8]) {
    // CRLFCRLF or LFLF
    let mut i = 0;
    while i + 3 < data.len() {
        if &data[i..i + 4] == b"\r\n\r\n" {
            return (&data[..i], &data[i + 4..]);
        }
        i += 1;
    }
    let mut i = 0;
    while i + 1 < data.len() {
        if &data[i..i + 2] == b"\n\n" {
            return (&data[..i], &data[i + 2..]);
        }
        i += 1;
    }
    (data, &[])
}

/// Case-insensitive lookup of a header value (without the `Name:` prefix).
pub fn get_header(headers: &[u8], name: &str) -> Option<String> {
    let name_l = name.to_ascii_lowercase();
    let text = String::from_utf8_lossy(headers).into_owned();
    for line in text.lines() {
        if let Some((h, v)) = line.split_once(':') {
            if h.trim().to_ascii_lowercase() == name_l {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// Build an IMAP `ENVELOPE` structure from a message.
pub fn build_envelope(data: &[u8]) -> String {
    let (headers, _) = split_message(data);
    let date = get_header(headers, "Date").unwrap_or_else(|| "NIL".to_string());
    let subject = get_header(headers, "Subject")
        .map(|s| quote_if_needed(&s))
        .unwrap_or_else(|| "NIL".to_string());
    let from = addr_list(get_header(headers, "From").as_deref());
    let sender = match get_header(headers, "Sender") {
        Some(s) => addr_list(Some(&s)),
        None => from.clone(),
    };
    let reply_to = addr_list(get_header(headers, "Reply-To").as_deref());
    let to = addr_list(get_header(headers, "To").as_deref());
    let cc = addr_list(get_header(headers, "Cc").as_deref());
    let bcc = addr_list(get_header(headers, "Bcc").as_deref());
    let in_reply_to = get_header(headers, "In-Reply-To")
        .map(|s| quote_if_needed(&s))
        .unwrap_or_else(|| "NIL".to_string());
    let message_id = get_header(headers, "Message-ID")
        .map(|s| quote_if_needed(&s))
        .unwrap_or_else(|| "NIL".to_string());
    format!(
        "({date} {subject} {from} {sender} {reply_to} {to} {cc} {bcc} {in_reply_to} {message_id})"
    )
}

/// Build the full `BODYSTRUCTURE` for a single-part text message.
pub fn build_bodystructure(body: &[u8], simple: bool) -> String {
    let size = body.len();
    let lines = body.split(|&c| c == b'\n').count() as u32;
    if simple {
        format!("(\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" {size} {lines})")
    } else {
        format!("(\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" {size} {lines} NIL NIL NIL)")
    }
}

fn addr_list(hdr: Option<&str>) -> String {
    let text = match hdr {
        Some(h) => h,
        None => return "NIL".to_string(),
    };
    let mut addrs = Vec::new();
    for part in text.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let email = if let Some(st) = part.find('<') {
            if let Some(en) = part[st..].find('>') {
                &part[st + 1..st + en]
            } else {
                part
            }
        } else {
            part
        };
        let (mb, host) = match email.find('@') {
            Some(at) => (email[..at].to_string(), quote_if_needed(&email[at + 1..])),
            None => (email.to_string(), "NIL".to_string()),
        };
        addrs.push(format!("(NIL NIL {} {})", quote_if_needed(&mb), host));
    }
    if addrs.is_empty() {
        "NIL".to_string()
    } else {
        format!("({})", addrs.join(" "))
    }
}

/// Helper: the union of all flags across a set of message snapshots.
pub fn all_flags(snaps: &[MessageSnapshot]) -> HashSet<Flag> {
    let mut set = HashSet::new();
    for m in snaps {
        for f in &m.flags {
            set.insert(f.clone());
        }
    }
    set
}
