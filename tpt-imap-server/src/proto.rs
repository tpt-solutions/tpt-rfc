// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Low-level IMAP line/literal framing. Reads a full client *request* (tag +
//! command + arguments, resolving inline literals with the standard
//! continuation handshake) and provides helpers to write responses.

use std::io::{self, BufRead, Read, Write};

/// A parsed token from an IMAP command line. Literals are already spliced in
/// as raw bytes by the reader, so they survive as a single token even when
/// their content contains spaces, quotes, or parentheses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// An atom / number / flag (anything that is not a structural char).
    Atom(String),
    /// A double-quoted string (with `\"` / `\\` escapes resolved).
    Quoted(String),
    /// A literal's raw bytes.
    Literal(Vec<u8>),
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `[`
    LBracket,
    /// `]`
    RBracket,
}

/// A fully parsed client request.
#[derive(Debug, Clone)]
pub struct Request {
    /// The command tag (echoed back in the response).
    pub tag: String,
    /// The command name, upper-cased (e.g. `FETCH`).
    pub command: String,
    /// The remaining argument tokens.
    pub args: Vec<Token>,
}

/// Read a single CRLF/LF-terminated line, returning `None` at EOF (0 bytes).
pub fn read_line<R: BufRead>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    let n = r.read_until(b'\n', &mut line)?;
    if n == 0 {
        return Ok(None);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(Some(line))
}

fn read_exact<R: Read>(r: &mut R, n: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn expect_crlf<R: BufRead>(r: &mut R) -> io::Result<()> {
    let mut crlf = [0u8; 2];
    r.read_exact(&mut crlf)?;
    if crlf == *b"\r\n" {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, "expected CRLF"))
    }
}

fn is_atom_char(c: u8) -> bool {
    !matches!(c, b' ' | b'\t' | b'(' | b')' | b'[' | b']' | b'"' | b'{')
}

fn read_quoted(line: &[u8], start: usize) -> io::Result<(String, usize)> {
    let mut i = start + 1;
    let mut s: Vec<u8> = Vec::new();
    while i < line.len() {
        match line[i] {
            b'\\' if i + 1 < line.len() => {
                s.push(line[i + 1]);
                i += 2;
            }
            b'"' => {
                return Ok((String::from_utf8_lossy(&s).into_owned(), i + 1));
            }
            c => {
                s.push(c);
                i += 1;
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "unterminated quoted string",
    ))
}

fn read_atom(line: &[u8], start: usize) -> (String, usize) {
    let mut i = start;
    while i < line.len() && is_atom_char(line[i]) {
        i += 1;
    }
    (String::from_utf8_lossy(&line[start..i]).into_owned(), i)
}

fn parse_literal_spec(line: &[u8], start: usize) -> io::Result<(usize, bool, usize)> {
    // line[start] == b'{'
    let mut i = start + 1;
    let mut n: usize = 0;
    while i < line.len() && line[i].is_ascii_digit() {
        n = n * 10 + (line[i] - b'0') as usize;
        i += 1;
    }
    let plus = line.get(i) == Some(&b'+');
    if plus {
        i += 1;
    }
    if line.get(i) != Some(&b'}') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed literal specification",
        ));
    }
    i += 1;
    Ok((n, plus, i))
}

/// Read one complete request, resolving inline literals. Returns `None` when
/// the connection is closed (EOF before any command).
///
/// `w` is used to emit the `+` continuation prompt for synchronising
/// literals (`{N}`); non-synchronising literals (`{N}+`) are read without a
/// prompt, as permitted by RFC 7888.
pub fn read_request<R, W>(r: &mut R, w: &mut W) -> io::Result<Option<Request>>
where
    R: BufRead + Read,
    W: Write,
{
    let mut toks: Vec<Token> = Vec::new();
    loop {
        let line = match read_line(r)? {
            Some(l) => l,
            None => return Ok(None),
        };
        if line.is_empty() {
            // Tolerate leading/superfluous blank lines.
            continue;
        }
        let mut i = 0usize;
        while i < line.len() {
            while i < line.len() && (line[i] == b' ' || line[i] == b'\t') {
                i += 1;
            }
            if i >= line.len() {
                break;
            }
            match line[i] {
                b'(' => {
                    toks.push(Token::LParen);
                    i += 1;
                }
                b')' => {
                    toks.push(Token::RParen);
                    i += 1;
                }
                b'[' => {
                    toks.push(Token::LBracket);
                    i += 1;
                }
                b']' => {
                    toks.push(Token::RBracket);
                    i += 1;
                }
                b'"' => {
                    let (s, ni) = read_quoted(&line, i)?;
                    toks.push(Token::Quoted(s));
                    i = ni;
                }
                b'{' => {
                    let (n, plus, ni) = parse_literal_spec(&line, i)?;
                    if !plus {
                        w.write_all(b"+ Ready for literal\r\n")?;
                        w.flush()?;
                    }
                    let lit = read_exact(r, n)?;
                    expect_crlf(r)?;
                    toks.push(Token::Literal(lit));
                    i = ni;
                }
                _ => {
                    let (s, ni) = read_atom(&line, i);
                    toks.push(Token::Atom(s));
                    i = ni;
                }
            }
        }
        // The literal's data (and its terminating CRLF) has already been
        // consumed above; any tokens following the literal on the same
        // logical line have also been scanned. The command is therefore
        // complete — do not read another line.
        break;
    }

    if toks.len() < 2 {
        return Ok(None);
    }
    let tag = match &toks[0] {
        Token::Atom(t) => t.clone(),
        _ => return Ok(None),
    };
    let command = match &toks[1] {
        Token::Atom(c) => c.to_ascii_uppercase(),
        _ => return Ok(None),
    };
    Ok(Some(Request {
        tag,
        command,
        args: toks[2..].to_vec(),
    }))
}

/// Write an untagged response line: `* <data>\r\n`.
pub fn write_untagged(w: &mut impl Write, data: &str) -> io::Result<()> {
    w.write_all(b"* ")?;
    w.write_all(data.as_bytes())?;
    w.write_all(b"\r\n")
}

/// Write a tagged status response: `<tag> <OK|NO|BAD> <text>\r\n`.
pub fn write_status(w: &mut impl Write, tag: &str, kind: &str, text: &str) -> io::Result<()> {
    w.write_all(tag.as_bytes())?;
    w.write_all(b" ")?;
    w.write_all(kind.as_bytes())?;
    w.write_all(b" ")?;
    w.write_all(text.as_bytes())?;
    w.write_all(b"\r\n")
}

/// Write a continuation prompt: `+ <text>\r\n`.
pub fn write_continuation(w: &mut impl Write, text: &str) -> io::Result<()> {
    w.write_all(b"+ ")?;
    w.write_all(text.as_bytes())?;
    w.write_all(b"\r\n")
}

/// Write a literal: `{<len>}\r\n<data>\r\n`.
pub fn write_literal(w: &mut impl Write, data: &[u8]) -> io::Result<()> {
    w.write_all(format!("{{{}}}\r\n", data.len()).as_bytes())?;
    w.write_all(data)?;
    w.write_all(b"\r\n")
}

/// Extract a `&str` from an `Atom` or `Quoted` token (used for mailbox names,
/// usernames, etc.).
pub fn token_str(t: &Token) -> Option<&str> {
    match t {
        Token::Atom(s) | Token::Quoted(s) => Some(s),
        Token::Literal(_) => None,
        _ => None,
    }
}
