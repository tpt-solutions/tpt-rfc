// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Lexer for Sieve scripts.
//!
//! The lexer turns Sieve source text (RFC 5228 §9 ABNF) into a flat list of
//! [`Token`]s, stripping whitespace and both line (`# ...`) and block
//! (`/* ... */`) comments. It recognizes identifiers, tags (`:is`, `:contains`,
//! ...), quoted strings, multi-line `text:` strings, numbers (with `K`/`M`/`G`
//! quantifiers), and the structural punctuation.

use crate::error::{SieveError, SieveResult};

/// A lexical token produced by the [`Lexer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// A command or test identifier (e.g. `if`, `header`). Case is preserved
    /// but compared case-insensitively by the parser.
    Ident(String),
    /// A tag such as `:is`, `:contains`, `:comparator`. Includes the leading
    /// colon. Compared case-insensitively.
    Tag(String),
    /// A string literal value (quoted or multi-line), with escapes resolved.
    String(String),
    /// An unsigned integer, with any `K`/`M`/`G` quantifier already applied.
    Number(u64),
    /// `[`
    LBracket,
    /// `]`
    RBracket,
    /// `{`
    LBrace,
    /// `}`
    RBrace,
    /// `,`
    Comma,
    /// `;`
    Semicolon,
    /// `(`
    LParen,
    /// `)`
    RParen,
}

/// Tokenizes Sieve source text into a [`Vec<Token>`].
pub struct Lexer {
    chars: Vec<char>,
    pos: usize,
}

impl Lexer {
    /// Create a lexer over the given source text.
    pub fn new(input: &str) -> Self {
        Lexer {
            chars: input.chars().collect(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek2(&self) -> Option<char> {
        self.chars.get(self.pos + 1).copied()
    }

    fn skip_ws_and_comments(&mut self) {
        loop {
            match self.peek() {
                Some(c @ (' ' | '\t' | '\r' | '\n')) => {
                    let _ = c;
                    self.pos += 1;
                }
                Some('#') => {
                    while let Some(c) = self.peek() {
                        if c == '\n' {
                            break;
                        }
                        self.pos += 1;
                    }
                }
                Some('/') if self.peek2() == Some('*') => {
                    self.pos += 2;
                    while let Some(c) = self.peek() {
                        if c == '*' && self.peek2() == Some('/') {
                            self.pos += 2;
                            break;
                        }
                        self.pos += 1;
                    }
                }
                _ => break,
            }
        }
    }

    fn starts_with_ci(&self, needle: &str) -> bool {
        let need: Vec<char> = needle.chars().collect();
        if self.pos + need.len() > self.chars.len() {
            return false;
        }
        for (i, nch) in need.iter().enumerate() {
            if self.chars[self.pos + i].to_ascii_lowercase() != nch.to_ascii_lowercase() {
                return false;
            }
        }
        true
    }

    /// Tokenize the entire input into a flat token list.
    pub fn tokenize(&mut self) -> SieveResult<Vec<Token>> {
        let mut toks = Vec::new();
        loop {
            self.skip_ws_and_comments();
            let Some(c) = self.peek() else {
                break;
            };

            // Multi-line string: `text:` (case-insensitive) ...
            if (c == 't' || c == 'T') && self.starts_with_ci("text:") {
                toks.push(Token::String(self.lex_multiline()?));
                continue;
            }

            let tok = match c {
                '"' => Token::String(self.lex_quoted()?),
                '[' => {
                    self.pos += 1;
                    Token::LBracket
                }
                ']' => {
                    self.pos += 1;
                    Token::RBracket
                }
                '{' => {
                    self.pos += 1;
                    Token::LBrace
                }
                '}' => {
                    self.pos += 1;
                    Token::RBrace
                }
                ',' => {
                    self.pos += 1;
                    Token::Comma
                }
                ';' => {
                    self.pos += 1;
                    Token::Semicolon
                }
                '(' => {
                    self.pos += 1;
                    Token::LParen
                }
                ')' => {
                    self.pos += 1;
                    Token::RParen
                }
                ':' => Token::Tag(self.lex_tag()?),
                c if c.is_ascii_digit() => Token::Number(self.lex_number()?),
                c if is_ident_start(c) => Token::Ident(self.lex_ident()),
                _ => {
                    return Err(SieveError::Lex(
                        self.pos,
                        format!("unexpected character `{c}`"),
                    ))
                }
            };
            toks.push(tok);
        }
        Ok(toks)
    }

    fn lex_quoted(&mut self) -> SieveResult<String> {
        // Current char is `"`.
        self.pos += 1;
        let mut s = String::new();
        loop {
            match self.peek() {
                None => {
                    return Err(SieveError::Lex(self.pos, "unterminated quoted string".into()));
                }
                Some('"') => {
                    self.pos += 1;
                    return Ok(s);
                }
                Some('\\') => {
                    self.pos += 1;
                    match self.peek() {
                        Some('"') => {
                            s.push('"');
                            self.pos += 1;
                        }
                        Some('\\') => {
                            s.push('\\');
                            self.pos += 1;
                        }
                        Some(c @ (' ' | '\t' | '\r' | '\n')) => {
                            // Line continuation: backslash + CRLF is removed.
                            let _ = c;
                            self.pos += 1;
                            if self.peek() == Some('\r') {
                                self.pos += 1;
                            }
                            if self.peek() == Some('\n') {
                                self.pos += 1;
                            }
                        }
                        Some(other) => {
                            s.push('\\');
                            s.push(other);
                            self.pos += 1;
                        }
                        None => {
                            return Err(SieveError::Lex(
                                self.pos,
                                "unterminated escape in quoted string".into(),
                            ));
                        }
                    }
                }
                Some(c) => {
                    s.push(c);
                    self.pos += 1;
                }
            }
        }
    }

    fn lex_multiline(&mut self) -> SieveResult<String> {
        // Current position is at the `t` of `text:`.
        self.pos += 5; // consume "text:"
        while let Some(c) = self.peek() {
            if c == ' ' || c == '\t' {
                self.pos += 1;
            } else {
                break;
            }
        }
        match self.peek() {
            Some('\r') => {
                self.pos += 1;
                if self.peek() == Some('\n') {
                    self.pos += 1;
                }
            }
            Some('\n') => {
                self.pos += 1;
            }
            _ => {
                return Err(SieveError::Lex(
                    self.pos,
                    "expected newline after `text:`".into(),
                ));
            }
        }
        let mut out = String::new();
        loop {
            let mut line = String::new();
            let mut saw_newline = false;
            while let Some(c) = self.peek() {
                if c == '\r' || c == '\n' {
                    saw_newline = true;
                    break;
                }
                line.push(c);
                self.pos += 1;
            }
            if !saw_newline {
                return Err(SieveError::Lex(self.pos, "unterminated multi-line string".into()));
            }
            if self.peek() == Some('\r') {
                self.pos += 1;
            }
            if self.peek() == Some('\n') {
                self.pos += 1;
            }
            if line == "." {
                break;
            }
            // Dot-stuffing: a line beginning with a single dot has it removed.
            let processed = if line.starts_with('.') {
                line[1..].to_string()
            } else {
                line
            };
            out.push_str(&processed);
            out.push('\n');
        }
        Ok(out)
    }

    fn lex_tag(&mut self) -> SieveResult<String> {
        // Current char is `:`.
        self.pos += 1;
        let id = self.lex_ident();
        Ok(format!(":{id}"))
    }

    fn lex_ident(&mut self) -> String {
        let mut s = String::new();
        while let Some(c) = self.peek() {
            if is_ident_char(c) {
                s.push(c);
                self.pos += 1;
            } else {
                break;
            }
        }
        s
    }

    fn lex_number(&mut self) -> SieveResult<u64> {
        let mut n: u64 = 0;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                n = n
                    .checked_mul(10)
                    .and_then(|v| v.checked_add((c as u64) - ('0' as u64)))
                    .ok_or_else(|| SieveError::Lex(self.pos, "number too large".into()))?;
                self.pos += 1;
            } else {
                break;
            }
        }
        let mult = match self.peek() {
            Some('K') | Some('k') => {
                self.pos += 1;
                1024u64
            }
            Some('M') | Some('m') => {
                self.pos += 1;
                1024u64 * 1024
            }
            Some('G') | Some('g') => {
                self.pos += 1;
                1024u64 * 1024 * 1024
            }
            _ => 1,
        };
        n.checked_mul(mult)
            .ok_or_else(|| SieveError::Lex(self.pos, "number too large".into()))
    }
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '?')
}
