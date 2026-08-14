// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Recursive-descent parser turning a token stream into a [`Script`] (RFC 5228
//! §9 grammar).

use crate::ast::*;
use crate::error::{SieveError, SieveResult};
use crate::lexer::{Lexer, Token};

/// Parses Sieve tokens into a [`Script`].
pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    /// Build a parser from already-lexed tokens.
    pub fn new(tokens: Vec<Token>) -> Self {
        Parser { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn err<T>(&self, msg: impl Into<String>) -> SieveResult<T> {
        Err(SieveError::Parse(self.pos, msg.into()))
    }

    /// Parse a complete script. Returns the [`Script`] (or an error).
    pub fn parse_script(&mut self) -> SieveResult<Script> {
        let mut commands = Vec::new();
        let mut capabilities = std::collections::HashSet::new();
        let mut seen_non_require = false;

        while let Some(tok) = self.peek() {
            match tok {
                Token::Ident(name) => {
                    let lower = name.to_ascii_lowercase();
                    if lower == "require" {
                        if seen_non_require {
                            return self.err("`require` must precede all other commands");
                        }
                        let req = self.parse_require()?;
                        for c in &req {
                            capabilities.insert(c.clone());
                        }
                        commands.push(Command::Require(req));
                    } else {
                        seen_non_require = true;
                        commands.push(self.parse_top_command()?);
                    }
                }
                _ => return self.err("expected a command identifier at top level"),
            }
        }

        Ok(Script {
            commands,
            capabilities,
        })
    }

    fn parse_require(&mut self) -> SieveResult<Vec<String>> {
        self.next(); // consume "require"
        let list = self.parse_string_list()?;
        if self.next() != Some(Token::Semicolon) {
            return self.err("`require` must be terminated with `;`");
        }
        Ok(list)
    }

    fn parse_top_command(&mut self) -> SieveResult<Command> {
        let name = match self.next() {
            Some(Token::Ident(n)) => n,
            _ => return self.err("expected a command identifier"),
        };
        let lower = name.to_ascii_lowercase();
        if lower == "if" {
            Ok(Command::If(self.parse_if()?))
        } else {
            let action = self.parse_action(&lower)?;
            if self.next() != Some(Token::Semicolon) {
                return self.err(format!("action `{lower}` must be terminated with `;`"));
            }
            Ok(Command::Action(action))
        }
    }

    fn parse_if(&mut self) -> SieveResult<IfCommand> {
        // "if" already consumed.
        let test = self.parse_test()?;
        let block = self.parse_block()?;
        let mut elsif = Vec::new();
        let mut else_block = None;
        loop {
            match self.peek() {
                Some(Token::Ident(n)) if n.eq_ignore_ascii_case("elsif") => {
                    self.next();
                    let t = self.parse_test()?;
                    let b = self.parse_block()?;
                    elsif.push((t, b));
                }
                Some(Token::Ident(n)) if n.eq_ignore_ascii_case("else") => {
                    self.next();
                    let b = self.parse_block()?;
                    else_block = Some(b);
                }
                _ => break,
            }
        }
        Ok(IfCommand {
            test,
            block,
            elsif,
            else_block,
        })
    }

    fn parse_block(&mut self) -> SieveResult<Vec<Command>> {
        if self.next() != Some(Token::LBrace) {
            return self.err("expected `{` to open a block");
        }
        let mut cmds = Vec::new();
        loop {
            match self.peek() {
                Some(Token::RBrace) => {
                    self.next();
                    break;
                }
                Some(Token::Ident(n)) => {
                    let lower = n.to_ascii_lowercase();
                    match lower.as_str() {
                        "require" => return self.err("`require` is not allowed inside a block"),
                        "if" => {
                            self.next();
                            cmds.push(Command::If(self.parse_if()?));
                        }
                        "elsif" | "else" => {
                            return self.err("unexpected `elsif`/`else` without matching `if`")
                        }
                        _ => {
                            self.next(); // consume the action identifier
                            let action = self.parse_action(&lower)?;
                            if self.next() != Some(Token::Semicolon) {
                                return self
                                    .err(format!("action `{lower}` must be terminated with `;`"));
                            }
                            cmds.push(Command::Action(action));
                        }
                    }
                }
                Some(_) => return self.err("expected a command or `}`"),
                None => return self.err("unterminated block (missing `}`)"),
            }
        }
        Ok(cmds)
    }

    fn parse_action(&mut self, lower: &str) -> SieveResult<Action> {
        match lower {
            "keep" => Ok(Action::Keep),
            "discard" => Ok(Action::Discard),
            "stop" => Ok(Action::Stop),
            "redirect" => {
                let list = self.parse_string_list()?;
                if list.len() != 1 {
                    return self.err("`redirect` requires exactly one string argument");
                }
                Ok(Action::Redirect(list.into_iter().next().unwrap()))
            }
            "fileinto" => {
                let list = self.parse_string_list()?;
                if list.len() != 1 {
                    return self.err("`fileinto` requires exactly one string argument");
                }
                Ok(Action::FileInto(list.into_iter().next().unwrap()))
            }
            other => self.err(format!("unknown action `{other}`")),
        }
    }

    fn parse_string_list(&mut self) -> SieveResult<Vec<String>> {
        match self.peek() {
            Some(Token::LBracket) => {
                self.next();
                let mut v = Vec::new();
                while let Some(Token::String(s)) = self.next() {
                    v.push(s);
                    match self.next() {
                        Some(Token::Comma) => continue,
                        Some(Token::RBracket) => return Ok(v),
                        _ => return self.err("expected `,` or `]` in string list"),
                    }
                }
                // The loop exited on a non-string token. A well-formed list ends
                // with `]`, which the inner match already returned for; reaching
                // here means a stray token or an empty list `[]`.
                match self.peek() {
                    Some(Token::RBracket) => {
                        self.next();
                        Ok(v)
                    }
                    _ => self.err("expected `]` to close string list"),
                }
            }
            Some(Token::String(s)) => {
                let s = s.clone();
                self.next();
                Ok(vec![s])
            }
            _ => self.err("expected a string or `[ string-list ]`"),
        }
    }

    fn parse_test(&mut self) -> SieveResult<Test> {
        let name = match self.next() {
            Some(Token::Ident(n)) => n,
            _ => return self.err("expected a test identifier"),
        };
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "allof" => Ok(Test::AllOf(self.parse_test_list()?)),
            "anyof" => Ok(Test::AnyOf(self.parse_test_list()?)),
            "not" => {
                let t = self.parse_test()?;
                Ok(Test::Not(Box::new(t)))
            }
            "exists" => {
                let list = self.parse_string_list()?;
                Ok(Test::Exists(list))
            }
            "true" => Ok(Test::True),
            "false" => Ok(Test::False),
            "size" => {
                let tag = match self.next() {
                    Some(Token::Tag(t)) => t,
                    _ => return self.err("`size` requires `:over` or `:under`"),
                };
                let over = match tag.as_str() {
                    ":over" => true,
                    ":under" => false,
                    other => return self.err(format!("`size` invalid tag `{other}`")),
                };
                let amount = match self.next() {
                    Some(Token::Number(n)) => n,
                    _ => return self.err("`size` requires a numeric argument"),
                };
                Ok(Test::Size { over, amount })
            }
            "header" => {
                let (comparator, match_type) = self.parse_common_tags()?;
                let names = self.parse_string_list()?;
                let keys = self.parse_string_list()?;
                Ok(Test::Header(HeaderTest {
                    comparator,
                    match_type,
                    names,
                    keys,
                }))
            }
            "address" => {
                let (address_part, comparator, match_type) = self.parse_address_tags()?;
                let headers = self.parse_string_list()?;
                let keys = self.parse_string_list()?;
                Ok(Test::Address(AddressTest {
                    address_part,
                    comparator,
                    match_type,
                    headers,
                    keys,
                }))
            }
            "envelope" => {
                let (comparator, match_type) = self.parse_common_tags()?;
                let parts = self.parse_string_list()?;
                let keys = self.parse_string_list()?;
                Ok(Test::Envelope(EnvelopeTest {
                    comparator,
                    match_type,
                    parts,
                    keys,
                }))
            }
            other => self.err(format!("unknown test `{other}`")),
        }
    }

    fn parse_test_list(&mut self) -> SieveResult<Vec<Test>> {
        let mut v = Vec::new();
        let paren = matches!(self.peek(), Some(Token::LParen));
        if paren {
            self.next();
        }
        loop {
            match self.peek() {
                Some(Token::Ident(n)) if is_test_name(n) => {
                    v.push(self.parse_test()?);
                }
                _ => break,
            }
            match self.peek() {
                Some(Token::Comma) => {
                    self.next();
                    continue;
                }
                Some(Token::RParen) if paren => {
                    self.next();
                    break;
                }
                Some(Token::RParen) => return self.err("unexpected `)` in test list"),
                _ if paren => return self.err("expected `,` or `)` in test list"),
                _ => break,
            }
        }
        if v.is_empty() {
            return self.err("expected at least one test in `allof`/`anyof`");
        }
        Ok(v)
    }

    fn parse_common_tags(&mut self) -> SieveResult<(Comparator, MatchType)> {
        let mut comparator = Comparator::AsciiCasemap;
        let mut match_type = MatchType::Is;
        while let Some(Token::Tag(t)) = self.peek().cloned() {
            match t.as_str() {
                ":comparator" => {
                    self.next();
                    let c = self.parse_string_list()?;
                    comparator = parse_comparator(&c)?;
                }
                ":is" => {
                    self.next();
                    match_type = MatchType::Is;
                }
                ":contains" => {
                    self.next();
                    match_type = MatchType::Contains;
                }
                ":matches" => {
                    self.next();
                    match_type = MatchType::Matches;
                }
                other => return self.err(format!("unknown tag `{other}`")),
            }
        }
        Ok((comparator, match_type))
    }

    fn parse_address_tags(&mut self) -> SieveResult<(AddressPart, Comparator, MatchType)> {
        let mut address_part = AddressPart::All;
        let mut comparator = Comparator::AsciiCasemap;
        let mut match_type = MatchType::Is;
        while let Some(Token::Tag(t)) = self.peek().cloned() {
            match t.as_str() {
                ":localpart" => {
                    self.next();
                    address_part = AddressPart::LocalPart;
                }
                ":domain" => {
                    self.next();
                    address_part = AddressPart::DomainPart;
                }
                ":all" => {
                    self.next();
                    address_part = AddressPart::All;
                }
                ":comparator" => {
                    self.next();
                    let c = self.parse_string_list()?;
                    comparator = parse_comparator(&c)?;
                }
                ":is" => {
                    self.next();
                    match_type = MatchType::Is;
                }
                ":contains" => {
                    self.next();
                    match_type = MatchType::Contains;
                }
                ":matches" => {
                    self.next();
                    match_type = MatchType::Matches;
                }
                other => return self.err(format!("unknown tag `{other}`")),
            }
        }
        Ok((address_part, comparator, match_type))
    }
}

fn is_test_name(s: &str) -> bool {
    matches!(
        s.to_ascii_lowercase().as_str(),
        "allof"
            | "anyof"
            | "not"
            | "exists"
            | "true"
            | "false"
            | "size"
            | "header"
            | "address"
            | "envelope"
    )
}

fn parse_comparator(list: &[String]) -> SieveResult<Comparator> {
    if list.len() != 1 {
        return Err(SieveError::Parse(
            0,
            "`:comparator` requires exactly one string argument".into(),
        ));
    }
    match list[0].as_str() {
        "i;ascii-casemap" => Ok(Comparator::AsciiCasemap),
        "i;octet" => Ok(Comparator::Octet),
        other => Err(SieveError::Parse(
            0,
            format!("unsupported comparator `{other}` (base RFC 5228 supports i;ascii-casemap and i;octet)"),
        )),
    }
}

/// Parse Sieve source text into a [`Script`].
///
/// # Errors
///
/// Returns a [`SieveError`] if the input fails to lex or parse.
pub fn parse(input: &str) -> SieveResult<Script> {
    let mut lexer = Lexer::new(input);
    let tokens = lexer.tokenize()?;
    let mut parser = Parser::new(tokens);
    parser.parse_script()
}
