// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Evaluation engine for a parsed Sieve [`Script`](crate::ast::Script).
//!
//! The engine walks the command tree, evaluates tests against a
//! [`MessageContext`], and accumulates [`ActionSet`](crate::actions::ActionSet).

use crate::actions::ActionSet;
use crate::ast::*;
use crate::context::MessageContext;
use crate::error::{SieveError, SieveResult};

/// Evaluate a parsed [`Script`](crate::ast::Script) against the given message
/// context.
///
/// # Errors
///
/// Returns a [`SieveError`] if an action or test requires a capability that
/// was not declared with `require`, or if an unsupported comparator is used.
pub fn evaluate<C: MessageContext>(script: &Script, ctx: &C) -> SieveResult<ActionSet> {
    let mut state = EvalState::default();
    let mut ev = Evaluator {
        state: &mut state,
        script,
        ctx,
    };
    ev.run_block(&script.commands)?;
    Ok(state.actions)
}

#[derive(Default)]
struct EvalState {
    actions: ActionSet,
    stopped: bool,
}

struct Evaluator<'a, C: MessageContext> {
    state: &'a mut EvalState,
    script: &'a Script,
    ctx: &'a C,
}

impl<'a, C: MessageContext> Evaluator<'a, C> {
    fn run_block(&mut self, cmds: &[Command]) -> SieveResult<()> {
        for cmd in cmds {
            if self.state.stopped {
                break;
            }
            match cmd {
                Command::Require(_) => {}
                Command::Action(a) => self.exec_action(a)?,
                Command::If(ifc) => {
                    if self.eval_test(&ifc.test)? {
                        self.run_block(&ifc.block)?;
                    } else {
                        let mut matched = false;
                        for (t, b) in &ifc.elsif {
                            if self.state.stopped {
                                break;
                            }
                            if self.eval_test(t)? {
                                matched = true;
                                self.run_block(b)?;
                                break;
                            }
                        }
                        if !matched {
                            if let Some(b) = &ifc.else_block {
                                self.run_block(b)?;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn exec_action(&mut self, a: &Action) -> SieveResult<()> {
        match a {
            Action::Keep => self.state.actions.keep_explicit = true,
            Action::Discard => self.state.actions.discard = true,
            Action::Stop => self.state.stopped = true,
            Action::Redirect(addr) => self.state.actions.redirect.push(addr.clone()),
            Action::FileInto(folder) => {
                if !self.script.capabilities.contains("fileinto") {
                    return Err(SieveError::MissingCapability("fileinto".to_string()));
                }
                self.state.actions.fileinto.push(folder.clone());
            }
        }
        Ok(())
    }

    fn eval_test(&mut self, t: &Test) -> SieveResult<bool> {
        match t {
            Test::AllOf(subs) => {
                for s in subs {
                    if !self.eval_test(s)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Test::AnyOf(subs) => {
                for s in subs {
                    if self.eval_test(s)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Test::Not(s) => Ok(!self.eval_test(s)?),
            Test::Exists(names) => {
                for n in names {
                    if self.ctx.header_values(n).is_empty() {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Test::True => Ok(true),
            Test::False => Ok(false),
            Test::Size { over, amount } => {
                let s = self.ctx.size();
                Ok(if *over {
                    s > *amount as usize
                } else {
                    s < *amount as usize
                })
            }
            Test::Header(h) => Ok(self.eval_header(h)),
            Test::Address(a) => Ok(self.eval_address(a)),
            Test::Envelope(e) => {
                if !self.script.capabilities.contains("envelope") {
                    return Err(SieveError::MissingCapability("envelope".to_string()));
                }
                Ok(self.eval_envelope(e))
            }
        }
    }

    fn eval_header(&self, h: &HeaderTest) -> bool {
        let mut sources = Vec::new();
        for name in &h.names {
            for v in self.ctx.header_values(name) {
                sources.push(v);
            }
        }
        any_match(&sources, &h.keys, h.comparator, h.match_type)
    }

    fn eval_address(&self, a: &AddressTest) -> bool {
        let mut sources = Vec::new();
        for name in &a.headers {
            for v in self.ctx.header_values(name) {
                for (local, domain) in extract_addresses(&v) {
                    let s = match a.address_part {
                        AddressPart::All => format!("{}@{}", local, domain),
                        AddressPart::LocalPart => local,
                        AddressPart::DomainPart => domain,
                    };
                    sources.push(s);
                }
            }
        }
        any_match(&sources, &a.keys, a.comparator, a.match_type)
    }

    fn eval_envelope(&self, e: &EnvelopeTest) -> bool {
        let mut sources = Vec::new();
        for part in &e.parts {
            for v in self.ctx.envelope_values(part) {
                sources.push(v);
            }
        }
        any_match(&sources, &e.keys, e.comparator, e.match_type)
    }
}

fn any_match(
    sources: &[String],
    keys: &[String],
    comparator: Comparator,
    match_type: MatchType,
) -> bool {
    for v in sources {
        for k in keys {
            if string_matches(comparator, match_type, v, k) {
                return true;
            }
        }
    }
    false
}

fn string_matches(comparator: Comparator, mt: MatchType, value: &str, key: &str) -> bool {
    match comparator {
        Comparator::AsciiCasemap => {
            let v = value.to_ascii_lowercase();
            let k = key.to_ascii_lowercase();
            match mt {
                MatchType::Is => v == k,
                MatchType::Contains => v.contains(&k),
                MatchType::Matches => glob_match(&v, &k),
            }
        }
        Comparator::Octet => match mt {
            MatchType::Is => value == key,
            MatchType::Contains => value.contains(key),
            MatchType::Matches => glob_match(value, key),
        },
    }
}

/// Wildcard match for Sieve `:matches` (`*` = zero or more, `?` = exactly one).
///
/// This is the canonical iterative backtracking matcher: a single `*` records a
/// backtrack point and absorbs any amount of text.
fn glob_match(text: &str, pattern: &str) -> bool {
    let t: Vec<char> = text.chars().collect();
    let p: Vec<char> = pattern.chars().collect();
    let (mut ti, mut pi) = (0usize, 0usize);
    let (mut star_t, mut star_p): (Option<usize>, Option<usize>) = (None, None);
    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            star_p = Some(pi);
            star_t = Some(ti);
            pi += 1;
        } else if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            ti += 1;
            pi += 1;
        } else if let (Some(sp), Some(st)) = (star_p, star_t) {
            let st = st + 1;
            star_t = Some(st);
            ti = st;
            pi = sp + 1;
        } else {
            return false;
        }
    }
    // A trailing `*` matches any remaining text; anything else must be gone.
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Extract `(local-part, domain)` pairs from a header field value.
///
/// This is a pragmatic, spec-derived extractor: angle-addr contents (`<...>`)
/// are preferred; if none are present the value is split on commas and each
/// part is scanned for an `addr-spec` (`local@domain`). Quoted local parts are
/// unwrapped.
fn extract_addresses(value: &str) -> Vec<(String, String)> {
    let mut candidates: Vec<&str> = Vec::new();
    let mut rest = value;
    while let Some(open) = rest.find('<') {
        let after = &rest[open + 1..];
        if let Some(close) = after.find('>') {
            candidates.push(&after[..close]);
            rest = &after[close + 1..];
        } else {
            break;
        }
    }
    if candidates.is_empty() {
        for part in value.split(',') {
            let part = part.trim();
            if !part.is_empty() {
                candidates.push(part);
            }
        }
    }
    let mut out = Vec::new();
    for cand in candidates {
        if let Some(at) = cand.find('@') {
            let local = &cand[..at];
            let domain = &cand[at + 1..];
            if let Some(parsed) = normalize_addr(local, domain) {
                out.push(parsed);
            }
        }
    }
    out
}

fn normalize_addr(local: &str, domain: &str) -> Option<(String, String)> {
    let local = local.trim();
    let domain = domain.trim();
    let local = if local.starts_with('"') && local.ends_with('"') && local.len() >= 2 {
        local[1..local.len() - 1].to_string()
    } else {
        local.to_string()
    };
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        return None;
    }
    Some((local, domain.to_string()))
}
