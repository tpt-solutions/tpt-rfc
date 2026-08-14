// Copyright 2026 TPT Solutions
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Accumulated actions from evaluating a Sieve script and their final resolution.

/// The set of actions accumulated while evaluating a script.
///
/// A script may execute several actions; this struct records them as they
/// happen. Call [`ActionSet::finalize`] to resolve the set into the effective
/// [`FinalActions`] once evaluation is complete.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActionSet {
    /// Whether an explicit `keep` action was executed.
    pub keep_explicit: bool,
    /// Folders targeted by `fileinto` actions, in execution order.
    pub fileinto: Vec<String>,
    /// Addresses targeted by `redirect` actions, in execution order.
    pub redirect: Vec<String>,
    /// Whether a `discard` action was executed.
    pub discard: bool,
}

impl ActionSet {
    /// Resolve the accumulated actions into the effective delivery decision.
    ///
    /// The resolution follows RFC 5228 §2.10: an explicit `keep`,
    /// `fileinto`, or `redirect` delivers the message (and `keep` wins over
    /// `discard`); a lone `discard` discards it; and if nothing ran at all the
    /// implicit `keep` applies.
    pub fn finalize(&self) -> FinalActions {
        let has_delivery = !self.fileinto.is_empty() || !self.redirect.is_empty();
        if self.keep_explicit && !has_delivery {
            // An explicit `keep` with no other delivery action keeps the message
            // in the main mailbox, identical to the implicit keep outcome.
            return FinalActions::Keep;
        }
        if self.keep_explicit || has_delivery {
            return FinalActions::Deliver(DeliverActions {
                keep: self.keep_explicit,
                fileinto: self.fileinto.clone(),
                redirect: self.redirect.clone(),
            });
        }
        if self.discard {
            return FinalActions::Discard;
        }
        FinalActions::Keep
    }
}

/// The effective outcome of a Sieve script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalActions {
    /// The message is kept in the user's main mailbox (explicitly or implicitly).
    Keep,
    /// The message is silently discarded.
    Discard,
    /// The message is delivered via one or more explicit actions.
    Deliver(DeliverActions),
}

/// Explicit delivery actions produced by a script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliverActions {
    /// Whether the message is also kept in the main mailbox.
    pub keep: bool,
    /// Folders targeted by `fileinto`, in execution order.
    pub fileinto: Vec<String>,
    /// Addresses targeted by `redirect`, in execution order.
    pub redirect: Vec<String>,
}
