//! Which execution mode a call runs under, when the caller did not say (D56 §rung 2).
//!
//! `execution: "sync" | "async" | "hybrid"` (D62, D68) started life request-only,
//! which left the one party who reliably knows an action takes four minutes —
//! the template author — with no way to say so. A caller who did not know
//! either simply rode into a 504 at the synchronous ceiling. This module is the
//! rung that fixes that, and it is deliberately shaped like
//! [`call_timeout`](super::call_timeout): pure, query-free, and resolved once
//! before every dispatch fork.
//!
//! # The cascade
//!
//! | rung | source | where it lives |
//! |------|--------|----------------|
//! | 1 | per-call | `CallRequest.execution` |
//! | 2 | action | `ServiceAction::wait_mode` (`x-overslash-wait-mode`), *post-fold* |
//! | 3 | — | [`ExecutionMode::Sync`], the historical behaviour |
//!
//! There is no service rung and no org rung, on purpose. `x-overslash-wait-mode`
//! is per-action knowledge — "*this* export is slow", not "this vendor is slow"
//! — and a whole-service default would mostly be a way to make fast actions
//! defer for no reason. The naming leaves room: `info.x-overslash-default_wait_mode`
//! is unclaimed if that ever turns out to be wanted.
//!
//! # Why the template rung yields instead of refusing
//!
//! A deferred mode is incoherent with several other request flags, and with two
//! template facts. When the *caller* names such a combination it is a 400, from
//! [`flags`](crate::routes::actions::flags), unchanged by any of this. When the
//! *template* would have supplied the mode, it is silently demoted to
//! [`Sync`](ExecutionMode::Sync) instead.
//!
//! That asymmetry is D56's, transplanted from a number onto a mode. The caller
//! is present, asked explicitly, and can act on an error, so refusing is honest
//! and costs one round trip. The template author is not the caller — a
//! misconfigured template value that 400s every call in the org is a strictly
//! worse failure than one that quietly runs synchronously, which is exactly the
//! behaviour every caller had before the key existed.
//!
//! Silent to the *call* is not invisible: [`ResolvedWaitMode::demoted_from`]
//! carries the mode that was dropped and [`Blockers::first`] names why, and
//! `call.rs` turns both into a `tracing` event, a counter, and the
//! `execution_mode_source` field on the audit row.

use overslash_core::types::service::ExecutionMode;

/// Everything that makes a deferred mode impossible for this call.
///
/// Assembled from both halves of the flag gate — the request-only checks and
/// the ones that need the resolved template — so the demotion rule and the
/// refusal rule cannot drift apart. Every field is `true` when the thing is
/// *present and blocking*.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Blockers {
    /// `prefer_stream: true` — there is no response to stream onto once the
    /// call leaves this connection.
    pub prefer_stream: bool,
    /// `deliver: "url"` — the download token would start expiring before the
    /// call runs.
    pub deliver_url: bool,
    /// `return_url` — nobody is waiting on this connection to be redirected.
    pub return_url: bool,
    /// `runtime: platform` — platform actions run in-process and return
    /// immediately, so there is nothing to defer.
    pub platform_runtime: bool,
    /// `response_type: "binary"` — the bytes would be mangled by
    /// `String::from_utf8_lossy` on their way into the execution row.
    pub binary_response: bool,
    /// `ASYNC_EXECUTION_ENABLED` is off, so nothing drains the queue. A
    /// caller-named mode is refused for this at the top of the handler; the
    /// template rung just never gets adopted.
    pub async_disabled: bool,
}

impl Blockers {
    /// The first blocker in play, as a stable snake_case label for a metric
    /// dimension and a log field.
    ///
    /// First rather than all: this feeds a counter, and an unbounded
    /// combination of reasons would shred its cardinality for no benefit.
    /// Ordered cheapest-to-explain first, matching the order `flags` reports
    /// them in, so a call that trips two gets the same name from both.
    pub fn first(self) -> Option<&'static str> {
        if self.async_disabled {
            Some("async_disabled")
        } else if self.prefer_stream {
            Some("prefer_stream")
        } else if self.deliver_url {
            Some("deliver_url")
        } else if self.return_url {
            Some("return_url")
        } else if self.platform_runtime {
            Some("platform_runtime")
        } else if self.binary_response {
            Some("binary_response")
        } else {
            None
        }
    }

    fn any(self) -> bool {
        self.first().is_some()
    }
}

/// Which rung produced the mode this call runs under.
///
/// Reaches the caller on the `accepted` envelope, because a 202 nobody asked
/// for has to be able to explain itself: an agent that reads
/// `execution_mode_source: "action_template"` knows to expect the same shape
/// next time instead of treating it as a transient oddity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WaitModeSource {
    /// The request named it. Always wins.
    PerCall,
    /// `x-overslash-wait-mode` on the resolved action.
    ActionTemplate,
    /// Nobody had an opinion, or the template's was demoted.
    Default,
}

impl WaitModeSource {
    /// Wire spelling, for the envelope field and the audit row.
    pub fn label(self) -> &'static str {
        match self {
            WaitModeSource::PerCall => "per_call",
            WaitModeSource::ActionTemplate => "action_template",
            WaitModeSource::Default => "default",
        }
    }
}

/// A resolved mode, plus enough provenance to explain a response shape the
/// caller did not ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedWaitMode {
    mode: ExecutionMode,
    source: WaitModeSource,
    demoted_from: Option<ExecutionMode>,
    blocked_by: Option<&'static str>,
}

impl ResolvedWaitMode {
    pub fn mode(self) -> ExecutionMode {
        self.mode
    }

    pub fn source(self) -> WaitModeSource {
        self.source
    }

    /// The mode a template asked for and did not get. `None` on every
    /// ordinary call, including one the caller drove itself.
    pub fn demoted_from(self) -> Option<ExecutionMode> {
        self.demoted_from
    }

    /// Which blocker did it, when [`demoted_from`](Self::demoted_from) is set.
    pub fn blocked_by(self) -> Option<&'static str> {
        self.blocked_by
    }

    /// Whether the mode came from anywhere other than the request. The
    /// envelope and the audit row only carry the source when this is true —
    /// a caller who named `execution` does not need telling.
    pub fn is_derived(self) -> bool {
        !matches!(self.source, WaitModeSource::PerCall)
    }
}

/// Reconcile the request, the action template, and the blockers into the one
/// mode every fork below will read.
///
/// Infallible by construction. A caller-supplied mode that conflicts with a
/// flag has already been refused by `flags::validate_request` /
/// `validate_resolved` before this runs, so rung 1 is passed through
/// untouched — re-deriving that refusal here would put the same rule in two
/// places, which is how the two would eventually disagree.
pub fn resolve(
    per_call: Option<ExecutionMode>,
    action: Option<ExecutionMode>,
    blockers: Blockers,
) -> ResolvedWaitMode {
    if let Some(mode) = per_call {
        return ResolvedWaitMode {
            mode,
            source: WaitModeSource::PerCall,
            demoted_from: None,
            blocked_by: None,
        };
    }

    match action {
        // A template that says `sync` is saying the same thing as silence, and
        // nothing blocks synchronous execution — so it is never demoted, and
        // it still reports `action_template` because the author did author it.
        Some(mode) if !mode.is_deferred() => ResolvedWaitMode {
            mode,
            source: WaitModeSource::ActionTemplate,
            demoted_from: None,
            blocked_by: None,
        },
        Some(mode) if blockers.any() => ResolvedWaitMode {
            mode: ExecutionMode::Sync,
            source: WaitModeSource::Default,
            demoted_from: Some(mode),
            blocked_by: blockers.first(),
        },
        Some(mode) => ResolvedWaitMode {
            mode,
            source: WaitModeSource::ActionTemplate,
            demoted_from: None,
            blocked_by: None,
        },
        None => ResolvedWaitMode {
            mode: ExecutionMode::Sync,
            source: WaitModeSource::Default,
            demoted_from: None,
            blocked_by: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLEAR: Blockers = Blockers {
        prefer_stream: false,
        deliver_url: false,
        return_url: false,
        platform_runtime: false,
        binary_response: false,
        async_disabled: false,
    };

    #[test]
    fn the_caller_always_wins() {
        // Including *down*: an action tagged hybrid that a caller asked to run
        // synchronously runs synchronously. Without this the key would be a
        // cap rather than a default, and an agent that needs the answer inline
        // would have no way to say so.
        for per_call in [
            ExecutionMode::Sync,
            ExecutionMode::Async,
            ExecutionMode::Hybrid,
        ] {
            let r = resolve(Some(per_call), Some(ExecutionMode::Hybrid), CLEAR);
            assert_eq!(r.mode(), per_call);
            assert_eq!(r.source(), WaitModeSource::PerCall);
            assert!(!r.is_derived());
        }
    }

    #[test]
    fn a_caller_named_mode_is_never_demoted_here() {
        // The 400 for this combination is `flags`'. If this function demoted
        // it instead, the caller would get a 200 for a request it was told
        // elsewhere is illegal — the two rules must not both own it.
        let blocked = Blockers {
            prefer_stream: true,
            ..CLEAR
        };
        let r = resolve(Some(ExecutionMode::Hybrid), None, blocked);
        assert_eq!(r.mode(), ExecutionMode::Hybrid);
        assert_eq!(r.demoted_from(), None);
    }

    #[test]
    fn the_template_rung_is_adopted_when_nothing_blocks() {
        for mode in [ExecutionMode::Async, ExecutionMode::Hybrid] {
            let r = resolve(None, Some(mode), CLEAR);
            assert_eq!(r.mode(), mode);
            assert_eq!(r.source(), WaitModeSource::ActionTemplate);
            assert!(r.is_derived());
            assert_eq!(r.demoted_from(), None);
        }
    }

    #[test]
    fn every_blocker_demotes_the_template_rung_to_sync() {
        let each: [(Blockers, &str); 6] = [
            (
                Blockers {
                    prefer_stream: true,
                    ..CLEAR
                },
                "prefer_stream",
            ),
            (
                Blockers {
                    deliver_url: true,
                    ..CLEAR
                },
                "deliver_url",
            ),
            (
                Blockers {
                    return_url: true,
                    ..CLEAR
                },
                "return_url",
            ),
            (
                Blockers {
                    platform_runtime: true,
                    ..CLEAR
                },
                "platform_runtime",
            ),
            (
                Blockers {
                    binary_response: true,
                    ..CLEAR
                },
                "binary_response",
            ),
            (
                Blockers {
                    async_disabled: true,
                    ..CLEAR
                },
                "async_disabled",
            ),
        ];
        for (blockers, reason) in each {
            let r = resolve(None, Some(ExecutionMode::Hybrid), blockers);
            assert_eq!(r.mode(), ExecutionMode::Sync, "{reason}");
            assert_eq!(r.source(), WaitModeSource::Default, "{reason}");
            assert_eq!(r.demoted_from(), Some(ExecutionMode::Hybrid), "{reason}");
            assert_eq!(r.blocked_by(), Some(reason));
        }
    }

    #[test]
    fn a_template_that_says_sync_is_never_demoted() {
        // Demoting sync to sync would report a demotion that did not happen,
        // and the counter it feeds is how the silent path stays auditable.
        let r = resolve(
            None,
            Some(ExecutionMode::Sync),
            Blockers {
                prefer_stream: true,
                ..CLEAR
            },
        );
        assert_eq!(r.mode(), ExecutionMode::Sync);
        assert_eq!(r.source(), WaitModeSource::ActionTemplate);
        assert_eq!(r.demoted_from(), None);
        assert_eq!(r.blocked_by(), None);
    }

    #[test]
    fn silence_at_every_rung_is_sync() {
        let r = resolve(None, None, CLEAR);
        assert_eq!(r.mode(), ExecutionMode::Sync);
        assert_eq!(r.source(), WaitModeSource::Default);
        assert_eq!(r.demoted_from(), None);
        // Blockers alone never demote anything, because there is nothing to
        // demote — a call with no opinion anywhere was always synchronous.
        let r = resolve(
            None,
            None,
            Blockers {
                binary_response: true,
                ..CLEAR
            },
        );
        assert_eq!(r.demoted_from(), None);
    }

    #[test]
    fn the_blocker_label_is_stable_and_bounded() {
        assert_eq!(CLEAR.first(), None);
        // Two at once reports one name, not a combination: this is a metric
        // dimension, and the set of values has to stay small.
        let both = Blockers {
            prefer_stream: true,
            binary_response: true,
            ..CLEAR
        };
        assert_eq!(both.first(), Some("prefer_stream"));
    }
}
