//! How long an action call may wait on its upstream (D56).
//!
//! Five places can have an opinion, and they disagree for good reasons: the
//! deployment knows its own request cap, the org knows its tolerance, the
//! template author knows the upstream, and the caller knows this particular
//! query. This module is the one place that reconciles them, kept pure and
//! query-free so both call paths — inline `/v1/actions/call` and the approval
//! replay — resolve identically and can be tested without a database.
//!
//! # The cascade
//!
//! Defaults cascade by specificity, most specific first. The first layer that
//! has an opinion wins:
//!
//! | rung | source | where it lives |
//! |------|--------|----------------|
//! | 1 | per-call | `CallRequest.timeout_ms` |
//! | 2 | action | `ServiceAction::timeout_ms`, *post-fold* |
//! | 3 | service | `ServiceDefinition::default_timeout_ms`, post-fold |
//! | 4 | org | `orgs.call_timeout_ms` |
//! | 5 | deployment | `Config::call_timeout_ms` |
//!
//! Rung 2 says "post-fold" because an org's `ActionPatch::timeout_ms` has
//! already overwritten the shipped template's value by the time anything gets
//! here. That is what collapses what would otherwise be a sixth rung — there
//! is no separate "org per-action" layer left to consult.
//!
//! # Caps
//!
//! Whatever the cascade produces is then clamped by `orgs.max_call_timeout_ms`
//! and `Config::call_timeout_max_ms`. The two are *not* symmetric with the
//! defaults above: a cap is a ceiling on everything below it, so the tightest
//! one wins rather than the most specific.
//!
//! # Why the asymmetry between "asked for" and "defaulted to"
//!
//! A caller who names a `timeout_ms` above the cap gets a `400`. A template or
//! org *default* above the cap is silently clamped. This looks inconsistent
//! and is deliberate: the caller is present, is asking explicitly, and can act
//! on the error, so refusing is honest and costs one round trip. The template
//! author is not the caller — a misconfigured template value that 400s every
//! call in the org is a strictly worse failure than one that quietly runs at
//! the ceiling.

use std::time::Duration;

/// What every layer had to say, before any of it is reconciled.
///
/// Every field is `Option` for the same reason: "this layer has no opinion" is
/// the common case at every rung, and it must be distinguishable from "this
/// layer says zero".
#[derive(Debug, Clone, Copy, Default)]
pub struct TimeoutLayers {
    /// `CallRequest.timeout_ms` — what this one call asked for.
    pub per_call_ms: Option<u64>,
    /// `ServiceAction::timeout_ms` after the org layer has been folded in.
    pub action_ms: Option<u64>,
    /// `ServiceDefinition::default_timeout_ms` after the fold.
    pub service_ms: Option<u64>,
    /// `orgs.call_timeout_ms`.
    pub org_default_ms: Option<u64>,
    /// `orgs.max_call_timeout_ms`.
    pub org_max_ms: Option<u64>,
}

/// Which rung of the cascade produced the resolved value.
///
/// Carried all the way out to the 504 body. This is the highest-value thing
/// this module produces for anyone debugging a timeout: "why is Metabase
/// timing out at 30s when I set the org default to 90s" is answered instantly
/// by seeing `action_template` here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeoutSource {
    PerCall,
    ActionTemplate,
    ServiceTemplate,
    OrgDefault,
    GlobalDefault,
    /// Replayed from a stored approval — the layers were resolved when the
    /// call was first made and are not re-derivable now (the stored payload
    /// has no action key to look up).
    Stored,
}

impl TimeoutSource {
    fn label(self) -> &'static str {
        match self {
            Self::PerCall => "the request",
            Self::ActionTemplate => "the action template",
            Self::ServiceTemplate => "the service template",
            Self::OrgDefault => "the org default",
            Self::GlobalDefault => "the deployment default",
            Self::Stored => "the approved request",
        }
    }
}

/// Which ceiling, if any, cut the cascade's answer down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutCap {
    None,
    Org,
    Global,
}

/// A resolved timeout, plus enough provenance to explain itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallTimeout {
    ms: u64,
    source: TimeoutSource,
    cap: TimeoutCap,
    requested_ms: u64,
    max_ms: u64,
}

impl CallTimeout {
    pub fn ms(self) -> u64 {
        self.ms
    }

    pub fn duration(self) -> Duration {
        Duration::from_millis(self.ms)
    }

    pub fn source(self) -> TimeoutSource {
        self.source
    }

    /// The tightest ceiling that applied — the number a caller would have to
    /// get raised to ask for more. Carried on the resolved value so the 504
    /// can name it without re-deriving the layers.
    pub fn max_ms(self) -> u64 {
        self.max_ms
    }

    /// One human-readable sentence naming the value, who set it, and whether
    /// it was clamped. Goes in the 504 hint and in `tracing` fields.
    pub fn describe(self) -> String {
        let base = format!("{}ms, set by {}", self.ms, self.source.label());
        match self.cap {
            TimeoutCap::None => base,
            TimeoutCap::Org => {
                format!(
                    "{base} (clamped from {}ms by the org maximum)",
                    self.requested_ms
                )
            }
            TimeoutCap::Global => format!(
                "{base} (clamped from {}ms by the deployment maximum)",
                self.requested_ms
            ),
        }
    }
}

/// Why a caller-supplied `timeout_ms` was refused.
///
/// Only ever produced for rung 1 — every other rung clamps instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TimeoutRejected {
    #[error(
        "timeout_ms {requested_ms} exceeds the maximum call timeout for this org ({max_ms}). \
         Lower it, or raise the org's max_call_timeout_ms"
    )]
    AboveMax { requested_ms: u64, max_ms: u64 },
    #[error("timeout_ms must be greater than zero")]
    Zero,
}

/// Reconcile every layer into the single duration the transport will use.
///
/// `global_default_ms` and `global_max_ms` come from [`crate::config::Config`]
/// and are passed rather than read so this stays a pure function.
pub fn resolve(
    layers: TimeoutLayers,
    global_default_ms: u64,
    global_max_ms: u64,
) -> Result<CallTimeout, TimeoutRejected> {
    // The tightest ceiling in play. Both are ceilings rather than defaults, so
    // unlike the cascade below they combine by `min`, not by specificity — an
    // org cannot raise itself above what the deployment allows.
    let effective_max = layers
        .org_max_ms
        .map_or(global_max_ms, |o| o.min(global_max_ms));

    if let Some(requested) = layers.per_call_ms {
        if requested == 0 {
            return Err(TimeoutRejected::Zero);
        }
        if requested > effective_max {
            return Err(TimeoutRejected::AboveMax {
                requested_ms: requested,
                max_ms: effective_max,
            });
        }
        return Ok(CallTimeout {
            ms: requested,
            source: TimeoutSource::PerCall,
            cap: TimeoutCap::None,
            requested_ms: requested,
            max_ms: effective_max,
        });
    }

    let (requested, source) = layers
        .action_ms
        .map(|ms| (ms, TimeoutSource::ActionTemplate))
        .or_else(|| {
            layers
                .service_ms
                .map(|ms| (ms, TimeoutSource::ServiceTemplate))
        })
        .or_else(|| {
            layers
                .org_default_ms
                .map(|ms| (ms, TimeoutSource::OrgDefault))
        })
        .unwrap_or((global_default_ms, TimeoutSource::GlobalDefault));

    Ok(clamp(requested, source, layers.org_max_ms, global_max_ms))
}

/// Re-apply the caps to a timeout that was resolved when an approval was
/// created, possibly long ago.
///
/// Replay cannot re-run the cascade: the stored payload carries the resolved
/// number, not the action key the template layers were read from. What it
/// *can* do is re-clamp, so an org that tightened its maximum after granting
/// an approval has that tightening bind retroactively — the alternative is a
/// stale approval that outranks current policy.
///
/// A stored `None` is a pre-D56 approval; it falls through to the deployment
/// default rather than to "unbounded".
pub fn reclamp_stored(
    stored_ms: Option<u64>,
    org_max_ms: Option<u64>,
    global_default_ms: u64,
    global_max_ms: u64,
) -> CallTimeout {
    match stored_ms {
        Some(ms) => clamp(ms, TimeoutSource::Stored, org_max_ms, global_max_ms),
        None => clamp(
            global_default_ms,
            TimeoutSource::GlobalDefault,
            org_max_ms,
            global_max_ms,
        ),
    }
}

/// Cut `requested` down to the tightest ceiling, recording which one bit.
///
/// The org cap is checked first so that when both would clamp, the resulting
/// message names the ceiling the org admin can actually do something about.
fn clamp(
    requested: u64,
    source: TimeoutSource,
    org_max_ms: Option<u64>,
    global_max_ms: u64,
) -> CallTimeout {
    let mut ms = requested;
    let mut cap = TimeoutCap::None;

    if let Some(org_max) = org_max_ms
        && ms > org_max
    {
        ms = org_max;
        cap = TimeoutCap::Org;
    }
    if ms > global_max_ms {
        ms = global_max_ms;
        cap = TimeoutCap::Global;
    }

    if cap != TimeoutCap::None {
        // Not an error — see the module docs on why defaults clamp rather than
        // reject — but it is always a misconfiguration worth a line in the log.
        tracing::warn!(
            requested_ms = requested,
            resolved_ms = ms,
            ?source,
            "call timeout clamped to the configured maximum"
        );
    }

    CallTimeout {
        ms,
        source,
        cap,
        requested_ms: requested,
        max_ms: org_max_ms.map_or(global_max_ms, |o| o.min(global_max_ms)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GLOBAL_DEFAULT: u64 = 30_000;
    const GLOBAL_MAX: u64 = 110_000;

    fn resolved(layers: TimeoutLayers) -> CallTimeout {
        resolve(layers, GLOBAL_DEFAULT, GLOBAL_MAX).expect("layers resolve")
    }

    #[test]
    fn falls_all_the_way_through_to_the_deployment_default() {
        let t = resolved(TimeoutLayers::default());
        assert_eq!(t.ms(), GLOBAL_DEFAULT);
        assert_eq!(t.source(), TimeoutSource::GlobalDefault);
    }

    #[test]
    fn org_default_beats_the_deployment_default() {
        let t = resolved(TimeoutLayers {
            org_default_ms: Some(45_000),
            ..Default::default()
        });
        assert_eq!(t.ms(), 45_000);
        assert_eq!(t.source(), TimeoutSource::OrgDefault);
    }

    #[test]
    fn service_template_beats_the_org_default() {
        let t = resolved(TimeoutLayers {
            service_ms: Some(60_000),
            org_default_ms: Some(45_000),
            ..Default::default()
        });
        assert_eq!(t.ms(), 60_000);
        assert_eq!(t.source(), TimeoutSource::ServiceTemplate);
    }

    #[test]
    fn action_template_beats_the_service_template() {
        let t = resolved(TimeoutLayers {
            action_ms: Some(90_000),
            service_ms: Some(60_000),
            org_default_ms: Some(45_000),
            ..Default::default()
        });
        assert_eq!(t.ms(), 90_000);
        assert_eq!(t.source(), TimeoutSource::ActionTemplate);
    }

    #[test]
    fn per_call_beats_every_other_rung() {
        let t = resolved(TimeoutLayers {
            per_call_ms: Some(15_000),
            action_ms: Some(90_000),
            service_ms: Some(60_000),
            org_default_ms: Some(45_000),
            org_max_ms: None,
        });
        assert_eq!(t.ms(), 15_000);
        assert_eq!(t.source(), TimeoutSource::PerCall);
    }

    #[test]
    fn org_max_clamps_a_template_value_without_changing_its_source() {
        let t = resolved(TimeoutLayers {
            action_ms: Some(90_000),
            org_max_ms: Some(50_000),
            ..Default::default()
        });
        assert_eq!(t.ms(), 50_000);
        // The action template is still what *set* the timeout; the org only
        // trimmed it. Reporting `OrgDefault` here would send someone hunting
        // through org settings for a number that lives in a template.
        assert_eq!(t.source(), TimeoutSource::ActionTemplate);
        assert!(
            t.describe()
                .contains("clamped from 90000ms by the org maximum")
        );
    }

    #[test]
    fn global_max_clamps_when_the_org_sets_none() {
        let t = resolved(TimeoutLayers {
            action_ms: Some(500_000),
            ..Default::default()
        });
        assert_eq!(t.ms(), GLOBAL_MAX);
        assert!(t.describe().contains("deployment maximum"));
    }

    #[test]
    fn an_org_max_above_the_global_max_cannot_raise_the_ceiling() {
        let t = resolved(TimeoutLayers {
            action_ms: Some(500_000),
            org_max_ms: Some(600_000),
            ..Default::default()
        });
        assert_eq!(t.ms(), GLOBAL_MAX);
    }

    #[test]
    fn org_default_above_the_org_max_clamps_rather_than_erroring() {
        // Reachable despite the DB CHECK: the org max can be lowered while a
        // higher default is already stored under an older constraint, and the
        // resolver must not start 500ing every call in the org if it happens.
        let t = resolved(TimeoutLayers {
            org_default_ms: Some(90_000),
            org_max_ms: Some(40_000),
            ..Default::default()
        });
        assert_eq!(t.ms(), 40_000);
        assert_eq!(t.source(), TimeoutSource::OrgDefault);
    }

    #[test]
    fn per_call_above_the_effective_max_is_refused_naming_the_effective_max() {
        let err = resolve(
            TimeoutLayers {
                per_call_ms: Some(200_000),
                org_max_ms: Some(50_000),
                ..Default::default()
            },
            GLOBAL_DEFAULT,
            GLOBAL_MAX,
        )
        .expect_err("above the cap");
        // The org max, not the global one — it is the tighter of the two and
        // the one the caller has to get raised.
        assert_eq!(
            err,
            TimeoutRejected::AboveMax {
                requested_ms: 200_000,
                max_ms: 50_000
            }
        );
    }

    #[test]
    fn per_call_exactly_at_the_max_is_allowed() {
        let t = resolved(TimeoutLayers {
            per_call_ms: Some(GLOBAL_MAX),
            ..Default::default()
        });
        assert_eq!(t.ms(), GLOBAL_MAX);
    }

    #[test]
    fn per_call_zero_is_refused_rather_than_treated_as_absent() {
        let err = resolve(
            TimeoutLayers {
                per_call_ms: Some(0),
                ..Default::default()
            },
            GLOBAL_DEFAULT,
            GLOBAL_MAX,
        )
        .expect_err("zero");
        assert_eq!(err, TimeoutRejected::Zero);
    }

    #[test]
    fn stored_replay_value_is_reclamped_by_a_tightened_org_max() {
        let t = reclamp_stored(Some(90_000), Some(40_000), GLOBAL_DEFAULT, GLOBAL_MAX);
        assert_eq!(t.ms(), 40_000);
        assert_eq!(t.source(), TimeoutSource::Stored);
    }

    #[test]
    fn a_pre_d55_approval_replays_at_the_deployment_default_not_unbounded() {
        let t = reclamp_stored(None, None, GLOBAL_DEFAULT, GLOBAL_MAX);
        assert_eq!(t.ms(), GLOBAL_DEFAULT);
        assert_eq!(t.source(), TimeoutSource::GlobalDefault);
    }

    #[test]
    fn describe_names_the_source_when_nothing_clamped() {
        let t = resolved(TimeoutLayers {
            per_call_ms: Some(15_000),
            ..Default::default()
        });
        assert_eq!(t.describe(), "15000ms, set by the request");
    }
}
