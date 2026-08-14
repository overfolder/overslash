//! Resolving how long a `execution: "hybrid"` call holds its connection.
//!
//! Separate from [`super::call_timeout`] because the two numbers answer
//! different questions and are bounded by different things. The D56 budget is
//! how long the *upstream* may take, and after a handoff no connection is
//! waiting on it — so hybrid resolves it against the async ceiling. The handoff
//! is how long the *caller* waits, and it is bounded by the synchronous
//! connection ceiling no matter what the call's own budget says.

use std::time::Duration;

use crate::config::AsyncExecutionConfig;
use crate::error::AppError;

/// Floor on any resolved handoff.
///
/// A sub-100ms handoff is `execution: "async"` with two extra database writes
/// and none of its guarantees. Values below this are refused rather than
/// rounded up, so a caller who asked for one finds out instead of quietly
/// getting a different mode's behaviour.
const MIN_HANDOFF_MS: u64 = 100;

/// How long this hybrid call may wait on the connection before answering 202.
///
/// The clamp-versus-refuse split is the one `CallRequest::timeout_ms` already
/// makes, and for the same reason: a deployment default is something the caller
/// never saw, so silently narrowing it is the kind answer, while a number the
/// caller typed is a statement of intent and narrowing it would produce a
/// response shape they did not ask for.
/// `budget_ms` is the D56-resolved call timeout — taken as a plain number
/// rather than a [`super::call_timeout::CallTimeout`] because that is all this
/// needs, and it keeps the rules unit-testable without building one.
///
/// `template_ms` is `x-overslash-handoff_after_ms` on the resolved action. It
/// sits between the two existing rungs and takes the *deployment* side of the
/// split, not the caller's: the template author is not present to act on a
/// 400, and an out-of-range value there would otherwise refuse every hybrid
/// call to that action. A template that knows its upstream usually answers in
/// two seconds is the case this rung exists for — waiting the deployment's
/// five is latency nobody chose.
pub fn resolve_handoff(
    per_call_ms: Option<u64>,
    template_ms: Option<u64>,
    cfg: &AsyncExecutionConfig,
    budget_ms: u64,
    sync_ceiling_ms: u64,
) -> Result<Duration, AppError> {
    let ms = match per_call_ms {
        Some(asked) => {
            if asked > cfg.hybrid_handoff_max_ms {
                return Err(AppError::BadRequest(format!(
                    "handoff_after_ms {asked} exceeds the maximum of {} for this deployment",
                    cfg.hybrid_handoff_max_ms
                )));
            }
            if asked < MIN_HANDOFF_MS {
                return Err(AppError::BadRequest(format!(
                    "handoff_after_ms {asked} is below the minimum of {MIN_HANDOFF_MS}ms — \
                     a handoff that short is execution: \"async\" with extra bookkeeping"
                )));
            }
            // A handoff at or past the call's own budget can never fire: the
            // call is over first. Refusing names the contradiction instead of
            // handing back a "hybrid" call that is structurally synchronous.
            if asked >= budget_ms {
                return Err(AppError::BadRequest(format!(
                    "handoff_after_ms {asked} is not less than the call's timeout_ms \
                     {budget_ms} — the call would always finish before the handoff, so \
                     it could never answer 202. Lower handoff_after_ms or raise timeout_ms."
                )));
            }
            asked
        }
        // Template, then deployment default: clamped, never refused.
        //
        // Clamping to the budget is correct rather than degenerate. A call
        // whose own timeout is shorter than the deployment's handoff cannot
        // outrun it, so the timer never wins and the call always answers
        // `called` or an error — which is exactly what a short-budget call
        // should do.
        //
        // The floor applies to the template rung too, and by `max` rather than
        // by refusal: a template asking for a 10ms handoff is asking for
        // `execution: "async"` under another name, and the honest answer to
        // an absent author is the nearest legal value, not a dead action.
        None => template_ms
            .map(|ms| ms.clamp(MIN_HANDOFF_MS, cfg.hybrid_handoff_max_ms))
            .unwrap_or(cfg.hybrid_handoff_ms)
            .min(budget_ms),
    };

    // A handoff longer than the synchronous connection ceiling cannot fire
    // before the proxy cuts the connection, so it would turn a call the caller
    // asked to be answered at N into a 504 at the ceiling.
    Ok(Duration::from_millis(ms.min(sync_ceiling_ms)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> AsyncExecutionConfig {
        AsyncExecutionConfig {
            hybrid_handoff_ms: 5_000,
            hybrid_handoff_max_ms: 30_000,
            ..Default::default()
        }
    }

    #[test]
    fn the_deployment_default_applies_when_the_caller_says_nothing() {
        let d = resolve_handoff(None, None, &cfg(), 600_000, 110_000).unwrap();
        assert_eq!(d, Duration::from_millis(5_000));
    }

    #[test]
    fn a_caller_value_within_the_ceiling_is_honoured() {
        let d = resolve_handoff(Some(12_000), None, &cfg(), 600_000, 110_000).unwrap();
        assert_eq!(d, Duration::from_millis(12_000));
    }

    #[test]
    fn a_caller_value_above_the_maximum_is_refused_not_clamped() {
        let err = resolve_handoff(Some(45_000), None, &cfg(), 600_000, 110_000).unwrap_err();
        assert!(err.to_string().contains("exceeds the maximum"), "{err}");
    }

    #[test]
    fn a_caller_value_at_or_past_the_budget_is_refused() {
        // Equal is refused too: a handoff that fires exactly as the call times
        // out is a coin flip between two response shapes.
        let err = resolve_handoff(Some(9_000), None, &cfg(), 9_000, 110_000).unwrap_err();
        assert!(err.to_string().contains("not less than"), "{err}");
    }

    #[test]
    fn a_deployment_default_past_the_budget_is_clamped_instead() {
        // The same relationship the test above refuses, but from a default the
        // caller never saw — so it narrows silently rather than 400s.
        let d = resolve_handoff(None, None, &cfg(), 2_000, 110_000).unwrap();
        assert_eq!(d, Duration::from_millis(2_000));
    }

    #[test]
    fn the_template_rung_beats_the_deployment_default() {
        let d = resolve_handoff(None, Some(2_000), &cfg(), 600_000, 110_000).unwrap();
        assert_eq!(d, Duration::from_millis(2_000));
    }

    #[test]
    fn a_caller_value_beats_the_template_rung() {
        let d = resolve_handoff(Some(12_000), Some(2_000), &cfg(), 600_000, 110_000).unwrap();
        assert_eq!(d, Duration::from_millis(12_000));
    }

    #[test]
    fn a_template_value_out_of_range_is_clamped_not_refused() {
        // Both directions. The caller-supplied twins of these two are 400s;
        // the template author is not present to act on one, and refusing would
        // take every hybrid call to the action down over a number that was
        // inert before the key existed.
        let d = resolve_handoff(None, Some(45_000), &cfg(), 600_000, 110_000).unwrap();
        assert_eq!(d, Duration::from_millis(30_000), "above the maximum");
        let d = resolve_handoff(None, Some(10), &cfg(), 600_000, 110_000).unwrap();
        assert_eq!(d, Duration::from_millis(MIN_HANDOFF_MS), "below the floor");
    }

    #[test]
    fn a_template_value_past_the_budget_is_clamped_to_it() {
        // The caller-supplied twin is the "not less than" refusal above.
        let d = resolve_handoff(None, Some(20_000), &cfg(), 2_000, 110_000).unwrap();
        assert_eq!(d, Duration::from_millis(2_000));
    }

    #[test]
    fn the_sync_ceiling_bounds_even_an_accepted_caller_value() {
        let wide = AsyncExecutionConfig {
            hybrid_handoff_max_ms: 300_000,
            ..cfg()
        };
        let d = resolve_handoff(Some(200_000), None, &wide, 600_000, 110_000).unwrap();
        assert_eq!(d, Duration::from_millis(110_000));
    }

    /// The wall-clock sweep must always sit *past* the largest budget the
    /// resolver can hand out, for every value of `ASYNC_CALL_TIMEOUT_MAX_MS`.
    ///
    /// `fail_async_over_wall` deliberately carries no `triggered_by` guard —
    /// unlike the two reclaim sweeps, which must exclude hybrid because they
    /// set `pending` and that is the re-dial hybrid forbids. This one sets
    /// `failed`, which is terminal and safe, and it is the only thing that can
    /// reap a hybrid job alive enough to heartbeat but wedged on an upstream
    /// (no expired lease, so `fail_expired_hybrid_leases` cannot see it).
    ///
    /// What makes that safe is arithmetic rather than an operator's care: the
    /// wall is *derived from* the same knob that caps the budget, so raising
    /// the cap raises the wall by the same amount plus the grace. There is no
    /// configuration in which a healthy job outlives its own wall. This test
    /// is what keeps that true if either formula is ever edited apart.
    #[test]
    fn the_async_wall_always_outlives_the_largest_budget() {
        for max_ms in [1_000_u64, 30_000, 110_000, 900_000, 3_600_000, 86_400_000] {
            let mut cfg = crate::config::tests::empty_test_config();
            cfg.async_execution.call_timeout_max_ms = max_ms;

            let budget_secs = max_ms as i64 / 1_000;
            let sweep_secs = cfg.async_orphan_grace_secs();

            assert!(
                sweep_secs > budget_secs,
                "at ASYNC_CALL_TIMEOUT_MAX_MS={max_ms} the sweep fires at {sweep_secs}s                  but a job may legitimately run {budget_secs}s"
            );
            // And the job's own timeout must fire first, so the sweep only ever
            // reaches a row whose own guard failed.
            assert!(
                cfg.async_wall_clock().as_secs() as i64 <= sweep_secs,
                "the in-process wall must not outlast the sweep at max_ms={max_ms}"
            );
        }
    }
}
