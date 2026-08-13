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
pub fn resolve_handoff(
    per_call_ms: Option<u64>,
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
        // Deployment default: clamped, never refused.
        //
        // Clamping to the budget is correct rather than degenerate. A call
        // whose own timeout is shorter than the deployment's handoff cannot
        // outrun it, so the timer never wins and the call always answers
        // `called` or an error — which is exactly what a short-budget call
        // should do.
        None => cfg.hybrid_handoff_ms.min(budget_ms),
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
        let d = resolve_handoff(None, &cfg(), 600_000, 110_000).unwrap();
        assert_eq!(d, Duration::from_millis(5_000));
    }

    #[test]
    fn a_caller_value_within_the_ceiling_is_honoured() {
        let d = resolve_handoff(Some(12_000), &cfg(), 600_000, 110_000).unwrap();
        assert_eq!(d, Duration::from_millis(12_000));
    }

    #[test]
    fn a_caller_value_above_the_maximum_is_refused_not_clamped() {
        let err = resolve_handoff(Some(45_000), &cfg(), 600_000, 110_000).unwrap_err();
        assert!(err.to_string().contains("exceeds the maximum"), "{err}");
    }

    #[test]
    fn a_caller_value_at_or_past_the_budget_is_refused() {
        // Equal is refused too: a handoff that fires exactly as the call times
        // out is a coin flip between two response shapes.
        let err = resolve_handoff(Some(9_000), &cfg(), 9_000, 110_000).unwrap_err();
        assert!(err.to_string().contains("not less than"), "{err}");
    }

    #[test]
    fn a_deployment_default_past_the_budget_is_clamped_instead() {
        // The same relationship the test above refuses, but from a default the
        // caller never saw — so it narrows silently rather than 400s.
        let d = resolve_handoff(None, &cfg(), 2_000, 110_000).unwrap();
        assert_eq!(d, Duration::from_millis(2_000));
    }

    #[test]
    fn the_sync_ceiling_bounds_even_an_accepted_caller_value() {
        let wide = AsyncExecutionConfig {
            hybrid_handoff_max_ms: 300_000,
            ..cfg()
        };
        let d = resolve_handoff(Some(200_000), &wide, 600_000, 110_000).unwrap();
        assert_eq!(d, Duration::from_millis(110_000));
    }
}
