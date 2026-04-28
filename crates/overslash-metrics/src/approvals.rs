//! Approval lifecycle metrics.

use std::time::Duration;

use metrics::{counter, gauge, histogram};

/// `event` ∈ {`created`, `approved`, `denied`, `expired`, `auto_bubbled`,
/// `called`, `cancelled`}.
/// `identity_kind` ∈ {`user`, `agent`, `subagent`, `system`}.
/// `system` covers events emitted by background loops (e.g. expiry sweeps)
/// where there is no caller identity in scope.
pub fn record_event(event: &str, identity_kind: &str) {
    counter!(
        "overslash_approval_events_total",
        "event" => event.to_string(),
        "identity_kind" => identity_kind.to_string(),
    )
    .increment(1);
}

/// `decision` ∈ {`approved`, `denied`, `expired`}.
pub fn record_resolution(decision: &str, age: Duration) {
    histogram!(
        "overslash_approval_resolution_duration_seconds",
        "decision" => decision.to_string(),
    )
    .record(age.as_secs_f64());
}

/// Set the in-process count of currently pending approvals. The exporter
/// also publishes this as a business metric; this gauge is the fast view.
pub fn set_pending(count: f64) {
    gauge!("overslash_approvals_pending").set(count);
}

/// Convert a `time::Duration` into a `std::time::Duration` for histogram
/// recording, clamping negative values (clock skew, created_at in the future)
/// to zero. Histograms reject NaN/negatives, so the conversion can't be a
/// raw `try_into` at call sites.
pub fn duration_since(diff: time::Duration) -> std::time::Duration {
    diff.try_into().unwrap_or(std::time::Duration::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_since_clamps_negative() {
        let neg = time::Duration::seconds(-30);
        assert_eq!(duration_since(neg), std::time::Duration::ZERO);
    }

    #[test]
    fn duration_since_passes_positive() {
        let pos = time::Duration::milliseconds(2500);
        assert_eq!(duration_since(pos), std::time::Duration::from_millis(2500));
    }

    #[test]
    fn duration_since_zero() {
        assert_eq!(
            duration_since(time::Duration::ZERO),
            std::time::Duration::ZERO
        );
    }
}
