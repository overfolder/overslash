//! Rate-limit decision metrics.

use metrics::counter;

/// `scope` ∈ {`org`, `group`, `user`, `identity_cap`, `unscoped`}.
/// `decision` ∈ {`allow`, `deny`}.
pub fn record_decision(scope: &str, decision: &str) {
    counter!(
        "overslash_rate_limit_decisions_total",
        "scope" => scope.to_string(),
        "decision" => decision.to_string(),
    )
    .increment(1);
}
