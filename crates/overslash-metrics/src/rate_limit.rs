//! Rate-limit decision metrics.

use metrics::counter;

/// `scope` ∈ {`org`, `group`, `user`, `identity_cap`, `unscoped`, `free_unlimited`}.
/// `free_unlimited` is emitted (always with `allow`) when the rate-limit
/// middleware bypasses limits for an org marked `plan='free_unlimited'`.
/// `decision` ∈ {`allow`, `deny`}.
pub fn record_decision(scope: &str, decision: &str) {
    counter!(
        "overslash_rate_limit_decisions_total",
        "scope" => scope.to_string(),
        "decision" => decision.to_string(),
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_decision_does_not_panic() {
        record_decision("user", "allow");
        record_decision("identity_cap", "deny");
    }
}
