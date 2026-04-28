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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_decision_does_not_panic() {
        record_decision("user", "allow");
        record_decision("identity_cap", "deny");
    }
}
