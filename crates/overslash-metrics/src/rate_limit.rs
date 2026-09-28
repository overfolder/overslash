//! Rate-limit decision metrics.

use metrics::counter;

/// `scope` ∈ {`org`, `user`, `session`, `identity_cap`, `mcp_client`,
/// `oauth_ip`, `oauth_register_ip`, `free_unlimited`}.
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

/// A first-deny log line dropped because the fleet-wide deny-log budget was
/// spent — the signal that something is minting buckets faster than we will
/// log them. `scope` as in [`record_decision`].
pub fn record_deny_log_suppressed(scope: &str) {
    counter!(
        "overslash_rate_limit_deny_log_suppressed_total",
        "scope" => scope.to_string(),
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
        record_deny_log_suppressed("oauth_ip");
    }
}
