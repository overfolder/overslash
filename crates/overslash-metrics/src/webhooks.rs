//! Webhook delivery metrics.

use metrics::{counter, histogram};

/// Pre-register the delivery counter so it appears in `/internal/metrics`
/// from the very first scrape — even on an environment where no webhook has
/// been dispatched yet. GCP rejects creating a PromQL alert against a metric
/// that has never been seen in Managed Prometheus, so without this the
/// `webhook_failure_rate` alert can't be applied on a fresh project.
///
/// The seeded series uses a sentinel `event_type="_init"` and `status="success"`
/// so it never matches the alert's `status="failed"` filter.
pub fn init() {
    counter!(
        "overslash_webhook_deliveries_total",
        "event_type" => "_init",
        "status" => "success",
        "final" => "true",
    )
    .increment(0);
}

/// `status` ∈ {`success`, `retry`, `failed`}.
/// `final` is `"true"` once the delivery is terminal (success or exhausted).
pub fn record_delivery(event_type: &str, status: &str, terminal: bool) {
    counter!(
        "overslash_webhook_deliveries_total",
        "event_type" => event_type.to_string(),
        "status" => status.to_string(),
        "final" => terminal.to_string(),
    )
    .increment(1);
}

/// Record how many attempts a delivery took to reach a terminal outcome.
/// `outcome` ∈ {`success`, `exhausted`}.
pub fn record_attempts(event_type: &str, outcome: &str, attempts: u32) {
    histogram!(
        "overslash_webhook_delivery_attempts",
        "event_type" => event_type.to_string(),
        "outcome" => outcome.to_string(),
    )
    .record(f64::from(attempts));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_helpers_do_not_panic() {
        record_delivery("approval.created", "success", true);
        record_delivery("approval.resolved", "retry", false);
        record_delivery("approval.resolved", "failed", true);
        record_attempts("approval.created", "success", 1);
        record_attempts("approval.resolved", "exhausted", 5);
    }
}
