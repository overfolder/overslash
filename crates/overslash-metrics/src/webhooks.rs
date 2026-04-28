//! Webhook delivery metrics.

use metrics::{counter, histogram};

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
