//! OAuth flow metrics — bounded by `provider` (DB-managed key) and `flow`
//! enum. `status` is `"success"` or `"failure"`.

use std::time::Duration;

use metrics::{counter, histogram};

/// `flow` ∈ {`authorize`, `callback`, `token`, `refresh`, `dcr`, `revoke`}.
pub fn record_event(provider: &str, flow: &str, status: &str) {
    counter!(
        "overslash_oauth_events_total",
        "provider" => provider.to_string(),
        "flow" => flow.to_string(),
        "status" => status.to_string(),
    )
    .increment(1);
}

pub fn record_token_refresh(provider: &str, status: &str, elapsed: Duration) {
    histogram!(
        "overslash_oauth_token_refresh_duration_seconds",
        "provider" => provider.to_string(),
        "status" => status.to_string(),
    )
    .record(elapsed.as_secs_f64());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_helpers_do_not_panic() {
        record_event("google", "authorize", "success");
        record_event("github", "callback", "failure");
        record_token_refresh("google", "success", Duration::from_millis(50));
    }
}
