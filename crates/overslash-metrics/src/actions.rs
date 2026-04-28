//! Action execution metrics — Mode A (raw HTTP), Mode B (connection-based),
//! Mode C (service+action). `template_key` is the OpenAPI service template
//! identifier; for raw HTTP it is the literal `"_raw"`.

use std::time::Duration;

use metrics::{counter, histogram};

/// Record one action execution. `status` is one of:
/// `"called"`, `"failed"`, `"approval_required"`, `"filtered"`, `"denied"`.
pub fn record_execution(template_key: &str, mode: &str, status: &str, elapsed: Duration) {
    counter!(
        "overslash_action_executions_total",
        "template_key" => template_key.to_string(),
        "mode" => mode.to_string(),
        "status" => status.to_string(),
    )
    .increment(1);
    histogram!(
        "overslash_action_execution_duration_seconds",
        "template_key" => template_key.to_string(),
        "mode" => mode.to_string(),
    )
    .record(elapsed.as_secs_f64());
}

/// Record one outbound HTTP call made on behalf of an action.
/// `status_class` is one of `"2xx"`, `"3xx"`, `"4xx"`, `"5xx"`, `"error"`.
pub fn record_outbound(template_key: &str, status_class: &str, elapsed: Duration) {
    counter!(
        "overslash_outbound_http_total",
        "template_key" => template_key.to_string(),
        "status_class" => status_class.to_string(),
    )
    .increment(1);
    histogram!(
        "overslash_outbound_http_duration_seconds",
        "template_key" => template_key.to_string(),
        "status_class" => status_class.to_string(),
    )
    .record(elapsed.as_secs_f64());
}

/// Map a numeric HTTP status to its class label (`"2xx"`, `"4xx"`, etc).
pub fn status_class(code: u16) -> &'static str {
    match code {
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_class_covers_each_band() {
        assert_eq!(status_class(200), "2xx");
        assert_eq!(status_class(204), "2xx");
        assert_eq!(status_class(301), "3xx");
        assert_eq!(status_class(404), "4xx");
        assert_eq!(status_class(503), "5xx");
        assert_eq!(status_class(99), "other");
        assert_eq!(status_class(700), "other");
    }

    #[test]
    fn record_helpers_do_not_panic_without_recorder() {
        // Helpers must be safe to call before the recorder is installed —
        // tests in other modules exercise the same callsites without
        // necessarily having installed the global recorder first.
        record_execution("svc", "a", "called", std::time::Duration::from_millis(1));
        record_outbound("svc", "2xx", std::time::Duration::from_millis(1));
    }
}
