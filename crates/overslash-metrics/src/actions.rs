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
