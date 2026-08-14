//! Action execution metrics — `mode` on the execution/validation series is
//! the call shape: `action` (Service + defined action), `verb` (Service +
//! HTTP verb, SPEC §8 — raw HTTP rides on this via the `http`
//! pseudo-service), or `replay` (approval replay). `template_key` is the
//! registry-bounded service template identifier.

use std::time::Duration;

use metrics::{counter, histogram};

/// Record one action execution. `status` is one of:
/// `"called"`, `"upstream_error"` (transport succeeded but the upstream
/// itself failed — MCP in-band `is_error: true` or an upstream HTTP 5xx;
/// `"failed"` stays reserved for Overslash's own 5xx), `"rejected"`,
/// `"failed"`, `"approval_required"`, `"filtered"`, `"denied"`. `mode` is
/// `"action"`, `"verb"`, or `"replay"` (approval replay, where the
/// original call shape isn't stored).
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

/// Record one dry-run validation call (`POST /v1/actions/validate`).
/// `outcome` is one of: `"validated"` (args ok and permission allowed),
/// `"invalid_args"` (400), `"would_require_approval"`, `"denied"`,
/// `"exceeds_ceiling"`, `"rejected"` (other 4xx), `"failed"` (5xx).
pub fn record_validation(template_key: &str, mode: &str, outcome: &str, elapsed: Duration) {
    counter!(
        "overslash_action_validations_total",
        "template_key" => template_key.to_string(),
        "mode" => mode.to_string(),
        "outcome" => outcome.to_string(),
    )
    .increment(1);
    histogram!(
        "overslash_action_validation_duration_seconds",
        "template_key" => template_key.to_string(),
        "mode" => mode.to_string(),
    )
    .record(elapsed.as_secs_f64());
}

/// Record one upstream response received by an action execution. Emitted
/// only when an upstream response actually arrived — transport-level
/// failures (connect/TLS errors, MCP transport/RPC errors) record nothing
/// here; they surface through the `AppError` → 502 path and
/// `record_execution(status = "failed")`. This is what makes an upstream
/// outage distinguishable from Overslash's own errors: gateway health lives
/// on `run.googleapis.com/request_count`, upstream health lives here.
///
/// Labels:
/// * `template_key` — registry-bounded service key (same bounding rules as
///   [`record_execution`]: unknown keys collapse to `"_unknown"`).
/// * `mode` — the *runtime* that produced the response: `"http"` | `"mcp"`.
///   Deliberately a different label space than `record_execution`'s `mode`
///   (call shape: `action`/`verb`/`replay`) — don't try to reconcile them.
/// * `status_class` — HTTP runtime: `"2xx"`..`"5xx"` from the upstream
///   status (via [`status_class`]). MCP runtime: `"2xx"` when the tool
///   succeeded, `"error"` when it returned the in-band `is_error: true`.
pub fn record_upstream_response(template_key: &str, mode: &str, status_class: &str) {
    counter!(
        "overslash_upstream_responses_total",
        "template_key" => template_key.to_string(),
        "mode" => mode.to_string(),
        "status_class" => status_class.to_string(),
    )
    .increment(1);
}

/// One `execution: "hybrid"` call, by which branch answered the connection.
///
/// Labels:
/// * `template_key` — registry-bounded service key, same rules as
///   [`record_execution`].
/// * `outcome` — `"inline"` (beat the handoff, answered `called`),
///   `"inline_failed"` (failed before the handoff, answered with an error),
///   `"handed_off"` (answered `accepted`, job still running), or
///   `"queued_saturated"` (the in-flight cap was reached, so the call went onto
///   the ordinary async queue instead).
///
/// Deliberately *not* a new value on [`record_execution`]'s `mode`, which is the
/// call *shape* (`action`/`verb`/`replay`). A hybrid call keeps its shape there;
/// this is a separate question about the same call.
pub fn record_hybrid_outcome(template_key: &str, outcome: &str) {
    counter!(
        "overslash_hybrid_calls_total",
        "template_key" => template_key.to_string(),
        "outcome" => outcome.to_string(),
    )
    .increment(1);
}

/// How long a handed-off hybrid call held its connection before answering 202.
///
/// Separate from `overslash_action_execution_duration_seconds` on purpose:
/// folding handed-off calls into that histogram fills it with samples clustered
/// at the configured handoff, so its p99 becomes a reading of the deployment's
/// own config rather than of its upstreams. This series is what
/// `HYBRID_HANDOFF_MS` is actually tuned against.
pub fn record_hybrid_handoff_seconds(elapsed: Duration) {
    histogram!("overslash_hybrid_handoff_seconds").record(elapsed.as_secs_f64());
}

/// An action's `x-overslash-wait-mode` was dropped and the call ran
/// synchronously instead.
///
/// The one path where a template says one thing and the gateway does another
/// without telling the caller, which is exactly why it is counted. A rising
/// series here means a template is declaring a mode it can never get — the
/// author's own mistake, invisible to them by construction, since every
/// affected call still returns 200.
///
/// Deliberately unlabelled by template: `reason` is a closed set of six, while
/// a template dimension would grow with the catalog on a series that should
/// normally sit at zero.
pub fn record_wait_mode_demotion(reason: &'static str) {
    counter!(
        "overslash_wait_mode_demoted_total",
        "reason" => reason,
    )
    .increment(1);
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
        record_execution("svc", "verb", "called", std::time::Duration::from_millis(1));
        record_upstream_response("svc", "http", "2xx");
        record_upstream_response("svc", "mcp", "error");
    }
}
