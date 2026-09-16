//! Prometheus metrics for Overslash.
//!
//! Owns the global recorder install, the `/internal/metrics` Axum endpoint,
//! the HTTP golden-signals middleware, and small helper functions for each
//! domain area. Helpers exist so callsites stay one-liners with stable label
//! names — every label value should be a bounded enum or a known
//! provider/template key, never an org id, identity id, or secret name.

pub mod actions;
pub mod approvals;
pub mod background;
pub mod db;
pub mod http;
pub mod oauth;
pub mod permissions;
pub mod rate_limit;
pub mod resolve_cache;
pub mod search;
pub mod secrets;
pub mod webhooks;

use std::sync::OnceLock;
use std::time::Duration;

use axum::{Router, extract::State, routing::get};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Bucket bounds for `overslash_http_request_duration_seconds`, in seconds.
///
/// Without an explicit bucket set, `metrics-exporter-prometheus` renders every
/// histogram as a Prometheus *summary* — `{quantile="0.99"}` plus `_sum` and
/// `_count`, and no `_bucket` series at all. A summary's quantiles are computed
/// per process over a sliding window, so they cannot be aggregated across Cloud
/// Run instances and `histogram_quantile()` has nothing to read. The `api-use`
/// dashboard's "p99 Request Duration by Path" widget and the `[P1] API Slow
/// Requests` alert both query `_bucket`, so these bounds are what make either
/// one work at all.
///
/// `2.5` must stay in this list: it is the alert's threshold, and a
/// ratio-over-threshold alert is only exact when it lands on a real bucket edge.
const HTTP_LATENCY_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
];

/// Bucket bounds for `overslash_action_execution_duration_seconds`, in seconds.
///
/// Sized to the D56 timeout ladder rather than to the HTTP bounds above: this
/// histogram measures an upstream call, whose ceiling is `CALL_TIMEOUT_MS`
/// (pinned to 110s in production) and never the tens of milliseconds the
/// gateway's own routes run in. Feeds the actions dashboard's p99-by-template
/// widget; no alert is attached.
const ACTION_DURATION_BUCKETS: &[f64] =
    &[0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0, 30.0, 60.0, 120.0];

/// Install the global Prometheus recorder on first call; subsequent calls
/// return the same handle. Idempotent so tests that build many app routers
/// in one process don't fight over the global recorder.
///
/// Also spawns the upkeep task that drains histogram buckets every 5s.
/// `install_recorder` does NOT do this on its own (unlike `install()`,
/// which requires the builder to own its own runtime); without upkeep,
/// histogram memory grows unboundedly under sustained traffic.
pub fn setup() -> PrometheusHandle {
    HANDLE
        .get_or_init(|| {
            // `Matcher::Full` per metric, never a `Matcher::Suffix`
            // ("_duration_seconds") blanket: one bucket set cannot serve both
            // `overslash_resolve_cache_op_duration_seconds` (microseconds — every
            // sample would land in the first bucket) and
            // `overslash_approval_resolution_duration_seconds` (human wall-clock
            // hours — every sample would land in `+Inf`). Metrics not named here
            // stay summaries, which is correct for them.
            let handle = PrometheusBuilder::new()
                .set_buckets_for_metric(
                    Matcher::Full("overslash_http_request_duration_seconds".to_owned()),
                    HTTP_LATENCY_BUCKETS,
                )
                .expect("HTTP latency buckets are non-empty")
                .set_buckets_for_metric(
                    Matcher::Full("overslash_action_execution_duration_seconds".to_owned()),
                    ACTION_DURATION_BUCKETS,
                )
                .expect("action duration buckets are non-empty")
                .install_recorder()
                .expect("failed to install Prometheus recorder");
            spawn_upkeep(handle.clone(), Duration::from_secs(5));
            handle
        })
        .clone()
}

fn spawn_upkeep(handle: PrometheusHandle, interval: Duration) {
    // Best-effort: only spawn if a tokio runtime is present (always true in
    // production paths; some unit tests build the recorder outside a runtime).
    if tokio::runtime::Handle::try_current().is_err() {
        return;
    }
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            handle.run_upkeep();
        }
    });
}

/// Render the current metric snapshot as Prometheus text format.
pub async fn metrics_handler(State(handle): State<PrometheusHandle>) -> String {
    handle.render()
}

/// Router exposing `/internal/metrics`. Mount this at the app root, outside
/// any auth, rate-limiting, or subdomain middleware — the GMP / OTel sidecar
/// scrapes it over loopback and must never be gated.
pub fn metrics_router(handle: PrometheusHandle) -> Router {
    Router::new()
        .route("/internal/metrics", get(metrics_handler))
        .with_state(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn setup_is_idempotent() {
        // The global recorder may only be installed once per process. Calling
        // `setup` twice must not panic — tests build many app routers in one
        // process and rely on this. We can't compare rendered output across
        // calls here because other tests in this binary share the same global
        // recorder and may emit between renders.
        let _ = setup();
        let _ = setup();
    }

    #[tokio::test]
    async fn http_duration_renders_as_a_bucketed_histogram_not_a_summary() {
        // `metrics-exporter-prometheus` renders a histogram as a *summary*
        // unless buckets are set for it, and a summary has no `_bucket` series
        // and no `le` label. Both the `api-use` dashboard widget and the
        // `[P1] API Slow Requests` alert query `_bucket`, so a refactor that
        // drops `set_buckets_for_metric` would silently blank the dashboard and
        // leave the alert unable to fire — with nothing failing anywhere. This
        // test is the tripwire for that.
        let handle = setup();
        metrics::histogram!(
            "overslash_http_request_duration_seconds",
            "method" => "GET",
            "path" => "/v1/test",
        )
        .record(0.42);
        let text = handle.render();
        assert!(
            text.contains("overslash_http_request_duration_seconds_bucket{"),
            "expected a bucketed histogram, got: {text}",
        );
        assert!(
            text.contains(r#"le="2.5""#),
            "expected the alert's 2.5s bucket edge to exist verbatim, got: {text}",
        );
        assert!(
            !text.contains(r#"overslash_http_request_duration_seconds{quantile="#),
            "metric regressed to a Prometheus summary: {text}",
        );
        // The alert's denominator and its rate guard both read `_count`, and
        // every one of its label matchers is on `path`. Pinned here because a
        // drift in either spelling would leave the alert parsing fine and
        // matching nothing — failing open, silently.
        assert!(
            text.contains("overslash_http_request_duration_seconds_count{"),
            "alert denominator series missing: {text}",
        );
        assert!(
            text.contains(r#"path="/v1/test""#),
            "expected a `path` label the alert can exclude on, got: {text}",
        );
    }

    #[tokio::test]
    async fn metrics_endpoint_renders_prometheus_text() {
        let handle = setup();
        metrics::counter!("overslash_test_counter").increment(7);
        let app = metrics_router(handle);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/internal/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            text.contains("overslash_test_counter"),
            "metrics output missing counter: {text}",
        );
    }
}
