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
pub mod search;
pub mod secrets;
pub mod webhooks;

use std::sync::OnceLock;

use axum::{Router, extract::State, routing::get};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Install the global Prometheus recorder on first call; subsequent calls
/// return the same handle. Idempotent so tests that build many app routers
/// in one process don't fight over the global recorder.
pub fn setup() -> PrometheusHandle {
    HANDLE
        .get_or_init(|| {
            PrometheusBuilder::new()
                .install_recorder()
                .expect("failed to install Prometheus recorder")
        })
        .clone()
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
        // process and rely on this.
        let h1 = setup();
        let h2 = setup();
        assert_eq!(h1.render(), h2.render());
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
