//! Upstream-vs-gateway metrics for HTTP-runtime actions: an upstream 5xx
//! must record `overslash_upstream_responses_total{status_class="5xx"}` and
//! reclassify the execution as `status="upstream_error"` — never plain
//! `called` (buffered envelope) or `failed` (streamed passthrough), which
//! would make an upstream outage indistinguishable from Overslash's own
//! errors. The MCP-runtime equivalents live in `mcp_external.rs` /
//! `mcp_replay.rs`.

use crate::common;

use std::net::SocketAddr;

use axum::{Router, http::StatusCode, routing::any};
use serde_json::{Value, json};
use tokio::net::TcpListener;

/// Minimal upstream stub: `/boom` answers 500, `/ok` answers 200.
async fn start_5xx_stub() -> SocketAddr {
    let app = Router::new()
        .route(
            "/boom",
            any(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "upstream down") }),
        )
        .route("/ok", any(|| async { (StatusCode::OK, "fine") }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// Buffered raw-HTTP call whose upstream answers 500: the gateway response
/// stays a 200 envelope (status passthrough is in-band), but metrics must
/// say `upstream_error` + `status_class="5xx"`.
#[tokio::test]
async fn http_buffered_upstream_5xx_records_upstream_error() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let stub = start_5xx_stub().await;
    let (api_addr, client) = common::start_api(pool).await;
    let base = format!("http://{api_addr}");
    let (_user, _ident, api_key) = common::bootstrap_agent_on_fixtures(&base, &client, &fx).await;

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "service": "http",
            "method": "GET",
            "url": format!("http://{stub}/boom"),
        }))
        .send()
        .await
        .unwrap();

    // The gateway itself succeeded — the upstream failure is in-band.
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["result"]["status_code"], 500);

    let metrics = common::scrape_metrics(&base, &client).await;
    assert!(
        common::has_metric_series(
            &metrics,
            "overslash_upstream_responses_total",
            &[
                ("template_key", "http"),
                ("mode", "http"),
                ("status_class", "5xx"),
            ],
        ),
        "expected http 5xx upstream series in:\n{metrics}"
    );
    assert!(
        common::has_metric_series(
            &metrics,
            "overslash_action_executions_total",
            &[
                ("template_key", "http"),
                ("mode", "verb"),
                ("status", "upstream_error"),
            ],
        ),
        "expected upstream_error execution series in:\n{metrics}"
    );
}

/// Streamed call with an upstream 500: the 5xx passes straight through to
/// the caller, but the execution must record `upstream_error` — not
/// `failed`, which is reserved for Overslash's own errors.
#[tokio::test]
async fn http_streamed_upstream_5xx_records_upstream_error_not_failed() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let stub = start_5xx_stub().await;
    let (api_addr, client) = common::start_api(pool).await;
    let base = format!("http://{api_addr}");
    let (_user, _ident, api_key) = common::bootstrap_agent_on_fixtures(&base, &client, &fx).await;

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "service": "http",
            "method": "GET",
            "url": format!("http://{stub}/boom"),
            "prefer_stream": true,
        }))
        .send()
        .await
        .unwrap();

    // Streaming proxies the upstream status through.
    assert_eq!(resp.status(), 500);

    let metrics = common::scrape_metrics(&base, &client).await;
    assert!(
        common::has_metric_series(
            &metrics,
            "overslash_upstream_responses_total",
            &[
                ("template_key", "http"),
                ("mode", "http"),
                ("status_class", "5xx"),
            ],
        ),
        "expected http 5xx upstream series in:\n{metrics}"
    );
    assert!(
        common::has_metric_series(
            &metrics,
            "overslash_action_executions_total",
            &[
                ("template_key", "http"),
                ("mode", "verb"),
                ("status", "upstream_error"),
            ],
        ),
        "expected upstream_error execution series in:\n{metrics}"
    );
}

/// Happy-path control: a 2xx upstream records `status_class="2xx"` and the
/// execution stays `called`.
#[tokio::test]
async fn http_upstream_2xx_stays_called() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let stub = start_5xx_stub().await;
    let (api_addr, client) = common::start_api(pool).await;
    let base = format!("http://{api_addr}");
    let (_user, _ident, api_key) = common::bootstrap_agent_on_fixtures(&base, &client, &fx).await;

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "service": "http",
            "method": "GET",
            "url": format!("http://{stub}/ok"),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    assert_eq!(body["result"]["status_code"], 200);

    let metrics = common::scrape_metrics(&base, &client).await;
    assert!(
        common::has_metric_series(
            &metrics,
            "overslash_upstream_responses_total",
            &[
                ("template_key", "http"),
                ("mode", "http"),
                ("status_class", "2xx"),
            ],
        ),
        "expected http 2xx upstream series in:\n{metrics}"
    );
}
