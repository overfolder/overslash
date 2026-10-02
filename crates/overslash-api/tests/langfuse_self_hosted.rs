//! Langfuse's self-hosted read surface.
//!
//! Self-hosted Langfuse (every v3.x release) ships the v4 read handlers but
//! gates them: `GET /api/public/v2/observations` and `/v2/metrics` answer 501
//! or 404, and `/v3/scores` 404s on older releases. What such an instance
//! actually serves is the older surface — `/traces`, `/observations`,
//! `/sessions`, `/metrics`, `/v2/scores`, dataset runs — which Langfuse Cloud
//! sunsets on 2026-11-16. `services/langfuse.yaml` models both; this file
//! covers the self-hosted half.
//!
//! Two things are worth pinning:
//!
//!   1. every action on an old path is a read and opens with the self-hosted
//!      marker, so an agent on Cloud is told to go elsewhere and nobody adds a
//!      write (ingestion, say) to a surface that disappears on a date;
//!   2. the page-number lists walk, and `list_traces` sends its narrow
//!      `fields` default — Langfuse returns every field group when it is
//!      absent, whole prompts and completions included.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{Router, extract::State, response::IntoResponse, routing::any};
use serde_json::{Value, json};

use crate::common;
use crate::langfuse::{call, expected_basic, setup, shipped_registry, url_param};

/// The phrase every self-hosted action's description opens with. Agents read
/// it; the test below keys on it.
const MARKER: &str = "Self-hosted Langfuse read API.";

/// Paths only the self-hosted surface serves. Langfuse Cloud sunsets every one
/// of them on 2026-11-16.
const OLD_PATHS: &[&str] = &[
    "/api/public/traces",
    "/api/public/traces/{traceId}",
    "/api/public/sessions",
    "/api/public/sessions/{sessionId}",
    "/api/public/observations",
    "/api/public/observations/{observationId}",
    "/api/public/v2/scores",
    "/api/public/v2/scores/{scoreId}",
    "/api/public/metrics",
    "/api/public/datasets/{datasetName}/runs",
    "/api/public/datasets/{datasetName}/runs/{runName}",
    "/api/public/dataset-run-items",
    "/api/public/ingestion",
];

// ============================================================================
// Shape
// ============================================================================

/// The old surface is read-only and marked, and the marker means exactly that.
///
/// This is what the template's original "no sunset path" guard became once
/// self-hosted support needed those paths back. The date still matters: an
/// unmarked action on one of them would read to an agent on Cloud as a normal
/// endpoint until 2026-11-16 turns it into a 404 nobody is looking at.
#[test]
fn every_action_on_an_old_path_is_a_marked_self_hosted_read() {
    let reg = shipped_registry();
    let svc = reg.get("langfuse").unwrap();

    let mut marked: Vec<&str> = Vec::new();
    for (key, action) in &svc.actions {
        let on_old_path = OLD_PATHS.contains(&action.path.as_str());
        // `DELETE /traces` and `/traces/{traceId}` are not part of the sunset:
        // Cloud v4 still serves them, so they stay ordinary actions.
        let surviving_delete =
            action.method == "DELETE" && action.path.starts_with("/api/public/traces");
        let is_marked = action.description.starts_with(MARKER);

        if on_old_path && !surviving_delete {
            assert_eq!(
                action.method, "GET",
                "{key}: the self-hosted surface is read-only here ({} {})",
                action.method, action.path
            );
            assert!(
                is_marked,
                "{key} reads {}, which Langfuse Cloud sunsets on 2026-11-16 — \
                 its description must open with {MARKER:?}",
                action.path
            );
        } else {
            assert!(
                !is_marked,
                "{key} is marked self-hosted but {} is a Cloud path",
                action.path
            );
        }
        if is_marked {
            marked.push(key.as_str());
        }
    }

    marked.sort_unstable();
    assert_eq!(
        marked,
        [
            "get_dataset_run",
            "get_metrics_self_hosted",
            "get_observation",
            "get_score",
            "get_session",
            "get_trace",
            "list_dataset_run_items",
            "list_dataset_runs",
            "list_observations_self_hosted",
            "list_scores_self_hosted",
            "list_sessions",
            "list_traces",
        ]
    );
}

/// Each Cloud action an agent will try first on a self-hosted instance names
/// its way out. Without the pointer the 501 is a dead end.
#[test]
fn every_cloud_read_names_its_self_hosted_counterpart() {
    let reg = shipped_registry();
    let svc = reg.get("langfuse").unwrap();

    for (cloud, self_hosted) in [
        ("list_observations", "list_traces"),
        ("list_observations", "list_observations_self_hosted"),
        ("get_metrics", "get_metrics_self_hosted"),
        ("list_scores", "list_scores_self_hosted"),
        ("list_experiments", "list_dataset_runs"),
        ("list_experiment_items", "list_dataset_run_items"),
    ] {
        assert!(
            svc.actions[cloud].description.contains(self_hosted),
            "{cloud} must point a self-hosted caller at {self_hosted}"
        );
    }
}

/// Langfuse's old lists all answer `{data, meta: {page, limit, totalItems,
/// totalPages}}`, and `page` must declare `default: 1` or validation cannot
/// tell whether pages count from zero.
#[test]
fn every_self_hosted_list_pages_by_number() {
    let reg = shipped_registry();
    let svc = reg.get("langfuse").unwrap();

    for key in [
        "list_traces",
        "list_sessions",
        "list_observations_self_hosted",
        "list_scores_self_hosted",
        "list_dataset_runs",
        "list_dataset_run_items",
    ] {
        let p = svc.actions[key]
            .pagination
            .as_ref()
            .unwrap_or_else(|| panic!("{key} declares pagination"));
        assert_eq!(p.next.param.as_deref(), Some("page"), "{key}");
        assert_eq!(p.items.as_deref(), Some("data"), "{key}");
        assert!(
            p.has_more.is_none(),
            "{key}: the end is inferred structurally"
        );
    }

    // The io-bearing lists stay below Langfuse's own 50, for the same reason
    // list_observations does.
    for key in ["list_traces", "list_observations_self_hosted"] {
        let size = svc.actions[key]
            .pagination
            .as_ref()
            .unwrap()
            .page_size
            .as_ref()
            .expect("a page size");
        assert_eq!(size.default, Some(25), "{key}: io rows are large");
    }
}

// ============================================================================
// Mock self-hosted Langfuse
// ============================================================================

#[derive(Clone, Debug)]
struct Seen {
    path: String,
    query: String,
    authorization: Option<String>,
}

type SeenLog = Arc<Mutex<Vec<Seen>>>;

/// A self-hosted Langfuse: the old surface answers, and the Cloud-only v2
/// endpoints refuse exactly as a real v3 instance does.
async fn start_mock_self_hosted() -> (SocketAddr, SeenLog) {
    let seen: SeenLog = Arc::new(Mutex::new(Vec::new()));

    async fn handler(
        State(seen): State<SeenLog>,
        req: axum::extract::Request,
    ) -> axum::response::Response {
        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or_default().to_string();
        seen.lock().unwrap().push(Seen {
            path: path.clone(),
            query: query.clone(),
            authorization: req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
        });

        let page_meta = |page: u64, rows: usize, total: usize| json!({ "page": page, "limit": rows, "totalItems": total, "totalPages": 2 });
        let payload = match path.as_str() {
            "/api/public/v2/observations" | "/api/public/v2/metrics" => {
                return (
                    axum::http::StatusCode::NOT_IMPLEMENTED,
                    axum::Json(json!({
                        "message": "v2 APIs are currently in beta and only available on Langfuse Cloud",
                        "error": "NotImplementedError",
                    })),
                )
                    .into_response();
            }
            "/api/public/traces" if query.contains("page=2") => json!({
                "data": [{ "id": "tr-26", "name": "checkout" }],
                "meta": page_meta(2, 25, 26),
            }),
            "/api/public/traces" => {
                // A full page at limit=25, so the traversal has a successor.
                let rows: Vec<Value> = (0..25)
                    .map(|i| json!({ "id": format!("tr-{i}"), "name": "checkout" }))
                    .collect();
                json!({ "data": rows, "meta": page_meta(1, 25, 26) })
            }
            "/api/public/observations" => json!({
                "data": [{ "id": "obs-1", "traceId": "tr-1", "type": "GENERATION" }],
                "meta": page_meta(1, 25, 1),
            }),
            "/api/public/v2/scores" => json!({
                "data": [{ "id": "sc-1", "name": "helpfulness", "value": 0.9 }],
                "meta": page_meta(1, 50, 1),
            }),
            "/api/public/metrics" => {
                json!({ "data": [{ "name": "checkout", "sum_totalCost": 3.5 }] })
            }
            _ => json!({ "ok": true }),
        };
        axum::Json(payload).into_response()
    }

    let app = Router::new()
        .route("/{*path}", any(handler))
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, seen)
}

fn last(seen: &SeenLog) -> Seen {
    seen.lock().unwrap().last().cloned().expect("mock saw none")
}

// ============================================================================
// Behaviour
// ============================================================================

/// The page walk, plus the narrow `fields` default reaching the wire without
/// the caller naming it.
#[tokio::test]
async fn traces_walk_the_page_number_with_narrow_fields() {
    let pool = common::test_pool().await;
    let (mock, seen) = start_mock_self_hosted().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "read").await;

    let page_one = call(&base, &client, &agent_key, "list_traces", json!({})).await;
    assert_eq!(page_one["status"], json!("called"), "{page_one}");

    let req = last(&seen);
    assert_eq!(req.path, "/api/public/traces");
    assert_eq!(
        req.authorization.as_deref(),
        Some(expected_basic().as_str())
    );
    assert_eq!(url_param(&req.query, "limit").as_deref(), Some("25"));
    assert_eq!(
        url_param(&req.query, "fields").as_deref(),
        Some("core,metrics"),
        "Langfuse returns every field group when `fields` is absent: {}",
        req.query
    );

    let pagination = &page_one["result"]["_pagination"];
    assert_eq!(pagination["has_more"], json!(true), "{page_one}");
    assert_eq!(
        pagination["next"]["params"],
        json!({ "page": 2, "limit": 25 }),
        "a full page must offer the next page number: {page_one}"
    );

    let page_two = call(
        &base,
        &client,
        &agent_key,
        "list_traces",
        json!({ "page": 2 }),
    )
    .await;
    assert_eq!(
        page_two["result"]["_pagination"]["has_more"],
        json!(false),
        "an underfull page is the last: {page_two}"
    );
}

/// The reads a self-hosted user hit 501/404 on now land on paths the instance
/// serves, with the key pair attached.
#[tokio::test]
async fn observations_and_scores_reach_the_paths_self_hosted_serves() {
    let pool = common::test_pool().await;
    let (mock, seen) = start_mock_self_hosted().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "read").await;

    // The Cloud action against this instance fails the way the user saw.
    // Asserted on the upstream status rather than the envelope, which may
    // report the call as made either way.
    let cloud = call(&base, &client, &agent_key, "list_observations", json!({})).await;
    let upstream = cloud["result"]["status_code"]
        .as_u64()
        .or_else(|| cloud["status_code"].as_u64());
    assert_ne!(upstream, Some(200), "{cloud}");

    for (action, params, path) in [
        (
            "list_observations_self_hosted",
            json!({ "trace_id": "tr-1" }),
            "/api/public/observations",
        ),
        (
            "list_scores_self_hosted",
            json!({ "name": "helpfulness" }),
            "/api/public/v2/scores",
        ),
    ] {
        let body = call(&base, &client, &agent_key, action, params).await;
        assert_eq!(body["status"], json!("called"), "{action}: {body}");
        let req = last(&seen);
        assert_eq!(req.path, path, "{action}");
        assert_eq!(
            req.authorization.as_deref(),
            Some(expected_basic().as_str()),
            "{action}"
        );
    }
    let req = last(&seen);
    assert_eq!(
        url_param(&req.query, "name").as_deref(),
        Some("helpfulness")
    );
}

/// The v1 metrics query rides the same JSON-in-a-query-param mechanism as
/// get_metrics: an object is encoded once, a string passes through untouched.
#[tokio::test]
async fn a_self_hosted_metrics_query_is_serialized_once() {
    let pool = common::test_pool().await;
    let (mock, seen) = start_mock_self_hosted().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "read").await;

    let query = json!({
        "view": "traces",
        "dimensions": [{ "field": "name" }],
        "metrics": [{ "measure": "totalCost", "aggregation": "sum" }],
        "fromTimestamp": "2026-09-01T00:00:00Z",
        "toTimestamp": "2026-09-08T00:00:00Z",
    });
    let body = call(
        &base,
        &client,
        &agent_key,
        "get_metrics_self_hosted",
        json!({ "query": query }),
    )
    .await;
    assert_eq!(body["status"], json!("called"), "{body}");

    let req = last(&seen);
    assert_eq!(req.path, "/api/public/metrics");
    let sent = url_param(&req.query, "query").expect("a query param");
    let round_tripped: Value = serde_json::from_str(&sent)
        .unwrap_or_else(|e| panic!("query must reach the wire as JSON ({e}): {sent}"));
    assert_eq!(round_tripped, query);

    let literal = r#"{"view":"traces","metrics":[{"measure":"count","aggregation":"count"}],"fromTimestamp":"2026-09-01T00:00:00Z","toTimestamp":"2026-09-08T00:00:00Z"}"#;
    let body = call(
        &base,
        &client,
        &agent_key,
        "get_metrics_self_hosted",
        json!({ "query": literal }),
    )
    .await;
    assert_eq!(body["status"], json!("called"), "{body}");
    assert_eq!(
        url_param(&last(&seen).query, "query").as_deref(),
        Some(literal)
    );
}
