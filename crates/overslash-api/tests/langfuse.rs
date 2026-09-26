//! Langfuse service template, end to end through the gateway against an
//! in-test mock Langfuse.
//!
//! Five things are worth proving here that a unit test cannot:
//!
//!   1. the shipped YAML compiles into the actions and risk classes it claims;
//!   2. no action reaches an endpoint Langfuse Cloud sunsets on 2026-11-16 —
//!      the failure mode this template exists to avoid, and the only one that
//!      arrives on a calendar date rather than on a code change;
//!   3. the key pair reaches the upstream as `Authorization: Basic
//!      base64(pk:sk)` and nowhere else. The two halves are joined by a jq
//!      template, so a mistake here is a credential that is subtly wrong
//!      rather than absent, and only a live Langfuse would say so;
//!   4. both pagination shapes walk — a cursor from `meta.cursor` and a page
//!      number — and the declared page size reaches the wire uninvited;
//!   5. the writes that deploy a prompt or erase telemetry disclose what they
//!      are about, including the fields whose *absence* is the dangerous case.
//!
//! The real-account test at the bottom is `#[ignore]`d and needs
//! `LANGFUSE_TEST_PUBLIC_KEY` / `LANGFUSE_TEST_SECRET_KEY`. It only reads: the
//! project behind those keys is somebody's production telemetry.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{Router, extract::State, response::IntoResponse, routing::any};
use serde_json::{Value, json};

use crate::common::{self, auth, bootstrap_org_identity, start_api_with_registry};

const PUBLIC_KEY: &str = "pk-lf-00000000-0000-0000-0000-000000000000";
const SECRET_KEY: &str = "sk-lf-11111111-1111-1111-1111-111111111111";

/// What `"Basic " + (.public_key + ":" + .secret_key | @base64)` must render
/// to. Computed here rather than pasted so the test states the rule, not a
/// checksum of it.
fn expected_basic() -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{PUBLIC_KEY}:{SECRET_KEY}"))
    )
}

fn shipped_registry() -> overslash_core::registry::ServiceRegistry {
    let ws_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    overslash_core::registry::ServiceRegistry::load_from_dir(
        &ws_root.join("services"),
        overslash_core::template_vars::Vars::for_tests(),
    )
    .expect("services/ should load cleanly")
}

// ============================================================================
// Parse smoke test
// ============================================================================

#[test]
fn langfuse_yaml_parses() {
    let reg = shipped_registry();
    let svc = reg.get("langfuse").expect("langfuse should be registered");

    assert_eq!(svc.display_name, "Langfuse");
    // `${LANGFUSE_URL:https://cloud.langfuse.com}` with the variable unset, so
    // this also pins that the literal default survives expansion — a template
    // whose host silently became empty would compile host-less and quietly
    // turn into "the operator supplies the endpoint".
    assert_eq!(svc.hosts, vec!["cloud.langfuse.com".to_string()]);

    // The curated surface, spelled out so that dropping one is a test failure
    // rather than a silently smaller service.
    for action in [
        "list_projects",
        "list_observations",
        "get_metrics",
        "list_scores",
        "create_score",
        "delete_score",
        "delete_trace",
        "delete_traces",
        "list_prompts",
        "create_prompt",
        "get_prompt",
        "delete_prompt",
        "update_prompt_labels",
        "list_datasets",
        "create_dataset",
        "get_dataset",
        "list_dataset_items",
        "create_dataset_item",
        "delete_dataset_item",
        "list_experiments",
        "list_experiment_items",
    ] {
        assert!(svc.actions.contains_key(action), "missing action: {action}");
    }
    assert_eq!(svc.actions.len(), 21, "the curated set is 21 actions");

    // The delete-class set, named rather than counted: each of these erases
    // telemetry or prompt history irreversibly, and a *new* one appearing
    // without a decision is what this pins.
    let mut deleting: Vec<&str> = svc
        .actions
        .iter()
        .filter(|(_, a)| matches!(a.risk.display_risk(), overslash_core::types::Risk::Delete))
        .map(|(k, _)| k.as_str())
        .collect();
    deleting.sort_unstable();
    assert_eq!(
        deleting,
        [
            "delete_dataset_item",
            "delete_prompt",
            "delete_score",
            "delete_trace",
            "delete_traces",
        ]
    );

    // Which endpoint the "Check it works" button hits is a product decision,
    // not an accident: `/api/public/health` is unauthenticated and would
    // answer 200 for a key pair that does not work.
    let probe = svc
        .test_action()
        .expect("langfuse declares a credential probe");
    assert_eq!(probe.0, "list_projects");
}

/// Langfuse Cloud sunsets the whole v1 read surface on 2026-11-16, and
/// self-hosted v4 already refuses it under the default `events_only` write
/// mode. Every one of these paths has a v4 replacement that this template
/// models instead.
///
/// This is the one failure in the service that arrives on a date rather than
/// on a commit: a contributor "helpfully" adding `GET /api/public/traces` back
/// would see it pass every other test, ship, and break in production on a day
/// nobody is looking at this file.
#[test]
fn no_action_targets_an_endpoint_langfuse_sunsets() {
    const SUNSET: &[&str] = &[
        "/api/public/ingestion",
        "/api/public/metrics",
        "/api/public/observations",
        "/api/public/observations/{observationId}",
        "/api/public/sessions",
        "/api/public/sessions/{sessionId}",
        "/api/public/dataset-run-items",
        "/api/public/v2/scores",
        "/api/public/v2/scores/{scoreId}",
    ];

    let reg = shipped_registry();
    let svc = reg.get("langfuse").unwrap();

    for (key, action) in &svc.actions {
        assert!(
            !SUNSET.contains(&action.path.as_str()),
            "{key} targets {}, which Langfuse Cloud sunsets on 2026-11-16",
            action.path
        );
        // `/api/public/traces` survives only for its two DELETE verbs; the
        // GETs on it and on `/traces/{traceId}` are sunset. Keyed on the verb
        // so the surviving deletes stay expressible.
        if action.method == "GET" {
            assert!(
                !action.path.starts_with("/api/public/traces"),
                "{key} reads {} — sunset; use list_observations",
                action.path
            );
            assert!(
                !action.path.starts_with("/api/public/datasets/"),
                "{key} reads {} — sunset; use list_experiments",
                action.path
            );
        }
    }
}

/// Both pagination shapes, asserted where they are declared rather than only
/// where they are walked — a block that names the wrong `from:` path still
/// returns a first page, and only a traversal test that happens to cover that
/// action would notice.
#[test]
fn every_list_declares_the_pagination_shape_its_endpoint_answers_with() {
    let reg = shipped_registry();
    let svc = reg.get("langfuse").unwrap();

    // Cursor lists: Langfuse answers `{data, meta: {cursor}}`, and an absent
    // cursor is the last page.
    for key in [
        "list_observations",
        "list_scores",
        "list_experiments",
        "list_experiment_items",
    ] {
        let p = svc.actions[key]
            .pagination
            .as_ref()
            .unwrap_or_else(|| panic!("{key} declares pagination"));
        assert_eq!(p.next.param.as_deref(), Some("cursor"), "{key}");
        assert_eq!(p.next.from.as_deref(), Some("meta.cursor"), "{key}");
        assert_eq!(p.items.as_deref(), Some("data"), "{key}");
        assert!(
            p.has_more.is_none(),
            "{key}: Langfuse's cursor meta carries no boolean, so the end is \
             inferred structurally"
        );
    }

    // Page lists: Langfuse answers `{data, meta: {page, limit, totalItems,
    // totalPages}}`. `page` must declare its own `default: 1` or template
    // validation cannot tell whether pages count from zero.
    for key in ["list_prompts", "list_datasets", "list_dataset_items"] {
        let p = svc.actions[key]
            .pagination
            .as_ref()
            .unwrap_or_else(|| panic!("{key} declares pagination"));
        assert_eq!(p.next.param.as_deref(), Some("page"), "{key}");
        assert_eq!(p.items.as_deref(), Some("data"), "{key}");
    }

    // The two io-bearing lists are bounded below Langfuse's own default of 50,
    // because one page of whole prompts and completions is past the transport
    // cap. This is the assertion that keeps a future tidy-up from "restoring"
    // the upstream default.
    for key in ["list_observations", "list_experiment_items"] {
        let size = svc.actions[key]
            .pagination
            .as_ref()
            .unwrap()
            .page_size
            .as_ref()
            .expect("a page size");
        assert_eq!(size.param, "limit", "{key}");
        assert_eq!(size.default, Some(25), "{key}: io rows are large");
    }
}

/// A field an agent *reads* under a snake_case alias must be *writable* under
/// the same one.
///
/// The asymmetry is easy to ship and invisible until an agent hits it: alias
/// entries on `parameters[]` are the obvious half, and `requestBody`
/// properties take them too (`Ext::Aliases` reads at `Pos::BodyProperty`) but
/// are easy to forget. The result would be that `trace_id` works on
/// `list_scores` and is rejected as an unknown argument on `create_score` —
/// so an agent that reads an id out of a list cannot write it back.
#[test]
fn a_field_readable_under_an_alias_is_writable_under_the_same_one() {
    // (action, upstream field, alias the read side already accepts)
    const PAIRS: &[(&str, &str, &str)] = &[
        ("create_score", "traceId", "trace_id"),
        ("create_score", "observationId", "observation_id"),
        ("create_score", "sessionId", "session_id"),
        ("create_score", "dataType", "data_type"),
        ("create_score", "configId", "config_id"),
        ("create_score", "queueId", "queue_id"),
        // `list_scores` spells this `experimentId` because that is the name
        // that endpoint puts on the wire; the write spells it `datasetRunId`.
        // Each accepts the other's name.
        ("create_score", "datasetRunId", "experiment_id"),
        ("create_dataset_item", "datasetName", "dataset_name"),
        ("create_dataset_item", "sourceTraceId", "source_trace_id"),
        (
            "create_dataset_item",
            "sourceObservationId",
            "source_observation_id",
        ),
        ("create_dataset_item", "expectedOutput", "expected_output"),
        ("create_dataset", "inputSchema", "input_schema"),
        (
            "create_dataset",
            "expectedOutputSchema",
            "expected_output_schema",
        ),
        ("create_prompt", "commitMessage", "commit_message"),
        ("update_prompt_labels", "newLabels", "new_labels"),
        ("delete_traces", "traceIds", "trace_ids"),
    ];

    let reg = shipped_registry();
    let svc = reg.get("langfuse").unwrap();

    for (action, field, alias) in PAIRS {
        let param = svc.actions[*action]
            .params
            .get(*field)
            .unwrap_or_else(|| panic!("{action} declares no `{field}`"));
        assert!(
            param.aliases.iter().any(|a| a == alias),
            "{action}.{field} must accept `{alias}` — the read side already \
             does, and an agent reads an id before it writes one"
        );
    }
}

// ============================================================================
// Mock Langfuse
// ============================================================================

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    query: String,
    authorization: Option<String>,
    body: Value,
}

type SeenLog = Arc<Mutex<Vec<Seen>>>;

/// Answers the handful of endpoints these tests touch, in Langfuse's own
/// envelopes, and records every request so the auth header can be asserted on
/// rather than assumed.
async fn start_mock_langfuse() -> (SocketAddr, SeenLog) {
    let seen: SeenLog = Arc::new(Mutex::new(Vec::new()));

    async fn handler(
        State(seen): State<SeenLog>,
        req: axum::extract::Request,
    ) -> impl IntoResponse {
        let (parts, body) = req.into_parts();
        let bytes = axum::body::to_bytes(body, 1 << 20)
            .await
            .unwrap_or_default();
        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let path = parts.uri.path().to_string();
        let query = parts.uri.query().unwrap_or_default().to_string();
        seen.lock().unwrap().push(Seen {
            method: parts.method.to_string(),
            path: path.clone(),
            query: query.clone(),
            authorization: parts
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
            body,
        });

        let payload = if path == "/api/public/projects" {
            json!({ "data": [{ "id": "clp-1", "name": "checkout-agent" }] })
        } else if path == "/api/public/v2/observations" {
            // Two pages, so a traversal has somewhere to go and somewhere to
            // stop. `meta.cursor` is simply absent on the last page — Langfuse
            // ships no boolean to go with it.
            if query.contains("cursor=") {
                json!({
                    "data": [{ "id": "obs-2", "traceId": "tr-2", "type": "SPAN" }],
                    "meta": {},
                })
            } else {
                json!({
                    "data": [{ "id": "obs-1", "traceId": "tr-1", "type": "GENERATION" }],
                    "meta": { "cursor": "eyJpZCI6Im9icy0xIn0" },
                })
            }
        } else if path == "/api/public/v2/prompts" && parts.method == "GET" {
            if query.contains("page=2") {
                json!({
                    "data": [{ "name": "refund-agent", "versions": [1] }],
                    "meta": { "page": 2, "limit": 50, "totalItems": 51, "totalPages": 2 },
                })
            } else {
                // A full page: 50 rows at limit=50, so the traversal has a
                // successor to offer.
                let rows: Vec<Value> = (0..50)
                    .map(|i| json!({ "name": format!("prompt-{i}"), "versions": [1] }))
                    .collect();
                json!({
                    "data": rows,
                    "meta": { "page": 1, "limit": 50, "totalItems": 51, "totalPages": 2 },
                })
            }
        } else if path == "/api/public/v2/metrics" {
            json!({ "data": [{ "providedModelName": "claude-opus-5", "sum_totalCost": 12.5 }] })
        } else {
            json!({ "ok": true })
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

/// Boot the API on the shipped registry, seed the `langfuse_secret_key` vault
/// entry, and create an org-level `langfuse` instance pointed at the mock with
/// the public key set as instance config.
async fn setup(
    pool: sqlx::PgPool,
    mock: SocketAddr,
    access_level: &str,
) -> (String, reqwest::Client, String, String) {
    common::allow_loopback_ssrf();
    let (base, client) = start_api_with_registry(pool, None).await;
    let (_org_id, _ident_id, agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    let put = client
        .put(format!("{base}/v1/secrets/langfuse_secret_key"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "value": SECRET_KEY }))
        .send()
        .await
        .unwrap();
    assert!(put.status().is_success(), "secret put: {}", put.status());

    let everyone_id = common::everyone_group_id(&base, &client, &admin_key).await;
    let svc: Value = client
        .post(format!("{base}/v1/services"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "template_key": "langfuse",
            "name": "langfuse",
            "url": format!("http://{mock}"),
            "user_level": false,
            "groups": [{
                "group_id": everyone_id.to_string(),
                "access_level": access_level,
                "auto_approve_reads": true,
            }],
            "status": "active",
            // The split credential: only the secret half is a vault
            // reference; the public half is a plain instance config value.
            "credentials": { "secret_key": "langfuse_secret_key" },
            "config": { "public_key": PUBLIC_KEY },
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    svc["id"].as_str().expect("service create failed");

    (base, client, agent_key, admin_key)
}

async fn call(
    base: &str,
    client: &reqwest::Client,
    agent_key: &str,
    action: &str,
    params: Value,
) -> Value {
    client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(agent_key).0, auth(agent_key).1)
        .json(&json!({ "service": "langfuse", "action": action, "params": params }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

// ============================================================================
// Auth
// ============================================================================

/// The key pair goes out as `Authorization: Basic base64(pk:sk)`.
///
/// Worth its own test because the header is *composed*: the public half comes
/// from instance config and the secret half from the vault, joined by a jq
/// template. Every way that can go wrong — the halves swapped, the separator
/// missing, one side empty — produces a well-formed header that Langfuse reads
/// as a wrong key. Nothing but this assertion distinguishes those from the
/// right one.
#[tokio::test]
async fn the_key_pair_is_injected_as_basic_and_nowhere_else() {
    let pool = common::test_pool().await;
    let (mock, seen) = start_mock_langfuse().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "read").await;

    let body = call(&base, &client, &agent_key, "list_projects", json!({})).await;
    assert_eq!(body["status"], json!("called"), "{body}");

    let req = seen.lock().unwrap().last().cloned().expect("mock saw none");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/api/public/projects");
    assert_eq!(
        req.authorization.as_deref(),
        Some(expected_basic().as_str())
    );

    // Neither half may reach the query string. The public key is not a secret,
    // but a URL carrying it is still a URL that identifies the project in
    // every proxy log between here and Langfuse.
    assert!(
        !req.query.contains(SECRET_KEY) && !req.query.contains(PUBLIC_KEY),
        "no half of the key pair may reach the query string: {}",
        req.query
    );
    // Nor the body. A composed credential is assembled from two sources, and
    // the failure worth guarding is one of them being written somewhere it
    // was never meant to go.
    assert!(
        !serde_json::to_string(&req.body)
            .unwrap()
            .contains(SECRET_KEY),
        "the secret key must not reach the request body: {:?}",
        req.body
    );
}

// ============================================================================
// Pagination
// ============================================================================

/// The cursor shape: `meta.cursor` on page one, absent on page two.
#[tokio::test]
async fn observations_walk_the_cursor_and_stop_when_meta_carries_none() {
    let pool = common::test_pool().await;
    let (mock, seen) = start_mock_langfuse().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "read").await;

    let page_one = call(&base, &client, &agent_key, "list_observations", json!({})).await;
    assert_eq!(page_one["status"], json!("called"), "{page_one}");

    let pagination = &page_one["result"]["_pagination"];
    assert_eq!(pagination["has_more"], json!(true), "{page_one}");
    // The marker carries Langfuse's opaque cursor *and* the page size the call
    // was made with, so following it keeps the 25-row bound rather than
    // silently reverting to Langfuse's own default of 50.
    assert_eq!(
        pagination["next"]["params"],
        json!({ "cursor": "eyJpZCI6Im9icy0xIn0", "limit": 25 }),
    );
    assert_eq!(pagination["next"]["action"], json!("list_observations"));

    // The declared page size reached the wire without the caller naming it.
    let first = seen.lock().unwrap().last().cloned().unwrap();
    assert!(
        first.query.contains("limit=25"),
        "page size not bounded: {}",
        first.query
    );

    let page_two = call(
        &base,
        &client,
        &agent_key,
        "list_observations",
        json!({ "cursor": "eyJpZCI6Im9icy0xIn0" }),
    )
    .await;
    assert_eq!(
        page_two["result"]["_pagination"]["has_more"],
        json!(false),
        "an absent meta.cursor is the last page: {page_two}"
    );
}

/// The page-number shape, which is the other half of the service and shares no
/// code path with the cursor one.
#[tokio::test]
async fn prompts_walk_the_page_number() {
    let pool = common::test_pool().await;
    let (mock, _seen) = start_mock_langfuse().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "read").await;

    let page_one = call(&base, &client, &agent_key, "list_prompts", json!({})).await;
    assert_eq!(page_one["status"], json!("called"), "{page_one}");
    let pagination = &page_one["result"]["_pagination"];
    assert_eq!(pagination["has_more"], json!(true), "{page_one}");
    assert_eq!(
        pagination["next"]["params"],
        json!({ "page": 2, "limit": 50 }),
        "a full page must offer the next page number: {page_one}"
    );

    let page_two = call(
        &base,
        &client,
        &agent_key,
        "list_prompts",
        json!({ "page": 2 }),
    )
    .await;
    assert_eq!(
        page_two["result"]["_pagination"]["has_more"],
        json!(false),
        "an underfull page is the last: {page_two}"
    );
}

/// The probe reads a collection-shaped body but is not a page of anything: a
/// project-scoped key sees exactly one project. It is in the pagination gate's
/// allow-list, and this is the behavioural half of that entry.
#[tokio::test]
async fn the_credential_probe_offers_no_continuation() {
    let pool = common::test_pool().await;
    let (mock, _seen) = start_mock_langfuse().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "read").await;

    let body = call(&base, &client, &agent_key, "list_projects", json!({})).await;
    assert_eq!(body["status"], json!("called"), "{body}");
    assert!(
        body["result"]["_pagination"].is_null(),
        "the probe must offer no continuation: {body}"
    );
}

// ============================================================================
// The JSON-string query DSL
// ============================================================================

/// Metrics v2 takes its whole query as one serialized JSON document in a query
/// parameter. The template declares it as the string it is on the wire, with a
/// `contentSchema` saying what the string spells — so a caller may hand over
/// the object and have it encoded exactly once.
///
/// The second half is the load-bearing one: a caller who already has the
/// serialized form must get those bytes through untouched. Re-encoding a
/// string would re-sort its keys, and a cursor or signature computed over the
/// original ordering would stop matching.
#[tokio::test]
async fn a_metrics_query_is_serialized_once_and_a_string_passes_through() {
    let pool = common::test_pool().await;
    let (mock, seen) = start_mock_langfuse().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "read").await;

    let query = json!({
        "view": "observations",
        "dimensions": [{ "field": "providedModelName" }],
        "metrics": [{ "measure": "totalCost", "aggregation": "sum" }],
        "fromTimestamp": "2026-09-01T00:00:00Z",
        "toTimestamp": "2026-09-08T00:00:00Z",
    });

    // (a) the object form.
    let body = call(
        &base,
        &client,
        &agent_key,
        "get_metrics",
        json!({ "query": query }),
    )
    .await;
    assert_eq!(body["status"], json!("called"), "{body}");

    let req = seen.lock().unwrap().last().cloned().unwrap();
    assert_eq!(req.path, "/api/public/v2/metrics");
    let sent = url_param(&req.query, "query").expect("a query param");
    let round_tripped: Value = serde_json::from_str(&sent)
        .unwrap_or_else(|e| panic!("query must reach the wire as JSON ({e}): {sent}"));
    assert_eq!(
        round_tripped, query,
        "the object must survive encoding once"
    );

    // (b) the pre-serialized form, byte for byte. Deliberately written with
    // keys out of alphabetical order, which is exactly what a re-encode would
    // silently rewrite.
    let literal = r#"{"view":"observations","metrics":[{"measure":"count","aggregation":"count"}],"fromTimestamp":"2026-09-01T00:00:00Z","toTimestamp":"2026-09-08T00:00:00Z"}"#;
    let body = call(
        &base,
        &client,
        &agent_key,
        "get_metrics",
        json!({ "query": literal }),
    )
    .await;
    assert_eq!(body["status"], json!("called"), "{body}");

    let req = seen.lock().unwrap().last().cloned().unwrap();
    let sent = url_param(&req.query, "query").expect("a query param");
    assert_eq!(
        sent, literal,
        "a caller's serialized form must reach Langfuse unchanged"
    );
}

/// The other half of declaring `contentSchema`: a malformed query is rejected
/// here, naming the field, rather than spending an upstream call to learn the
/// same thing.
#[tokio::test]
async fn a_metrics_query_missing_required_fields_is_refused_locally() {
    let pool = common::test_pool().await;
    let (mock, seen) = start_mock_langfuse().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "read").await;

    let body = call(
        &base,
        &client,
        &agent_key,
        "get_metrics",
        json!({ "query": { "view": "observations" } }),
    )
    .await;
    assert_ne!(
        body["status"],
        json!("called"),
        "a query with no metrics and no time bounds must not be sent: {body}"
    );

    assert!(
        seen.lock().unwrap().is_empty(),
        "nothing should have reached Langfuse"
    );
}

/// Decode one `key=value` pair out of a raw query string.
fn url_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| urlencoding::decode(v).ok().map(|s| s.into_owned()))?
    })
}

// ============================================================================
// Disclosure
// ============================================================================

/// Moving the `production` label is a deployment: every SDK resolving that
/// label serves the new version from its next fetch. An approver who is shown
/// only "PATCH a prompt" cannot tell that apart from editing a draft.
#[tokio::test]
async fn relabelling_a_prompt_discloses_that_it_is_a_deployment() {
    let pool = common::test_pool().await;
    let (mock, seen) = start_mock_langfuse().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "admin").await;

    let body = call(
        &base,
        &client,
        &agent_key,
        "update_prompt_labels",
        json!({ "name": "checkout-agent", "version": 7, "newLabels": ["production"] }),
    )
    .await;
    assert_eq!(
        body["status"],
        json!("pending_approval"),
        "an ungranted write must bubble: {body}"
    );

    let rendered = serde_json::to_string(&body["disclosed_fields"]).unwrap();
    assert!(
        rendered.contains("checkout-agent") && rendered.contains('7'),
        "the disclosure must name the prompt and version: {rendered}"
    );
    assert!(
        rendered.contains("live SDK traffic"),
        "moving `production` must say what it deploys: {rendered}"
    );

    assert!(
        seen.lock().unwrap().is_empty(),
        "nothing should have reached Langfuse before approval"
    );
}

/// An empty label list means "strip every label from this version", which is
/// the case `// empty` would render as nothing at all — so the filter tests
/// presence instead. This is the regression that guards that choice.
#[tokio::test]
async fn stripping_every_label_is_disclosed_rather_than_rendered_blank() {
    let pool = common::test_pool().await;
    let (mock, _seen) = start_mock_langfuse().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "admin").await;

    let body = call(
        &base,
        &client,
        &agent_key,
        "update_prompt_labels",
        json!({ "name": "checkout-agent", "version": 7, "newLabels": [] }),
    )
    .await;
    assert_eq!(body["status"], json!("pending_approval"), "{body}");

    let rendered = serde_json::to_string(&body["disclosed_fields"]).unwrap();
    assert!(
        rendered.contains("every label removed"),
        "an empty label list must be spelled out, not vanish: {rendered}"
    );
}

/// The whole justification for shipping a bulk delete at all: the approver
/// sees every id, so declining one they cannot account for is possible.
#[tokio::test]
async fn a_bulk_trace_delete_discloses_every_id() {
    let pool = common::test_pool().await;
    let (mock, seen) = start_mock_langfuse().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "admin").await;

    let body = call(
        &base,
        &client,
        &agent_key,
        "delete_traces",
        json!({ "traceIds": ["tr-aaa", "tr-bbb", "tr-ccc"] }),
    )
    .await;
    assert_eq!(body["status"], json!("pending_approval"), "{body}");

    let rendered = serde_json::to_string(&body["disclosed_fields"]).unwrap();
    for id in ["tr-aaa", "tr-bbb", "tr-ccc"] {
        assert!(
            rendered.contains(id),
            "every id must be named for the approver: {rendered}"
        );
    }
    assert!(
        seen.lock().unwrap().is_empty(),
        "nothing should have been deleted before approval"
    );
}

/// Dataset items upsert on `id`, so supplying one silently replaces an
/// existing item. That is the single fact an approver needs and the one the
/// request shape hides — an "add an item" call that is really an overwrite.
#[tokio::test]
async fn adding_a_dataset_item_with_an_id_discloses_the_overwrite() {
    let pool = common::test_pool().await;
    let (mock, _seen) = start_mock_langfuse().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "admin").await;

    let with_id = call(
        &base,
        &client,
        &agent_key,
        "create_dataset_item",
        json!({ "datasetName": "refunds", "id": "case-42", "input": { "q": "hi" } }),
    )
    .await;
    assert_eq!(with_id["status"], json!("pending_approval"), "{with_id}");
    let rendered = serde_json::to_string(&with_id["disclosed_fields"]).unwrap();
    assert!(
        rendered.contains("Overwrites existing item") && rendered.contains("case-42"),
        "an explicit id must be disclosed as an overwrite: {rendered}"
    );

    // Without an id it is a plain insert, and the label must be absent rather
    // than present-and-empty — a reviewer reading "Overwrites existing item:"
    // with nothing after it learns the wrong thing.
    let without_id = call(
        &base,
        &client,
        &agent_key,
        "create_dataset_item",
        json!({ "datasetName": "refunds", "input": { "q": "hi" } }),
    )
    .await;
    assert_eq!(
        without_id["status"],
        json!("pending_approval"),
        "{without_id}"
    );
    let rendered = serde_json::to_string(&without_id["disclosed_fields"]).unwrap();
    assert!(
        !rendered.contains("Overwrites existing item"),
        "a plain insert must not claim to overwrite: {rendered}"
    );
}

/// A score of 0 and a score of `false` are real results, and `// empty` would
/// disclose neither. The filter tests presence for exactly that reason.
#[tokio::test]
async fn a_zero_score_is_still_disclosed() {
    let pool = common::test_pool().await;
    let (mock, _seen) = start_mock_langfuse().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "admin").await;

    let body = call(
        &base,
        &client,
        &agent_key,
        "create_score",
        // Deliberately snake_case, which is the alias rather than Langfuse's
        // own spelling: this doubles as the end-to-end half of
        // `a_field_readable_under_an_alias_is_writable_under_the_same_one`.
        // The disclosure filter reads `.body.traceId`, so a Subject line
        // naming the trace proves the alias was normalized *before* disclose
        // ran — not merely that the call was accepted.
        json!({ "name": "hallucination", "value": 0, "trace_id": "tr-1" }),
    )
    .await;
    assert_eq!(body["status"], json!("pending_approval"), "{body}");

    let fields = body["disclosed_fields"]
        .as_array()
        .cloned()
        .expect("inline disclosed_fields present");
    let value = fields
        .iter()
        .find(|f| f["label"] == json!("Value"))
        .expect("a zero value must still be disclosed");
    assert!(
        serde_json::to_string(value).unwrap().contains('0'),
        "the zero must be rendered, not dropped: {value}"
    );

    let subject = fields
        .iter()
        .find(|f| f["label"] == json!("Subject"))
        .expect("the scored subject must be disclosed");
    assert!(
        serde_json::to_string(subject).unwrap().contains("tr-1"),
        "the alias must be normalized before disclose runs: {subject}"
    );
}

// ============================================================================
// Real account
// ============================================================================

/// Reads only, against a real Langfuse project. The project behind these keys
/// is somebody's production telemetry.
#[ignore = "hits the real Langfuse API; needs LANGFUSE_TEST_PUBLIC_KEY / _SECRET_KEY"]
#[tokio::test]
async fn langfuse_live_read_smoke() {
    let (Ok(public_key), Ok(secret_key)) = (
        std::env::var("LANGFUSE_TEST_PUBLIC_KEY"),
        std::env::var("LANGFUSE_TEST_SECRET_KEY"),
    ) else {
        eprintln!("SKIP: LANGFUSE_TEST_PUBLIC_KEY / LANGFUSE_TEST_SECRET_KEY not set");
        return;
    };

    let pool = common::test_pool().await;
    let (base, client) = start_api_with_registry(pool, None).await;
    let (_org_id, _ident_id, agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    client
        .put(format!("{base}/v1/secrets/langfuse_secret_key"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "value": secret_key }))
        .send()
        .await
        .unwrap();

    let everyone_id = common::everyone_group_id(&base, &client, &admin_key).await;
    client
        .post(format!("{base}/v1/services"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "template_key": "langfuse",
            "name": "langfuse",
            "user_level": false,
            "groups": [{
                "group_id": everyone_id.to_string(),
                "access_level": "read",
                "auto_approve_reads": true,
            }],
            "status": "active",
            "credentials": { "secret_key": "langfuse_secret_key" },
            "config": { "public_key": public_key },
        }))
        .send()
        .await
        .unwrap();

    let project = call(&base, &client, &agent_key, "list_projects", json!({})).await;
    assert_eq!(
        project["status"],
        json!("called"),
        "the credential probe must succeed: {project}"
    );

    let observations = call(
        &base,
        &client,
        &agent_key,
        "list_observations",
        json!({ "limit": 1 }),
    )
    .await;
    assert_eq!(observations["status"], json!("called"), "{observations}");
}
