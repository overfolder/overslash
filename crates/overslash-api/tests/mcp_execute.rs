//! End-to-end integration tests for the MCP-runtime execute branch.
//!
//! A tiny mock of `docker/mcp-runtime/` runs inside the test process and
//! exposes the same `/invoke` HTTP contract. Requests it receives are
//! captured in a `Mutex<Vec<InvokeCall>>` so tests can assert on the
//! payload the api assembled (service_instance_id, tool name, env, args,
//! env_hash). The real TS runtime has its own unit tests in
//! `docker/mcp-runtime/src/*.test.ts`; here we only care that the api
//! builds the right call and unpacks the response.
//!
//! Demo template used here is shaped like the shipped `services/mcp_hn.yaml`:
//! read-only Hacker News. Env map is empty — lets us exercise env_hash
//! equality and the no-secrets path. A second test wires an env binding
//! and asserts env_hash rotation when the secret value changes.

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio::net::TcpListener;
use uuid::Uuid;

// ── Mock MCP runtime ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct InvokeCall {
    service_instance_id: Uuid,
    tool: String,
    arguments: Value,
    env: std::collections::HashMap<String, String>,
    env_hash: String,
}

#[derive(Debug, Deserialize)]
struct MockInvokeBody {
    service_instance_id: Uuid,
    tool: String,
    arguments: Value,
    env: std::collections::HashMap<String, String>,
    env_hash: String,
}

#[derive(Debug, Serialize)]
struct MockInvokeResponse {
    result: Value,
    warm: bool,
    duration_ms: u64,
}

#[derive(Clone)]
struct MockState {
    bearer: String,
    calls: Arc<Mutex<Vec<InvokeCall>>>,
    responder: Arc<dyn Fn(&MockInvokeBody) -> Value + Send + Sync>,
}

async fn invoke_handler(
    State(s): State<MockState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<MockInvokeBody>,
) -> (StatusCode, Json<Value>) {
    let expected = format!("Bearer {}", s.bearer);
    match headers.get("authorization").and_then(|v| v.to_str().ok()) {
        Some(v) if v == expected => {}
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": { "code": "unauthorized", "message": "bad bearer" } })),
            );
        }
    }
    let result = (s.responder)(&body);
    s.calls.lock().unwrap().push(InvokeCall {
        service_instance_id: body.service_instance_id,
        tool: body.tool.clone(),
        arguments: body.arguments.clone(),
        env: body.env.clone(),
        env_hash: body.env_hash.clone(),
    });
    (
        StatusCode::OK,
        Json(
            serde_json::to_value(MockInvokeResponse {
                result,
                warm: false,
                duration_ms: 7,
            })
            .unwrap(),
        ),
    )
}

async fn start_mock_runtime<F>(
    bearer: String,
    responder: F,
) -> (SocketAddr, Arc<Mutex<Vec<InvokeCall>>>)
where
    F: Fn(&MockInvokeBody) -> Value + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = MockState {
        bearer,
        calls: Arc::new(Mutex::new(Vec::new())),
        responder: Arc::new(responder),
    };
    let calls = state.calls.clone();
    let app = Router::new()
        .route("/invoke", post(invoke_handler))
        .with_state(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, calls)
}

// ── Shared setup ─────────────────────────────────────────────────────

async fn setup(
    pool: PgPool,
    runtime_addr: SocketAddr,
    bearer: &str,
) -> (String, Client, Uuid, Uuid, String, String) {
    let (addr, client) = common::start_api_with_mcp_runtime(
        pool,
        format!("http://{runtime_addr}"),
        bearer.to_string(),
    )
    .await;
    let base = format!("http://{addr}");
    let (org_id, identity_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    (base, client, org_id, identity_id, api_key, admin_key)
}

/// Minimal MCP template shaped like services/mcp_hn.yaml. Uses the
/// `runtime: mcp` info alias + `x-overslash-actions` block. No env bindings
/// so we can assert env_hash equality across calls.
fn mcp_hn_like_template(key: &str) -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "HN (MCP)",
            "key": key,
            "category": "developer",
            "runtime": "mcp",
        },
        "mcp": {
            "package": "mcp-hn",
            "version": "latest",
            "env": {},
        },
        "paths": {},
        "actions": {
            "get_stories": {
                "tool": "get_stories",
                "description": "List {story_type} stories",
                "risk": "read",
                "params": {
                    "story_type": { "type": "string", "required": false, "default": "top" },
                    "num_stories": { "type": "integer", "required": false, "default": 10 },
                },
            },
        },
    })
}

/// Variant that declares one secret-backed env var so we can test env_hash rotation.
fn secret_env_template(key: &str) -> Value {
    json!({
        "openapi": "3.1.0",
        "info": { "title": "T", "key": key, "runtime": "mcp" },
        "mcp": {
            "package": "fake-mcp",
            "version": "0.0.1",
            "env": {
                "TOKEN": { "from": "secret", "default_secret_name": "DEMO_TOKEN" },
            },
        },
        "paths": {},
        "actions": {
            "ping": { "tool": "ping", "description": "ping", "risk": "read" }
        },
    })
}

async fn create_template(base: &str, client: &Client, admin_key: &str, openapi: Value) {
    // POST /v1/templates expects the `openapi` field as a YAML/JSON *string*,
    // not a nested object. Serialize first.
    let openapi_str = serde_json::to_string(&openapi).unwrap();
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "openapi": openapi_str, "user_level": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "template create failed: {}",
        resp.text().await.unwrap()
    );
}

async fn create_service(
    base: &str,
    client: &Client,
    api_key: &str,
    template_key: &str,
    name: &str,
) -> Uuid {
    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({ "template_key": template_key, "name": name }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "service create failed: {}",
        resp.text().await.unwrap()
    );
    let inst: Value = resp.json().await.unwrap();
    inst["id"].as_str().unwrap().parse().unwrap()
}

async fn grant_rule(
    base: &str,
    client: &Client,
    admin_key: &str,
    identity_id: Uuid,
    pattern: &str,
) {
    let resp = client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "identity_id": identity_id,
            "action_pattern": pattern,
            "effect": "allow",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "permission create failed: {}",
        resp.text().await.unwrap()
    );
}

// ── Tests ────────────────────────────────────────────────────────────

#[tokio::test]
async fn mcp_execute_round_trip_happy_path() {
    let pool = common::test_pool().await;
    // Return a canned HN-style stories list so we can assert the body passes through.
    let (runtime_addr, calls) =
        start_mock_runtime("bearer-token".into(), |body: &MockInvokeBody| {
            assert_eq!(body.tool, "get_stories");
            json!({
                "content": [
                    { "type": "text", "text": "1. An HN story about MCP" }
                ]
            })
        })
        .await;
    let (base, client, _org_id, identity_id, api_key, admin_key) =
        setup(pool, runtime_addr, "bearer-token").await;

    create_template(
        &base,
        &client,
        &admin_key,
        mcp_hn_like_template("mcp_hn_t1"),
    )
    .await;
    let service_id = create_service(&base, &client, &api_key, "mcp_hn_t1", "hn-1").await;

    // Permission keys are `{service_instance_name}:{action}:{arg}`, not the
    // template key — so grant against "hn-1", the name the execute call uses.
    grant_rule(
        &base,
        &client,
        &admin_key,
        identity_id,
        "hn-1:get_stories:*",
    )
    .await;

    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "service": "hn-1",
            "action": "get_stories",
            "params": { "story_type": "top", "num_stories": 5 },
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "execute failed: {}",
        resp.text().await.unwrap()
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let result_body = body["result"]["body"].as_str().expect("body is a string");
    let envelope: Value = serde_json::from_str(result_body).unwrap();
    assert_eq!(envelope["runtime"], "mcp");
    assert_eq!(envelope["tool"], "get_stories");
    assert_eq!(
        envelope["result"]["content"][0]["text"],
        "1. An HN story about MCP"
    );

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].service_instance_id, service_id);
    assert_eq!(calls[0].tool, "get_stories");
    assert_eq!(calls[0].arguments["story_type"], "top");
    assert_eq!(calls[0].arguments["num_stories"], 5);
    assert!(calls[0].env.is_empty(), "no env bindings declared");
    assert!(calls[0].env_hash.starts_with("sha256:"));
}

#[tokio::test]
async fn mcp_execute_without_permission_creates_approval() {
    let pool = common::test_pool().await;
    let (runtime_addr, calls) =
        start_mock_runtime("b".into(), |_| json!({ "should": "not-reach" })).await;
    let (base, client, _org_id, _identity_id, api_key, admin_key) =
        setup(pool, runtime_addr, "b").await;

    // Use a `risk: delete` action so the group ceiling's auto_approve_reads
    // doesn't short-circuit the chain walk — we want to force a gap.
    let tpl = json!({
        "openapi": "3.1.0",
        "info": { "title": "DangerMCP", "key": "mcp_danger", "runtime": "mcp" },
        "mcp": { "package": "fake-mcp", "version": "0.0.1", "env": {} },
        "paths": {},
        "actions": {
            "wipe": { "tool": "wipe", "description": "wipe everything", "risk": "delete" }
        },
    });
    create_template(&base, &client, &admin_key, tpl).await;
    create_service(&base, &client, &api_key, "mcp_danger", "dang-1").await;
    // No permission grant.

    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({ "service": "dang-1", "action": "wipe", "params": {} }))
        .send()
        .await
        .unwrap();

    // Same gating machinery as HTTP services — missing permission on a
    // mutating action should create an approval, not dispatch to the runtime.
    let status = resp.status();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        status, 202,
        "expected pending_approval; got {status} with body {body}"
    );
    assert_eq!(body["status"], "pending_approval");
    assert!(body["approval_id"].is_string());
    assert_eq!(
        calls.lock().unwrap().len(),
        0,
        "runtime must not be called when approval is pending"
    );
}

#[tokio::test]
async fn mcp_execute_env_hash_rotates_when_secret_rotates() {
    let pool = common::test_pool().await;
    let (runtime_addr, calls) = start_mock_runtime("b".into(), |_| json!({ "ok": true })).await;
    let (base, client, _org_id, identity_id, api_key, admin_key) =
        setup(pool, runtime_addr, "b").await;

    create_template(&base, &client, &admin_key, secret_env_template("mcp_rot_t")).await;
    create_service(&base, &client, &api_key, "mcp_rot_t", "rot-1").await;

    grant_rule(&base, &client, &admin_key, identity_id, "rot-1:ping:*").await;

    // First call with TOKEN=v1.
    client
        .put(format!("{base}/v1/secrets/DEMO_TOKEN"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "value": "v1" }))
        .send()
        .await
        .unwrap();
    let r1 = client
        .post(format!("{base}/v1/actions/execute"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({ "service": "rot-1", "action": "ping", "params": {} }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r1.status(),
        200,
        "first execute failed: {}",
        r1.text().await.unwrap()
    );

    // Rotate the secret to v2 and re-execute.
    client
        .put(format!("{base}/v1/secrets/DEMO_TOKEN"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "value": "v2" }))
        .send()
        .await
        .unwrap();
    let r2 = client
        .post(format!("{base}/v1/actions/execute"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({ "service": "rot-1", "action": "ping", "params": {} }))
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 200);

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2, "runtime received both invokes");
    assert_eq!(calls[0].env.get("TOKEN").map(String::as_str), Some("v1"));
    assert_eq!(calls[1].env.get("TOKEN").map(String::as_str), Some("v2"));
    assert_ne!(
        calls[0].env_hash, calls[1].env_hash,
        "env_hash must change when secret rotates — runtime relies on this to restart the subprocess"
    );
}

#[tokio::test]
async fn mcp_execute_with_no_runtime_configured_returns_409() {
    let pool = common::test_pool().await;
    // start_api (NOT start_api_with_mcp_runtime) leaves mcp_runtime=None.
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, identity_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    create_template(
        &base,
        &client,
        &admin_key,
        mcp_hn_like_template("mcp_no_rt"),
    )
    .await;
    create_service(&base, &client, &api_key, "mcp_no_rt", "hn-no").await;
    grant_rule(
        &base,
        &client,
        &admin_key,
        identity_id,
        "hn-no:get_stories:*",
    )
    .await;

    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({ "service": "hn-no", "action": "get_stories", "params": {} }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "denied");
    assert!(
        body["reason"]
            .as_str()
            .unwrap_or("")
            .contains("mcp_runtime_unavailable"),
        "reason should mention mcp_runtime_unavailable, got: {}",
        body["reason"]
    );
}
