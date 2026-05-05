//! Tests for the universal `auto_call_on_approve` toggle on identities.
//!
//! Pre-migration this lived on `mcp_client_agent_bindings` and only fired
//! for MCP-bound agents. After the move, it sits on the agent identity and
//! applies to REST + white-label agents too. The org-level
//! `default_deferred_execution` flag flips the seed value at agent
//! creation time without touching existing rows.
//!
//! Run with `--test-threads=4` (or similar) — see CLAUDE.md.

#![allow(clippy::disallowed_methods)]

mod common;

use std::time::Duration;

use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
};
use reqwest::Client;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use uuid::Uuid;

// ── Mock target with introspectable webhook receiver ────────────────────

#[derive(Default)]
struct WebhookSink {
    payloads: Vec<Value>,
}

type Sink = Arc<Mutex<WebhookSink>>;

async fn echo(_uri: axum::http::Uri, _headers: HeaderMap, body: axum::body::Bytes) -> Json<Value> {
    Json(json!({
        "ok": true,
        "echoed": String::from_utf8_lossy(&body).to_string(),
    }))
}

async fn receive_webhook(State(s): State<Sink>, Json(p): Json<Value>) -> &'static str {
    s.lock().unwrap().payloads.push(p);
    "ok"
}

async fn list_webhooks(State(s): State<Sink>) -> Json<Value> {
    Json(json!({"webhooks": s.lock().unwrap().payloads.clone()}))
}

async fn start_mock() -> (std::net::SocketAddr, Sink) {
    common::allow_loopback_ssrf();
    let sink: Sink = Arc::new(Mutex::new(WebhookSink::default()));
    let app = Router::new()
        .route("/echo", get(echo).post(echo))
        .route("/webhooks/receive", post(receive_webhook))
        .route("/webhooks/received", get(list_webhooks))
        .with_state(sink.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, sink)
}

// ── Helpers (local to this file — `common::bootstrap_org_identity`
// disables auto-call by default so existing manual-call tests keep
// passing; here we want the post-migration default ON, so we roll our
// own bootstrap that does NOT flip the toggle.) ─────────────────────────

async fn bootstrap_with_auto_call_on(
    pool: sqlx::PgPool,
) -> (
    std::net::SocketAddr,
    Sink,
    String,
    Uuid,
    Uuid,
    String,
    String,
) {
    let (api_addr, client) = common::start_api(pool).await;
    let base = format!("http://{api_addr}");
    let (mock_addr, sink) = start_mock().await;

    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "AutoCallOrg", "slug": format!("auto-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();

    let bootstrap_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "org-admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin_key = bootstrap_resp["key"].as_str().unwrap().to_string();

    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": "test-user", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id: Uuid = user["id"].as_str().unwrap().parse().unwrap();

    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": "test-agent", "kind": "agent", "parent_id": user_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id: Uuid = agent["id"].as_str().unwrap().parse().unwrap();
    // The new agent honours the column default — auto_call_on_approve = true.
    assert_eq!(
        agent["auto_call_on_approve"],
        json!(true),
        "fresh agent should default to auto_call_on_approve=true"
    );

    let agent_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"org_id": org_id, "identity_id": agent_id, "name": "agent"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_key = agent_key_resp["key"].as_str().unwrap().to_string();

    client
        .put(format!("{base}/v1/secrets/tk"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"value": "v"}))
        .send()
        .await
        .unwrap();

    (
        mock_addr, sink, base, org_id, agent_id, agent_key, admin_key,
    )
}

async fn create_pending_approval(
    base: &str,
    agent_key: &str,
    mock_addr: std::net::SocketAddr,
) -> String {
    let resp = Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "method": "GET",
            "url": format!("http://{mock_addr}/echo"),
            "secrets": [{"name": "tk", "inject_as": "header", "header_name": "X-Auth"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202, "expected pending_approval");
    let body: Value = resp.json().await.unwrap();
    body["approval_id"].as_str().unwrap().to_string()
}

/// Poll the execution row until it reaches a terminal state (or timeout).
/// Auto-call is async — `/resolve` returns before the spawned task has run.
async fn poll_execution(base: &str, key: &str, approval_id: &str) -> Value {
    let client = Client::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let resp = client
            .get(format!("{base}/v1/approvals/{approval_id}/execution"))
            .header("Authorization", format!("Bearer {key}"))
            .send()
            .await
            .unwrap();
        if resp.status() == 200 {
            let body: Value = resp.json().await.unwrap();
            let status = body["status"].as_str().unwrap_or("");
            if status == "executed" || status == "failed" {
                return body;
            }
        }
        if std::time::Instant::now() > deadline {
            panic!("execution did not finalize within 5s");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn rest_agent_auto_executes_by_default_after_resolve() {
    let pool = common::test_pool().await;
    let (mock_addr, _sink, base, _org_id, _agent_id, agent_key, admin_key) =
        bootstrap_with_auto_call_on(pool).await;

    let approval_id = create_pending_approval(&base, &agent_key, mock_addr).await;

    // Resolver allows. With universal auto-call ON (default), the resolve
    // handler must spawn a background execution — no manual /call needed.
    let resp = Client::new()
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"resolution": "allow"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let exec = poll_execution(&base, &agent_key, &approval_id).await;
    assert_eq!(exec["status"], "executed");
    assert_eq!(
        exec["triggered_by"], "auto",
        "auto-call must stamp triggered_by=auto"
    );
    // Replay result is on the row.
    assert!(exec["result"]["status_code"].as_u64().is_some());
}

#[tokio::test]
async fn per_agent_disable_falls_back_to_manual_call() {
    let pool = common::test_pool().await;
    let (mock_addr, _sink, base, _org_id, agent_id, agent_key, admin_key) =
        bootstrap_with_auto_call_on(pool).await;

    // Flip the per-agent toggle off. Subsequent approvals stay pending
    // until something explicitly POSTs /call.
    let updated: Value = Client::new()
        .patch(format!(
            "{base}/v1/identities/{agent_id}/auto-call-on-approve"
        ))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"enabled": false}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(updated["auto_call_on_approve"], json!(false));

    let approval_id = create_pending_approval(&base, &agent_key, mock_addr).await;

    let resp = Client::new()
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"resolution": "allow"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Auto-call must NOT have fired. The execution row exists but stays
    // pending. Give the runtime a beat so a (buggy) auto-call would have
    // landed before we sample.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let exec: Value = Client::new()
        .get(format!("{base}/v1/approvals/{approval_id}/execution"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(exec["status"], "pending");

    // Manual /call wins the claim and stamps triggered_by=agent.
    let resp = Client::new()
        .post(format!("{base}/v1/approvals/{approval_id}/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["execution"]["status"], "executed");
    assert_eq!(body["execution"]["triggered_by"], "agent");
}

#[tokio::test]
async fn org_default_deferred_execution_seeds_new_agents_off() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool).await;
    let base = format!("http://{api_addr}");

    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "DefOrg", "slug": format!("def-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();

    let bootstrap_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin_key = bootstrap_resp["key"].as_str().unwrap().to_string();

    // Create an agent BEFORE flipping the org default — it should be
    // born with the universal default (auto_call_on_approve=true).
    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": "u", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = user["id"].as_str().unwrap();
    let agent_before: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": "before", "kind": "agent", "parent_id": user_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(agent_before["auto_call_on_approve"], json!(true));

    // Flip the org default to deferred-by-default.
    let updated: Value = client
        .patch(format!("{base}/v1/orgs/{org_id}/execution-settings"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"default_deferred_execution": true}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(updated["default_deferred_execution"], json!(true));

    // A NEW agent created after the flip is seeded with auto-call OFF.
    let agent_after: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": "after", "kind": "agent", "parent_id": user_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        agent_after["auto_call_on_approve"],
        json!(false),
        "post-flip agent should be seeded with auto_call_on_approve=false"
    );

    // The pre-flip agent is NOT touched retroactively.
    let agent_before_again: Value = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let arr = agent_before_again.as_array().unwrap();
    let before_row = arr
        .iter()
        .find(|i| i["id"] == agent_before["id"])
        .expect("pre-flip agent listed");
    assert_eq!(
        before_row["auto_call_on_approve"],
        json!(true),
        "existing agents must not be retroactively flipped by org policy"
    );
}

#[tokio::test]
async fn webhook_payload_carries_result_only_for_auto_calls() {
    let pool = common::test_pool().await;
    let (mock_addr, sink, base, _org_id, agent_id, agent_key, admin_key) =
        bootstrap_with_auto_call_on(pool).await;

    // Subscribe a webhook for both events we'll observe.
    Client::new()
        .post(format!("{base}/v1/webhooks"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "url": format!("http://{mock_addr}/webhooks/receive"),
            "events": ["approval.executed"],
        }))
        .send()
        .await
        .unwrap();

    // 1) Auto-fired execution → payload carries `result`.
    let approval_id = create_pending_approval(&base, &agent_key, mock_addr).await;
    Client::new()
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"resolution": "allow"}))
        .send()
        .await
        .unwrap();
    let _ = poll_execution(&base, &agent_key, &approval_id).await;

    // 2) Manually-fired execution against the same agent (after flipping
    // auto-call off) → payload omits `result`.
    Client::new()
        .patch(format!(
            "{base}/v1/identities/{agent_id}/auto-call-on-approve"
        ))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    let approval_id_manual = create_pending_approval(&base, &agent_key, mock_addr).await;
    Client::new()
        .post(format!("{base}/v1/approvals/{approval_id_manual}/resolve"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"resolution": "allow"}))
        .send()
        .await
        .unwrap();
    Client::new()
        .post(format!("{base}/v1/approvals/{approval_id_manual}/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap();

    // Webhook delivery is fire-and-forget; allow the dispatcher loop time.
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    loop {
        let payloads = sink.lock().unwrap().payloads.clone();
        let auto = payloads.iter().find(|p| {
            p["data"]["approval_id"] == approval_id && p["data"]["triggered_by"] == "auto"
        });
        let manual = payloads.iter().find(|p| {
            p["data"]["approval_id"] == approval_id_manual && p["data"]["triggered_by"] == "agent"
        });
        if let (Some(auto), Some(manual)) = (auto, manual) {
            assert!(
                auto["data"].get("result").is_some(),
                "auto-fired webhook payload must include result: {auto}"
            );
            assert!(
                manual["data"].get("result").is_none(),
                "manual-call webhook payload must NOT include result: {manual}"
            );
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!(
                "did not observe both webhook deliveries; got: {:?}",
                sink.lock().unwrap().payloads
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
