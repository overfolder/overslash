//! End-to-end integration test for the shipped `email` service (the overfwd
//! Mailbox Gateway), exercised through the real `/v1/actions/call` path.
//!
//! Proves the three overfwd-enabling changes together, against an in-process
//! mock that impersonates an overfwd deployment:
//!   • Core A — base64 `SecretRef` encoding: the mailbox `user:pass` secret is
//!     injected as `X-Mailbox-Auth: Basic base64(user:pass)`.
//!   • Core B — multi-injection auth: the gateway key (`secret_source: org`)
//!     and the mailbox credential (`secret_source: instance`) ride the SAME
//!     request as `Authorization: Bearer …` + `X-Mailbox-Auth: Basic …`.
//!   • Core C — per-instance `url` override: the request routes to the org's
//!     own deployment URL (scheme + port preserved), not the template default.
//!
//! Also asserts `send` is `write`-gated (approval) and discloses To/From/Subject.
//!
//! Run with `--test-threads=4` (see CLAUDE.md).

#![allow(clippy::disallowed_methods)]

mod common;

use std::sync::{Arc, Mutex};

use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use common::{bootstrap_org_identity, start_api_with_registry};

// base64("user@example.com:app-password"), STANDARD alphabet.
const MAILBOX_CRED: &str = "user@example.com:app-password";
const MAILBOX_BASIC: &str = "Basic dXNlckBleGFtcGxlLmNvbTphcHAtcGFzc3dvcmQ=";
const GATEWAY_KEY: &str = "gw-secret-key";

#[derive(Clone, Default)]
struct Captured {
    path: String,
    authorization: Option<String>,
    mailbox_auth: Option<String>,
    body: Value,
}

type Sink = Arc<Mutex<Vec<Captured>>>;

/// In-process stand-in for a deployed overfwd gateway. Records the two auth
/// headers, the path, and the JSON body of every request, then returns a
/// minimal overfwd-shaped success.
async fn start_mock_overfwd() -> (String, Sink) {
    common::allow_loopback_ssrf();
    let sink: Sink = Arc::new(Mutex::new(Vec::new()));

    async fn handler(
        State(sink): State<Sink>,
        uri: axum::http::Uri,
        headers: HeaderMap,
        body: axum::body::Bytes,
    ) -> Json<Value> {
        let header = |k: &str| {
            headers
                .get(k)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        sink.lock().unwrap().push(Captured {
            path: uri.path().to_string(),
            authorization: header("authorization"),
            mailbox_auth: header("x-mailbox-auth"),
            body: serde_json::from_slice(&body).unwrap_or(Value::Null),
        });
        Json(json!({ "messages": [], "sent": true }))
    }

    let app = Router::new()
        .route("/email/search", post(handler))
        .route("/email/get", post(handler))
        .route("/email/send", post(handler))
        .with_state(sink.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), sink)
}

/// Boot the API with the shipped registry (so `services/email.yaml` loads),
/// seed both secrets, create an `email` instance pointed at `gateway_url`, and
/// grant it to Everyone (admin + auto-approve reads). Returns
/// `(base, agent_key)` for issuing action calls.
async fn setup_email_instance(pool: sqlx::PgPool, gateway_url: &str) -> (String, String) {
    let (base, client) = start_api_with_registry(pool, None).await;
    let (_org_id, _ident_id, agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    // The gateway key is an org-vault secret referenced by the template's
    // fixed `default_secret_name` (secret_source: org); the mailbox credential
    // is the per-instance bound secret (secret_source: instance).
    for (name, value) in [
        ("overfwd_gateway_key", GATEWAY_KEY),
        ("mailbox_credential", MAILBOX_CRED),
    ] {
        let resp = client
            .put(format!("{base}/v1/secrets/{name}"))
            .header("Authorization", format!("Bearer {admin_key}"))
            .json(&json!({ "value": value }))
            .send()
            .await
            .unwrap();
        assert!(
            resp.status().is_success(),
            "secret {name} create failed: {}",
            resp.status()
        );
    }

    // Per-instance url override → the org's own overfwd deployment.
    let instance: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "email",
            "name": "email",
            "url": gateway_url,
            "secret_name": "mailbox_credential",
            "user_level": false,
            "status": "active",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let svc_id = instance["id"]
        .as_str()
        .unwrap_or_else(|| panic!("email instance create failed: {instance:?}"));

    let groups: Vec<Value> = client
        .get(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let everyone_id = groups
        .iter()
        .find(|g| g["system_kind"].as_str() == Some("everyone"))
        .and_then(|g| g["id"].as_str())
        .expect("Everyone group not found");

    let grant = client
        .post(format!("{base}/v1/groups/{everyone_id}/grants"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "service_instance_id": svc_id,
            "access_level": "admin",
            "auto_approve_reads": true,
        }))
        .send()
        .await
        .unwrap();
    assert!(
        grant.status() == 200 || grant.status() == 409,
        "grant failed: {}",
        grant.status()
    );

    (base, agent_key)
}

#[tokio::test]
async fn email_search_dual_injects_auth_and_routes_to_instance_url() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, agent_key) = setup_email_instance(pool, &gateway_url).await;

    // `search` is a read → auto-approved by the grant → executes inline.
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "email",
            "action": "search",
            "params": { "query": "UNSEEN" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "read should auto-execute: {}",
        resp.text().await.unwrap()
    );

    let captured = sink.lock().unwrap().clone();
    assert_eq!(
        captured.len(),
        1,
        "gateway should receive exactly one request"
    );
    let req = &captured[0];

    // Core C — routed to the per-instance url (this mock), on the right path.
    assert_eq!(req.path, "/email/search");
    // Core B — the gateway key rode as Authorization: Bearer.
    assert_eq!(
        req.authorization.as_deref(),
        Some("Bearer gw-secret-key"),
        "gateway (secret_source: org) key must inject as Authorization: Bearer"
    );
    // Core A + B — the mailbox credential rode as X-Mailbox-Auth: Basic base64.
    assert_eq!(
        req.mailbox_auth.as_deref(),
        Some(MAILBOX_BASIC),
        "mailbox (secret_source: instance) must inject as Basic base64(user:pass)"
    );
    // The search key made it into the JSON body.
    assert_eq!(req.body["query"], json!("UNSEEN"));
}

#[tokio::test]
async fn email_send_is_write_gated_and_discloses_message() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, agent_key) = setup_email_instance(pool, &gateway_url).await;

    // `send` is a write → gated: the call returns a pending approval BEFORE any
    // HTTP request is made, and the approval discloses the message.
    let exec: Value = reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "email",
            "action": "send",
            "params": {
                "from": "me@example.com",
                "to": ["boss@example.com"],
                "subject": "Q3 numbers",
                "text": "Attached."
            }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(
        exec["status"].as_str(),
        Some("pending_approval"),
        "write action must be gated: {exec:?}"
    );

    // The disclosed fields carry the human-meaningful parts of the message.
    let disclosed = exec["disclosed_fields"]
        .as_array()
        .expect("disclosed_fields present on the pending_approval envelope");
    let by_label = |label: &str| -> Option<String> {
        disclosed
            .iter()
            .find(|f| f["label"] == json!(label))
            .and_then(|f| f["value"].as_str())
            .map(str::to_string)
    };
    assert_eq!(by_label("Subject").as_deref(), Some("Q3 numbers"));
    assert_eq!(by_label("From").as_deref(), Some("me@example.com"));
    assert_eq!(
        by_label("To").as_deref(),
        Some("boss@example.com"),
        "To (array) should be joined for disclosure"
    );

    // Gated before any HTTP call — the gateway saw nothing.
    assert_eq!(sink.lock().unwrap().len(), 0);
}
