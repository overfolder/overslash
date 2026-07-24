//! Slack E2E tests — Overslash wrapping Slack's official MCP server.
//!
//! Slack ships a first-party MCP server (https://mcp.slack.com/mcp). Overslash
//! is the MCP *client*: it wraps Slack's tools, resolves a Slack OAuth
//! connection into the outbound bearer, and layers permission chain + approvals
//! + audit on top. These tests cover:
//!   * `slack_mcp_yaml_parses` — the shipped global template loads as an
//!     mcp-runtime service with `auth.kind: oauth` and the decorated tools.
//!   * `slack_mcp_oauth_forwards_connection_token` — a full connection-based
//!     (Mode B/C) MCP call: the owner's Slack OAuth token is auto-resolved and
//!     forwarded as `Authorization: Bearer …` to the upstream MCP server.
//!   * `slack_mcp_missing_connection_is_reported` — no connection → a clear
//!     error before any upstream call, proving OAuth resolution is wired.
//!
//! Everything runs against an in-process MCP stub; nothing reaches the network.

// Test setup requires dynamic SQL for DB seeding.
#![allow(clippy::disallowed_methods)]

use crate::common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
use overslash_core::registry::ServiceRegistry;
use overslash_core::types::{McpAuth, Runtime};
use serde_json::{Value, json};
use std::path::Path;
use tokio::net::TcpListener;

// ── MCP stub: records the Authorization header, echoes tool arguments ──────

#[derive(Default)]
struct StubInner {
    last_auth: Option<String>,
}

#[derive(Clone, Default)]
struct Stub {
    inner: Arc<Mutex<StubInner>>,
}

impl Stub {
    fn last_auth(&self) -> Option<String> {
        self.inner.lock().unwrap().last_auth.clone()
    }
}

async fn stub_handler(
    State(stub): State<Stub>,
    headers: HeaderMap,
    Json(req): Json<Value>,
) -> Json<Value> {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");

    stub.inner.lock().unwrap().last_auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let result = match method {
        "initialize" => json!({
            "protocolVersion": "2025-06-18",
            "serverInfo": { "name": "slack-mcp-stub", "version": "0" },
            "capabilities": {}
        }),
        "tools/call" => {
            let args = req
                .get("params")
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or(Value::Null);
            json!({
                "content": [{ "type": "text", "text": "ok" }],
                "structuredContent": { "echo": args },
                "isError": false
            })
        }
        _ => json!({}),
    };

    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

async fn start_stub() -> (SocketAddr, Stub) {
    common::allow_loopback_ssrf();
    let stub = Stub::default();
    let app = Router::new()
        .route("/mcp", post(stub_handler))
        .with_state(stub.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, stub)
}

// ── An org-tier Slack-MCP template pointed at the stub. Mirrors the shipped
//    global's shape (runtime mcp, auth oauth provider slack) so the OAuth path
//    is what's under test, but with a distinct key + stub URL. ───────────────
fn slack_mcp_template_yaml(key: &str, url: &str) -> String {
    format!(
        r#"openapi: 3.1.0
info:
  title: Slack (MCP test)
  x-overslash-key: {key}
x-overslash-runtime: mcp
paths: {{}}
x-overslash-mcp:
  url: {url}
  auth:
    kind: oauth
    provider: slack
    scopes: [channels:read, chat:write]
  autodiscover: true
  tools:
    - name: list_channels
      risk: read
      description: List channels
      input_schema:
        type: object
        properties:
          limit: {{ type: integer }}
        required: []
"#
    )
}

/// Seed a Slack OAuth connection (+ BYOC so client-credential resolution
/// succeeds) on `owner_id`, mirroring the HTTP-runtime OAuth seeding. Returns
/// the new connection's id.
async fn seed_slack_connection(
    pool: &sqlx::PgPool,
    org_id: uuid::Uuid,
    owner_id: uuid::Uuid,
) -> uuid::Uuid {
    let enc_key = overslash_core::crypto::Keyring::test();
    let token = overslash_core::crypto::encrypt(&enc_key, b"slack-mcp-user-token").unwrap();
    let cid = overslash_core::crypto::encrypt(&enc_key, b"mock_client_id").unwrap();
    let csec = overslash_core::crypto::encrypt(&enc_key, b"mock_client_secret").unwrap();
    let future = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let byoc = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_byoc_credential(owner_id, "slack", &cid, &csec, &serde_json::json!({}))
        .await
        .unwrap();
    overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: owner_id,
            provider_key: "slack",
            encrypted_access_token: &token,
            encrypted_refresh_token: None,
            token_expires_at: Some(future),
            scopes: None,
            account_email: None,
            byoc_credential_id: Some(byoc.id),
        })
        .await
        .unwrap()
        .id
}

// ============================================================================
// Parse smoke test — the shipped global loads as an oauth mcp-runtime service
// ============================================================================

#[test]
fn slack_mcp_yaml_parses() {
    let ws_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let reg = ServiceRegistry::load_from_dir(&ws_root.join("services"))
        .expect("services/ should load cleanly");
    let svc = reg.get("slack").expect("slack should be registered");

    // Runtime + upstream MCP endpoint.
    assert_eq!(svc.runtime, Runtime::Mcp);
    let mcp = svc.mcp.as_ref().expect("slack should carry an mcp block");
    assert_eq!(mcp.url.as_deref(), Some("https://mcp.slack.com/mcp"));

    // OAuth auth wired to the slack provider (not a static bearer secret).
    match &mcp.auth {
        McpAuth::OAuth { provider, .. } => assert_eq!(provider, "slack"),
        other => panic!("expected oauth auth, got {other:?}"),
    }

    // Tools present.
    for tool in [
        "send_message",
        "list_channels",
        "read_channel_history",
        "get_user",
        "search_messages",
    ] {
        assert!(svc.actions.contains_key(tool), "missing tool '{tool}'");
    }

    // Decorations applied only where they help: the write tool carries a
    // disclosure projection + channel scope; the ID-scoped reads carry scopes.
    let send = &svc.actions["send_message"];
    assert_eq!(send.risk, overslash_core::types::Risk::Write);
    assert_eq!(send.scope_param, "channel".into());
    assert!(
        !send.disclose.is_empty(),
        "send_message should disclose channel + text for approval review"
    );
    assert_eq!(
        svc.actions["read_channel_history"].scope_param,
        "channel".into()
    );
    assert_eq!(svc.actions["get_user"].scope_param, "user".into());
    // Undecorated reads stay plain.
    assert!(svc.actions["list_channels"].scope_param.is_empty());
    assert_eq!(
        svc.actions["list_channels"].risk,
        overslash_core::types::Risk::Read
    );
}

// ============================================================================
// OAuth MCP execution — the connection token is forwarded to the MCP server
// ============================================================================

#[tokio::test]
async fn slack_mcp_oauth_forwards_connection_token() {
    let pool = common::test_pool().await;
    let (addr, stub) = start_stub().await;
    let stub_url = format!("http://{addr}/mcp");

    let (base, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{base}");
    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    let owner_id = common::owner_user_id(&pool, org_id).await;

    // Upload the org-tier Slack-MCP template (oauth / provider slack).
    let key_name = "slack_mcp_test";
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"openapi": slack_mcp_template_yaml(key_name, &stub_url)}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "template create: {:?}",
        resp.text().await
    );

    // The template-detail DTO must surface the oauth provider + scopes so the
    // dashboard connect flow requests the right scope set (not an empty one).
    let detail: Value = client
        .get(format!("{base}/v1/templates/{key_name}"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["mcp"]["auth_kind"], "oauth");
    assert_eq!(detail["mcp"]["provider"], "slack");
    let dto_scopes: Vec<String> = detail["mcp"]["scopes"]
        .as_array()
        .expect("mcp.scopes should be present for oauth")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(
        dto_scopes.contains(&"chat:write".to_string())
            && dto_scopes.contains(&"channels:read".to_string()),
        "mcp.scopes should round-trip through McpDetail, got {dto_scopes:?}"
    );
    // The top-level `scopes` (for white-label/token-vault consumers) must also
    // include the mcp oauth scopes — MCP tools carry no per-action scopes.
    let top_scopes: Vec<String> = detail["scopes"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        top_scopes.contains(&"chat:write".to_string()),
        "template-level scopes should include mcp oauth scopes, got {top_scopes:?}"
    );

    // Permission (`**` covers 2- and 3-segment MCP action keys) + Layer-1 access.
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": format!("{key_name}:**")}))
        .send()
        .await
        .unwrap();
    common::grant_service_to_everyone(&base, &client, &admin_key, key_name).await;

    // Seed the owner's Slack connection (D22 owner-resolve).
    seed_slack_connection(&pool, org_id, owner_id).await;

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": key_name,
            "action": "list_channels",
            "params": { "limit": 5 }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let envelope: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(envelope["runtime"], "mcp");
    assert_eq!(envelope["tool"], "list_channels");
    assert_eq!(envelope["structured"]["echo"]["limit"], 5);

    // The owner's Slack OAuth token was resolved and forwarded to the MCP server.
    assert_eq!(
        stub.last_auth().as_deref(),
        Some("Bearer slack-mcp-user-token"),
        "MCP call should carry the auto-resolved Slack connection token"
    );
}

// ============================================================================
// Pinning a Slack connection at service-create time must be accepted — the
// provider-match validation has to see the MCP `auth.kind: oauth` provider,
// not just an HTTP oauth scheme (regression: connection_provider_mismatch).
// ============================================================================

#[tokio::test]
async fn slack_mcp_pinned_connection_accepted() {
    let pool = common::test_pool().await;
    let (addr, _stub) = start_stub().await;
    let stub_url = format!("http://{addr}/mcp");

    let (base, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{base}");
    let (org_id, _ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    let owner_id = common::owner_user_id(&pool, org_id).await;

    let key_name = "slack_mcp_pin";
    client
        .post(format!("{base}/v1/templates"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"openapi": slack_mcp_template_yaml(key_name, &stub_url)}))
        .send()
        .await
        .unwrap();

    // Seed the connection and pin it explicitly on the new service instance.
    let conn_id = seed_slack_connection(&pool, org_id, owner_id).await;
    let resp = client
        .post(format!("{base}/v1/services"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "name": key_name,
            "template_key": key_name,
            "connection_id": conn_id,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "pinning a slack connection on the mcp-oauth template should be accepted: {:?}",
        resp.text().await
    );
}

// ============================================================================
// OAuth MCP with no connection — clean error, no upstream call
// ============================================================================

#[tokio::test]
async fn slack_mcp_missing_connection_is_reported() {
    let pool = common::test_pool().await;
    let (addr, stub) = start_stub().await;
    let stub_url = format!("http://{addr}/mcp");

    let (base, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{base}");
    let (_org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;

    let key_name = "slack_mcp_noconn";
    client
        .post(format!("{base}/v1/templates"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"openapi": slack_mcp_template_yaml(key_name, &stub_url)}))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": format!("{key_name}:**")}))
        .send()
        .await
        .unwrap();
    common::grant_service_to_everyone(&base, &client, &admin_key, key_name).await;

    // No connection seeded → resolution fails before any upstream call.
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": key_name,
            "action": "list_channels",
            "params": {}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "{:?}", resp.text().await);
    assert!(
        stub.last_auth().is_none(),
        "upstream MCP server must not be contacted when no connection exists"
    );
}
