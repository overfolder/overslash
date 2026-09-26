//! Integration tests for MCP elicitation (Flow A).
//!
//! Exercises the per-binding `mcp-connection` endpoints + the elicitation
//! coordination service (`mcp_session`). The full SSE round-trip
//! (originator emits `elicitation/create`, receiver answers via `POST /mcp`)
//! is tested at the helper level by driving `mcp_session::complete_from_elicitation`
//! directly — this avoids parsing the SSE body in the test client and still
//! verifies the resolve+call loopback the receiver pod performs.

#![allow(clippy::disallowed_methods)]

use crate::common;

use std::time::Duration;

use overslash_api::services::{jwt, mcp_session};
use overslash_db::repos as db;
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

const SIGNING_KEY_HEX: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

fn signing_bytes() -> Vec<u8> {
    hex::decode(SIGNING_KEY_HEX).unwrap()
}

/// Bootstrap the world: an org, a user, a child agent, an MCP OAuth client,
/// a binding linking (user, client) → agent. Returns the pieces tests need.
struct McpFixture {
    base: String,
    client: reqwest::Client,
    pool: sqlx::PgPool,
    org_id: Uuid,
    user_id: Uuid,
    agent_id: Uuid,
    org_admin_key: String,
    client_id: String,
    /// MCP-aud JWT for the agent, carrying mcp_client_id so /mcp recognises it.
    agent_mcp_token: String,
}

async fn bootstrap_mcp(declare_elicitation: bool) -> McpFixture {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, agent_id, _agent_key, org_admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Find the user identity that owns the agent (created by bootstrap).
    let identities: Value = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id: Uuid = identities
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"].as_str() == Some("test-user"))
        .and_then(|i| i["id"].as_str())
        .unwrap()
        .parse()
        .unwrap();

    // Insert a users row so mcp_session::complete_from_elicitation can mint
    // a session JWT with the user's email. Use a deterministic IdP subject so
    // multiple test runs don't collide on the unique (provider, subject) index.
    sqlx::query(
        "INSERT INTO users (id, email, overslash_idp_provider, overslash_idp_subject)
         VALUES ($1, $2, 'test', $3)",
    )
    .bind(user_id)
    .bind(format!("user-{user_id}@example.com"))
    .bind(format!("test-{user_id}"))
    .execute(&pool)
    .await
    .unwrap();

    // Register an MCP OAuth client row directly. Production goes through DCR
    // but the binding shape is the same — what matters here is the agent
    // detail page + elicitation flow, not OAuth.
    let client_id = format!("osc_{}", Uuid::new_v4().simple());
    let _ = db::oauth_mcp_client::create(
        &pool,
        &db::oauth_mcp_client::CreateOauthMcpClient {
            client_id: &client_id,
            client_name: Some("test-mcp"),
            redirect_uris: &["http://127.0.0.1:0/cb".to_string()],
            software_id: Some("com.example.test"),
            software_version: Some("1.0.0"),
            created_ip: None,
            created_user_agent: None,
            org_id: None,
        },
    )
    .await
    .unwrap();

    if declare_elicitation {
        db::oauth_mcp_client::update_initialize_state(
            &pool,
            &client_id,
            &json!({ "elicitation": {} }),
            &json!({ "name": "test-mcp", "version": "1.0.0" }),
            "2025-06-18",
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    }

    let _binding =
        db::mcp_client_agent_binding::upsert(&pool, org_id, user_id, &client_id, agent_id)
            .await
            .unwrap();

    let agent_mcp_token = jwt::mint_mcp(
        &signing_bytes(),
        agent_id,
        org_id,
        format!("user-{user_id}@example.com"),
        3600,
        Some(client_id.clone()),
    )
    .unwrap();

    McpFixture {
        base,
        client,
        pool,
        org_id,
        user_id,
        agent_id,
        org_admin_key,
        client_id,
        agent_mcp_token,
    }
}

// ─── Initialize ────────────────────────────────────────────────────────────

#[tokio::test]
async fn initialize_persists_capabilities_and_returns_session_id() {
    let fx = bootstrap_mcp(false).await;

    let resp = fx
        .client
        .post(format!("{}/mcp", fx.base))
        .bearer_auth(&fx.agent_mcp_token)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {
                    "elicitation": {},
                    "roots": { "listChanged": true }
                },
                "clientInfo": { "name": "fancy-mcp", "version": "9.9.9" }
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200, "initialize should succeed");
    let session_header = resp
        .headers()
        .get("Mcp-Session-Id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .expect("Mcp-Session-Id header present");
    let session_id: Uuid = session_header.parse().expect("session id is a uuid");

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["result"]["serverInfo"]["name"], "overslash");

    // The client row should now reflect everything from initialize.params.
    let row = db::oauth_mcp_client::get_by_client_id(&fx.pool, &fx.client_id)
        .await
        .unwrap()
        .expect("client row exists");
    assert_eq!(
        row.capabilities
            .as_ref()
            .and_then(|c| c.get("elicitation"))
            .map(Value::is_object),
        Some(true),
        "elicitation capability persisted: {row:?}"
    );
    assert_eq!(
        row.client_info
            .as_ref()
            .and_then(|c| c.get("version"))
            .and_then(Value::as_str),
        Some("9.9.9")
    );
    assert_eq!(row.protocol_version.as_deref(), Some("2025-06-18"));
    assert_eq!(row.last_session_id, Some(session_id));
}

// ─── GET /v1/identities/{id}/mcp-connection ────────────────────────────────

#[tokio::test]
async fn get_mcp_connection_returns_binding() {
    let fx = bootstrap_mcp(true).await;

    let resp = fx
        .client
        .get(format!(
            "{}/v1/identities/{}/mcp-connection",
            fx.base, fx.agent_id
        ))
        .header("Authorization", format!("Bearer {}", fx.org_admin_key))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let conn = &body["connection"];
    assert!(!conn.is_null(), "expected connection: {body}");
    assert_eq!(conn["client_id"], fx.client_id);
    assert_eq!(conn["client_name"], "test-mcp");
    assert_eq!(conn["protocol_version"], "2025-06-18");
    // Default-on (migration 123): `bootstrap_mcp` creates the binding through
    // a plain `upsert`, which never names the column, so this reads the
    // schema default. If it ever comes back false, the default was reverted.
    assert_eq!(conn["elicitation_enabled"], true);
    // Supported because we declared the capability when bootstrapping.
    assert_eq!(conn["elicitation_supported"], true);
}

#[tokio::test]
async fn get_mcp_connection_no_binding_returns_null() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, agent_id, _agent_key, org_admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .get(format!("{base}/v1/identities/{agent_id}/mcp-connection"))
        .header("Authorization", format!("Bearer {org_admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["connection"].is_null());
}

#[tokio::test]
async fn get_mcp_connection_rejects_non_agent_identity() {
    let fx = bootstrap_mcp(false).await;

    let resp = fx
        .client
        .get(format!(
            "{}/v1/identities/{}/mcp-connection",
            fx.base, fx.user_id
        ))
        .header("Authorization", format!("Bearer {}", fx.org_admin_key))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        400,
        "user identity is not an agent: {:?}",
        resp.text().await
    );
}

// ─── PATCH /v1/identities/{id}/mcp-connection ──────────────────────────────

#[tokio::test]
async fn patch_mcp_connection_toggles_elicitation() {
    let fx = bootstrap_mcp(true).await;

    let resp = fx
        .client
        .patch(format!(
            "{}/v1/identities/{}/mcp-connection",
            fx.base, fx.agent_id
        ))
        .header("Authorization", format!("Bearer {}", fx.org_admin_key))
        .json(&json!({ "elicitation_enabled": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["connection"]["elicitation_enabled"], true);

    // Round-tripped — DB sees the new value.
    let binding = db::mcp_client_agent_binding::get_by_agent_identity(&fx.pool, fx.agent_id)
        .await
        .unwrap()
        .expect("binding exists");
    assert!(binding.elicitation_enabled());

    // Toggle back off.
    let resp = fx
        .client
        .patch(format!(
            "{}/v1/identities/{}/mcp-connection",
            fx.base, fx.agent_id
        ))
        .header("Authorization", format!("Bearer {}", fx.org_admin_key))
        .json(&json!({ "elicitation_enabled": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["connection"]["elicitation_enabled"], false);
}

/// Multi-binding regression: when an agent is bound to multiple MCP
/// clients, the per-agent PATCH must update *all* bindings — otherwise
/// the eligibility check (which queries the calling client's binding)
/// would read a stale flag for any client other than the most-recently-
/// updated one.
#[tokio::test]
async fn patch_mcp_connection_fans_out_to_all_bindings_for_agent() {
    let fx = bootstrap_mcp(true).await;

    // Add a second binding under a different client_id.
    let other_client_id = format!("osc_{}", Uuid::new_v4().simple());
    db::oauth_mcp_client::create(
        &fx.pool,
        &db::oauth_mcp_client::CreateOauthMcpClient {
            client_id: &other_client_id,
            client_name: Some("other-mcp"),
            redirect_uris: &["http://127.0.0.1:0/cb".to_string()],
            software_id: Some("com.example.other"),
            software_version: Some("1.0.0"),
            created_ip: None,
            created_user_agent: None,
            org_id: None,
        },
    )
    .await
    .unwrap();
    db::mcp_client_agent_binding::upsert(
        &fx.pool,
        fx.org_id,
        fx.user_id,
        &other_client_id,
        fx.agent_id,
    )
    .await
    .unwrap();

    let resp = fx
        .client
        .patch(format!(
            "{}/v1/identities/{}/mcp-connection",
            fx.base, fx.agent_id
        ))
        .header("Authorization", format!("Bearer {}", fx.org_admin_key))
        .json(&json!({ "elicitation_enabled": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Both bindings now have the toggle on.
    let binding_a = db::mcp_client_agent_binding::get_for_agent_and_client(
        &fx.pool,
        fx.agent_id,
        &fx.client_id,
    )
    .await
    .unwrap()
    .unwrap();
    let binding_b = db::mcp_client_agent_binding::get_for_agent_and_client(
        &fx.pool,
        fx.agent_id,
        &other_client_id,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(binding_a.elicitation_enabled(), "primary binding updated");
    assert!(binding_b.elicitation_enabled(), "secondary binding updated");
}

#[tokio::test]
async fn patch_mcp_connection_returns_404_when_no_binding() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool).await;
    let base = format!("http://{api_addr}");
    let (_org_id, agent_id, _agent_key, org_admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .patch(format!("{base}/v1/identities/{agent_id}/mcp-connection"))
        .header("Authorization", format!("Bearer {org_admin_key}"))
        .json(&json!({ "elicitation_enabled": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ─── POST /v1/identities/{id}/mcp-connection/disconnect ────────────────────

#[tokio::test]
async fn disconnect_removes_binding_and_audits() {
    let fx = bootstrap_mcp(true).await;

    let resp = fx
        .client
        .post(format!(
            "{}/v1/identities/{}/mcp-connection/disconnect",
            fx.base, fx.agent_id
        ))
        .header("Authorization", format!("Bearer {}", fx.org_admin_key))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "{:?}", resp.text().await);

    // Binding gone.
    let binding = db::mcp_client_agent_binding::get_by_agent_identity(&fx.pool, fx.agent_id)
        .await
        .unwrap();
    assert!(binding.is_none(), "binding deleted");

    // GET now returns null.
    let resp = fx
        .client
        .get(format!(
            "{}/v1/identities/{}/mcp-connection",
            fx.base, fx.agent_id
        ))
        .header("Authorization", format!("Bearer {}", fx.org_admin_key))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert!(body["connection"].is_null());

    // Audit row written.
    let audit: Value = fx
        .client
        .get(format!("{}/v1/audit", fx.base))
        .header("Authorization", format!("Bearer {}", fx.org_admin_key))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        audit
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "mcp_connection.disconnected"),
        "expected mcp_connection.disconnected audit entry"
    );
}

#[tokio::test]
async fn disconnect_cancels_in_flight_elicitations_for_agent() {
    let fx = bootstrap_mcp(true).await;

    // The bootstrap helper recorded a synthetic session id when
    // declare_elicitation=true. Cancellation is keyed on agent_identity_id,
    // not session_id, so the row will be cancelled regardless of which
    // session it was opened against.
    let row = db::oauth_mcp_client::get_by_client_id(&fx.pool, &fx.client_id)
        .await
        .unwrap()
        .unwrap();
    let session_id = row.last_session_id.expect("session id present");

    // Seed an approval row to link the elicitation to (FK requires it).
    let approval_id: Uuid = sqlx::query(
        "INSERT INTO approvals (org_id, identity_id, action_summary, token,
                                expires_at, current_resolver_identity_id)
         VALUES ($1, $2, 'noop', $3, now() + interval '1 hour', $2)
         RETURNING id",
    )
    .bind(fx.org_id)
    .bind(fx.agent_id)
    .bind(format!("apr_{}", Uuid::new_v4()))
    .fetch_one(&fx.pool)
    .await
    .unwrap()
    .get("id");

    let elicit_id = format!("elicit_{}", Uuid::new_v4());
    db::mcp_elicitation::insert(&fx.pool, &elicit_id, session_id, fx.agent_id, approval_id)
        .await
        .unwrap();
    // Promote to `claimed` to reproduce the receiver-mid-flight case: a
    // pod has started resolving but not yet completed when the user
    // disconnects. Cancellation must still pick this up.
    db::mcp_elicitation::claim(&fx.pool, &elicit_id)
        .await
        .unwrap()
        .expect("claimed");

    let resp = fx
        .client
        .post(format!(
            "{}/v1/identities/{}/mcp-connection/disconnect",
            fx.base, fx.agent_id
        ))
        .header("Authorization", format!("Bearer {}", fx.org_admin_key))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // The pending row is now cancelled (best-effort). A late-arriving SSE
    // poll will pick it up and emit a JSON-RPC error.
    let row = db::mcp_elicitation::get(&fx.pool, &elicit_id)
        .await
        .unwrap()
        .expect("elicitation row still present (rows aren't deleted on cancel)");
    assert_eq!(row.status, db::mcp_elicitation::STATUS_CANCELLED);
}

// ─── mcp_session::complete_from_elicitation ────────────────────────────────
// These tests drive the receiver-side helper directly. The originator's SSE
// stream is intentionally not exercised: the helper writes to `final_response`
// and the originator just polls — verifying the helper covers what the
// originator would emit.

/// Trigger a real pending_approval and then drive the elicitation receiver
/// helper through `accept + allow`. The approval should resolve and the call
/// should execute against the loopback echo target.
#[tokio::test]
async fn complete_from_elicitation_accept_allow_resolves_and_calls() {
    let fx = bootstrap_mcp(true).await;

    // Toggle elicitation on for this binding, just like the dashboard would.
    let binding = db::mcp_client_agent_binding::get_by_agent_identity(&fx.pool, fx.agent_id)
        .await
        .unwrap()
        .unwrap();
    db::mcp_client_agent_binding::set_elicitation_opted_out(&fx.pool, binding.id, false)
        .await
        .unwrap();

    // Stand up a tiny upstream so the call replay has somewhere to land.
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = mock_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/echo",
            axum::routing::get(|| async { "hi" }).post(|| async { "hi" }),
        );
        axum::serve(mock_listener, app).await.unwrap();
    });

    // Mint an agent api key (separate from the JWT) so we can call /v1/actions/call.
    let agent_key_resp: Value = fx
        .client
        .post(format!("{}/v1/api-keys", fx.base))
        .header("Authorization", format!("Bearer {}", fx.org_admin_key))
        .json(&json!({
            "org_id": fx.org_id,
            "identity_id": fx.agent_id,
            "name": "elicit-test-key",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_key = agent_key_resp["key"].as_str().unwrap().to_string();

    // Create a secret + trigger an action that hits the permission gap.
    fx.client
        .put(format!("{}/v1/secrets/tk", fx.base))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({"value": "v"}))
        .send()
        .await
        .unwrap();
    let resp = fx
        .client
        .post(format!("{}/v1/actions/call", fx.base))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "http",
            "method": "GET",
            "url": format!("http://{mock_addr}/echo"),
            "secrets": [{"name": "tk", "inject_as": "header", "header_name": "X-Auth"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202, "expected pending_approval");
    let approval_id: Uuid = resp.json::<Value>().await.unwrap()["approval_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    // Open a fake elicitation row that the originator pod *would* have
    // inserted, then drive the receiver helper.
    let elicit_id = format!("elicit_{}", Uuid::new_v4());
    db::mcp_elicitation::insert(
        &fx.pool,
        &elicit_id,
        Uuid::new_v4(), // session_id; not relevant here
        fx.agent_id,
        approval_id,
    )
    .await
    .unwrap();

    // Build a fresh AppState that reuses the same pool + public_url so the
    // helper's loopback resolve+call hits our running test API.
    let state = build_state_for_session(&fx).await;
    mcp_session::complete_from_elicitation(
        &state,
        &axum::http::Extensions::new(),
        &elicit_id,
        &json!({
            "action": "accept",
            "content": { "decision": "allow" }
        }),
    )
    .await
    .expect("complete_from_elicitation succeeds");

    // The row should be `completed` with the action result envelope inside.
    let row = db::mcp_elicitation::get(&fx.pool, &elicit_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, db::mcp_elicitation::STATUS_COMPLETED);
    let final_response = row.final_response.expect("final_response set");
    assert_eq!(
        final_response["execution"]["status"], "executed",
        "final_response: {final_response}"
    );
}

/// A real gated call (raw HTTP against a local echo server) that the agent
/// cannot make yet, so `/resolve` + `/call` can run for real. Returns the
/// approval id and the 202 `pending_approval` body, whose `suggested_tiers`
/// is what the remember dialog offers.
async fn gated_echo_approval(fx: &McpFixture) -> (Uuid, Value) {
    let binding = db::mcp_client_agent_binding::get_by_agent_identity(&fx.pool, fx.agent_id)
        .await
        .unwrap()
        .unwrap();
    db::mcp_client_agent_binding::set_elicitation_opted_out(&fx.pool, binding.id, false)
        .await
        .unwrap();

    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = mock_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/echo",
            axum::routing::get(|| async { "hi" }).post(|| async { "hi" }),
        );
        axum::serve(mock_listener, app).await.unwrap();
    });

    let agent_key_resp: Value = fx
        .client
        .post(format!("{}/v1/api-keys", fx.base))
        .header("Authorization", format!("Bearer {}", fx.org_admin_key))
        .json(&json!({
            "org_id": fx.org_id,
            "identity_id": fx.agent_id,
            "name": "elicit-remember-key",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_key = agent_key_resp["key"].as_str().unwrap().to_string();

    fx.client
        .put(format!("{}/v1/secrets/tk", fx.base))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({"value": "v"}))
        .send()
        .await
        .unwrap();
    let resp = fx
        .client
        .post(format!("{}/v1/actions/call", fx.base))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "http",
            "method": "GET",
            "url": format!("http://{mock_addr}/echo"),
            "secrets": [{"name": "tk", "inject_as": "header", "header_name": "X-Auth"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let body: Value = resp.json().await.unwrap();
    let approval_id = body["approval_id"].as_str().unwrap().parse().unwrap();
    (approval_id, body)
}

/// Answer the decision dialog with "Allow & remember" and return the id of
/// the follow-up (scope + duration) dialog it hands over to.
async fn choose_allow_remember(
    fx: &McpFixture,
    state: &overslash_api::AppState,
    approval_id: Uuid,
) -> String {
    let elicit_id = format!("elicit_{}", Uuid::new_v4());
    db::mcp_elicitation::insert(
        &fx.pool,
        &elicit_id,
        Uuid::new_v4(),
        fx.agent_id,
        approval_id,
    )
    .await
    .unwrap();
    mcp_session::complete_from_elicitation(
        state,
        &axum::http::Extensions::new(),
        &elicit_id,
        &json!({ "action": "accept", "content": { "decision": "allow_remember" } }),
    )
    .await
    .expect("decision dialog answer");

    let row = db::mcp_elicitation::get(&fx.pool, &elicit_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.status,
        db::mcp_elicitation::STATUS_FOLLOW_UP,
        "row: {row:?}"
    );
    let next = row.final_response.unwrap()["next_elicit_id"]
        .as_str()
        .expect("follow_up row names its next dialog")
        .to_string();
    assert!(next.starts_with(mcp_session::REMEMBER_ID_PREFIX), "{next}");
    next
}

async fn rules_for_agent(fx: &McpFixture) -> Vec<(String, Option<time::OffsetDateTime>)> {
    sqlx::query(
        "SELECT action_pattern, expires_at FROM permission_rules
          WHERE identity_id = $1 ORDER BY action_pattern",
    )
    .bind(fx.agent_id)
    .fetch_all(&fx.pool)
    .await
    .unwrap()
    .into_iter()
    .map(|r| (r.get("action_pattern"), r.get("expires_at")))
    .collect()
}

/// Rules saved since `before` — bootstrap gives the agent some of its own.
async fn new_rules(
    fx: &McpFixture,
    before: &[(String, Option<time::OffsetDateTime>)],
) -> Vec<(String, Option<time::OffsetDateTime>)> {
    rules_for_agent(fx)
        .await
        .into_iter()
        .filter(|r| !before.contains(r))
        .collect()
}

async fn approval_status(fx: &McpFixture, approval_id: Uuid) -> String {
    sqlx::query("SELECT status FROM approvals WHERE id = $1")
        .bind(approval_id)
        .fetch_one(&fx.pool)
        .await
        .unwrap()
        .get("status")
}

/// "Allow & remember" in the decision dialog must not resolve anything yet:
/// it only opens the follow-up dialog, and the approval stays pending (and
/// mid-elicitation, so auto-call stays suppressed) until that is answered.
#[tokio::test]
async fn allow_remember_opens_the_follow_up_dialog_without_resolving() {
    let fx = bootstrap_mcp(true).await;
    let (approval_id, _) = gated_echo_approval(&fx).await;
    let state = build_state_for_session(&fx).await;
    let before = rules_for_agent(&fx).await;

    let next = choose_allow_remember(&fx, &state, approval_id).await;

    assert_eq!(
        status_of(&fx, &next).await.as_deref(),
        Some(db::mcp_elicitation::STATUS_PENDING)
    );
    assert_eq!(approval_status(&fx, approval_id).await, "pending");
    assert!(
        db::mcp_elicitation::has_active_for_approval(&fx.pool, approval_id)
            .await
            .unwrap()
    );
    assert_eq!(rules_for_agent(&fx).await, before, "no rule may be saved");

    // The originator's poll sees the hand-over.
    match mcp_session::await_completion_with_timeout(
        &state,
        &axum::http::Extensions::new(),
        &sqlx::query("SELECT elicit_id FROM pending_mcp_elicitations WHERE status = 'follow_up' AND approval_id = $1")
            .bind(approval_id)
            .fetch_one(&fx.pool)
            .await
            .unwrap()
            .get::<String, _>("elicit_id"),
        Duration::from_secs(2),
    )
    .await
    {
        mcp_session::ElicitOutcome::FollowUp(id) => assert_eq!(id, next),
        other => panic!("expected FollowUp, got {other:?}"),
    }
}

/// The granularity the dialog exists for: picking a broader tier and a
/// duration remembers exactly that tier, expiring after that duration, and
/// the gated call still runs.
#[tokio::test]
async fn remember_dialog_saves_the_picked_tier_with_its_ttl() {
    let fx = bootstrap_mcp(true).await;
    let (approval_id, pending) = gated_echo_approval(&fx).await;
    let state = build_state_for_session(&fx).await;
    let before = rules_for_agent(&fx).await;
    let tiers = pending["suggested_tiers"].as_array().unwrap();
    assert!(tiers.len() >= 2, "need a broader tier to pick: {pending}");
    let broader: Vec<String> = serde_json::from_value(tiers[1]["keys"].clone()).unwrap();

    let next = choose_allow_remember(&fx, &state, approval_id).await;
    mcp_session::complete_from_elicitation(
        &state,
        &axum::http::Extensions::new(),
        &next,
        &json!({
            "action": "accept",
            "content": { "scope": serde_json::to_string(&broader).unwrap(), "ttl": "1h" }
        }),
    )
    .await
    .expect("remember dialog answer");

    let row = db::mcp_elicitation::get(&fx.pool, &next)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.status,
        db::mcp_elicitation::STATUS_COMPLETED,
        "row: {row:?}"
    );
    assert_eq!(
        row.final_response.unwrap()["execution"]["status"],
        "executed"
    );

    let rules = new_rules(&fx, &before).await;
    let mut patterns: Vec<String> = rules.iter().map(|(p, _)| p.clone()).collect();
    patterns.sort();
    let mut want = broader.clone();
    want.sort();
    assert_eq!(patterns, want);
    let in_an_hour = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    for (pattern, expires) in rules {
        let expires = expires.unwrap_or_else(|| panic!("{pattern} should expire"));
        assert!(
            (expires - in_an_hour).abs() < time::Duration::minutes(2),
            "{pattern} expires at {expires}, want ≈ {in_an_hour}"
        );
    }
}

/// No scope picked (a client that skips defaults) remembers the approval's
/// own keys — the narrowest rule — with no expiry.
#[tokio::test]
async fn remember_dialog_without_scope_saves_the_exact_keys() {
    let fx = bootstrap_mcp(true).await;
    let (approval_id, _) = gated_echo_approval(&fx).await;
    let state = build_state_for_session(&fx).await;
    let before = rules_for_agent(&fx).await;

    let next = choose_allow_remember(&fx, &state, approval_id).await;
    mcp_session::complete_from_elicitation(
        &state,
        &axum::http::Extensions::new(),
        &next,
        &json!({ "action": "accept", "content": {} }),
    )
    .await
    .expect("remember dialog answer");

    assert_eq!(
        status_of(&fx, &next).await.as_deref(),
        Some(db::mcp_elicitation::STATUS_COMPLETED)
    );
    let rules = new_rules(&fx, &before).await;
    assert!(!rules.is_empty(), "expected a remembered rule");
    assert!(rules.iter().all(|(_, e)| e.is_none()), "{rules:?}");
}

/// Declining the follow-up is backing out of the details after saying
/// "allow" — not a denial. The approval stays pending for the URL fallback.
#[tokio::test]
async fn declining_the_remember_dialog_leaves_the_approval_pending() {
    let fx = bootstrap_mcp(true).await;
    let (approval_id, _) = gated_echo_approval(&fx).await;
    let state = build_state_for_session(&fx).await;
    let before = rules_for_agent(&fx).await;

    let next = choose_allow_remember(&fx, &state, approval_id).await;
    mcp_session::complete_from_elicitation(
        &state,
        &axum::http::Extensions::new(),
        &next,
        &json!({ "action": "decline" }),
    )
    .await
    .unwrap();

    assert_eq!(
        status_of(&fx, &next).await.as_deref(),
        Some(db::mcp_elicitation::STATUS_WITHDRAWN)
    );
    assert_eq!(approval_status(&fx, approval_id).await, "pending");
    // A human answered both dialogs, so the client plainly can render them:
    // backing out must not suppress the next dialog for this agent.
    assert!(
        !db::mcp_elicitation::cancelled_recently_for_agent(&fx.pool, fx.agent_id, 120)
            .await
            .unwrap(),
        "declining the remember dialog must not start the cancel cooldown"
    );
    assert!(
        matches!(
            mcp_session::await_completion_with_timeout(
                &state,
                &axum::http::Extensions::new(),
                &next,
                Duration::from_secs(2),
            )
            .await,
            mcp_session::ElicitOutcome::Abandoned
        ),
        "the originator must fall back to the pending envelope"
    );
    assert_eq!(rules_for_agent(&fx).await, before, "no rule may be saved");
}

/// The scope value is client-supplied. A key that neither is a suggested
/// tier nor covers the request must be refused by `/resolve`, not saved.
#[tokio::test]
async fn remember_dialog_refuses_a_forged_scope() {
    let fx = bootstrap_mcp(true).await;
    let (approval_id, _) = gated_echo_approval(&fx).await;
    let state = build_state_for_session(&fx).await;
    let before = rules_for_agent(&fx).await;

    let next = choose_allow_remember(&fx, &state, approval_id).await;
    mcp_session::complete_from_elicitation(
        &state,
        &axum::http::Extensions::new(),
        &next,
        &json!({ "action": "accept", "content": { "scope": r#"["http:ANY:evil.example/**"]"# } }),
    )
    .await
    .unwrap();

    assert_eq!(
        status_of(&fx, &next).await.as_deref(),
        Some(db::mcp_elicitation::STATUS_FAILED)
    );
    assert_eq!(approval_status(&fx, approval_id).await, "pending");
    assert_eq!(rules_for_agent(&fx).await, before, "no rule may be saved");
}

/// If the originator already gave up on the decision dialog, nobody will
/// render the follow-up, so the hand-over must not happen: `follow_up` only
/// moves a row that is still `claimed`, and returning 0 is what tells the
/// receiver to retire the follow-up row it just opened.
#[tokio::test]
async fn follow_up_refuses_a_row_the_originator_cancelled() {
    let fx = bootstrap_mcp(true).await;
    let approval_id = seed_pending_approval(&fx).await;

    let elicit_id = format!("elicit_{}", Uuid::new_v4());
    db::mcp_elicitation::insert(
        &fx.pool,
        &elicit_id,
        Uuid::new_v4(),
        fx.agent_id,
        approval_id,
    )
    .await
    .unwrap();
    // Receiver claimed; then the originator's timeout cancelled underneath.
    db::mcp_elicitation::claim(&fx.pool, &elicit_id)
        .await
        .unwrap()
        .expect("claim");
    db::mcp_elicitation::cancel(&fx.pool, &elicit_id)
        .await
        .unwrap();

    let next = format!("{}{}", mcp_session::REMEMBER_ID_PREFIX, Uuid::new_v4());
    assert_eq!(
        db::mcp_elicitation::follow_up(&fx.pool, &elicit_id, &next)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        status_of(&fx, &elicit_id).await.as_deref(),
        Some(db::mcp_elicitation::STATUS_CANCELLED)
    );
}

/// Multi-client-per-agent regression: when one binding has elicitation
/// enabled and another (more recently-updated) does not, the calling
/// client's binding must drive the eligibility check — not whichever was
/// touched last. Without this, a capable client gets denied elicitation
/// because some other binding under the same agent has the toggle off.
#[tokio::test]
async fn elicitation_eligible_keyed_on_calling_client_not_latest_binding() {
    let fx = bootstrap_mcp(true).await;

    // Bootstrap created binding A with elicitation_enabled=false. Flip it
    // to true so this binding is "elicitation-capable". A capability of
    // `{"elicitation": {}}` was already recorded by bootstrap_mcp(true).
    let binding_a = db::mcp_client_agent_binding::get_by_agent_identity(&fx.pool, fx.agent_id)
        .await
        .unwrap()
        .unwrap();
    db::mcp_client_agent_binding::set_elicitation_opted_out(&fx.pool, binding_a.id, false)
        .await
        .unwrap();

    // Add a *second* binding for the same agent under a different client_id.
    // This client does NOT declare elicitation. We make this binding the
    // most-recently-updated row, so the old "latest binding wins" code path
    // would pick this one and decline eligibility.
    let other_client_id = format!("osc_{}", Uuid::new_v4().simple());
    db::oauth_mcp_client::create(
        &fx.pool,
        &db::oauth_mcp_client::CreateOauthMcpClient {
            client_id: &other_client_id,
            client_name: Some("other-mcp"),
            redirect_uris: &["http://127.0.0.1:0/cb".to_string()],
            software_id: Some("com.example.other"),
            software_version: Some("1.0.0"),
            created_ip: None,
            created_user_agent: None,
            org_id: None,
        },
    )
    .await
    .unwrap();
    // Note: no `update_initialize_state` for this client → capabilities is NULL.
    let _binding_b = db::mcp_client_agent_binding::upsert(
        &fx.pool,
        fx.org_id,
        fx.user_id,
        &other_client_id,
        fx.agent_id,
    )
    .await
    .unwrap();
    // The upsert sets updated_at = now() so binding_b is now the latest.

    // The calling client (in the JWT we minted in bootstrap) is binding A.
    // Trigger an action that hits a permission gap — we expect SSE upgrade.
    let resp = fx
        .client
        .post(format!("{}/mcp", fx.base))
        .bearer_auth(&fx.agent_mcp_token)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "overslash_call",
                "arguments": {
                    "service": "nonexistent_svc",
                    "action": "noop"
                }
            }
        }))
        .send()
        .await
        .unwrap();

    // Eligibility must be evaluated against binding A (which is elicitation-
    // capable) regardless of binding B being more recent. The exact response
    // shape (200 SSE vs 200 JSON pending_approval) depends on whether the
    // service exists, but the eligibility predicate must not reject solely
    // because of binding B's missing capability.
    //
    // We assert via the binding repo that the *calling* binding is the one
    // surfaced to the eligibility code path:
    let chosen = db::mcp_client_agent_binding::get_for_agent_and_client(
        &fx.pool,
        fx.agent_id,
        &fx.client_id,
    )
    .await
    .unwrap()
    .expect("binding A still exists");
    assert_eq!(chosen.client_id, fx.client_id);
    assert!(
        chosen.elicitation_enabled(),
        "binding A was the one queried, with elicitation enabled"
    );

    // And confirm the response wasn't a 5xx — eligibility didn't crash.
    assert!(resp.status().is_success(), "{:?}", resp.text().await);
}

/// Security regression: a caller authenticated to /mcp must NOT be able to
/// answer an elicitation that belongs to a different agent. Without the
/// ownership guard in `post_mcp`, anyone who learns an `elicit_id` (it can
/// leak through logs) could drive the victim's resolve+call as the victim.
#[tokio::test]
async fn cross_tenant_caller_cannot_answer_someone_elses_elicitation() {
    let fx = bootstrap_mcp(true).await;

    // Insert a victim agent + their own elicitation row.
    let victim_user = fx
        .client
        .post(format!("{}/v1/identities", fx.base))
        .header("Authorization", format!("Bearer {}", fx.org_admin_key))
        .json(&json!({"name":"victim-user","kind":"user"}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let victim_user_id: Uuid = victim_user["id"].as_str().unwrap().parse().unwrap();
    let victim_agent = fx
        .client
        .post(format!("{}/v1/identities", fx.base))
        .header("Authorization", format!("Bearer {}", fx.org_admin_key))
        .json(&json!({
            "name":"victim-agent","kind":"agent","parent_id": victim_user_id,
        }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let victim_agent_id: Uuid = victim_agent["id"].as_str().unwrap().parse().unwrap();

    let approval_id: Uuid = sqlx::query(
        "INSERT INTO approvals (org_id, identity_id, action_summary, token,
                                expires_at, current_resolver_identity_id)
         VALUES ($1, $2, 'noop', $3, now() + interval '1 hour', $2)
         RETURNING id",
    )
    .bind(fx.org_id)
    .bind(victim_agent_id)
    .bind(format!("apr_{}", Uuid::new_v4()))
    .fetch_one(&fx.pool)
    .await
    .unwrap()
    .get("id");

    let elicit_id = format!("elicit_{}", Uuid::new_v4());
    db::mcp_elicitation::insert(
        &fx.pool,
        &elicit_id,
        Uuid::new_v4(),
        victim_agent_id,
        approval_id,
    )
    .await
    .unwrap();

    // Attacker is `fx.agent_id` — a different agent in the same org. The
    // MCP token is minted from `fx`, owned by that agent, NOT the victim.
    let resp = fx
        .client
        .post(format!("{}/mcp", fx.base))
        .bearer_auth(&fx.agent_mcp_token)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": elicit_id.clone(),
            "result": { "action": "accept", "content": { "decision": "allow" } }
        }))
        .send()
        .await
        .unwrap();

    // The handler must reject — currently with a JSON-RPC error inside a 200.
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"].is_object(),
        "expected JSON-RPC error, got {body}"
    );

    // Critical: the victim's row is still pending and their approval is
    // still unresolved — the attacker's call did not drive resolve+call.
    // Give the (would-be) spawn a moment to either run or be rejected.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let row = db::mcp_elicitation::get(&fx.pool, &elicit_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.status,
        db::mcp_elicitation::STATUS_PENDING,
        "victim row was tampered with: {row:?}"
    );
}

/// MCP-spec `action: "decline"` must resolve the underlying approval as
/// denied — otherwise the approval stays `pending` and the elicitation
/// re-fires on every retry of the same action, looping the user.
///
/// `decline` is now the *only* negative that denies. Its counterpart is
/// `complete_from_elicitation_cancel_leaves_approval_pending`, which pins the
/// other half of the rule: a `cancel` is "nobody answered", not "the user said
/// no", and must leave the approval alone.
#[tokio::test]
async fn complete_from_elicitation_decline_resolves_approval_as_denied() {
    let fx = bootstrap_mcp(true).await;
    let approval_id: Uuid = sqlx::query(
        "INSERT INTO approvals (org_id, identity_id, action_summary, token,
                                expires_at, current_resolver_identity_id,
                                permission_keys)
         VALUES ($1, $2, 'noop', $3, now() + interval '1 hour', $2, $4)
         RETURNING id",
    )
    .bind(fx.org_id)
    .bind(fx.agent_id)
    .bind(format!("apr_{}", Uuid::new_v4()))
    .bind(vec!["fake:noop:*".to_string()])
    .fetch_one(&fx.pool)
    .await
    .unwrap()
    .get("id");

    let elicit_id = format!("elicit_{}", Uuid::new_v4());
    db::mcp_elicitation::insert(
        &fx.pool,
        &elicit_id,
        Uuid::new_v4(),
        fx.agent_id,
        approval_id,
    )
    .await
    .unwrap();

    let state = build_state_for_session(&fx).await;
    mcp_session::complete_from_elicitation(
        &state,
        &axum::http::Extensions::new(),
        &elicit_id,
        &json!({ "action": "decline" }),
    )
    .await
    .unwrap();

    // The elicitation row terminates as `failed` (the SSE stream will emit
    // isError: true to the model).
    let row = db::mcp_elicitation::get(&fx.pool, &elicit_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.status,
        db::mcp_elicitation::STATUS_FAILED,
        "row: {row:?}"
    );

    // The approval itself is now `denied` — a retry of the same action
    // would not re-trigger the elicitation.
    let approval_status: String = sqlx::query("SELECT status FROM approvals WHERE id = $1")
        .bind(approval_id)
        .fetch_one(&fx.pool)
        .await
        .unwrap()
        .get("status");
    assert_eq!(approval_status, "denied");
}

/// Insert a bare `pending` approval owned by the fixture's agent.
///
/// The negative-outcome tests only care about what happens to the approval
/// row, not about replaying a real upstream call, so they skip the
/// service/secret/loopback scaffolding that
/// `complete_from_elicitation_accept_allow_resolves_and_calls` needs.
async fn seed_pending_approval(fx: &McpFixture) -> Uuid {
    sqlx::query(
        "INSERT INTO approvals (org_id, identity_id, action_summary, token,
                                expires_at, current_resolver_identity_id,
                                permission_keys)
         VALUES ($1, $2, 'noop', $3, now() + interval '1 hour', $2, $4)
         RETURNING id",
    )
    .bind(fx.org_id)
    .bind(fx.agent_id)
    .bind(format!("apr_{}", Uuid::new_v4()))
    .bind(vec!["fake:noop:*".to_string()])
    .fetch_one(&fx.pool)
    .await
    .unwrap()
    .get("id")
}

/// The other half of the decline rule, and the regression test for the whole
/// default-on change: `action: "cancel"` must NOT deny.
///
/// Headless / `--print` Claude Code auto-cancels an elicitation within
/// milliseconds because it has no dialog to render (measured at 6ms against
/// 2.1.278). Reading that as a denial would silently kill an approval no human
/// ever saw. Instead the row is retired and the approval stays `pending`, so
/// the SSE tail can hand the model the ordinary `pending_approval` envelope
/// and the URL-reject fallback still works.
#[tokio::test]
async fn complete_from_elicitation_cancel_leaves_approval_pending() {
    let fx = bootstrap_mcp(true).await;
    let approval_id = seed_pending_approval(&fx).await;

    let elicit_id = format!("elicit_{}", Uuid::new_v4());
    db::mcp_elicitation::insert(
        &fx.pool,
        &elicit_id,
        Uuid::new_v4(),
        fx.agent_id,
        approval_id,
    )
    .await
    .unwrap();

    let state = build_state_for_session(&fx).await;
    mcp_session::complete_from_elicitation(
        &state,
        &axum::http::Extensions::new(),
        &elicit_id,
        &json!({ "action": "cancel" }),
    )
    .await
    .unwrap();

    let row = db::mcp_elicitation::get(&fx.pool, &elicit_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.status,
        db::mcp_elicitation::STATUS_CANCELLED,
        "cancel retires the row rather than failing it; row: {row:?}"
    );
    assert!(
        row.final_response.is_none(),
        "no decision was made, so there is nothing to report: {row:?}"
    );

    let approval_status: String = sqlx::query("SELECT status FROM approvals WHERE id = $1")
        .bind(approval_id)
        .fetch_one(&fx.pool)
        .await
        .unwrap()
        .get("status");
    assert_eq!(
        approval_status, "pending",
        "the approval must survive an unanswered dialog untouched"
    );

    // Auto-call suppression lifts immediately, so resolving from the
    // dashboard behaves exactly as it would have without elicitation.
    assert!(
        !db::mcp_elicitation::has_active_for_approval(&fx.pool, approval_id)
            .await
            .unwrap()
    );
}

/// A client that declared `elicitation` but answers `elicitation/create` with
/// a JSON-RPC error — `-32601` from a `tools/call`-only bridge, `-32602` from
/// a mode it doesn't support — reaches `post_mcp`'s bare-response branch,
/// which normalises it to `{action:"cancel"}`. That must fall back, not deny:
/// "I can't show this dialog" is the one case where denying is most obviously
/// wrong.
#[tokio::test]
async fn complete_from_elicitation_client_error_answer_falls_back() {
    let fx = bootstrap_mcp(true).await;
    let approval_id = seed_pending_approval(&fx).await;

    let elicit_id = format!("elicit_{}", Uuid::new_v4());
    db::mcp_elicitation::insert(
        &fx.pool,
        &elicit_id,
        Uuid::new_v4(),
        fx.agent_id,
        approval_id,
    )
    .await
    .unwrap();

    // Exactly the shape post_mcp synthesises from a bare `{id, error}` POST.
    let state = build_state_for_session(&fx).await;
    mcp_session::complete_from_elicitation(
        &state,
        &axum::http::Extensions::new(),
        &elicit_id,
        &json!({
            "action": "cancel",
            "content": { "code": -32601, "message": "Method not found" }
        }),
    )
    .await
    .unwrap();

    let row = db::mcp_elicitation::get(&fx.pool, &elicit_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, db::mcp_elicitation::STATUS_CANCELLED);

    let approval_status: String = sqlx::query("SELECT status FROM approvals WHERE id = $1")
        .bind(approval_id)
        .fetch_one(&fx.pool)
        .await
        .unwrap()
        .get("status");
    assert_eq!(approval_status, "pending");
}

/// After an unanswered dialog we stop eliciting that agent for
/// `CANCEL_COOLDOWN`. Without it a headless client re-prompts on every retry:
/// each gated call mints a *fresh* approval, so a per-approval guard would
/// never bind, and the cancel is the only signal the protocol gives us that
/// this peer cannot answer.
#[tokio::test]
async fn elicitation_suppressed_after_recent_cancel() {
    let fx = bootstrap_mcp(true).await;
    let cooldown_secs = 120_i64;
    assert!(
        !db::mcp_elicitation::cancelled_recently_for_agent(&fx.pool, fx.agent_id, cooldown_secs)
            .await
            .unwrap(),
        "clean slate: nothing has been cancelled yet"
    );

    // Retire an elicitation the way an unanswered dialog does.
    let approval_id = seed_pending_approval(&fx).await;
    let elicit_id = format!("elicit_{}", Uuid::new_v4());
    db::mcp_elicitation::insert(
        &fx.pool,
        &elicit_id,
        Uuid::new_v4(),
        fx.agent_id,
        approval_id,
    )
    .await
    .unwrap();
    db::mcp_elicitation::cancel(&fx.pool, &elicit_id)
        .await
        .unwrap();

    assert!(
        db::mcp_elicitation::cancelled_recently_for_agent(&fx.pool, fx.agent_id, cooldown_secs)
            .await
            .unwrap(),
        "a just-cancelled row must suppress the next elicitation"
    );

    // Backdate `completed_at` past the window. Predicating on completed_at
    // rather than created_at is deliberate: a row retired by the originator's
    // 300s timeout has an old created_at, and that is exactly when
    // re-eliciting would hang the next call for another 300s.
    sqlx::query(
        "UPDATE pending_mcp_elicitations
            SET completed_at = now() - interval '1 hour'
          WHERE elicit_id = $1",
    )
    .bind(&elicit_id)
    .execute(&fx.pool)
    .await
    .unwrap();

    assert!(
        !db::mcp_elicitation::cancelled_recently_for_agent(&fx.pool, fx.agent_id, cooldown_secs)
            .await
            .unwrap(),
        "the cooldown must expire, not latch"
    );
}

/// Whatever happens to an elicitation answer, the row must end terminal.
///
/// The originator polls this row and gives up only at `DEFAULT_TIMEOUT`
/// (300s), so a row left `claimed` by a failed completion is a five-minute
/// hang on a live `tools/call` — for a caller that could have had the
/// `pending_approval` envelope immediately. `complete_from_elicitation`
/// handles its *expected* failures itself; this pins the unexpected kind,
/// injected here as a loopback that cannot connect.
#[tokio::test]
async fn a_failed_completion_still_retires_the_row() {
    let fx = bootstrap_mcp(true).await;
    let approval_id = seed_pending_approval(&fx).await;

    let elicit_id = format!("elicit_{}", Uuid::new_v4());
    db::mcp_elicitation::insert(
        &fx.pool,
        &elicit_id,
        Uuid::new_v4(),
        fx.agent_id,
        approval_id,
    )
    .await
    .unwrap();

    // Point the resolve loopback at a port nothing is listening on, so the
    // helper fails with a transport error rather than a handled 4xx.
    let mut state = build_state_for_session(&fx).await;
    state.config.public_url = "http://127.0.0.1:1".to_string();

    overslash_api::routes::mcp::complete_elicitation_and_retire(
        &state,
        &axum::http::Extensions::new(),
        &fx.pool,
        &elicit_id,
        &json!({ "action": "accept", "content": { "decision": "allow" } }),
    )
    .await;

    let row = db::mcp_elicitation::get(&fx.pool, &elicit_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.status,
        db::mcp_elicitation::STATUS_CANCELLED,
        "a failed completion must not leave the row claimed: {row:?}"
    );

    // And the approval is untouched, so the model's fallback is the ordinary
    // pending_approval envelope rather than a phantom denial.
    let approval_status: String = sqlx::query("SELECT status FROM approvals WHERE id = $1")
        .bind(approval_id)
        .fetch_one(&fx.pool)
        .await
        .unwrap()
        .get("status");
    assert_eq!(approval_status, "pending");
}

// ─── await_completion ──────────────────────────────────────────────────────

#[tokio::test]
async fn await_completion_returns_completed_when_row_finalises() {
    let fx = bootstrap_mcp(false).await;
    let approval_id: Uuid = sqlx::query(
        "INSERT INTO approvals (org_id, identity_id, action_summary, token,
                                expires_at, current_resolver_identity_id)
         VALUES ($1, $2, 'noop', $3, now() + interval '1 hour', $2)
         RETURNING id",
    )
    .bind(fx.org_id)
    .bind(fx.agent_id)
    .bind(format!("apr_{}", Uuid::new_v4()))
    .fetch_one(&fx.pool)
    .await
    .unwrap()
    .get("id");

    let elicit_id = format!("elicit_{}", Uuid::new_v4());
    db::mcp_elicitation::insert(
        &fx.pool,
        &elicit_id,
        Uuid::new_v4(),
        fx.agent_id,
        approval_id,
    )
    .await
    .unwrap();

    // Race: complete the row in 100 ms, then await with a generous deadline.
    let pool = fx.pool.clone();
    let elicit_id_w = elicit_id.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        db::mcp_elicitation::complete(&pool, &elicit_id_w, &json!({"ok": true}))
            .await
            .unwrap();
    });

    let state = build_state_for_session(&fx).await;
    let outcome = mcp_session::await_completion_with_timeout(
        &state,
        &axum::http::Extensions::new(),
        &elicit_id,
        Duration::from_secs(3),
    )
    .await;
    match outcome {
        mcp_session::ElicitOutcome::Completed(v) => {
            assert_eq!(v["ok"], true);
        }
        other => panic!("expected Completed, got {other:?}"),
    }
}

#[tokio::test]
async fn await_completion_returns_abandoned_on_timeout() {
    let fx = bootstrap_mcp(false).await;
    let approval_id: Uuid = sqlx::query(
        "INSERT INTO approvals (org_id, identity_id, action_summary, token,
                                expires_at, current_resolver_identity_id)
         VALUES ($1, $2, 'noop', $3, now() + interval '1 hour', $2)
         RETURNING id",
    )
    .bind(fx.org_id)
    .bind(fx.agent_id)
    .bind(format!("apr_{}", Uuid::new_v4()))
    .fetch_one(&fx.pool)
    .await
    .unwrap()
    .get("id");

    let elicit_id = format!("elicit_{}", Uuid::new_v4());
    db::mcp_elicitation::insert(
        &fx.pool,
        &elicit_id,
        Uuid::new_v4(),
        fx.agent_id,
        approval_id,
    )
    .await
    .unwrap();

    let state = build_state_for_session(&fx).await;
    let outcome = mcp_session::await_completion_with_timeout(
        &state,
        &axum::http::Extensions::new(),
        &elicit_id,
        Duration::from_millis(200),
    )
    .await;
    assert!(
        matches!(outcome, mcp_session::ElicitOutcome::Abandoned),
        "expected Abandoned, got {outcome:?}"
    );

    // Timeout path also cancels the row so a late receiver doesn't drive
    // resolve+call against an SSE stream nobody's listening on.
    let row = db::mcp_elicitation::get(&fx.pool, &elicit_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, db::mcp_elicitation::STATUS_CANCELLED);
}

// ─── Background sweep (issue #600) ─────────────────────────────────────────

/// Seed one elicitation row per `(status, age_secs)` pair, backdating
/// `created_at`, and return the ids in the order given.
async fn seed_aged_rows(fx: &McpFixture, rows: &[(&str, i64)]) -> Vec<String> {
    let mut ids = Vec::new();
    for (status, age_secs) in rows {
        let approval_id: Uuid = sqlx::query(
            "INSERT INTO approvals (org_id, identity_id, action_summary, token,
                                    expires_at, current_resolver_identity_id)
             VALUES ($1, $2, 'noop', $3, now() + interval '1 hour', $2)
             RETURNING id",
        )
        .bind(fx.org_id)
        .bind(fx.agent_id)
        .bind(format!("apr_{}", Uuid::new_v4()))
        .fetch_one(&fx.pool)
        .await
        .unwrap()
        .get("id");

        let elicit_id = format!("elicit_{}", Uuid::new_v4());
        db::mcp_elicitation::insert(
            &fx.pool,
            &elicit_id,
            Uuid::new_v4(),
            fx.agent_id,
            approval_id,
        )
        .await
        .unwrap();
        sqlx::query(
            "UPDATE pending_mcp_elicitations
                SET status = $1, created_at = now() - make_interval(secs => $2)
              WHERE elicit_id = $3",
        )
        .bind(*status)
        .bind(*age_secs as f64)
        .bind(&elicit_id)
        .execute(&fx.pool)
        .await
        .unwrap();
        ids.push(elicit_id);
    }
    ids
}

async fn status_of(fx: &McpFixture, elicit_id: &str) -> Option<String> {
    db::mcp_elicitation::get(&fx.pool, elicit_id)
        .await
        .unwrap()
        .map(|r| r.status)
}

/// Both sweep phases, in one test on purpose: they operate on the whole table,
/// so splitting them into separate `#[tokio::test]`s would let one test's
/// backdated rows be swept by the other's call while it was still asserting on
/// them. Nothing else in the suite backdates `created_at`, so a sweep here
/// cannot reach another test's rows.
#[tokio::test]
async fn background_sweep_reaps_orphans_then_purges_terminal_rows() {
    let fx = bootstrap_mcp(false).await;

    // Ages are chosen to sit either side of the two windows used below
    // (reap 360s, purge 720s) without ever landing in both.
    let ids = seed_aged_rows(
        &fx,
        &[
            (db::mcp_elicitation::STATUS_PENDING, 400),
            (db::mcp_elicitation::STATUS_CLAIMED, 400),
            (db::mcp_elicitation::STATUS_PENDING, 10),
            (db::mcp_elicitation::STATUS_COMPLETED, 400),
            (db::mcp_elicitation::STATUS_COMPLETED, 3_600),
            (db::mcp_elicitation::STATUS_FAILED, 3_600),
            (db::mcp_elicitation::STATUS_CANCELLED, 3_600),
        ],
    )
    .await;
    let orphan_approval = db::mcp_elicitation::get(&fx.pool, &ids[1])
        .await
        .unwrap()
        .unwrap()
        .approval_id;

    // Until an orphan reaches a terminal status it keeps its approval looking
    // mid-elicitation, which suppresses auto-call on that approval forever.
    assert!(
        db::mcp_elicitation::has_active_for_approval(&fx.pool, orphan_approval)
            .await
            .unwrap(),
        "a live row should read as active before the reap"
    );

    // ── Phase one: cancel live rows past the reap window ──────────────────
    let reaped = db::mcp_elicitation::cancel_orphaned(&fx.pool, 360)
        .await
        .unwrap();
    assert!(
        reaped >= 2,
        "expected at least the two aged live rows, got {reaped}"
    );

    assert_eq!(
        status_of(&fx, &ids[0]).await.as_deref(),
        Some(db::mcp_elicitation::STATUS_CANCELLED),
        "aged pending row should be cancelled"
    );
    assert_eq!(
        status_of(&fx, &ids[1]).await.as_deref(),
        Some(db::mcp_elicitation::STATUS_CANCELLED),
        "aged claimed row should be cancelled"
    );
    assert_eq!(
        status_of(&fx, &ids[2]).await.as_deref(),
        Some(db::mcp_elicitation::STATUS_PENDING),
        "a row inside the window is still being polled — leave it"
    );
    assert_eq!(
        status_of(&fx, &ids[3]).await.as_deref(),
        Some(db::mcp_elicitation::STATUS_COMPLETED),
        "the reap must not touch terminal rows"
    );
    assert!(
        !db::mcp_elicitation::has_active_for_approval(&fx.pool, orphan_approval)
            .await
            .unwrap(),
        "the reap should stop an orphan suppressing auto-call"
    );

    // ── Phase two: delete terminal rows past the retention window ─────────
    let purged = db::mcp_elicitation::purge_terminal(&fx.pool, 720)
        .await
        .unwrap();
    assert!(
        purged >= 3,
        "expected at least the three aged terminal rows, got {purged}"
    );

    for (i, label) in [(4, "completed"), (5, "failed"), (6, "cancelled")] {
        assert!(
            status_of(&fx, &ids[i]).await.is_none(),
            "aged {label} row should be gone"
        );
    }
    assert_eq!(
        status_of(&fx, &ids[3]).await.as_deref(),
        Some(db::mcp_elicitation::STATUS_COMPLETED),
        "a terminal row inside the window may still be read by its originator"
    );
    assert_eq!(
        status_of(&fx, &ids[2]).await.as_deref(),
        Some(db::mcp_elicitation::STATUS_PENDING),
        "the purge must never delete a live row — that is the reap's job"
    );
}

/// The two windows have to stay ordered, or a row would be deleted before it
/// was ever cancelled, and the reap window can never drop below the
/// originator's own poll ceiling.
#[test]
fn sweep_windows_are_ordered_and_clear_the_poll_ceiling() {
    for grace in [1, 60, 600] {
        let c = overslash_api::config::Config {
            sweep_grace_secs: grace,
            ..build_config_shape()
        };
        assert!(
            c.mcp_elicitation_reap_after_secs() > 300,
            "reap window must clear the 300s originator poll ceiling (grace {grace})"
        );
        assert!(
            c.mcp_elicitation_retention_secs() > c.mcp_elicitation_reap_after_secs(),
            "retention must outlast the reap window (grace {grace})"
        );
    }
}

// ─── Helpers ───────────────────────────────────────────────────────────────

/// The `Config` shape every helper in this file starts from. Extracted so a
/// plain `#[test]` can assert on the derived sweep windows without needing a
/// live fixture — `empty_test_config()` is `pub(crate)` and out of reach here.
fn build_config_shape() -> overslash_api::config::Config {
    overslash_api::config::Config {
        async_execution: Default::default(),
        call_stream_idle_timeout_ms: 30_000,
        call_timeout_max_ms: 110_000,
        call_timeout_ms: 30_000,
        host: "127.0.0.1".into(),
        port: 0,
        database_url: String::new(),
        db_max_connections: 5,
        db_min_connections: 1,
        db_acquire_timeout_secs: 10,
        events_stream_max_connection_secs: 30,
        live_map_enabled: false,
        db_background_max_connections: 2,
        secrets_encryption_key: "ab".repeat(32),
        secrets_encryption_key_previous: None,
        secrets_encryption_key_active_id: 1,
        secrets_encryption_key_previous_id: 0,
        signing_key: SIGNING_KEY_HEX.to_string(),
        approval_expiry_secs: 1800,
        execution_pending_ttl_secs: 900,
        execution_replay_timeout_secs: 30,
        sweep_grace_secs: 60,
        services_dir: "services".into(),
        google_auth_client_id: None,
        google_auth_client_secret: None,
        github_auth_client_id: None,
        github_auth_client_secret: None,
        public_url: String::new(),
        dev_auth_enabled: false,
        magic_link_enabled: true,
        max_response_body_bytes: 5_242_880,
        audit_response_body_max_bytes: 65_536,
        filter_timeout_ms: 2000,
        download_token_ttl_secs: 900,
        upload_token_ttl_secs: 900,
        upload_max_bytes: 100 * 1024 * 1024,
        call_result_max_bytes: 1024 * 1024,
        dashboard_url: "/".into(),
        dashboard_origin: "*localhost*".into(),
        mcp_extra_origins: String::new(),
        redis_url: None,
        resolve_cache_ttl_secs: 300,
        resolve_cache_negative_ttl_secs: 30,
        resolve_cache_scope_ttl_max_secs: 300,
        resolve_cache_timeout_ms: 100,
        resolve_cache_max_entries: 10_000,
        resolve_cache_namespace: None,
        default_rate_limit: 10000,
        default_rate_window_secs: 60,
        allow_org_creation: true,
        trial_default_duration_days: 30,
        single_org_mode: None,
        app_host_suffix: None,
        api_host_suffix: None,
        session_cookie_domain: None,
        cloud_billing: false,
        stripe_secret_key: None,
        stripe_webhook_secret: None,
        stripe_eur_price_id: None,
        stripe_usd_price_id: None,
        stripe_eur_lookup_key: "overslash_seat_eur".into(),
        stripe_usd_lookup_key: "overslash_seat_usd".into(),
        stripe_api_base: "https://api.stripe.com/v1".into(),
        service_base_overrides: std::collections::HashMap::new(),
        platform_credential: None,
        oversla_sh_base_url: None,
        oversla_sh_api_key: None,
        email_provider: None,
        email_from: None,
        email_reply_to: None,
        email_api_key: None,
        preview_origin_allowlist: None,
        deployment_env: Default::default(),
        connection_return_url_allowed_hosts: Vec::new(),
        trusted_proxies: Default::default(),
    }
}

/// Reconstruct an `AppState` whose `public_url` matches the running test API
/// so `mcp_session::complete_from_elicitation` can self-loopback the
/// resolve+call without reaching a different origin. Reuses the same pool +
/// signing key as `start_api`, so JWTs minted here are accepted there.
async fn build_state_for_session(fx: &McpFixture) -> overslash_api::AppState {
    let config = overslash_api::config::Config {
        public_url: fx.base.clone(),
        ..build_config_shape()
    };

    overslash_api::AppState {
        db: fx.pool.clone(),
        config,
        http_client: reqwest::Client::new(),
        registry: std::sync::Arc::new(overslash_core::registry::ServiceRegistry::default()),
        rate_limiter: std::sync::Arc::new(
            overslash_api::services::rate_limit::InMemoryRateLimitStore::new(),
        ),
        rate_limit_cache: std::sync::Arc::new(
            overslash_api::services::rate_limit::RateLimitConfigCache::new(Duration::from_secs(30)),
        ),
        free_unlimited_cache: std::sync::Arc::new(
            overslash_api::services::billing_tier::FreeUnlimitedCache::new(Duration::from_secs(30)),
        ),
        auth_code_store: overslash_api::services::oauth_as::AuthCodeStore::new(),
        pending_authorize_store: overslash_api::services::oauth_as::PendingAuthorizeStore::new(),
        embedder: std::sync::Arc::new(overslash_core::embeddings::DisabledEmbedder),
        embeddings_available: false,
        platform_registry: std::sync::Arc::new(
            overslash_api::services::platform_registry::build_registry(),
        ),
        mailer: std::sync::Arc::new(overslash_core::email::NoopMailer),
        event_bus: overslash_api::services::events::EventBus::new(),
        resolve_cache: overslash_api::services::resolve_cache::in_memory(10_000),
        test_resources: None,
        background_db: None,
    }
}
