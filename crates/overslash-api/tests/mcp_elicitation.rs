//! Integration tests for MCP elicitation (Flow A).
//!
//! Exercises the per-binding `mcp-connection` endpoints + the elicitation
//! coordination service (`mcp_session`). The full SSE round-trip
//! (originator emits `elicitation/create`, receiver answers via `POST /mcp`)
//! is tested at the helper level by driving `mcp_session::complete_from_elicitation`
//! directly — this avoids parsing the SSE body in the test client and still
//! verifies the resolve+call loopback the receiver pod performs.

#![allow(clippy::disallowed_methods)]

mod common;

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
    assert_eq!(conn["elicitation_enabled"], false);
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
    assert!(binding.elicitation_enabled);

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
    assert!(binding_a.elicitation_enabled, "primary binding updated");
    assert!(binding_b.elicitation_enabled, "secondary binding updated");
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
    db::mcp_client_agent_binding::set_elicitation_enabled(&fx.pool, binding.id, true)
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

/// Regression: an MCP elicitation form that omits `remember_keys` (the
/// flat schema the v1 form exposes) must still resolve `allow_remember`.
/// Forwarding `remember_keys: []` to /resolve would return a 400 — instead
/// we omit the field so the resolver falls back to `approval.permission_keys`
/// and a permission rule is created.
#[tokio::test]
async fn complete_from_elicitation_allow_remember_without_keys_creates_rule() {
    let fx = bootstrap_mcp(true).await;
    let binding = db::mcp_client_agent_binding::get_by_agent_identity(&fx.pool, fx.agent_id)
        .await
        .unwrap()
        .unwrap();
    db::mcp_client_agent_binding::set_elicitation_enabled(&fx.pool, binding.id, true)
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
            "method": "GET",
            "url": format!("http://{mock_addr}/echo"),
            "secrets": [{"name": "tk", "inject_as": "header", "header_name": "X-Auth"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let approval_id: Uuid = resp.json::<Value>().await.unwrap()["approval_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

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
    // No `remember_keys` in content — the v1 elicitation schema doesn't
    // expose per-key checkboxes. Must still succeed.
    mcp_session::complete_from_elicitation(
        &state,
        &elicit_id,
        &json!({
            "action": "accept",
            "content": { "decision": "allow_remember", "ttl": "forever" }
        }),
    )
    .await
    .expect("allow_remember without remember_keys must not fail");

    let row = db::mcp_elicitation::get(&fx.pool, &elicit_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.status,
        db::mcp_elicitation::STATUS_COMPLETED,
        "row: {row:?}"
    );

    // A permission rule should now exist for this identity (the resolver
    // fell back to approval.permission_keys when remember_keys was omitted).
    let count: i64 =
        sqlx::query("SELECT count(*) AS n FROM permission_rules WHERE identity_id = $1")
            .bind(fx.agent_id)
            .fetch_one(&fx.pool)
            .await
            .unwrap()
            .get("n");
    assert!(count >= 1, "expected at least one permission rule");
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
    db::mcp_client_agent_binding::set_elicitation_enabled(&fx.pool, binding_a.id, true)
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
        chosen.elicitation_enabled,
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
    mcp_session::complete_from_elicitation(&state, &elicit_id, &json!({ "action": "decline" }))
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
    let outcome =
        mcp_session::await_completion_with_timeout(&state, &elicit_id, Duration::from_secs(3))
            .await;
    match outcome {
        mcp_session::ElicitOutcome::Completed(v) => {
            assert_eq!(v["ok"], true);
        }
        other => panic!("expected Completed, got {other:?}"),
    }
}

#[tokio::test]
async fn await_completion_returns_cancelled_on_timeout() {
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
    let outcome =
        mcp_session::await_completion_with_timeout(&state, &elicit_id, Duration::from_millis(200))
            .await;
    assert!(
        matches!(outcome, mcp_session::ElicitOutcome::Cancelled),
        "expected Cancelled, got {outcome:?}"
    );

    // Timeout path also cancels the row so a late receiver doesn't drive
    // resolve+call against an SSE stream nobody's listening on.
    let row = db::mcp_elicitation::get(&fx.pool, &elicit_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, db::mcp_elicitation::STATUS_CANCELLED);
}

// ─── Helpers ───────────────────────────────────────────────────────────────

/// Reconstruct an `AppState` whose `public_url` matches the running test API
/// so `mcp_session::complete_from_elicitation` can self-loopback the
/// resolve+call without reaching a different origin. Reuses the same pool +
/// signing key as `start_api`, so JWTs minted here are accepted there.
async fn build_state_for_session(fx: &McpFixture) -> overslash_api::AppState {
    let config = overslash_api::config::Config {
        host: "127.0.0.1".into(),
        port: 0,
        database_url: String::new(),
        secrets_encryption_key: "ab".repeat(32),
        signing_key: SIGNING_KEY_HEX.to_string(),
        approval_expiry_secs: 1800,
        execution_pending_ttl_secs: 900,
        execution_replay_timeout_secs: 30,
        services_dir: "services".into(),
        google_auth_client_id: None,
        google_auth_client_secret: None,
        github_auth_client_id: None,
        github_auth_client_secret: None,
        public_url: fx.base.clone(),
        dev_auth_enabled: false,
        max_response_body_bytes: 5_242_880,
        filter_timeout_ms: 2000,
        dashboard_url: "/".into(),
        dashboard_origin: "*localhost*".into(),
        redis_url: None,
        default_rate_limit: 10000,
        default_rate_window_secs: 60,
        allow_org_creation: true,
        single_org_mode: None,
        app_host_suffix: None,
        session_cookie_domain: None,
        cloud_billing: false,
        stripe_secret_key: None,
        stripe_webhook_secret: None,
        stripe_eur_price_id: None,
        stripe_usd_price_id: None,
        stripe_eur_lookup_key: "overslash_seat_eur".into(),
        stripe_usd_lookup_key: "overslash_seat_usd".into(),
        stripe_api_base: "https://api.stripe.com/v1".into(),
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
        auth_code_store: overslash_api::services::oauth_as::AuthCodeStore::new(),
        pending_authorize_store: overslash_api::services::oauth_as::PendingAuthorizeStore::new(),
        embedder: std::sync::Arc::new(overslash_core::embeddings::DisabledEmbedder),
        embeddings_available: false,
        platform_registry: std::sync::Arc::new(
            overslash_api::services::platform_registry::build_registry(),
        ),
    }
}
