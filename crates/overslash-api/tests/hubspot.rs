//! HubSpot CRM E2E tests — exercised through HubSpot's remote MCP server
//! (https://mcp.hubspot.com) over the connection-based (Mode C) path.
//!
//! HubSpot's remote MCP authenticates callers with OAuth (a custom "MCP auth"
//! app, brought to Overslash as a BYOC credential). These tests stand up a
//! local MCP fake, point the bundled `hubspot` template's `mcp.url` at it via
//! `service_base_overrides`, and verify:
//!   - a tool call resolves the caller's OAuth connection and injects the
//!     access token as `Authorization: Bearer` on the outbound MCP request;
//!   - a write tool with no covering permission gates to an approval carrying
//!     the template's `disclose` fields;
//!   - a call with no connection yet returns `needs_authentication` with a
//!     freshly-minted OAuth URL.
//!
//! There is no `#[ignore]`'d real test: hitting mcp.hubspot.com needs a live
//! OAuth token from an interactive HubSpot install, which can't be scripted.

// Test setup requires dynamic SQL for provider endpoint overrides and DB seeding.
#![allow(clippy::disallowed_methods)]

mod common;

use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

/// CRM scopes seeded onto the test connection — the subset the template's
/// `mcp.auth.scopes` declares that the tools under test rely on.
fn crm_scopes() -> Vec<String> {
    [
        "crm.objects.contacts.read",
        "crm.objects.contacts.write",
        "crm.objects.companies.read",
        "crm.objects.deals.read",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Every `tools/call` the fake MCP server received: `{tool, auth, arguments}`.
type CallLog = Arc<Mutex<Vec<Value>>>;

/// Start a local MCP fake that speaks Streamable-HTTP JSON-RPC on `POST /`
/// (the root, matching `https://mcp.hubspot.com`). It records each
/// `tools/call` (tool name, Authorization header, arguments) and echoes the
/// arguments back in `structuredContent`. Returns `(base_url, call_log)`.
async fn start_mcp_fake() -> (String, CallLog) {
    common::allow_loopback_ssrf();
    let calls: CallLog = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/", post(mcp_rpc))
        .with_state(calls.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), calls)
}

async fn mcp_rpc(
    State(calls): State<CallLog>,
    headers: HeaderMap,
    Json(req): Json<Value>,
) -> Json<Value> {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let params = req.get("params").cloned().unwrap_or(Value::Null);

    let result = match method {
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let args = params.get("arguments").cloned().unwrap_or(Value::Null);
            calls.lock().unwrap().push(json!({
                "tool": name,
                "auth": auth,
                "arguments": args,
            }));
            json!({
                "content": [{ "type": "text", "text": "ok" }],
                "structuredContent": { "tool": name, "echo": args },
                "isError": false
            })
        }
        _ => json!({}),
    };
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

/// Boot the API with the bundled registry and route `mcp.hubspot.com` at the
/// local fake. Returns the same tuple `bootstrap_org_identity` yields.
async fn start_with_hubspot_mcp(
    pool: sqlx::PgPool,
    mock_host: String,
) -> (String, reqwest::Client) {
    common::start_api_with_registry_customized(pool, None, move |cfg| {
        cfg.service_base_overrides
            .insert("mcp.hubspot.com".to_string(), mock_host);
    })
    .await
}

/// Seed a BYOC credential + a future-dated OAuth connection for `hubspot` at
/// the owner identity so the resolver injects the token without a refresh.
async fn seed_hubspot_connection(
    pool: &sqlx::PgPool,
    org_id: uuid::Uuid,
    ident_id: uuid::Uuid,
    owner_id: uuid::Uuid,
) {
    let enc_key = overslash_core::crypto::Keyring::test();
    let encrypted_token =
        overslash_core::crypto::encrypt(&enc_key, b"hubspot-mcp-token-xyz").unwrap();
    let encrypted_cid = overslash_core::crypto::encrypt(&enc_key, b"mock_client_id").unwrap();
    let encrypted_csec = overslash_core::crypto::encrypt(&enc_key, b"mock_client_secret").unwrap();
    let future = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let byoc = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_byoc_credential(ident_id, "hubspot", &encrypted_cid, &encrypted_csec)
        .await
        .unwrap();
    let scopes = crm_scopes();
    overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: owner_id,
            provider_key: "hubspot",
            encrypted_access_token: &encrypted_token,
            encrypted_refresh_token: None,
            token_expires_at: Some(future),
            scopes: Some(&scopes),
            account_email: None,
            byoc_credential_id: Some(byoc.id),
        })
        .await
        .unwrap();
}

// ============================================================================
// Tool call resolves + injects the OAuth bearer on the outbound MCP request.
// ============================================================================

#[tokio::test]
async fn test_hubspot_mcp_tool_call_injects_oauth_bearer() {
    let pool = common::test_pool().await;
    let (mock_host, calls) = start_mcp_fake().await;
    let (base, client) = start_with_hubspot_mcp(pool.clone(), mock_host).await;

    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    let owner_id = common::owner_user_id(&pool, org_id).await;

    // Layer-1 ceiling + Layer-2 grant so tool calls execute (not gate to approval).
    common::grant_service_to_everyone(&base, &client, &admin_key, "hubspot").await;
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "hubspot:*:*"}))
        .send()
        .await
        .unwrap();

    seed_hubspot_connection(&pool, org_id, ident_id, owner_id).await;

    // Helper: call a tool and return the structured echo the fake produced.
    async fn call(
        client: &reqwest::Client,
        base: &str,
        key: &str,
        tool: &str,
        params: Value,
    ) -> Value {
        let resp = client
            .post(format!("{base}/v1/actions/call"))
            .header(common::auth(key).0, common::auth(key).1)
            .json(&json!({ "service": "hubspot", "action": tool, "params": params }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "tool {tool} failed");
        let envelope: Value = resp.json().await.unwrap();
        assert_eq!(envelope["status"], "called", "envelope: {envelope}");
        // MCP result body is the `{runtime, tool, structured, content, is_error}` envelope.
        serde_json::from_str(envelope["result"]["body"].as_str().unwrap()).unwrap()
    }

    // hubspot-list-objects
    let body = call(
        &client,
        &base,
        &key,
        "hubspot_list_objects",
        json!({"objectType": "contacts", "limit": 5}),
    )
    .await;
    // The fake echoes the UPSTREAM tool name (dashed mcp_tool override).
    assert_eq!(body["structured"]["tool"], "hubspot-list-objects");
    assert_eq!(body["structured"]["echo"]["objectType"], "contacts");
    assert_eq!(body["structured"]["echo"]["limit"], 5);

    // hubspot-search-objects
    let body = call(
        &client,
        &base,
        &key,
        "hubspot_search_objects",
        json!({"objectType": "deals", "query": "acme"}),
    )
    .await;
    assert_eq!(body["structured"]["echo"]["objectType"], "deals");
    assert_eq!(body["structured"]["echo"]["query"], "acme");

    // hubspot-batch-create-objects (write)
    let body = call(
        &client,
        &base,
        &key,
        "hubspot_batch_create_objects",
        json!({
            "objectType": "contacts",
            "inputs": [{"properties": {"email": "ada@analytical.example", "firstname": "Ada"}}]
        }),
    )
    .await;
    assert_eq!(body["structured"]["echo"]["objectType"], "contacts");

    // Every recorded call carried the auto-resolved OAuth bearer.
    let recorded = calls.lock().unwrap().clone();
    assert_eq!(recorded.len(), 3, "expected 3 tool calls, got {recorded:?}");
    for c in &recorded {
        assert_eq!(
            c["auth"], "Bearer hubspot-mcp-token-xyz",
            "MCP call should carry the auto-resolved OAuth bearer: {c}"
        );
    }
    // Upstream tool name the MCP client sent (dashed mcp_tool override).
    assert_eq!(recorded[0]["tool"], "hubspot-list-objects");
}

// ============================================================================
// Write tool with no covering permission → approval carrying disclose fields.
// ============================================================================

#[tokio::test]
async fn test_hubspot_mcp_write_disclosure_gates_to_approval() {
    let pool = common::test_pool().await;
    let (mock_host, _calls) = start_mcp_fake().await;
    let (base, client) = start_with_hubspot_mcp(pool.clone(), mock_host).await;

    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    let owner_id = common::owner_user_id(&pool, org_id).await;

    // Layer-1 clears, but NO `hubspot:*:*` rule → the write hits a Layer-2 gap
    // and gates to an approval, which is where the disclose fields surface.
    common::grant_service_to_everyone(&base, &client, &admin_key, "hubspot").await;
    seed_hubspot_connection(&pool, org_id, ident_id, owner_id).await;

    let exec: Value = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "hubspot",
            "action": "hubspot_batch_create_objects",
            "params": {
                "objectType": "contacts",
                "inputs": [{"properties": {"email": "grace@navy.example", "firstname": "Grace"}}]
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
        "write with no permission rule should gate to approval: {exec:?}"
    );
    let disclosed: std::collections::HashMap<String, String> = exec["disclosed_fields"]
        .as_array()
        .expect("disclosed_fields present")
        .iter()
        .map(|f| {
            (
                f["label"].as_str().unwrap().to_string(),
                f["value"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    assert_eq!(
        disclosed.get("Object type").map(String::as_str),
        Some("contacts")
    );
    assert_eq!(disclosed.get("Count").map(String::as_str), Some("1"));
    assert_eq!(
        disclosed.get("First email").map(String::as_str),
        Some("grace@navy.example"),
        "disclose should extract the first record's email from .arguments: {disclosed:?}"
    );
}

// ============================================================================
// No connection yet → needs_authentication with a minted OAuth URL.
// ============================================================================

#[tokio::test]
async fn test_hubspot_mcp_needs_authentication_without_connection() {
    let pool = common::test_pool().await;
    let (mock_host, _calls) = start_mcp_fake().await;
    let (base, client) = start_with_hubspot_mcp(pool.clone(), mock_host).await;

    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    let owner_id = common::owner_user_id(&pool, org_id).await;

    common::grant_service_to_everyone(&base, &client, &admin_key, "hubspot").await;
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "hubspot:*:*"}))
        .send()
        .await
        .unwrap();

    // A BYOC client exists (so an auth URL can be minted) but there is NO
    // connection yet — the resolver must gate rather than call the MCP server.
    // The auth-URL mint resolves client credentials at the owner identity (D22),
    // so the BYOC lives there too.
    let enc_key = overslash_core::crypto::Keyring::test();
    let encrypted_cid =
        overslash_core::crypto::encrypt(&enc_key, b"mcp-auth-app-client-id").unwrap();
    let encrypted_csec =
        overslash_core::crypto::encrypt(&enc_key, b"mcp-auth-app-client-secret").unwrap();
    overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_byoc_credential(owner_id, "hubspot", &encrypted_cid, &encrypted_csec)
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "hubspot",
            "action": "hubspot_list_objects",
            "params": {"objectType": "contacts"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "no connection should yield needs_authentication (401)"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "needs_authentication", "body: {body}");
    assert_eq!(body["service"], "hubspot");
    // A gated connect URL was minted (it 302s through Overslash to HubSpot's
    // authorize endpoint) — assert one is present rather than its final target.
    assert!(
        body["auth_url"].as_str().is_some_and(|u| !u.is_empty()),
        "should mint a gated OAuth URL, got: {body}"
    );
}
