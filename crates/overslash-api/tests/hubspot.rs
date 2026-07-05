//! HubSpot CRM E2E tests — exercised through HubSpot's remote MCP server
//! (https://mcp.hubspot.com) over the connection-based (Mode C) path.
//!
//! HubSpot's remote MCP authenticates callers with OAuth (a custom "MCP auth"
//! app, brought to Overslash as a BYOC credential). These tests stand up a
//! local MCP fake, point the bundled `hubspot` template's `mcp.url` at it via
//! `service_base_overrides`, and verify:
//!   - a tool call resolves the caller's OAuth connection and injects the
//!     access token as `Authorization: Bearer` on the outbound MCP request;
//!   - the tool names sent upstream are the live-catalog names (HubSpot
//!     retired its original `hubspot-list-objects`-style catalog — the fake
//!     rejects unknown names the same way the real server does, so a stale
//!     template shows up as a failing test, not a prod 502);
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

/// The tool catalog mcp.hubspot.com actually serves (verified via tools/list,
/// 2026-07-05). The fake only accepts these names and answers unknown ones
/// with JSON-RPC -32603 "Unknown tool: invalid_tool_name" — byte-for-byte what
/// the real server returns — so template/catalog drift fails loudly here.
const LIVE_CATALOG: &[&str] = &[
    "search_crm_objects",
    "submit_feedback",
    "get_campaign_contacts_by_type",
    "manage_crm_objects",
    "manage_landing_page",
    "search_owners",
    "get_campaign_analytics",
    "query_crm_data",
    "render_landing_page_ui",
    "get_organization_details",
    "get_content_analytics_report",
    "get_properties",
    "get_campaign_asset_metrics",
    "search_properties",
    "get_crm_objects",
    "get_user_details",
    "tool_guidance",
];

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
/// `tools/call` (tool name, Authorization header, arguments), echoes the
/// arguments back in `structuredContent` for known catalog names, and returns
/// the real server's -32603 error for unknown ones. Returns
/// `(base_url, call_log)`.
async fn start_mcp_fake() -> (String, CallLog) {
    start_mcp_fake_with(LIVE_CATALOG).await
}

/// Same fake with a custom accepted catalog — pass `&[]` to simulate HubSpot
/// having drifted its catalog away from every name the template sends.
async fn start_mcp_fake_with(catalog: &'static [&'static str]) -> (String, CallLog) {
    common::allow_loopback_ssrf();
    let calls: CallLog = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/", post(mcp_rpc))
        .with_state((calls.clone(), catalog));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), calls)
}

async fn mcp_rpc(
    State((calls, catalog)): State<(CallLog, &'static [&'static str])>,
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

    if method == "tools/call" {
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
        if !catalog.contains(&name.as_str()) {
            // Exactly what mcp.hubspot.com answers for a retired/unknown name.
            return Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32603, "message": "Unknown tool: invalid_tool_name" }
            }));
        }
        return Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [{ "type": "text", "text": "ok" }],
                "structuredContent": { "tool": name, "echo": args },
                "isError": false
            }
        }));
    }
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": {} }))
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
// Every read tool in the shipped template resolves against the live catalog,
// executes through the fake, and carries the auto-resolved OAuth bearer.
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

    // search_crm_objects — the workhorse read.
    let body = call(
        &client,
        &base,
        &key,
        "search_crm_objects",
        json!({"objectType": "contacts", "query": "ada", "limit": 5}),
    )
    .await;
    assert_eq!(body["structured"]["tool"], "search_crm_objects");
    assert_eq!(body["structured"]["echo"]["objectType"], "contacts");
    assert_eq!(body["structured"]["echo"]["limit"], 5);

    // get_crm_objects — batch read by id.
    let body = call(
        &client,
        &base,
        &key,
        "get_crm_objects",
        json!({"objectType": "deals", "objectIds": ["101", "102"]}),
    )
    .await;
    assert_eq!(body["structured"]["echo"]["objectType"], "deals");
    assert_eq!(body["structured"]["echo"]["objectIds"][1], "102");

    // query_crm_data — the SQL surface.
    let body = call(
        &client,
        &base,
        &key,
        "query_crm_data",
        json!({"sql": "SELECT email FROM contacts LIMIT 3"}),
    )
    .await;
    assert_eq!(
        body["structured"]["echo"]["sql"],
        "SELECT email FROM contacts LIMIT 3"
    );

    // manage_crm_objects (write) — executes because the `hubspot:*:*` rule covers it.
    let body = call(
        &client,
        &base,
        &key,
        "manage_crm_objects",
        json!({
            "createRequest": {
                "objectType": "contacts",
                "objects": [{"properties": {"email": "ada@analytical.example", "firstname": "Ada"}}]
            },
            "confirmationStatus": "CONFIRMED"
        }),
    )
    .await;
    assert_eq!(
        body["structured"]["echo"]["createRequest"]["objectType"],
        "contacts"
    );

    // Every recorded call carried the auto-resolved OAuth bearer and a
    // live-catalog tool name (the fake -32603s anything else).
    let recorded = calls.lock().unwrap().clone();
    assert_eq!(recorded.len(), 4, "expected 4 tool calls, got {recorded:?}");
    for c in &recorded {
        assert_eq!(
            c["auth"], "Bearer hubspot-mcp-token-xyz",
            "MCP call should carry the auto-resolved OAuth bearer: {c}"
        );
        let tool = c["tool"].as_str().unwrap();
        assert!(
            LIVE_CATALOG.contains(&tool),
            "sent a tool name mcp.hubspot.com doesn't serve: {tool}"
        );
    }
}

// ============================================================================
// Template ↔ catalog sync: every tool the shipped template exposes must exist
// in the live catalog snapshot. This is the regression test for the 2026-07
// incident where HubSpot replaced its entire tool catalog and every "Try it"
// 502'd with -32603 "Unknown tool".
// ============================================================================

#[tokio::test]
async fn test_hubspot_template_tools_exist_in_live_catalog() {
    let pool = common::test_pool().await;
    let (mock_host, _calls) = start_mcp_fake().await;
    let (base, client) = start_with_hubspot_mcp(pool.clone(), mock_host).await;

    let (_org_id, _ident_id, key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Read the shipped template's action list through the API (the same
    // normalized view the executor resolves tools from).
    let tpl: Value = client
        .get(format!("{base}/v1/templates/hubspot"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let actions = tpl["actions"]
        .as_array()
        .unwrap_or_else(|| panic!("template has actions: {tpl}"));
    assert!(!actions.is_empty(), "hubspot template exposes tools: {tpl}");

    for a in actions {
        // The upstream name is `mcp_tool` when aliased, else the action key.
        let upstream = a["mcp_tool"]
            .as_str()
            .or_else(|| a["key"].as_str())
            .unwrap();
        assert!(
            LIVE_CATALOG.contains(&upstream),
            "template exposes `{upstream}`, which mcp.hubspot.com does not serve — \
             HubSpot's catalog moved again; re-run tools/list and re-sync \
             services/hubspot.yaml (see the LIVE_CATALOG constant)"
        );
    }
}

// ============================================================================
// Catalog drift surfaces as 502 Bad Gateway carrying the upstream -32603 —
// pinning the failure shape of the 2026-07 incident so it stays diagnosable.
// ============================================================================

#[tokio::test]
async fn test_hubspot_catalog_drift_maps_to_bad_gateway() {
    let pool = common::test_pool().await;
    // Empty catalog: the "server" recognizes none of the template's tools,
    // exactly what a catalog replacement looks like from Overslash's side.
    let (mock_host, calls) = start_mcp_fake_with(&[]).await;
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
    seed_hubspot_connection(&pool, org_id, ident_id, owner_id).await;

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "hubspot",
            "action": "search_crm_objects",
            "params": {"objectType": "contacts"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        502,
        "unknown-tool RPC error should surface as 502"
    );
    let body: Value = resp.json().await.unwrap();
    let msg = body.to_string();
    assert!(
        msg.contains("-32603"),
        "error body should carry the upstream JSON-RPC code for diagnosis: {msg}"
    );
    // The call did reach the server with the right name — the drift is
    // upstream, not in Overslash's resolution.
    let recorded = calls.lock().unwrap().clone();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0]["tool"], "search_crm_objects");
}

// ============================================================================
// OAuth callback: HubSpot's token endpoint never echoes `scope`. Per
// RFC 6749 §5.1 that means the requested set was granted verbatim — the
// connection must record it, not a known-empty `{}` (which the scope gate
// would then enforce as "no scopes granted").
// ============================================================================

#[tokio::test]
async fn test_hubspot_callback_records_requested_scopes_when_token_omits_scope() {
    let pool = common::test_pool().await;
    // The fakes' authorization_code response carries no `scope` field —
    // byte-compatible with HubSpot's real token endpoint.
    let mock_addr = common::start_mock().await;
    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'hubspot'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();

    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, _api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // HubSpot is BYOC-only (custom MCP auth app) — seed the credential the
    // token exchange will resolve.
    let byoc: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({
            "provider": "hubspot",
            "client_id": "hs_mcp_auth_app_id",
            "client_secret": "hs_mcp_auth_app_secret",
            "identity_id": ident_id,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(byoc["id"].is_string(), "byoc create failed: {byoc}");

    let requested = crm_scopes();
    let state_param =
        common::seed_oauth_flow_with_scopes(&pool, org_id, ident_id, "hubspot", None, &requested)
            .await;

    let callback_resp: Value = client
        .get(format!(
            "{base}/v1/oauth/callback?code=hs_code_1&state={state_param}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(callback_resp["status"], "connected", "{callback_resp}");
    assert_eq!(callback_resp["provider"], "hubspot");
    let echoed: Vec<String> = callback_resp["scopes"]
        .as_array()
        .expect("scopes in callback body")
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        echoed, requested,
        "callback should report the requested set as granted"
    );

    // And the connection row records them (not `{}`).
    let conn_id: uuid::Uuid = callback_resp["connection_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let conn = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .get_connection(conn_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        conn.scopes.as_deref(),
        Some(requested.as_slice()),
        "connection.scopes should carry the RFC 6749 fallback set"
    );
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
            "action": "manage_crm_objects",
            "params": {
                "createRequest": {
                    "objectType": "contacts",
                    "objects": [{"properties": {"email": "grace@navy.example", "firstname": "Grace"}}]
                }
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
        disclosed.get("Operation").map(String::as_str),
        Some("create")
    );
    assert_eq!(
        disclosed.get("Object type").map(String::as_str),
        Some("contacts")
    );
    let payload = disclosed.get("Payload").cloned().unwrap_or_default();
    assert!(
        payload.contains("grace@navy.example"),
        "Payload disclose should carry the record content: {disclosed:?}"
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
            "action": "search_crm_objects",
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
