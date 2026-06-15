//! End-to-end coverage for the MCP `tools/call` typed-error contract.
//!
//! The REST layer renders typed envelopes for `needs_authentication`,
//! `reauth_required`, `missing_scopes`, `credential_missing`, and
//! `not_in_your_chain` (see `crates/overslash-api/src/error.rs`). Without
//! these tests an upstream regression in `mcp::forward()` could silently
//! revert to stringifying every non-2xx response into JSON-RPC
//! `INTERNAL_ERROR (-32603)` and the agent-facing contract would break
//! with no test surface complaining.
//!
//! These tests drive the JSON-RPC `/mcp` endpoint and assert:
//!   * the response shape is `result.isError == true` (NOT a JSON-RPC error)
//!   * `result.content[0].text` parses as the typed envelope JSON
//!   * the typed `error` discriminator and contextual fields are present
#![allow(clippy::disallowed_methods)]

mod common;

use overslash_core::crypto;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

/// JSON-RPC `tools/call` against the MCP endpoint. Returns the parsed
/// response frame so callers can inspect both the success and isError paths.
async fn rpc_tools_call(
    client: &reqwest::Client,
    base: &str,
    bearer: &str,
    id: i64,
    arguments: Value,
) -> Value {
    client
        .post(format!("{base}/mcp"))
        .header("Authorization", format!("Bearer {bearer}"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": "overslash_call",
                "arguments": arguments,
            }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Seed an OAuth connection directly into the DB. Mirrors the helper in
/// `oauth_connections_ux.rs` — kept inline because that helper isn't `pub`
/// from `common/mod.rs` and copying it is cheaper than re-exporting.
///
/// The seeded row has an access token that's already 1 hour past expiry and
/// no refresh token, so `resolve_access_token` returns
/// `OAuthError::NoRefreshToken` and the action handler emits
/// `reauth_required`.
async fn seed_connection_no_refresh_expired(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    provider_key: &str,
) -> Uuid {
    let enc_key = crypto::Keyring::test();
    let access = crypto::encrypt(&enc_key, b"mock_expired_access_token").unwrap();
    let expired_at = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    // No `encrypted_refresh_token` → resolver returns `OAuthError::NoRefreshToken`
    // → `classify_oauth` → `Reauth("no_refresh_token")` → typed reauth_required.
    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO connections (org_id, identity_id, provider_key,
         encrypted_access_token, token_expires_at, scopes, account_email)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(org_id)
    .bind(identity_id)
    .bind(provider_key)
    .bind(&access)
    .bind(expired_at)
    .bind::<Vec<String>>(vec!["tweet.read".into(), "users.read".into()])
    .bind(Some("mock@x"))
    .fetch_one(pool)
    .await
    .unwrap();
    row.0
}

/// MCP `tools/call overslash_call` against an OAuth-using service with no
/// connection bound returns a tool result with `isError: true` whose content
/// is the typed `needs_authentication` envelope. Regressions in
/// `mcp::forward()` that re-stringify the response would produce a JSON-RPC
/// `INTERNAL_ERROR` here and fail the assertion.
#[tokio::test]
async fn mcp_call_no_connection_returns_typed_needs_authentication() {
    let pool = common::test_pool().await;

    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_secret");
    }

    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (_org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Create the bundled `x` service without a connection. The recovery arm
    // fires the moment an action targets it.
    let create_resp = client
        .post(format!("{base}/v1/services"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({
            "template_key": "x",
            "name": "x",
            "user_level": false,
            "status": "active",
        }))
        .send()
        .await
        .unwrap();
    assert!(
        create_resp.status().is_success(),
        "service create failed: {} {:?}",
        create_resp.status(),
        create_resp.text().await
    );
    let svc: Value = create_resp.json().await.unwrap();
    let svc_id = svc["id"].as_str().unwrap().to_string();

    // Grant the agent permission to call any X action.
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "x:*:*"}))
        .send()
        .await
        .unwrap();

    let frame = rpc_tools_call(
        &client,
        &base,
        &api_key,
        1,
        json!({"service": "x", "action": "get_me", "params": {}}),
    )
    .await;

    // The typed envelope must travel as a tool RESULT (not a JSON-RPC error)
    // so MCP clients pass it to the model. -32603 here would mean forward()
    // stringified the upstream 401 — exactly the regression we're guarding.
    assert!(
        frame.get("error").is_none_or(Value::is_null),
        "expected tool result, got JSON-RPC error frame: {frame}"
    );
    let result = &frame["result"];
    assert_eq!(
        result["isError"],
        json!(true),
        "result.isError must be true for typed-error envelopes; got: {result}"
    );

    let text = result["content"][0]["text"]
        .as_str()
        .expect("content[0].text missing");
    let envelope: Value = serde_json::from_str(text)
        .unwrap_or_else(|e| panic!("content text was not JSON: {e}; raw: {text}"));

    assert_eq!(envelope["error"], "needs_authentication");
    assert_eq!(envelope["service"], "x");
    assert_eq!(envelope["service_instance_id"].as_str().unwrap(), svc_id);
    let auth_url = envelope["auth_url"].as_str().expect("auth_url required");
    assert!(
        auth_url.contains("/connect-authorize?id="),
        "auth_url should be a gated link: {auth_url}"
    );
    // The upstream provider authorize URL (`raw`) is never surfaced on any
    // OAuth error envelope (REST or MCP) — white-label partners import tokens
    // instead of wrapping an Overslash-built authorize URL, so there is no raw
    // URL to leak to a chat-delivered agent.
    assert!(
        envelope.get("raw").is_none_or(Value::is_null),
        "MCP envelope must not include `raw` (upstream provider URL): {envelope}"
    );
}

/// MCP `tools/call overslash_call` against an OAuth-using service whose
/// caller has a connection with an expired access token and no refresh
/// token returns a typed `reauth_required` envelope. Drives the
/// `OAuthError::NoRefreshToken → Reauth → reauth_required_envelope`
/// classify path so the integration test exercises the same code that
/// the unit test (`classify_oauth_*`) covers, but at the MCP boundary.
#[tokio::test]
async fn mcp_call_expired_no_refresh_returns_typed_reauth_required() {
    let pool = common::test_pool().await;

    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_secret");
    }

    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Seed a broken X connection for this identity BEFORE creating the
    // service so resolution finds it via `find_my_connection_by_provider`.
    let connection_id = seed_connection_no_refresh_expired(&pool, org_id, ident_id, "x").await;

    // Create the X service. No `connection_id` field — auto-resolve will
    // pick up the seeded connection by provider key.
    let create_resp = client
        .post(format!("{base}/v1/services"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({
            "template_key": "x",
            "name": "x",
            "user_level": false,
            "status": "active",
        }))
        .send()
        .await
        .unwrap();
    assert!(create_resp.status().is_success());

    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "x:*:*"}))
        .send()
        .await
        .unwrap();

    let frame = rpc_tools_call(
        &client,
        &base,
        &api_key,
        2,
        json!({"service": "x", "action": "get_me", "params": {}}),
    )
    .await;

    assert!(
        frame.get("error").is_none_or(Value::is_null),
        "expected tool result, got JSON-RPC error frame: {frame}"
    );
    let result = &frame["result"];
    assert_eq!(result["isError"], json!(true), "got: {result}");

    let text = result["content"][0]["text"].as_str().unwrap();
    let envelope: Value = serde_json::from_str(text).unwrap();

    assert_eq!(envelope["error"], "reauth_required");
    assert_eq!(
        envelope["connection_id"].as_str().unwrap(),
        connection_id.to_string(),
        "envelope must reference the seeded connection"
    );
    assert!(
        envelope["auth_url"]
            .as_str()
            .map(|u| !u.is_empty())
            .unwrap_or(false),
        "auth_url must be non-empty: {envelope}"
    );
    assert!(
        envelope["reason"]
            .as_str()
            .map(|r| !r.is_empty())
            .unwrap_or(false),
        "reason must be non-empty: {envelope}"
    );
    // See note in `mcp_call_no_connection_returns_typed_needs_authentication`:
    // the upstream-provider `raw` URL is never surfaced on any OAuth error
    // envelope, so chat delivery can't bypass the Overslash-branded checkpoint.
    assert!(
        envelope.get("raw").is_none_or(Value::is_null),
        "MCP envelope must not include `raw` (upstream provider URL): {envelope}"
    );
}

// `credential_missing` envelope coverage: the REST render arm is unit-
// tested in `crates/overslash-api/src/error.rs::tests`; the call-site
// migration is exercised by the existing
// `mcp_external::mcp_missing_secret_returns_400_before_upstream_call` test
// (asserts the 400 status). The MCP-layer transport for typed errors is
// covered by the two OAuth tests above plus the negative-path test below
// — a dedicated `credential_missing` MCP integration test would duplicate
// that coverage, so it's intentionally left as a future addition once
// slice 5's secret-bag scenarios need the explicit assertion.

/// Non-whitelisted error codes must NOT travel as tool results — they
/// land as JSON-RPC `INTERNAL_ERROR (-32603)` so the contract widens
/// only when a typed envelope is explicitly added to the
/// `forward()` allow-list (see `crates/overslash-api/src/routes/mcp.rs`
/// `TYPED_ERROR_CODES`).
///
/// Calling `overslash_call` against a service that does not exist for
/// the caller's org produces a 404 envelope whose `error` string ("not
/// found ...") is *not* in the allow-list. The MCP wrapper must keep
/// it as a JSON-RPC error rather than reframing as `isError: true`.
#[tokio::test]
async fn mcp_call_unknown_service_stays_jsonrpc_error_not_tool_result() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let (_org_id, _ident_id, api_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let frame = rpc_tools_call(
        &client,
        &base,
        &api_key,
        4,
        json!({"service": "this_service_does_not_exist", "action": "noop", "params": {}}),
    )
    .await;

    // The whitelist gate's negative path: response carries `error.code`
    // (JSON-RPC error envelope), and `result` is absent. If a future
    // change loosens the gate to "any JSON with an error field", this
    // test fails because the body would land as a tool result instead.
    assert!(
        frame.get("error").is_some() && !frame["error"].is_null(),
        "expected JSON-RPC error frame for non-typed failure; got: {frame}"
    );
    assert!(
        frame.get("result").is_none_or(Value::is_null),
        "result must be absent on JSON-RPC error path; got: {frame}"
    );
    let code = frame["error"]["code"].as_i64().unwrap();
    assert_eq!(code, -32603, "expected INTERNAL_ERROR code; got: {frame}");
}
