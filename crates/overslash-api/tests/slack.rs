//! Slack over its Web API (`services/slack.yaml`).
//!
//! The shipped template is a plain HTTP template on the `slack` OAuth provider
//! (user tokens, migration 134). These tests boot the bundled registry, route
//! `slack.com` at an in-process fake via `service_base_overrides`, and cover:
//!   * the template loads as HTTP with the full action set, and every action
//!     carries the template-wide `x-overslash-success` predicate;
//!   * a call forwards the owner's connection token as a bearer and the
//!     arguments as a JSON body;
//!   * Slack's in-band failure (`200 {"ok": false}`) comes back as `is_error`
//!     and is audited as one, with the status left at 200;
//!   * a paged read offers the next cursor, and stops on an in-band failure;
//!   * a gated write discloses the channel by name, through the resolver;
//!   * no connection → a clean error before any upstream call.
//!
//! Nothing reaches the network.

// Test setup requires dynamic SQL for DB seeding and audit reads.
#![allow(clippy::disallowed_methods)]

use crate::common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{Router, extract::State, response::IntoResponse, routing::any};
use overslash_core::registry::ServiceRegistry;
use overslash_core::types::{Risk, Runtime};
use serde_json::{Value, json};

const TOKEN: &str = "xoxp-slack-user-token";

// ============================================================================
// Parse smoke test
// ============================================================================

#[test]
fn slack_yaml_parses_as_a_web_api_template() {
    let ws_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let reg = ServiceRegistry::load_from_dir(
        &ws_root.join("services"),
        overslash_core::template_vars::Vars::for_tests(),
    )
    .expect("services/ should load cleanly");
    let svc = reg.get("slack").expect("slack should be registered");

    assert_eq!(svc.runtime, Runtime::Http);
    assert!(svc.mcp.is_none());
    assert_eq!(svc.hosts, vec!["slack.com".to_string()]);
    assert_eq!(
        svc.oauth_provider_for_mode(None),
        Some("slack"),
        "slack authenticates through the slack OAuth provider"
    );

    // The operationIds the MCP tools had, plus four more. Keeping the old names
    // is what keeps existing `slack:<action>` grants matching.
    for action in [
        "send_message",
        "update_message",
        "add_reaction",
        "list_channels",
        "read_channel_history",
        "get_thread_replies",
        "get_user",
        "list_users",
        "search_messages",
    ] {
        let a = svc
            .actions
            .get(action)
            .unwrap_or_else(|| panic!("slack.yaml should declare {action}"));
        assert_eq!(
            a.success.as_deref(),
            Some(".ok == true"),
            "{action} should inherit the info-level success predicate"
        );
        assert!(
            !a.required_scopes.is_empty(),
            "{action} should declare the user scopes it needs"
        );
    }
    assert_eq!(svc.actions.len(), 9);

    // The predicate is valid jq, so the register gate would accept it.
    overslash_api::services::response_filter::validate_syntax(
        &overslash_api::services::response_filter::ResponseFilter::Jq {
            expr: ".ok == true".into(),
        },
    )
    .unwrap();

    let send = &svc.actions["send_message"];
    assert_eq!(send.risk, Risk::Write);
    assert_eq!(send.scope_param, "channel".into());
    assert_eq!(send.required_scopes, vec!["chat:write".to_string()]);
    assert!(!send.disclose.is_empty());
    assert_eq!(svc.actions["get_user"].scope_param, "user".into());
    assert_eq!(svc.test_action().map(|(k, _)| k), Some("list_channels"));
}

// ============================================================================
// Fake slack.com
// ============================================================================

#[derive(Clone, Debug)]
struct Seen {
    path: String,
    query: String,
    authorization: Option<String>,
    body: Value,
}

type SeenLog = Arc<Mutex<Vec<Seen>>>;

/// Answers in Slack's own envelope: HTTP 200 always, `ok` saying the rest.
async fn start_fake_slack() -> (String, SeenLog) {
    common::allow_loopback_ssrf();
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
            path: path.clone(),
            query: query.clone(),
            authorization: parts
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
            body: body.clone(),
        });

        let payload = match path.as_str() {
            "/api/chat.postMessage" if body["channel"] == "C_GONE" => {
                json!({ "ok": false, "error": "channel_not_found" })
            }
            "/api/chat.postMessage" => {
                json!({ "ok": true, "channel": body["channel"], "ts": "1700000000.000100" })
            }
            "/api/conversations.info" => json!({ "ok": true, "channel": { "name": "general" } }),
            // Page one offers a cursor. Following it hits an in-band failure,
            // which must end the walk rather than offer the cursor again.
            "/api/conversations.list" if query.contains("cursor=") => {
                json!({ "ok": false, "error": "invalid_cursor" })
            }
            "/api/conversations.list" => json!({
                "ok": true,
                "channels": [{ "id": "C1", "name": "general" }],
                "response_metadata": { "next_cursor": "dXNlcjpVMDYxTkZUVDI=" }
            }),
            _ => json!({ "ok": false, "error": "unknown_method" }),
        };
        axum::Json(payload).into_response()
    }

    let app = Router::new()
        .route("/{*path}", any(handler))
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), seen)
}

struct Harness {
    pool: sqlx::PgPool,
    base: String,
    client: reqwest::Client,
    org_id: uuid::Uuid,
    agent_key: String,
    seen: SeenLog,
}

/// Bundled registry with `slack.com` routed at the fake, an org-level `slack`
/// instance, and — when `permit` — a rule covering every Slack action so calls
/// execute instead of gating.
async fn setup(pool: sqlx::PgPool, permit: bool) -> Harness {
    let (fake, seen) = start_fake_slack().await;
    let (base, client) =
        common::start_api_with_registry_customized(pool.clone(), None, move |cfg| {
            cfg.service_base_overrides
                .insert("slack.com".to_string(), fake);
        })
        .await;
    let (org_id, ident_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    common::grant_service_to_everyone(&base, &client, &admin_key, "slack").await;
    if permit {
        client
            .post(format!("{base}/v1/permissions"))
            .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
            .json(&json!({"identity_id": ident_id, "action_pattern": "slack:*:*"}))
            .send()
            .await
            .unwrap();
    }
    Harness {
        pool,
        base,
        client,
        org_id,
        agent_key,
        seen,
    }
}

/// A future-dated `slack` connection (+ BYOC) on the org's owner user, which
/// is where an agent's call resolves its credential (D22).
async fn seed_slack_connection(h: &Harness) {
    let owner_id = common::owner_user_id(&h.pool, h.org_id).await;
    let enc_key = overslash_core::crypto::Keyring::test();
    let token = overslash_core::crypto::encrypt(&enc_key, TOKEN.as_bytes()).unwrap();
    let cid = overslash_core::crypto::encrypt(&enc_key, b"mock_client_id").unwrap();
    let csec = overslash_core::crypto::encrypt(&enc_key, b"mock_client_secret").unwrap();
    let future = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let org = overslash_db::scopes::OrgScope::new(h.org_id, h.pool.clone());
    let byoc = org
        .create_byoc_credential(owner_id, "slack", &cid, &csec, &json!({}))
        .await
        .unwrap();
    org.create_connection(overslash_db::repos::connection::CreateConnection {
        org_id: h.org_id,
        identity_id: owner_id,
        provider_key: "slack",
        encrypted_access_token: &token,
        encrypted_refresh_token: None,
        token_expires_at: Some(future),
        scopes: None,
        account_email: None,
        account_picture: None,
        byoc_credential_id: Some(byoc.id),
    })
    .await
    .unwrap();
}

async fn call(h: &Harness, action: &str, params: Value) -> (u16, Value) {
    let resp = h
        .client
        .post(format!("{}/v1/actions/call", h.base))
        .header(common::auth(&h.agent_key).0, common::auth(&h.agent_key).1)
        .json(&json!({ "service": "slack", "action": action, "params": params }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

fn calls_to(seen: &SeenLog, path: &str) -> Vec<Seen> {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|s| s.path == path)
        .cloned()
        .collect()
}

// ============================================================================
// Execution
// ============================================================================

#[tokio::test]
async fn send_message_forwards_the_user_token_and_a_json_body() {
    let h = setup(common::test_pool().await, true).await;
    seed_slack_connection(&h).await;

    let (status, body) = call(
        &h,
        "send_message",
        json!({ "channel": "C1", "text": "hello from overslash" }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "called", "{body}");
    assert_eq!(body["is_error"], false, "{body}");

    let sent = calls_to(&h.seen, "/api/chat.postMessage");
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].authorization.as_deref(),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    assert_eq!(
        sent[0].body,
        json!({ "channel": "C1", "text": "hello from overslash" })
    );
}

/// Slack says "failed" with a 200. The predicate turns that into an upstream
/// error everywhere the gateway reports one, and leaves the status alone.
#[tokio::test]
async fn an_ok_false_answer_is_an_upstream_error_and_audited_as_one() {
    let h = setup(common::test_pool().await, true).await;
    seed_slack_connection(&h).await;

    let (status, body) = call(
        &h,
        "send_message",
        json!({ "channel": "C_GONE", "text": "hi" }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "called", "{body}");
    assert_eq!(body["is_error"], true, "{body}");
    assert_eq!(body["result"]["status_code"], 200, "{body}");
    assert!(
        body["result"]["body"]
            .as_str()
            .unwrap_or_default()
            .contains("channel_not_found"),
        "Slack's error code must reach the agent: {body}"
    );

    let detail: Value = sqlx::query_scalar(
        "SELECT detail FROM audit_log
          WHERE org_id = $1 AND action = 'action.executed'
          ORDER BY created_at DESC LIMIT 1",
    )
    .bind(h.org_id)
    .fetch_one(&h.pool)
    .await
    .expect("the call must write an audit row");
    assert_eq!(detail["is_error"], true, "{detail}");
    assert_eq!(detail["status_code"], 200, "{detail}");
}

#[tokio::test]
async fn list_channels_offers_the_next_cursor_and_stops_on_an_in_band_failure() {
    let h = setup(common::test_pool().await, true).await;
    seed_slack_connection(&h).await;

    let (_, page_one) = call(&h, "list_channels", json!({})).await;
    assert_eq!(page_one["is_error"], false, "{page_one}");
    let pagination = &page_one["result"]["_pagination"];
    assert_eq!(pagination["has_more"], true, "{page_one}");
    assert_eq!(
        pagination["next"]["params"]["cursor"], "dXNlcjpVMDYxTkZUVDI=",
        "{page_one}"
    );
    // The declared default page size reached the wire.
    let first = calls_to(&h.seen, "/api/conversations.list");
    assert!(first[0].query.contains("limit=100"), "{}", first[0].query);

    let (_, page_two) = call(&h, "list_channels", pagination["next"]["params"].clone()).await;
    assert_eq!(page_two["is_error"], true, "{page_two}");
    assert_eq!(
        page_two["result"]["_pagination"]["has_more"], false,
        "an in-band failure has no page two: {page_two}"
    );
}

// ============================================================================
// Approval disclosure
// ============================================================================

/// With no rule covering it, a write gates. The reviewer sees the channel by
/// name, looked up through `conversations.info`, rather than an opaque ID.
#[tokio::test]
async fn a_gated_send_discloses_the_channel_by_name() {
    let h = setup(common::test_pool().await, false).await;
    seed_slack_connection(&h).await;

    let (_, body) = call(
        &h,
        "send_message",
        json!({ "channel": "C1", "text": "ship it" }),
    )
    .await;
    assert_eq!(body["status"], "pending_approval", "{body}");
    let disclosed: std::collections::HashMap<String, String> = body["disclosed_fields"]
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
        disclosed.get("Channel").map(String::as_str),
        Some("general")
    );
    assert_eq!(
        disclosed.get("Message").map(String::as_str),
        Some("ship it")
    );
    assert!(
        calls_to(&h.seen, "/api/chat.postMessage").is_empty(),
        "a gated write must not reach Slack"
    );
}

// ============================================================================
// No connection
// ============================================================================

#[tokio::test]
async fn a_call_without_a_connection_never_reaches_slack() {
    let h = setup(common::test_pool().await, true).await;

    let (status, body) = call(&h, "list_channels", json!({})).await;
    assert_ne!(status, 200, "{body}");
    assert!(
        h.seen.lock().unwrap().is_empty(),
        "slack.com must not be contacted without a connection"
    );
}
