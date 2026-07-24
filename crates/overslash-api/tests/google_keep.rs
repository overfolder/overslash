//! Google Keep E2E tests — list/create/get/delete notes, mock + real API.
//!
//! The parse smoke test and the mock test run by default. The real test is
//! `#[ignore]`'d — run with:
//!   cargo test --test google_keep -- --ignored
//!
//! Env vars for the real test (all required; the official Keep API is
//! Workspace-Enterprise-only):
//!   OAUTH_GOOGLE_CLIENT_ID         — OAuth 2.0 client ID from Google Cloud Console
//!   OAUTH_GOOGLE_CLIENT_SECRET     — OAuth 2.0 client secret
//!   GOOGLE_KEEP_TEST_REFRESH_TOKEN — Long-lived refresh token (scope auth/keep)
//!
//! The real test creates a note and deletes it at the end — use a dedicated
//! test account, not a personal one.

// Test setup requires dynamic SQL for provider endpoint overrides and DB seeding.
#![allow(clippy::disallowed_methods)]

use crate::common;

use overslash_core::registry::ServiceRegistry;
use serde_json::{Value, json};
use std::path::Path;

// ============================================================================
// Parse smoke test — the shipped template loads and exposes the four actions
// ============================================================================

#[test]
fn google_keep_yaml_parses() {
    let ws_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let reg = ServiceRegistry::load_from_dir(&ws_root.join("services"))
        .expect("services/ should load cleanly");
    let svc = reg
        .get("google_keep")
        .expect("google_keep should be registered");
    assert_eq!(svc.display_name, "Google Keep");
    assert_eq!(svc.hosts, vec!["keep.googleapis.com".to_string()]);
    for action in ["list_notes", "create_note", "get_note", "delete_note"] {
        assert!(
            svc.actions.contains_key(action),
            "missing action '{action}'"
        );
    }
}

// ============================================================================
// Mock-based test — exercises create/list/get/delete against a local mock server
// ============================================================================

#[tokio::test]
async fn test_google_keep_mock() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let mock_host = format!("http://{mock_addr}");

    // Point google provider's token_endpoint at the mock.
    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'google'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();

    // Start API with registry, override google_keep host to the mock.
    let (base, client) =
        common::start_api_with_registry(pool.clone(), Some(("google_keep", mock_host.clone())))
            .await;

    // Bootstrap org + identity + API key.
    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    // Connections resolve at the owner identity (D22): the agent shares its
    // owner user's connection.
    let owner_id = common::owner_user_id(&pool, org_id).await;

    // Grant google_keep:** so every Keep action clears the permission check.
    // `**` (not `*:*`) is required: list_notes/create_note have no scope_param,
    // so their action keys are two-segment (`google_keep:create_note`), while
    // get_note/delete_note carry a scope_param and are three-segment.
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "google_keep:**"}))
        .send()
        .await
        .unwrap();

    // Mode C needs Layer-1 access to the google_keep service instance.
    common::grant_service_to_everyone(&base, &client, &admin_key, "google_keep").await;

    // Create an OAuth connection (on the owner user) the action-shape calls pick up.
    let enc_key = overslash_core::crypto::Keyring::test();
    let encrypted_token =
        overslash_core::crypto::encrypt(&enc_key, b"google-oauth-token-123").unwrap();
    let future_time = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let encrypted_cid = overslash_core::crypto::encrypt(&enc_key, b"mock_client_id").unwrap();
    let encrypted_csec = overslash_core::crypto::encrypt(&enc_key, b"mock_client_secret").unwrap();
    let byoc = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_byoc_credential(
            ident_id,
            "google",
            &encrypted_cid,
            &encrypted_csec,
            &serde_json::json!({}),
        )
        .await
        .unwrap();
    let _conn = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: owner_id,
            provider_key: "google",
            encrypted_access_token: &encrypted_token,
            encrypted_refresh_token: None,
            token_expires_at: Some(future_time),
            scopes: Some(&["https://www.googleapis.com/auth/keep".to_string()]),
            account_email: None,
            byoc_credential_id: Some(byoc.id),
        })
        .await
        .unwrap();

    // ===== create_note (POST): path + JSON body + OAuth auto-resolve =====
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "google_keep",
            "action": "create_note",
            "params": {
                "title": "Shopping list",
                "body": {"text": {"text": "milk, eggs, bread"}}
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let uri = echo["uri"].as_str().unwrap();
    assert!(
        uri.contains("/v1/notes"),
        "create_note: URL should contain /v1/notes, got: {uri}"
    );
    let req_body: Value = serde_json::from_str(echo["body"].as_str().unwrap()).unwrap();
    assert_eq!(req_body["title"], "Shopping list");
    assert_eq!(req_body["body"]["text"]["text"], "milk, eggs, bread");
    assert_eq!(
        echo["headers"]["authorization"], "Bearer google-oauth-token-123",
        "create_note: OAuth token should be auto-resolved from the connection"
    );

    // ===== list_notes (GET): query param construction =====
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "google_keep",
            "action": "list_notes",
            "params": {"pageSize": 10, "filter": "trashed = false"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let uri = echo["uri"].as_str().unwrap();
    assert!(
        uri.contains("/v1/notes"),
        "list_notes: URL should contain /v1/notes, got: {uri}"
    );
    assert!(
        uri.contains("pageSize="),
        "list_notes: query params should be appended, got: {uri}"
    );
    assert!(
        uri.contains("filter="),
        "list_notes: query params should be appended, got: {uri}"
    );

    // ===== get_note (GET): path param =====
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "google_keep",
            "action": "get_note",
            "params": {"noteId": "notes/abc123"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let uri = echo["uri"].as_str().unwrap();
    assert!(
        uri.contains("/v1/notes/notes/abc123") || uri.contains("/v1/notes/notes%2Fabc123"),
        "get_note: URL should contain the resolved note path, got: {uri}"
    );

    // ===== delete_note (DELETE): path param, no body =====
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "google_keep",
            "action": "delete_note",
            "params": {"noteId": "notes/abc123"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let uri = echo["uri"].as_str().unwrap();
    assert!(
        uri.contains("/v1/notes/notes/abc123") || uri.contains("/v1/notes/notes%2Fabc123"),
        "delete_note: URL should contain the resolved note path, got: {uri}"
    );
    assert_eq!(echo["body"], "", "delete_note: no body should be sent");
}

// ============================================================================
// Real Google Keep API test (requires GOOGLE_KEEP_TEST_REFRESH_TOKEN + OAUTH_GOOGLE_*)
// ============================================================================

#[ignore] // Write test: creates/deletes a real note. Run with --ignored.
#[tokio::test]
async fn test_google_keep_real_byoc() {
    let pool = common::test_pool().await;
    let refresh_token = match std::env::var("GOOGLE_KEEP_TEST_REFRESH_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            eprintln!("SKIP: GOOGLE_KEEP_TEST_REFRESH_TOKEN not set");
            return;
        }
    };
    let client_id = std::env::var("OAUTH_GOOGLE_CLIENT_ID")
        .expect("OAUTH_GOOGLE_CLIENT_ID required for real test");
    let client_secret = std::env::var("OAUTH_GOOGLE_CLIENT_SECRET")
        .expect("OAUTH_GOOGLE_CLIENT_SECRET required for real test");

    // Start API with the real service registry (no host override — hits real Google).
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;

    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;

    // Store BYOC credential via API (production path).
    let byoc_resp: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({
            "provider": "google",
            "client_id": client_id,
            "client_secret": client_secret
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let byoc_id: uuid::Uuid = byoc_resp["id"].as_str().unwrap().parse().unwrap();

    // Exchange refresh token for an access token via the real Google token endpoint.
    let token_resp: Value = reqwest::Client::new()
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh_token),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let access_token = token_resp["access_token"]
        .as_str()
        .expect("failed to get access_token from Google token endpoint");
    let expires_in = token_resp["expires_in"].as_i64().unwrap_or(3600);

    let enc_key = overslash_core::crypto::Keyring::test();
    let encrypted_access =
        overslash_core::crypto::encrypt(&enc_key, access_token.as_bytes()).unwrap();
    let encrypted_refresh =
        overslash_core::crypto::encrypt(&enc_key, refresh_token.as_bytes()).unwrap();
    let expires_at = time::OffsetDateTime::now_utc() + time::Duration::seconds(expires_in);

    overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: ident_id,
            provider_key: "google",
            encrypted_access_token: &encrypted_access,
            encrypted_refresh_token: Some(&encrypted_refresh),
            token_expires_at: Some(expires_at),
            scopes: Some(&["https://www.googleapis.com/auth/keep".to_string()]),
            account_email: None,
            byoc_credential_id: Some(byoc_id),
        })
        .await
        .unwrap();

    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "google_keep:**"}))
        .send()
        .await
        .unwrap();

    // create_note
    let title = format!(
        "Overslash Test - {}",
        time::OffsetDateTime::now_utc().unix_timestamp()
    );
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "google_keep",
            "action": "create_note",
            "params": {"title": title, "body": {"text": {"text": "integration test — will be deleted"}}}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let created: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let note_name = created["name"]
        .as_str()
        .expect("created note should have a name");
    eprintln!("  create_note: created {note_name}");

    // get_note
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({"service": "google_keep", "action": "get_note", "params": {"noteId": note_name}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let fetched: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(fetched["title"].as_str().unwrap(), title);

    // delete_note (cleanup)
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({"service": "google_keep", "action": "delete_note", "params": {"noteId": note_name}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    eprintln!("  delete_note: cleaned up test note");
}
