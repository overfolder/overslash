//! Google Drive E2E tests — about, list files, create folder, read metadata, delete.
//! Requires real Google OAuth credentials. Run with:
//!   cargo test --test google_drive -- --ignored --nocapture
//!
//! Setup (one-time):
//!   1. In Google Cloud Console, create an OAuth 2.0 Client (Desktop or Web app)
//!      and enable the Google Drive API for the project.
//!   2. Mint an access token for your test account with the
//!      `https://www.googleapis.com/auth/drive` scope. The easiest way is the
//!      OAuth 2.0 Playground (https://developers.google.com/oauthplayground):
//!        - Click the gear icon and check "Use your own OAuth credentials".
//!        - Paste your client id/secret.
//!        - Select scope `https://www.googleapis.com/auth/drive`.
//!        - Click "Authorize APIs" -> "Exchange authorization code for tokens".
//!        - Copy the `access_token` value.
//!   3. Access tokens are short-lived (~1h). Re-mint before each test run, or
//!      wire a refresh token into your shell and export a fresh one.
//!
//! Env vars:
//!   OAUTH_GOOGLE_CLIENT_ID       — OAuth client id (BYOC credential)
//!   OAUTH_GOOGLE_CLIENT_SECRET   — OAuth client secret (BYOC credential)
//!   GOOGLE_DRIVE_ACCESS_TOKEN    — Valid access token with drive scope
//!   GOOGLE_DRIVE_TEST_PARENT_ID  — (optional) Parent folder id for the test folder;
//!                                  defaults to the user's My Drive root.

mod common;

use serde_json::{Value, json};
use uuid::Uuid;

/// Not ignored: smoke-checks that `services/google_drive.yaml` deserializes
/// into a `ServiceDefinition` and exposes the key actions the E2E test relies
/// on. This runs under default `cargo test` so a malformed template trips CI
/// immediately, without needing real Google credentials.
#[test]
fn google_drive_yaml_parses() {
    let ws_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let reg = overslash_core::registry::ServiceRegistry::load_from_dir(&ws_root.join("services"))
        .expect("services/ directory should parse without errors");
    let svc = reg
        .get("google_drive")
        .expect("google_drive service template should be registered");
    assert_eq!(svc.display_name, "Google Drive");
    assert_eq!(svc.hosts, vec!["www.googleapis.com".to_string()]);
    for action in [
        "get_about",
        "list_files",
        "get_file",
        "get_file_content",
        "create_folder",
        "update_file_metadata",
        "copy_file",
        "delete_file",
        "list_permissions",
        "create_permission",
        "delete_permission",
    ] {
        assert!(
            svc.actions.contains_key(action),
            "missing google_drive action '{action}'"
        );
    }
}

#[ignore] // E2E test: hits real Google Drive API. Run with --ignored.
#[tokio::test]
async fn test_google_drive_e2e() {
    let pool = common::test_pool().await;

    // --- Guard: skip if credentials not set ---
    let access_token = match std::env::var("GOOGLE_DRIVE_ACCESS_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            eprintln!("SKIP: GOOGLE_DRIVE_ACCESS_TOKEN not set");
            return;
        }
    };
    let client_id = std::env::var("OAUTH_GOOGLE_CLIENT_ID")
        .expect("OAUTH_GOOGLE_CLIENT_ID required for real test");
    let client_secret = std::env::var("OAUTH_GOOGLE_CLIENT_SECRET")
        .expect("OAUTH_GOOGLE_CLIENT_SECRET required for real test");
    let parent_id =
        std::env::var("GOOGLE_DRIVE_TEST_PARENT_ID").unwrap_or_else(|_| "root".to_string());

    // Enable reading OAuth secrets from env vars (so BYOC resolution falls
    // back to env-provided client credentials if DB lookup is bypassed).
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_GOOGLE_CLIENT_ID", &client_id);
        std::env::set_var("OAUTH_GOOGLE_CLIENT_SECRET", &client_secret);
    }

    // Start API with real service registry (no host override — hits real Google Drive).
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;

    // Bootstrap org + identity + API key.
    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;

    // Store BYOC credential via API.
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
    let byoc_id: Uuid = byoc_resp["id"].as_str().unwrap().parse().unwrap();

    // Encrypt access token with the test encryption key and insert a connection
    // directly into the DB. We skip the refresh-token flow: the caller is
    // expected to supply a fresh access token for each run.
    let enc_key = overslash_core::crypto::parse_hex_key(&"ab".repeat(32)).unwrap();
    let encrypted_access =
        overslash_core::crypto::encrypt(&enc_key, access_token.as_bytes()).unwrap();

    let _conn = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: ident_id,
            // provider_key matches the `provider:` field in the service auth stanza
            // (shared across google_calendar and google_drive).
            provider_key: "google",
            encrypted_access_token: &encrypted_access,
            encrypted_refresh_token: None,
            token_expires_at: None,
            scopes: &["https://www.googleapis.com/auth/drive".to_string()],
            account_email: None,
            byoc_credential_id: Some(byoc_id),
        })
        .await
        .unwrap();

    // Grant permissions: http:** for any raw HTTP fallback, google_drive:*:* for Mode C.
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "http:**"}))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "google_drive:*:*"}))
        .send()
        .await
        .unwrap();

    // ===== TEST 1: get_about (Mode C) =====
    eprintln!("  [1/5] get_about ...");
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "google_drive",
            "action": "get_about",
            "params": {
                "fields": "user(displayName,emailAddress),storageQuota"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let about: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let email = about["user"]["emailAddress"]
        .as_str()
        .expect("get_about should return user.emailAddress");
    eprintln!("  get_about: authenticated as {email}");

    // ===== TEST 2: list_files (Mode C) =====
    eprintln!("  [2/5] list_files ...");
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "google_drive",
            "action": "list_files",
            "params": {
                "pageSize": 5,
                "fields": "files(id,name,mimeType)"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let listing: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let files = listing["files"]
        .as_array()
        .expect("list_files should return files array");
    eprintln!("  list_files: {} files returned", files.len());

    // ===== TEST 3: create_folder (Mode C) =====
    let folder_name = format!("overslash-e2e-{}", Uuid::new_v4());
    eprintln!("  [3/5] create_folder '{folder_name}' ...");
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "google_drive",
            "action": "create_folder",
            "params": {
                "name": folder_name,
                "parents": [parent_id]
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let folder: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let folder_id = folder["id"]
        .as_str()
        .expect("create_folder should return id")
        .to_string();
    assert_eq!(
        folder["mimeType"].as_str(),
        Some("application/vnd.google-apps.folder"),
        "expected a folder mimeType, got {folder}"
    );
    eprintln!("  create_folder: id={folder_id}");

    // ===== TEST 4: get_file on the folder we just created (Mode C) =====
    eprintln!("  [4/5] get_file ...");
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "google_drive",
            "action": "get_file",
            "params": {
                "fileId": folder_id,
                "fields": "id,name,mimeType,parents"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let fetched: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(fetched["id"].as_str(), Some(folder_id.as_str()));
    assert_eq!(fetched["name"].as_str(), Some(folder_name.as_str()));
    assert_eq!(
        fetched["mimeType"].as_str(),
        Some("application/vnd.google-apps.folder")
    );
    eprintln!(
        "  get_file: name='{}' mimeType='{}'",
        fetched["name"].as_str().unwrap_or(""),
        fetched["mimeType"].as_str().unwrap_or("")
    );

    // ===== TEST 5: delete_file to clean up (Mode C) =====
    eprintln!("  [5/5] delete_file ...");
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "google_drive",
            "action": "delete_file",
            "params": {
                "fileId": folder_id
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    // Drive returns 204 No Content on a successful delete.
    let upstream_status = body["result"]["status_code"].as_u64().unwrap();
    assert!(
        upstream_status == 204 || upstream_status == 200,
        "delete_file expected 204/200, got {upstream_status}"
    );
    eprintln!("  delete_file: upstream status {upstream_status}");

    eprintln!("  All Google Drive E2E tests completed!");
}
