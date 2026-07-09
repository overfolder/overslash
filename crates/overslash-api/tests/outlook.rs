//! Outlook (Microsoft Graph mail) E2E tests — profile, messages (search/read/send/
//! move/delete), drafts (create/send), mail folders, and per-action OAuth scope gating.
//!
//! The mock test runs by default. The real test is `#[ignore]`'d — run with:
//!   cargo test --test outlook -- --ignored --nocapture
//!
//! Env vars for the real test (all required unless noted):
//!   OAUTH_MICROSOFT_CLIENT_ID       — Azure app registration (client) ID
//!   OAUTH_MICROSOFT_CLIENT_SECRET   — Azure app client secret
//!   MICROSOFT_MAIL_TEST_REFRESH_TOKEN — Refresh token for a test Outlook mailbox with scopes:
//!                                       https://graph.microsoft.com/Mail.Read
//!                                       https://graph.microsoft.com/Mail.ReadWrite
//!                                       https://graph.microsoft.com/Mail.Send
//!                                       https://graph.microsoft.com/User.Read
//!                                       offline_access
//!                                      Each scope must be requested explicitly: Overslash's per-action
//!                                      scope gate matches recorded scope strings exactly.
//!   OUTLOOK_TEST_SEND_TO            — (optional) Recipient for send_mail. If unset, the send test is skipped.
//!
//! How to get a refresh token: register a Web app in the Azure portal with the
//! scopes above (+ offline_access), run the Overslash OAuth flow (or any auth-code
//! flow) against login.microsoftonline.com to obtain an offline refresh token. The
//! test mints fresh access tokens on each run via grant_type=refresh_token.
//!
//! The real test creates a draft and folder and deletes them at the end — use a
//! dedicated test mailbox, not a personal account.

// Test setup requires dynamic SQL for provider endpoint overrides and DB seeding.
#![allow(clippy::disallowed_methods)]

mod common;

use serde_json::{Value, json};
use uuid::Uuid;

// ============================================================================
// Mock-based test — verifies auth injection, `$`-query forwarding, and body
// shape against a local echo server (no real Microsoft credentials needed).
// ============================================================================

#[tokio::test]
async fn test_outlook_mock() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let mock_host = format!("http://{mock_addr}");

    // Point the microsoft provider's token endpoint at the mock (defensive — the
    // seeded token below is unexpired, so no refresh should actually fire).
    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'microsoft'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();

    // Start API with the real registry, overriding the outlook host to the mock.
    let (base, client) =
        common::start_api_with_registry(pool.clone(), Some(("outlook", mock_host))).await;

    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    // Connections resolve at the owner identity (D22).
    let owner_id = common::owner_user_id(&pool, org_id).await;

    // Grant the service shapes to the agent identity.
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "outlook:*:*"}))
        .send()
        .await
        .unwrap();
    // Mode C requires Layer-1 access to the `outlook` service instance.
    common::grant_service_to_everyone(&base, &client, &admin_key, "outlook").await;

    // Seed a connection carrying every Mail scope so all actions clear the gate.
    let enc_key = overslash_core::crypto::Keyring::test();
    let encrypted_token =
        overslash_core::crypto::encrypt(&enc_key, b"outlook-mock-token-123").unwrap();
    let future_time = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let encrypted_cid = overslash_core::crypto::encrypt(&enc_key, b"mock_client_id").unwrap();
    let encrypted_csec = overslash_core::crypto::encrypt(&enc_key, b"mock_client_secret").unwrap();
    let byoc = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_byoc_credential(ident_id, "microsoft", &encrypted_cid, &encrypted_csec)
        .await
        .unwrap();
    overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: owner_id,
            provider_key: "microsoft",
            encrypted_access_token: &encrypted_token,
            encrypted_refresh_token: None,
            token_expires_at: Some(future_time),
            scopes: Some(&[
                "https://graph.microsoft.com/Mail.Read".to_string(),
                "https://graph.microsoft.com/Mail.ReadWrite".to_string(),
                "https://graph.microsoft.com/Mail.Send".to_string(),
                "https://graph.microsoft.com/User.Read".to_string(),
            ]),
            account_email: None,
            byoc_credential_id: Some(byoc.id),
        })
        .await
        .unwrap();

    // ===== get_profile: no path/query params, auth auto-resolved =====
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({"service": "outlook", "action": "get_profile", "params": {}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert!(
        echo["uri"].as_str().unwrap().contains("/v1.0/me"),
        "get_profile should target /v1.0/me, got: {}",
        echo["uri"]
    );
    assert_eq!(
        echo["headers"]["authorization"], "Bearer outlook-mock-token-123",
        "OAuth token should be auto-resolved from the connection"
    );

    // ===== list_messages: `$`-prefixed OData query params forwarded intact =====
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "outlook",
            "action": "list_messages",
            "params": {"$search": "\"subject:hello\"", "$top": 5, "$select": "subject,from"}
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
        uri.contains("/v1.0/me/messages"),
        "list_messages path wrong: {uri}"
    );
    // `$` may be percent-encoded to %24, so assert on the key suffix + value.
    assert!(uri.contains("top=5"), "$top should be forwarded: {uri}");
    assert!(
        uri.contains("select=subject") || uri.contains("select=subject%2Cfrom"),
        "$select should be forwarded: {uri}"
    );
    assert!(
        uri.contains("search="),
        "$search should be forwarded: {uri}"
    );

    // ===== send_mail: structured JSON body preserved (no base64), wrapped in `message` =====
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "outlook",
            "action": "send_mail",
            "params": {
                "message": {
                    "subject": "Hello from Overslash",
                    "body": {"contentType": "Text", "content": "Test body"},
                    "toRecipients": [{"emailAddress": {"address": "dest@example.com"}}]
                },
                "saveToSentItems": true
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert!(
        echo["uri"].as_str().unwrap().contains("/v1.0/me/sendMail"),
        "send_mail path wrong: {}",
        echo["uri"]
    );
    let req_body: Value = serde_json::from_str(echo["body"].as_str().unwrap()).unwrap();
    assert_eq!(req_body["message"]["subject"], "Hello from Overslash");
    assert_eq!(
        req_body["message"]["toRecipients"][0]["emailAddress"]["address"],
        "dest@example.com"
    );
    assert_eq!(req_body["saveToSentItems"], true);
    assert_eq!(
        echo["headers"]["authorization"], "Bearer outlook-mock-token-123",
        "send_mail: OAuth token should be auto-resolved"
    );

    // ===== create_draft: message resource sent directly (no `message` wrapper) =====
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "outlook",
            "action": "create_draft",
            "params": {
                "subject": "Draft subject",
                "body": {"contentType": "Text", "content": "Draft body"},
                "toRecipients": [{"emailAddress": {"address": "dest@example.com"}}]
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert!(
        echo["uri"].as_str().unwrap().contains("/v1.0/me/messages"),
        "create_draft path wrong: {}",
        echo["uri"]
    );
    let req_body: Value = serde_json::from_str(echo["body"].as_str().unwrap()).unwrap();
    assert_eq!(
        req_body["subject"], "Draft subject",
        "create_draft: message fields sent at top level (no `message` wrapper)"
    );

    // ===== move_message: path param substituted, body carries destinationId =====
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "outlook",
            "action": "move_message",
            "params": {"id": "AAMkAGxyz123", "destinationId": "deleteditems"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert!(
        echo["uri"]
            .as_str()
            .unwrap()
            .contains("/v1.0/me/messages/AAMkAGxyz123/move"),
        "move_message path wrong: {}",
        echo["uri"]
    );
    let req_body: Value = serde_json::from_str(echo["body"].as_str().unwrap()).unwrap();
    assert_eq!(req_body["destinationId"], "deleteditems");
}

// ============================================================================
// Real Microsoft Graph test (requires MICROSOFT_MAIL_TEST_REFRESH_TOKEN + OAUTH_MICROSOFT_*)
// ============================================================================

#[ignore] // E2E test: hits real Microsoft Graph. Run with --ignored.
#[tokio::test]
async fn test_outlook_e2e() {
    let pool = common::test_pool().await;

    // --- Guard: skip if credentials not set ---
    let refresh_token = match std::env::var("MICROSOFT_MAIL_TEST_REFRESH_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            eprintln!("SKIP: MICROSOFT_MAIL_TEST_REFRESH_TOKEN not set");
            return;
        }
    };
    let client_id = std::env::var("OAUTH_MICROSOFT_CLIENT_ID")
        .expect("OAUTH_MICROSOFT_CLIENT_ID required for real test");
    let client_secret = std::env::var("OAUTH_MICROSOFT_CLIENT_SECRET")
        .expect("OAUTH_MICROSOFT_CLIENT_SECRET required for real test");
    let send_to = std::env::var("OUTLOOK_TEST_SEND_TO")
        .ok()
        .filter(|s| !s.is_empty());

    // Enable reading OAuth secrets from env vars.
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_MICROSOFT_CLIENT_ID", &client_id);
        std::env::set_var("OAUTH_MICROSOFT_CLIENT_SECRET", &client_secret);
    }

    // Start API with the real registry (no host override — hits real Graph).
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;

    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    let owner_id = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .get_identity(ident_id)
        .await
        .unwrap()
        .unwrap()
        .owner_id
        .unwrap();

    // Store BYOC credential via the API (production path).
    let byoc_resp: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({
            "provider": "microsoft",
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

    // Exchange refresh token for an access token via the real Microsoft endpoint.
    let token_resp: Value = reqwest::Client::new()
        .post("https://login.microsoftonline.com/common/oauth2/v2.0/token")
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
        .expect("failed to get access_token from Microsoft token endpoint");
    let expires_in = token_resp["expires_in"].as_i64().unwrap_or(3600);

    let enc_key = overslash_core::crypto::Keyring::test();
    let encrypted_access =
        overslash_core::crypto::encrypt(&enc_key, access_token.as_bytes()).unwrap();
    let encrypted_refresh =
        overslash_core::crypto::encrypt(&enc_key, refresh_token.as_bytes()).unwrap();
    let expires_at = time::OffsetDateTime::now_utc() + time::Duration::seconds(expires_in);

    let full_scopes = [
        "https://graph.microsoft.com/Mail.Read".to_string(),
        "https://graph.microsoft.com/Mail.ReadWrite".to_string(),
        "https://graph.microsoft.com/Mail.Send".to_string(),
        "https://graph.microsoft.com/User.Read".to_string(),
    ];
    overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: owner_id,
            provider_key: "microsoft",
            encrypted_access_token: &encrypted_access,
            encrypted_refresh_token: Some(&encrypted_refresh),
            token_expires_at: Some(expires_at),
            scopes: Some(&full_scopes),
            account_email: None,
            byoc_credential_id: Some(byoc_id),
        })
        .await
        .unwrap();

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
        .json(&json!({"identity_id": ident_id, "action_pattern": "outlook:*:*"}))
        .send()
        .await
        .unwrap();

    // ===== TEST 1: get_profile =====
    eprintln!("  [1/7] get_profile ...");
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({"service": "outlook", "action": "get_profile", "params": {}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let profile: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert!(
        profile["userPrincipalName"].is_string() || profile["mail"].is_string(),
        "get_profile should return userPrincipalName or mail, got: {profile}"
    );
    eprintln!("  get_profile: {}", profile["userPrincipalName"]);

    // ===== TEST 2: list_messages =====
    eprintln!("  [2/7] list_messages ...");
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "outlook",
            "action": "list_messages",
            "params": {"$top": 5, "$select": "subject,from,receivedDateTime"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let listing: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert!(
        listing["value"].is_array(),
        "list_messages should return a `value` array, got: {listing}"
    );
    eprintln!(
        "  list_messages: {} messages",
        listing["value"].as_array().unwrap().len()
    );

    // ===== TEST 3: create_draft =====
    eprintln!("  [3/7] create_draft ...");
    let now = time::OffsetDateTime::now_utc();
    let subject = format!("Overslash Outlook Test — {}", now.unix_timestamp());
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "outlook",
            "action": "create_draft",
            "params": {
                "subject": subject,
                "body": {"contentType": "Text", "content": "Integration test draft — will be deleted."},
                "toRecipients": [{"emailAddress": {"address": send_to.clone().unwrap_or_else(|| "nobody@example.com".to_string())}}]
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let draft: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let draft_id = draft["id"]
        .as_str()
        .expect("draft should have an id")
        .to_string();
    assert_eq!(draft["subject"].as_str().unwrap(), subject);
    eprintln!("  create_draft: created {draft_id}");

    // ===== TEST 4: get_message (verify the draft) =====
    eprintln!("  [4/7] get_message ...");
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "outlook",
            "action": "get_message",
            "params": {"id": draft_id, "$select": "subject,isDraft"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let fetched: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(fetched["subject"].as_str().unwrap(), subject);
    eprintln!("  get_message: verified draft {draft_id}");

    // ===== TEST 5: send_draft (only if a recipient is configured) =====
    if send_to.is_some() {
        eprintln!("  [5/7] send_draft ...");
        let resp = client
            .post(format!("{base}/v1/actions/call"))
            .header(common::auth(&key).0, common::auth(&key).1)
            .json(&json!({
                "service": "outlook",
                "action": "send_draft",
                "params": {"id": draft_id}
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["status"], "called");
        let status_code = body["result"]["status_code"].as_u64().unwrap();
        assert!(
            status_code == 202 || status_code == 200,
            "send_draft should return 202/200, got: {status_code}"
        );
        eprintln!("  send_draft: sent {draft_id}");
    } else {
        // No recipient — clean up the draft instead of sending it.
        eprintln!("  [5/7] send_draft SKIPPED (OUTLOOK_TEST_SEND_TO unset); deleting draft ...");
        let resp = client
            .post(format!("{base}/v1/actions/call"))
            .header(common::auth(&key).0, common::auth(&key).1)
            .json(&json!({
                "service": "outlook",
                "action": "delete_message",
                "params": {"id": draft_id}
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        eprintln!("  delete_message: cleaned up draft {draft_id}");
    }

    // ===== TEST 6: mail folder lifecycle (create + delete) =====
    eprintln!("  [6/7] create_folder + delete_folder ...");
    let folder_name = format!("Overslash Test {}", now.unix_timestamp());
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "outlook",
            "action": "create_folder",
            "params": {"displayName": folder_name}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let folder: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let folder_id = folder["id"]
        .as_str()
        .expect("folder should have an id")
        .to_string();
    assert_eq!(folder["displayName"].as_str().unwrap(), folder_name);

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "outlook",
            "action": "delete_folder",
            "params": {"id": folder_id}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let status_code = body["result"]["status_code"].as_u64().unwrap();
    assert!(
        status_code == 204 || status_code == 200,
        "delete_folder should return 204/200, got: {status_code}"
    );
    eprintln!("  folder lifecycle: created + deleted {folder_id}");

    // ===== TEST 7: per-action scope gating =====
    // A second identity with a connection scoped ONLY to Mail.Read:
    //   - list_messages (declared Mail.Read) → 200
    //   - send_mail (declared Mail.Send)     → 403 missing_scopes envelope
    eprintln!("  [7/7] scope gating (Mail.Read-only identity) ...");
    let ro_user: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"name": "readonly-user", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ro_ident_id: Uuid = ro_user["id"].as_str().unwrap().parse().unwrap();

    let ro_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"org_id": org_id, "identity_id": ro_ident_id, "name": "readonly-key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ro_key = ro_key_resp["key"].as_str().unwrap().to_string();

    overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: ro_ident_id,
            provider_key: "microsoft",
            encrypted_access_token: &encrypted_access,
            encrypted_refresh_token: Some(&encrypted_refresh),
            token_expires_at: Some(expires_at),
            scopes: Some(&["https://graph.microsoft.com/Mail.Read".to_string()]),
            account_email: None,
            byoc_credential_id: Some(byoc_id),
        })
        .await
        .unwrap();
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ro_ident_id, "action_pattern": "outlook:*:*"}))
        .send()
        .await
        .unwrap();

    // list_messages → covered by Mail.Read → succeeds
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&ro_key).0, common::auth(&ro_key).1)
        .json(&json!({
            "service": "outlook",
            "action": "list_messages",
            "params": {"$top": 1}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "list_messages should succeed for Mail.Read-only identity"
    );

    // send_mail → declared Mail.Send, not granted → 403 missing_scopes
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&ro_key).0, common::auth(&ro_key).1)
        .json(&json!({
            "service": "outlook",
            "action": "send_mail",
            "params": {
                "message": {
                    "subject": "should not send",
                    "toRecipients": [{"emailAddress": {"address": "nobody@example.com"}}]
                }
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "send_mail should 403 for Mail.Read-only identity"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "missing_scopes");
    let missing = body["missing"]
        .as_array()
        .expect("missing_scopes envelope should carry `missing` array");
    assert_eq!(
        missing[0].as_str(),
        Some("https://graph.microsoft.com/Mail.Send")
    );
    assert!(
        body["upgrade_url"].as_str().is_some_and(|s| !s.is_empty()),
        "missing_scopes envelope should carry a non-empty upgrade_url"
    );
    eprintln!("  scope gating: send_mail correctly returned missing_scopes");
    eprintln!("  All Outlook real tests passed!");
}
