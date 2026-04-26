//! Gmail E2E tests — get profile, list labels, search/read messages, send email, trash.
//! Requires real Google OAuth credentials with Gmail API enabled.
//! Run with: cargo test --test gmail -- --ignored --nocapture
//!
//! Required env vars:
//!   OAUTH_GOOGLE_CLIENT_ID           — OAuth 2.0 Client ID (Google Cloud Console, Web Application type)
//!   OAUTH_GOOGLE_CLIENT_SECRET       — OAuth 2.0 Client Secret
//!   GOOGLE_GMAIL_TEST_REFRESH_TOKEN  — Refresh token with scopes:
//!                                       https://www.googleapis.com/auth/gmail.readonly
//!                                       https://www.googleapis.com/auth/gmail.send
//!                                       https://www.googleapis.com/auth/gmail.modify
//!                                      Obtain via OAuth Playground (access_type=offline, prompt=consent)
//!
//! Optional env vars:
//!   GMAIL_TEST_SEND_TO  — Recipient email for the send_message test. If unset, send test is skipped.

mod common;

use base64::Engine;
use serde_json::{Value, json};
use uuid::Uuid;

#[ignore] // E2E test: hits real Gmail API. Run with --ignored.
#[tokio::test]
async fn test_gmail_e2e() {
    let pool = common::test_pool().await;

    // --- Guard: skip if credentials not set ---
    let refresh_token = match std::env::var("GOOGLE_GMAIL_TEST_REFRESH_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            eprintln!("SKIP: GOOGLE_GMAIL_TEST_REFRESH_TOKEN not set");
            return;
        }
    };
    let client_id = std::env::var("OAUTH_GOOGLE_CLIENT_ID")
        .expect("OAUTH_GOOGLE_CLIENT_ID required for real test");
    let client_secret = std::env::var("OAUTH_GOOGLE_CLIENT_SECRET")
        .expect("OAUTH_GOOGLE_CLIENT_SECRET required for real test");
    let send_to = std::env::var("GMAIL_TEST_SEND_TO")
        .ok()
        .filter(|s| !s.is_empty());

    // Enable reading OAuth secrets from env vars
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_GOOGLE_CLIENT_ID", &client_id);
        std::env::set_var("OAUTH_GOOGLE_CLIENT_SECRET", &client_secret);
    }

    // Start API with real service registry (no host override — hits real Gmail)
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;

    // Bootstrap org + identity + API key
    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;

    // Store BYOC credential via API
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

    // Exchange refresh token for access token via real Google token endpoint
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

    // Encrypt tokens and insert connection in DB
    let enc_key = overslash_core::crypto::parse_hex_key(&"ab".repeat(32)).unwrap();
    let encrypted_access =
        overslash_core::crypto::encrypt(&enc_key, access_token.as_bytes()).unwrap();
    let encrypted_refresh =
        overslash_core::crypto::encrypt(&enc_key, refresh_token.as_bytes()).unwrap();
    let expires_at = time::OffsetDateTime::now_utc() + time::Duration::seconds(expires_in);

    let _conn = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: ident_id,
            provider_key: "google",
            encrypted_access_token: &encrypted_access,
            encrypted_refresh_token: Some(&encrypted_refresh),
            token_expires_at: Some(expires_at),
            scopes: &[
                "https://www.googleapis.com/auth/gmail.readonly".to_string(),
                "https://www.googleapis.com/auth/gmail.send".to_string(),
                "https://www.googleapis.com/auth/gmail.modify".to_string(),
            ],
            account_email: None,
            byoc_credential_id: Some(byoc_id),
        })
        .await
        .unwrap();

    // Create broad permission rules: http:** for raw HTTP, gmail:*:* for Mode C
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
        .json(&json!({"identity_id": ident_id, "action_pattern": "gmail:*:*"}))
        .send()
        .await
        .unwrap();

    // ===== TEST 1: get_profile (Mode C) =====
    eprintln!("  [1/6] get_profile ...");
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "gmail",
            "action": "get_profile",
            "params": {"userId": "me"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let profile: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let email = profile["emailAddress"]
        .as_str()
        .expect("get_profile should return emailAddress");
    eprintln!("  get_profile: {email}");

    // ===== TEST 2: list_labels (Mode C) =====
    eprintln!("  [2/6] list_labels ...");
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "gmail",
            "action": "list_labels",
            "params": {"userId": "me"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let labels_resp: Value =
        serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let labels = labels_resp["labels"]
        .as_array()
        .expect("list_labels should return labels array");
    let has_inbox = labels.iter().any(|l| l["id"] == "INBOX");
    assert!(has_inbox, "labels should include INBOX, got: {labels_resp}");
    eprintln!("  list_labels: {} labels (INBOX present)", labels.len());

    // ===== TEST 3: list_messages with search query (Mode C) =====
    eprintln!("  [3/6] list_messages ...");
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "gmail",
            "action": "list_messages",
            "params": {"userId": "me", "q": "in:inbox", "maxResults": 5}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let messages_resp: Value =
        serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert!(
        messages_resp["resultSizeEstimate"].is_number(),
        "list_messages should return resultSizeEstimate, got: {messages_resp}"
    );
    let first_message_id = messages_resp["messages"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|m| m["id"].as_str())
        .map(String::from);
    eprintln!(
        "  list_messages: resultSizeEstimate={}, first_id={:?}",
        messages_resp["resultSizeEstimate"], first_message_id
    );

    // ===== TEST 4: get_message (Mode C, only if we have a message) =====
    if let Some(ref msg_id) = first_message_id {
        eprintln!("  [4/6] get_message ({msg_id}) ...");
        let resp = client
            .post(format!("{base}/v1/actions/call"))
            .header(common::auth(&key).0, common::auth(&key).1)
            .json(&json!({
                "service": "gmail",
                "action": "get_message",
                "params": {"userId": "me", "id": msg_id, "format": "metadata"}
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["status"], "called");
        let msg: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
        assert!(msg["id"].is_string(), "get_message should return id");
        assert!(
            msg["threadId"].is_string(),
            "get_message should return threadId"
        );
        assert!(
            msg["payload"]["headers"].is_array(),
            "get_message metadata should include payload.headers"
        );
        eprintln!(
            "  get_message: id={}, threadId={}",
            msg["id"], msg["threadId"]
        );
    } else {
        eprintln!("  [4/6] get_message: SKIPPED (no messages in inbox)");
    }

    // ===== TEST 5: send_message (Mode C, only if GMAIL_TEST_SEND_TO is set) =====
    let mut sent_message_id: Option<String> = None;
    if let Some(ref to) = send_to {
        eprintln!("  [5/6] send_message (to {to}) ...");
        let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
        let mime_message = format!(
            "To: {to}\r\nSubject: overslash-gmail-e2e {timestamp}\r\n\r\nAutomated test message from Overslash Gmail E2E suite."
        );
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mime_message.as_bytes());

        let resp = client
            .post(format!("{base}/v1/actions/call"))
            .header(common::auth(&key).0, common::auth(&key).1)
            .json(&json!({
                "service": "gmail",
                "action": "send_message",
                "params": {"userId": "me", "raw": raw}
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["status"], "called");
        let sent: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
        let sid = sent["id"]
            .as_str()
            .expect("send_message should return message id");
        eprintln!("  send_message: sent id={sid}");
        sent_message_id = Some(sid.to_string());
    } else {
        eprintln!("  [5/6] send_message: SKIPPED (GMAIL_TEST_SEND_TO not set)");
    }

    // ===== TEST 6: trash_message (Mode C) =====
    // Prefer trashing the sent message; fall back to first inbox message
    let trash_target = sent_message_id.as_deref().or(first_message_id.as_deref());
    if let Some(trash_id) = trash_target {
        eprintln!("  [6/6] trash_message ({trash_id}) ...");
        let resp = client
            .post(format!("{base}/v1/actions/call"))
            .header(common::auth(&key).0, common::auth(&key).1)
            .json(&json!({
                "service": "gmail",
                "action": "trash_message",
                "params": {"userId": "me", "id": trash_id}
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["status"], "called");
        let trashed: Value =
            serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
        assert!(
            trashed["id"].is_string(),
            "trash_message should return id, got: {trashed}"
        );
        let label_ids = trashed["labelIds"]
            .as_array()
            .expect("trash_message should return labelIds");
        let has_trash = label_ids.iter().any(|l| l == "TRASH");
        assert!(
            has_trash,
            "trashed message should have TRASH label, got: {label_ids:?}"
        );
        eprintln!("  trash_message: trashed {trash_id}");
    } else {
        eprintln!("  [6/6] trash_message: SKIPPED (no message available to trash)");
    }

    eprintln!("  All Gmail E2E tests completed!");
}
