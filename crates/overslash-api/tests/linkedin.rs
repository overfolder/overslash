//! LinkedIn service integration tests — profile read + member-share write.
//!
//! **Default CI** (non-ignored):
//!   1. `linkedin_yaml_parses` — the shipped `services/linkedin.yaml` loads and
//!      exposes get_profile / create_post / get_organization.
//!   2. `test_linkedin_mock_read_and_write` — Mode C get_profile (read) and
//!      create_post (write) execute against a local mock upstream, with the
//!      OAuth token auto-resolved from a connection (connection-based / Mode B+C).
//!   3. `test_linkedin_create_post_routes_through_approval` — with the service
//!      granted but no covering permission rule, get_profile (read) auto-approves
//!      while create_post (write, elevated risk) routes through human approval.
//!
//! **Real API E2E** (`#[ignore]`): hits the live LinkedIn API. Run with:
//!   cargo test --test linkedin -- --ignored --nocapture --test-threads=4
//!
//! Env vars for the real test:
//!   LINKEDIN_TEST_ACCESS_TOKEN — a member OAuth 2.0 access token granted
//!                                `openid profile email w_member_social`.
//!   LINKEDIN_TEST_ALLOW_POST   — set to `1` to also publish a real (visible)
//!                                share via create_post. Off by default so the
//!                                read path can be exercised without spamming a
//!                                real feed. Use a dedicated test account.
//!
//! LinkedIn access tokens are ~60-day and (outside the partner program) not
//! refreshable, so the real test takes a pre-minted token rather than a refresh
//! token — unlike oauth_x.rs / google_keep.rs.
// Test setup requires dynamic SQL for provider endpoint overrides and DB seeding.
#![allow(clippy::disallowed_methods)]

mod common;

use overslash_core::registry::ServiceRegistry;
use serde_json::{Value, json};
use std::path::Path;

/// A realistic UGC Posts body for a plain text member share.
fn ugc_post_body(author: &str, text: &str) -> Value {
    json!({
        "author": author,
        "lifecycleState": "PUBLISHED",
        "specificContent": {
            "com.linkedin.ugc.ShareContent": {
                "shareCommentary": {"text": text},
                "shareMediaCategory": "NONE"
            }
        },
        "visibility": {
            "com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"
        }
    })
}

// ============================================================================
// Parse smoke test — the shipped template loads and exposes its actions
// ============================================================================

#[test]
fn linkedin_yaml_parses() {
    let ws_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let reg = ServiceRegistry::load_from_dir(&ws_root.join("services"))
        .expect("services/ should load cleanly");
    let svc = reg.get("linkedin").expect("linkedin should be registered");
    assert_eq!(svc.display_name, "LinkedIn");
    assert_eq!(svc.hosts, vec!["api.linkedin.com".to_string()]);
    for action in ["get_profile", "create_post", "get_organization"] {
        assert!(
            svc.actions.contains_key(action),
            "missing action '{action}'"
        );
    }
    // Publishing a share is an elevated (mutating) action; reading the profile
    // is not. This is what routes create_post through approval.
    use overslash_core::types::service::Risk;
    assert_eq!(svc.actions["create_post"].risk, Risk::Write);
    assert_eq!(svc.actions["get_profile"].risk, Risk::Read);
}

// ============================================================================
// Mock-based Mode C — get_profile (read) + create_post (write) both execute
// ============================================================================

#[tokio::test]
async fn test_linkedin_mock_read_and_write() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let mock_host = format!("http://{mock_addr}");

    // Point the LinkedIn provider's token_endpoint at the mock (a refresh would
    // land here; the seeded token is unexpired so it isn't actually hit).
    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'linkedin'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();

    // Start API with the real registry, overriding linkedin's host to the mock.
    let (base, client) =
        common::start_api_with_registry(pool.clone(), Some(("linkedin", mock_host.clone()))).await;

    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    // Connections resolve at the owner identity (D22).
    let owner_id = common::owner_user_id(&pool, org_id).await;

    // Grant linkedin:** so both actions clear Layer 2 (no gap → no approval).
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "linkedin:**"}))
        .send()
        .await
        .unwrap();

    // Mode C needs Layer-1 access to the linkedin service instance.
    common::grant_service_to_everyone(&base, &client, &admin_key, "linkedin").await;

    // Seed an OAuth connection (on the owner user) with a BYOC credential.
    let enc_key = overslash_core::crypto::Keyring::test();
    let encrypted_token =
        overslash_core::crypto::encrypt(&enc_key, b"linkedin-oauth-token-123").unwrap();
    let future_time = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let encrypted_cid = overslash_core::crypto::encrypt(&enc_key, b"mock_client_id").unwrap();
    let encrypted_csec = overslash_core::crypto::encrypt(&enc_key, b"mock_client_secret").unwrap();
    let byoc = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_byoc_credential(ident_id, "linkedin", &encrypted_cid, &encrypted_csec)
        .await
        .unwrap();
    overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: owner_id,
            provider_key: "linkedin",
            encrypted_access_token: &encrypted_token,
            encrypted_refresh_token: None,
            token_expires_at: Some(future_time),
            scopes: Some(&[
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "w_member_social".to_string(),
            ]),
            account_email: None,
            byoc_credential_id: Some(byoc.id),
        })
        .await
        .unwrap();

    // ===== get_profile (GET): OIDC userinfo, OAuth auto-resolve =====
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({"service": "linkedin", "action": "get_profile", "params": {}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let uri = echo["uri"].as_str().unwrap();
    assert!(
        uri.contains("/v2/userinfo"),
        "get_profile: URL should contain /v2/userinfo, got: {uri}"
    );
    assert_eq!(
        echo["headers"]["authorization"], "Bearer linkedin-oauth-token-123",
        "get_profile: OAuth token should be auto-resolved from the connection"
    );

    // ===== create_post (POST): JSON body + OAuth auto-resolve =====
    let post_body = ugc_post_body(
        "urn:li:person:ABC123",
        "Hello from the Overslash integration test",
    );
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({"service": "linkedin", "action": "create_post", "params": post_body}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called", "create_post response: {body:?}");
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let uri = echo["uri"].as_str().unwrap();
    assert!(
        uri.contains("/v2/ugcPosts"),
        "create_post: URL should contain /v2/ugcPosts, got: {uri}"
    );
    let req_body: Value = serde_json::from_str(echo["body"].as_str().unwrap()).unwrap();
    assert_eq!(req_body["author"], "urn:li:person:ABC123");
    assert_eq!(
        req_body["specificContent"]["com.linkedin.ugc.ShareContent"]["shareCommentary"]["text"],
        "Hello from the Overslash integration test"
    );
    assert_eq!(
        echo["headers"]["authorization"], "Bearer linkedin-oauth-token-123",
        "create_post: OAuth token should be auto-resolved from the connection"
    );
}

// ============================================================================
// create_post (write) routes through approval; get_profile (read) does not
// ============================================================================

#[tokio::test]
async fn test_linkedin_create_post_routes_through_approval() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let mock_host = format!("http://{mock_addr}");

    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'linkedin'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();

    let (base, client) =
        common::start_api_with_registry(pool.clone(), Some(("linkedin", mock_host.clone()))).await;

    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    let owner_id = common::owner_user_id(&pool, org_id).await;

    // Grant Layer-1 service access (admin + auto_approve_reads) but intentionally
    // add NO permission rule: reads bypass Layer 2, writes must be approved.
    common::grant_service_to_everyone(&base, &client, &admin_key, "linkedin").await;

    // Seed a connection so read resolution has a token to inject.
    let enc_key = overslash_core::crypto::Keyring::test();
    let encrypted_token =
        overslash_core::crypto::encrypt(&enc_key, b"linkedin-oauth-token-abc").unwrap();
    let future_time = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let encrypted_cid = overslash_core::crypto::encrypt(&enc_key, b"mock_client_id").unwrap();
    let encrypted_csec = overslash_core::crypto::encrypt(&enc_key, b"mock_client_secret").unwrap();
    let byoc = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_byoc_credential(ident_id, "linkedin", &encrypted_cid, &encrypted_csec)
        .await
        .unwrap();
    overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: owner_id,
            provider_key: "linkedin",
            encrypted_access_token: &encrypted_token,
            encrypted_refresh_token: None,
            token_expires_at: Some(future_time),
            scopes: Some(&[
                "openid".to_string(),
                "profile".to_string(),
                "w_member_social".to_string(),
            ]),
            account_email: None,
            byoc_credential_id: Some(byoc.id),
        })
        .await
        .unwrap();

    // get_profile (read) → auto-approve-reads bypass → executes, no approval.
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({"service": "linkedin", "action": "get_profile", "params": {}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["status"], "called",
        "read should auto-approve, got: {body:?}"
    );

    // create_post (write) → no read bypass → Layer-2 gap → pending approval.
    let post_body = ugc_post_body("urn:li:person:ABC123", "This share should require approval");
    let exec: Value = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({"service": "linkedin", "action": "create_post", "params": post_body}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        exec["status"].as_str(),
        Some("pending_approval"),
        "write should route through approval, got: {exec:?}"
    );
    // `write` risk → "med" approval class.
    assert_eq!(exec["risk"].as_str(), Some("med"));
    let approval_id = exec["approval_id"].as_str().expect("approval_id present");

    // The disclose filters surfaced the share text for the reviewer.
    let disclosed = exec["disclosed_fields"]
        .as_array()
        .expect("disclosed_fields present");
    let text_field = disclosed
        .iter()
        .find(|f| f["label"] == "Text")
        .expect("Text disclosure present");
    assert_eq!(
        text_field["value"].as_str(),
        Some("This share should require approval")
    );

    // The approval is resolvable by the agent's owner (an ancestor user).
    let approval: Value = client
        .get(format!("{base}/v1/approvals/{approval_id}"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(approval["risk"], exec["risk"], "inline vs GET risk drift");
}

// ============================================================================
// Real LinkedIn API test (requires LINKEDIN_TEST_ACCESS_TOKEN)
// ============================================================================

#[ignore] // E2E: hits the real LinkedIn API. Run with --ignored.
#[tokio::test]
async fn test_linkedin_real_e2e() {
    let pool = common::test_pool().await;
    let access_token = match std::env::var("LINKEDIN_TEST_ACCESS_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            eprintln!("SKIP: LINKEDIN_TEST_ACCESS_TOKEN not set");
            return;
        }
    };

    // Real registry, no host override — hits real LinkedIn.
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    let owner_id = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .get_identity(ident_id)
        .await
        .unwrap()
        .unwrap()
        .owner_id
        .unwrap();

    // Store the pre-minted access token as a connection. No refresh token — the
    // token is used directly until it expires (~60 days).
    let enc_key = overslash_core::crypto::Keyring::test();
    let encrypted_access =
        overslash_core::crypto::encrypt(&enc_key, access_token.as_bytes()).unwrap();
    let expires_at = time::OffsetDateTime::now_utc() + time::Duration::days(30);
    overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: owner_id,
            provider_key: "linkedin",
            encrypted_access_token: &encrypted_access,
            encrypted_refresh_token: None,
            token_expires_at: Some(expires_at),
            scopes: Some(&[
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "w_member_social".to_string(),
            ]),
            account_email: None,
            byoc_credential_id: None,
        })
        .await
        .unwrap();

    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "linkedin:**"}))
        .send()
        .await
        .unwrap();
    common::grant_service_to_everyone(&base, &client, &admin_key, "linkedin").await;

    // ===== get_profile (read) =====
    eprintln!("  [1/2] get_profile ...");
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({"service": "linkedin", "action": "get_profile", "params": {}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called", "get_profile: {body:?}");
    let me: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let sub = me["sub"].as_str().expect("userinfo should return sub");
    eprintln!("  get_profile: sub={sub} name={:?}", me["name"]);

    // ===== create_post (write) — opt-in, publishes a real share =====
    if std::env::var("LINKEDIN_TEST_ALLOW_POST").as_deref() != Ok("1") {
        eprintln!("  [2/2] create_post SKIPPED (set LINKEDIN_TEST_ALLOW_POST=1 to publish)");
        return;
    }
    eprintln!("  [2/2] create_post ...");
    let author = format!("urn:li:person:{sub}");
    let text = format!(
        "Overslash e2e {} — automated test post",
        time::OffsetDateTime::now_utc().unix_timestamp()
    );
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "linkedin",
            "action": "create_post",
            "params": ugc_post_body(&author, &text)
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called", "create_post: {body:?}");
    let created: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    eprintln!("  create_post: created {:?}", created["id"]);
}
