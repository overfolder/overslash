//! X.com (Twitter) OAuth integration tests + real-API E2E.
//!
//! **Non-ignored tests** (run in default CI):
//!   OAuth callback, BYOC credential binding, token refresh, PKCE validation.
//!
//! **Real-API E2E** (`#[ignore]`): exercises all 4 actions in `services/x.yaml` via
//! Mode C (service+action) against the live X API v2. Run with:
//!   cargo test --test oauth_x -- --ignored --nocapture
//!
//! Required env vars for the real-API test:
//!   X_TEST_REFRESH_TOKEN       — OAuth 2.0 refresh token for a test X account
//!   OAUTH_X_CLIENT_ID          — OAuth 2.0 Client ID from your X app
//!   OAUTH_X_CLIENT_SECRET      — Client Secret
//!
//! How to obtain credentials:
//!   1. Register an OAuth 2.0 app at https://developer.x.com/ (type "Web App",
//!      confidential client) with a callback URL.
//!   2. Authorize with scopes: tweet.read tweet.write users.read offline.access
//!   3. Capture the refresh token from the dashboard OAuth flow or X's auth URL.
//!   4. Use a dedicated test account — the test posts a real (short-lived) tweet.
//!
//! Note: X rotates refresh tokens on every exchange. The test prints the new token
//! to stderr — update your env for the next run.
// Test setup requires dynamic SQL for provider endpoint overrides and DB seeding.
#![allow(clippy::disallowed_methods)]

mod common;

use serde_json::{Value, json};
use uuid::Uuid;

// --- Test 1: Callback exchanges code and stores connection ---

#[tokio::test]
async fn test_oauth_x_callback_stores_connection() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;

    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client_id");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_client_secret");
    }

    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'x'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();

    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key, _) = common::bootstrap_org_identity(&base, &client).await;

    // State with dummy verifier segment (mock doesn't validate PKCE)
    let state_param = format!("{org_id}:{ident_id}:x:_:_");
    let callback_resp: Value = client
        .get(format!(
            "{base}/v1/oauth/callback?code=x_auth_code_42&state={state_param}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(callback_resp["status"], "connected");
    assert_eq!(callback_resp["provider"], "x");
    assert!(callback_resp["connection_id"].is_string());

    // Verify connection is listed
    let conns: Vec<Value> = client
        .get(format!("{base}/v1/connections"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(conns.len(), 1);
    assert_eq!(conns[0]["provider_key"], "x");
}

// --- Test 2: Callback with BYOC credential ---

#[tokio::test]
async fn test_oauth_x_callback_with_byoc() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;

    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'x'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();

    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, _api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Create identity-bound BYOC credential for X
    let byoc: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "provider": "x",
            "client_id": "x_byoc_client_id",
            "client_secret": "x_byoc_client_secret",
            "identity_id": ident_id,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let byoc_id = byoc["id"].as_str().unwrap();

    let state_param = format!("{org_id}:{ident_id}:x:_:_");
    let callback_resp: Value = client
        .get(format!(
            "{base}/v1/oauth/callback?code=x_byoc_code&state={state_param}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(callback_resp["status"], "connected");
    assert_eq!(callback_resp["provider"], "x");

    // Verify BYOC credential is pinned on the connection
    let conn_id: Uuid = callback_resp["connection_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let conn = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .get_connection(conn_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(conn.byoc_credential_id.unwrap().to_string(), byoc_id);
}

// --- Test 3: Token refresh for expired X connection ---

#[tokio::test]
async fn test_oauth_x_token_refresh() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;

    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'x'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();

    let enc_key_hex = "ab".repeat(32);
    let enc_key = overslash_core::crypto::parse_hex_key(&enc_key_hex).unwrap();

    // Create org + identity directly
    let org = overslash_db::repos::org::create(&pool, "XRefreshOrg", "x-refresh-test")
        .await
        .unwrap();
    let ident = overslash_db::repos::identity::create(&pool, org.id, "agent", "agent", None)
        .await
        .unwrap();

    // Create a connection with an EXPIRED token
    let expired_at = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    let enc_access = overslash_core::crypto::encrypt(&enc_key, b"old_x_access_token").unwrap();
    let enc_refresh = overslash_core::crypto::encrypt(&enc_key, b"old_x_refresh_token").unwrap();

    let scope = overslash_db::scopes::OrgScope::new(org.id, pool.clone());
    let conn = scope
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id: org.id,
            identity_id: ident.id,
            provider_key: "x",
            encrypted_access_token: &enc_access,
            encrypted_refresh_token: Some(&enc_refresh),
            token_expires_at: Some(expired_at),
            scopes: &[],
            account_email: None,
            byoc_credential_id: None,
        })
        .await
        .unwrap();

    // Resolve should trigger a refresh
    let http_client = reqwest::Client::new();
    let new_token = overslash_api::services::oauth::resolve_access_token(
        &scope,
        &http_client,
        &enc_key,
        &conn,
        "dummy_client_id",
        "dummy_client_secret",
    )
    .await
    .unwrap();

    assert_eq!(new_token, "mock_refreshed_access_token");

    // Verify DB was updated
    let updated = scope.get_connection(conn.id).await.unwrap().unwrap();
    assert!(updated.token_expires_at.unwrap() > time::OffsetDateTime::now_utc());
}

// --- Test 4: PKCE parameters in auth URL ---

#[tokio::test]
async fn test_oauth_x_pkce_in_auth_url() {
    let pool = common::test_pool().await;
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_pkce_client");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_pkce_secret");
    }

    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, _ident_id, api_key, _) = common::bootstrap_org_identity(&base, &client).await;

    let resp: Value = client
        .post(format!("{base}/v1/connections"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "provider": "x",
            "scopes": ["tweet.read", "users.read", "offline.access"],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let auth_url = resp["auth_url"].as_str().unwrap();
    let state = resp["state"].as_str().unwrap();

    // Auth URL must contain PKCE parameters
    assert!(
        auth_url.contains("code_challenge="),
        "auth_url missing code_challenge: {auth_url}"
    );
    assert!(
        auth_url.contains("code_challenge_method=S256"),
        "auth_url missing code_challenge_method: {auth_url}"
    );

    // State must have 5 segments (org:ident:provider:byoc:verifier)
    let segments: Vec<&str> = state.splitn(5, ':').collect();
    assert_eq!(segments.len(), 5, "state should have 5 segments: {state}");
    assert_eq!(segments[2], "x");
    // The verifier segment must not be "_" (it should be an actual verifier)
    assert_ne!(segments[4], "_", "code_verifier should not be empty");
}

// ============================================================================
// Real X.com API test (requires X_TEST_REFRESH_TOKEN + OAUTH_X_* env vars)
// ============================================================================

#[ignore] // E2E test: hits real X API (all 4 actions via Mode C). Run with --ignored.
#[tokio::test]
async fn test_x_real_e2e() {
    let pool = common::test_pool().await;
    // --- Guard: skip if credentials not set ---
    let refresh_token = match std::env::var("X_TEST_REFRESH_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            eprintln!("SKIP: X_TEST_REFRESH_TOKEN not set");
            return;
        }
    };
    let client_id =
        std::env::var("OAUTH_X_CLIENT_ID").expect("OAUTH_X_CLIENT_ID required for real test");
    let client_secret = std::env::var("OAUTH_X_CLIENT_SECRET")
        .expect("OAUTH_X_CLIENT_SECRET required for real test");

    // Enable reading OAuth secrets from env vars
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", &client_id);
        std::env::set_var("OAUTH_X_CLIENT_SECRET", &client_secret);
    }

    // Start API with real service registry (no host override — hits real X)
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;

    // Store BYOC credential via API
    let byoc_resp: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({
            "provider": "x",
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

    // Exchange refresh token for access token via real X token endpoint
    // X uses client_secret_basic (HTTP Basic Auth)
    let token_resp: Value = reqwest::Client::new()
        .post("https://api.twitter.com/2/oauth2/token")
        .basic_auth(&client_id, Some(&client_secret))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let access_token = token_resp["access_token"]
        .as_str()
        .expect("failed to get access_token from X token endpoint");
    let new_refresh = token_resp["refresh_token"].as_str();
    let expires_in = token_resp["expires_in"].as_i64().unwrap_or(7200);

    // Save the new refresh token for future test runs
    if let Some(rt) = new_refresh {
        eprintln!("  NEW X_TEST_REFRESH_TOKEN={rt}");
        eprintln!("  (update .env if you want to reuse it)");
    }

    // Insert connection in DB
    let enc_key = overslash_core::crypto::parse_hex_key(&"ab".repeat(32)).unwrap();
    let encrypted_access =
        overslash_core::crypto::encrypt(&enc_key, access_token.as_bytes()).unwrap();
    let encrypted_refresh =
        new_refresh.map(|rt| overslash_core::crypto::encrypt(&enc_key, rt.as_bytes()).unwrap());
    let expires_at = time::OffsetDateTime::now_utc() + time::Duration::seconds(expires_in);

    let _conn = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: ident_id,
            provider_key: "x",
            encrypted_access_token: &encrypted_access,
            encrypted_refresh_token: encrypted_refresh.as_deref(),
            token_expires_at: Some(expires_at),
            scopes: &[],
            account_email: None,
            byoc_credential_id: Some(byoc_id),
        })
        .await
        .unwrap();

    // Create permission rules: http:** for raw HTTP, x:*:* for Mode C
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
        .json(&json!({"identity_id": ident_id, "action_pattern": "x:*:*"}))
        .send()
        .await
        .unwrap();

    // ===== TEST 1: get_me (Mode C) =====
    eprintln!("  [1/4] get_me ...");
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "x",
            "action": "get_me",
            "params": {}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let me: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert!(
        me["data"]["username"].is_string(),
        "get_me should return username, got: {me}"
    );
    let username = me["data"]["username"].as_str().unwrap();
    let user_id = me["data"]["id"]
        .as_str()
        .expect("get_me should return user id");
    eprintln!("  get_me: @{username} (id={user_id})");

    // ===== TEST 2: post_tweet (Mode C) =====
    eprintln!("  [2/4] post_tweet ...");
    let tweet_text = format!(
        "@grok overslash e2e {} — will be deleted",
        time::OffsetDateTime::now_utc().unix_timestamp()
    );
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "x",
            "action": "post_tweet",
            "params": {
                "text": tweet_text
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let tweet_resp: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let tweet_id = tweet_resp["data"]["id"]
        .as_str()
        .expect("post_tweet should return tweet id");
    eprintln!("  post_tweet: created {tweet_id}");

    // ===== TEST 3: delete_tweet (Mode C) — path param substitution =====
    eprintln!("  [3/4] delete_tweet ...");
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "x",
            "action": "delete_tweet",
            "params": {
                "tweet_id": tweet_id
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let del_resp: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(del_resp["data"]["deleted"], true, "tweet should be deleted");
    eprintln!("  delete_tweet: deleted {tweet_id}");

    // ===== TEST 4: get_user_tweets (Mode C) — path param + query string =====
    eprintln!("  [4/4] get_user_tweets ...");
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "x",
            "action": "get_user_tweets",
            "params": {
                "user_id": user_id,
                "max_results": 5
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let tweets_resp: Value =
        serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    // data may be absent if the test account has no tweets — that's fine,
    // the point is that the request succeeded and the URL was built correctly.
    let tweet_count = tweets_resp["data"].as_array().map(|a| a.len()).unwrap_or(0);
    eprintln!("  get_user_tweets: {tweet_count} tweets for user {user_id}");

    eprintln!("  All X.com E2E tests passed!");
}

// --- Test 5: Non-PKCE provider (github) auth URL has no PKCE params ---

#[tokio::test]
async fn test_oauth_github_no_pkce_in_auth_url() {
    let pool = common::test_pool().await;
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_GITHUB_CLIENT_ID", "gh_client");
        std::env::set_var("OAUTH_GITHUB_CLIENT_SECRET", "gh_secret");
    }

    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, _ident_id, api_key, _) = common::bootstrap_org_identity(&base, &client).await;

    let resp: Value = client
        .post(format!("{base}/v1/connections"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "provider": "github",
            "scopes": ["repo"],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let auth_url = resp["auth_url"].as_str().unwrap();
    let state = resp["state"].as_str().unwrap();

    // Non-PKCE provider should NOT have code_challenge
    assert!(
        !auth_url.contains("code_challenge="),
        "github auth_url should not have code_challenge: {auth_url}"
    );

    // State verifier segment should be "_"
    let segments: Vec<&str> = state.splitn(6, ':').collect();
    assert_eq!(segments.len(), 6);
    assert_eq!(
        segments[4], "_",
        "github should have '_' as verifier segment"
    );
}
