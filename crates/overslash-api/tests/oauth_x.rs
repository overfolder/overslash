//! X.com (Twitter) OAuth integration tests — callback, BYOC, token refresh, PKCE.
//! Includes a real API test (env-gated) that posts a tweet and deletes it.

mod common;

use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

// --- Test 1: Callback exchanges code and stores connection ---

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_oauth_x_callback_stores_connection(pool: PgPool) {
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
    let (org_id, ident_id, api_key) = common::bootstrap_org_identity(&base, &client).await;

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

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_oauth_x_callback_with_byoc(pool: PgPool) {
    let mock_addr = common::start_mock().await;

    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'x'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();

    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key) = common::bootstrap_org_identity(&base, &client).await;

    // Create org-level BYOC credential for X
    let byoc: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "provider": "x",
            "client_id": "x_byoc_client_id",
            "client_secret": "x_byoc_client_secret",
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
    let conn = overslash_db::repos::connection::get_by_id(&pool, conn_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(conn.byoc_credential_id.unwrap().to_string(), byoc_id);
}

// --- Test 3: Token refresh for expired X connection ---

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_oauth_x_token_refresh(pool: PgPool) {
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

    let conn = overslash_db::repos::connection::create(
        &pool,
        &overslash_db::repos::connection::CreateConnection {
            org_id: org.id,
            identity_id: ident.id,
            provider_key: "x",
            encrypted_access_token: &enc_access,
            encrypted_refresh_token: Some(&enc_refresh),
            token_expires_at: Some(expired_at),
            scopes: &[],
            account_email: None,
            byoc_credential_id: None,
        },
    )
    .await
    .unwrap();

    // Resolve should trigger a refresh
    let http_client = reqwest::Client::new();
    let new_token = overslash_api::services::oauth::resolve_access_token(
        &pool,
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
    let updated = overslash_db::repos::connection::get_by_id(&pool, conn.id)
        .await
        .unwrap()
        .unwrap();
    assert!(updated.token_expires_at.unwrap() > time::OffsetDateTime::now_utc());
}

// --- Test 4: PKCE parameters in auth URL ---

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_oauth_x_pkce_in_auth_url(pool: PgPool) {
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_pkce_client");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_pkce_secret");
    }

    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, _ident_id, api_key) = common::bootstrap_org_identity(&base, &client).await;

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

#[ignore] // Write test: posts/deletes real tweet on X.com. Run with --ignored.
#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_x_real_post_and_delete(pool: PgPool) {
    // Skip if required env vars are not set
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

    // Start API with real service registry
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, ident_id, key) = common::bootstrap_org_identity(&base, &client).await;

    // Store BYOC credential
    let byoc_resp: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header(common::auth(&key).0, common::auth(&key).1)
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

    let conn = overslash_db::repos::connection::create(
        &pool,
        &overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: ident_id,
            provider_key: "x",
            encrypted_access_token: &encrypted_access,
            encrypted_refresh_token: encrypted_refresh.as_deref(),
            token_expires_at: Some(expires_at),
            scopes: &[],
            account_email: None,
            byoc_credential_id: Some(byoc_id),
        },
    )
    .await
    .unwrap();

    // Create broad permission rule
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "http:**"}))
        .send()
        .await
        .unwrap();

    // ===== TEST 1: get_me (Mode B) =====
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "connection": conn.id.to_string(),
            "method": "GET",
            "url": "https://api.x.com/2/users/me"
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
        "get_me should return username"
    );
    let username = me["data"]["username"].as_str().unwrap();
    eprintln!("  get_me: @{username}");

    // ===== TEST 2: post_tweet (Mode B) — reply to @grok =====
    let tweet_text = format!(
        "@grok overslash integration test {} — will be deleted",
        time::OffsetDateTime::now_utc().unix_timestamp()
    );
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "connection": conn.id.to_string(),
            "method": "POST",
            "url": "https://api.x.com/2/tweets",
            "body": serde_json::to_string(&json!({"text": tweet_text})).unwrap()
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

    // ===== TEST 3: delete_tweet (Mode B) =====
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "connection": conn.id.to_string(),
            "method": "DELETE",
            "url": format!("https://api.x.com/2/tweets/{tweet_id}")
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
    eprintln!("  All X.com real tests passed!");
}

// --- Test 5: Non-PKCE provider (github) auth URL has no PKCE params ---

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_oauth_github_no_pkce_in_auth_url(pool: PgPool) {
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_GITHUB_CLIENT_ID", "gh_client");
        std::env::set_var("OAUTH_GITHUB_CLIENT_SECRET", "gh_secret");
    }

    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, _ident_id, api_key) = common::bootstrap_org_identity(&base, &client).await;

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
    let segments: Vec<&str> = state.splitn(5, ':').collect();
    assert_eq!(segments.len(), 5);
    assert_eq!(
        segments[4], "_",
        "github should have '_' as verifier segment"
    );
}
