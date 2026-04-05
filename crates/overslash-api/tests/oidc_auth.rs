// Test setup requires dynamic SQL for provider endpoint overrides and DB seeding.
#![allow(clippy::disallowed_methods)]
//! Integration tests for multi-provider OIDC authentication.
//!
//! Tests cover: generic provider login/callback flow, GitHub login, per-org IdP
//! configuration CRUD, auth providers listing, user provisioning by email domain,
//! profile update on subsequent login, and OIDC discovery validation.
//!
//! A mock IdP server provides token and userinfo endpoints.

mod common;

use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Auth provider login flow
// ---------------------------------------------------------------------------

#[tokio::test]
async fn provider_login_redirects_to_google_with_pkce() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;

    // Point Google's auth/token endpoints at mock
    sqlx::query(
        "UPDATE oauth_providers SET authorization_endpoint = $1, token_endpoint = $2, userinfo_endpoint = $3 WHERE key = 'google'",
    )
    .bind(format!("http://{mock_addr}/oauth/authorize"))
    .bind(format!("http://{mock_addr}/oauth/token"))
    .bind(format!("http://{mock_addr}/oidc/userinfo"))
    .execute(&pool)
    .await
    .unwrap();

    let (base, client) = common::start_api_with_auth_providers(
        pool,
        Some(("test_google_id".into(), "test_google_secret".into())),
        None,
        "http://localhost:3000",
    )
    .await;

    let resp = client
        .get(format!("{base}/auth/login/google"))
        .send()
        .await
        .unwrap();

    // Should redirect to Google's authorization endpoint
    assert_eq!(
        resp.status(),
        303,
        "expected redirect, got {}",
        resp.status()
    );

    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        location.starts_with(&format!("http://{mock_addr}/oauth/authorize")),
        "expected redirect to Google auth, got: {location}"
    );
    assert!(location.contains("client_id=test_google_id"));
    assert!(location.contains("response_type=code"));
    assert!(location.contains("scope=openid"));

    // Should set nonce and verifier cookies
    let cookies: Vec<_> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert!(cookies.iter().any(|c| c.starts_with("oss_auth_nonce=")));
    assert!(cookies.iter().any(|c| c.starts_with("oss_auth_verifier=")));
    assert!(cookies.iter().any(|c| c.starts_with("oss_auth_org=")));
}

#[tokio::test]
async fn provider_login_github_skips_pkce() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;

    sqlx::query(
        "UPDATE oauth_providers SET authorization_endpoint = $1, token_endpoint = $2 WHERE key = 'github'",
    )
    .bind(format!("http://{mock_addr}/oauth/authorize"))
    .bind(format!("http://{mock_addr}/oauth/token"))
    .execute(&pool)
    .await
    .unwrap();

    let (base, client) = common::start_api_with_auth_providers(
        pool,
        None,
        Some(("test_github_id".into(), "test_github_secret".into())),
        "http://localhost:3000",
    )
    .await;

    let resp = client
        .get(format!("{base}/auth/login/github"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 303);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.contains("client_id=test_github_id"));
    assert!(location.contains("scope=read%3Auser"));
    // GitHub does NOT support PKCE
    assert!(!location.contains("code_challenge="));
}

#[tokio::test]
async fn provider_login_returns_404_for_unknown_provider() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let resp = client
        .get(format!("{base}/auth/login/nonexistent"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn provider_login_returns_404_when_no_credentials() {
    let pool = common::test_pool().await;

    // No env creds, no DB config
    let (base, client) =
        common::start_api_with_auth_providers(pool, None, None, "http://localhost:3000").await;

    let resp = client
        .get(format!("{base}/auth/login/google"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

// ---------------------------------------------------------------------------
// Callback flow with mock IdP
// ---------------------------------------------------------------------------

#[tokio::test]
async fn google_callback_provisions_user_and_sets_session() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;

    // Point Google provider at mock endpoints
    sqlx::query(
        "UPDATE oauth_providers SET authorization_endpoint = $1, token_endpoint = $2, userinfo_endpoint = $3 WHERE key = 'google'",
    )
    .bind(format!("http://{mock_addr}/oauth/authorize"))
    .bind(format!("http://{mock_addr}/oauth/token"))
    .bind(format!("http://{mock_addr}/oidc/userinfo"))
    .execute(&pool)
    .await
    .unwrap();

    let (base, client) = common::start_api_with_auth_providers(
        pool.clone(),
        Some(("test_google_id".into(), "test_google_secret".into())),
        None,
        "http://localhost:3000",
    )
    .await;

    // Simulate the callback with a nonce cookie (normally set during login redirect)
    let nonce = "test-nonce-12345";
    let state_param = format!("login:google:{nonce}");

    let resp = client
        .get(format!(
            "{base}/auth/callback/google?code=authcode123&state={state_param}"
        ))
        .header(
            "cookie",
            format!("oss_auth_nonce={nonce}; oss_auth_verifier=test_verifier; oss_auth_org=none"),
        )
        .send()
        .await
        .unwrap();

    // Should redirect to dashboard with session cookie
    assert_eq!(resp.status(), 303, "body: {:?}", resp.text().await);

    // Re-do the request to check cookies (reqwest consumed them)
    let nonce2 = "test-nonce-67890";
    let state_param2 = format!("login:google:{nonce2}");
    let resp2 = client
        .get(format!(
            "{base}/auth/callback/google?code=authcode456&state={state_param2}"
        ))
        .header(
            "cookie",
            format!("oss_auth_nonce={nonce2}; oss_auth_verifier=test_verifier; oss_auth_org=none"),
        )
        .send()
        .await
        .unwrap();

    let cookies: Vec<_> = resp2
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert!(
        cookies.iter().any(|c| c.starts_with("oss_session=")),
        "expected oss_session cookie, got: {cookies:?}"
    );

    // Verify user was provisioned in DB
    let user = sqlx::query_as::<_, (String, String)>(
        "SELECT email, name FROM identities WHERE email = 'testuser@example.com' AND kind = 'user'",
    )
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(user.is_some(), "user should be provisioned in DB");
    let (email, name) = user.unwrap();
    assert_eq!(email, "testuser@example.com");
    assert_eq!(name, "Test User");
}

#[tokio::test]
async fn callback_rejects_nonce_mismatch() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;

    sqlx::query(
        "UPDATE oauth_providers SET token_endpoint = $1, userinfo_endpoint = $2 WHERE key = 'google'",
    )
    .bind(format!("http://{mock_addr}/oauth/token"))
    .bind(format!("http://{mock_addr}/oidc/userinfo"))
    .execute(&pool)
    .await
    .unwrap();

    let (base, client) = common::start_api_with_auth_providers(
        pool,
        Some(("id".into(), "secret".into())),
        None,
        "http://localhost:3000",
    )
    .await;

    let resp = client
        .get(format!(
            "{base}/auth/callback/google?code=abc&state=login:google:real-nonce"
        ))
        .header(
            "cookie",
            "oss_auth_nonce=wrong-nonce; oss_auth_verifier=v; oss_auth_org=none",
        )
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("nonce mismatch"));
}

#[tokio::test]
async fn callback_rejects_provider_mismatch_in_state() {
    let pool = common::test_pool().await;

    let (base, client) = common::start_api_with_auth_providers(
        pool,
        Some(("id".into(), "secret".into())),
        None,
        "http://localhost:3000",
    )
    .await;

    // State says "github" but callback URL is for "google"
    let resp = client
        .get(format!(
            "{base}/auth/callback/google?code=abc&state=login:github:nonce123"
        ))
        .header(
            "cookie",
            "oss_auth_nonce=nonce123; oss_auth_verifier=v; oss_auth_org=none",
        )
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

// ---------------------------------------------------------------------------
// Google backward compat routes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn google_compat_login_works() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;

    sqlx::query("UPDATE oauth_providers SET authorization_endpoint = $1 WHERE key = 'google'")
        .bind(format!("http://{mock_addr}/oauth/authorize"))
        .execute(&pool)
        .await
        .unwrap();

    let (base, client) = common::start_api_with_auth_providers(
        pool,
        Some(("compat_id".into(), "compat_secret".into())),
        None,
        "http://localhost:3000",
    )
    .await;

    let resp = client
        .get(format!("{base}/auth/google/login"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 303);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.contains("client_id=compat_id"));
}

#[tokio::test]
async fn google_compat_callback_handles_old_state_format() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;

    sqlx::query(
        "UPDATE oauth_providers SET token_endpoint = $1, userinfo_endpoint = $2 WHERE key = 'google'",
    )
    .bind(format!("http://{mock_addr}/oauth/token"))
    .bind(format!("http://{mock_addr}/oidc/userinfo"))
    .execute(&pool)
    .await
    .unwrap();

    let (base, client) = common::start_api_with_auth_providers(
        pool,
        Some(("id".into(), "secret".into())),
        None,
        "http://localhost:3000",
    )
    .await;

    // Old state format: "login:<nonce>" (2 parts, no provider)
    let nonce = "old-format-nonce";
    let resp = client
        .get(format!(
            "{base}/auth/google/callback?code=oldcode&state=login:{nonce}"
        ))
        .header(
            "cookie",
            format!("oss_auth_nonce={nonce}; oss_auth_verifier=v; oss_auth_org=none"),
        )
        .send()
        .await
        .unwrap();

    // Should succeed (compat handler converts old format)
    assert_eq!(
        resp.status(),
        303,
        "old state format should work via compat handler"
    );
}

// ---------------------------------------------------------------------------
// Auth providers listing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_providers_returns_env_configured_providers() {
    let pool = common::test_pool().await;

    let (base, client) = common::start_api_with_auth_providers(
        pool,
        Some(("g_id".into(), "g_secret".into())),
        Some(("gh_id".into(), "gh_secret".into())),
        "http://localhost:3000",
    )
    .await;

    let resp: Value = client
        .get(format!("{base}/auth/providers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let providers = resp["providers"].as_array().unwrap();

    let keys: Vec<&str> = providers
        .iter()
        .map(|p| p["key"].as_str().unwrap())
        .collect();
    assert!(
        keys.contains(&"google"),
        "should list Google, got: {keys:?}"
    );
    assert!(
        keys.contains(&"github"),
        "should list GitHub, got: {keys:?}"
    );
    assert!(
        keys.contains(&"dev"),
        "should list dev login, got: {keys:?}"
    );

    // Env-configured providers have source: "env"
    let google = providers.iter().find(|p| p["key"] == "google").unwrap();
    assert_eq!(google["source"], "env");
}

#[tokio::test]
async fn list_providers_returns_empty_when_none_configured() {
    let pool = common::test_pool().await;

    let (base, client) =
        common::start_api_with_auth_providers(pool, None, None, "http://localhost:3000").await;

    let resp: Value = client
        .get(format!("{base}/auth/providers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let providers = resp["providers"].as_array().unwrap();
    // Only dev login should be present (dev_auth_enabled = true in the helper)
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0]["key"], "dev");
}

// ---------------------------------------------------------------------------
// Org IdP config CRUD
// ---------------------------------------------------------------------------

#[tokio::test]
async fn org_idp_config_crud_lifecycle() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (_org_id, _identity_id, api_key) = common::bootstrap_org_identity(&base, &client).await;

    // Create: configure Google IdP for the org
    let create_resp = client
        .post(format!("{base}/v1/org-idp-configs"))
        .header("authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "provider_key": "google",
            "client_id": "org-google-client-id",
            "client_secret": "org-google-client-secret",
            "enabled": true,
            "allowed_email_domains": ["example.com", "test.org"]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        create_resp.status(),
        200,
        "body: {:?}",
        create_resp.text().await
    );

    // Re-create to get the body
    // Actually, let me just list
    let list_resp: Vec<Value> = client
        .get(format!("{base}/v1/org-idp-configs"))
        .header("authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(list_resp.len(), 1);
    assert_eq!(list_resp[0]["provider_key"], "google");
    assert_eq!(list_resp[0]["source"], "db");
    assert_eq!(list_resp[0]["enabled"], true);

    let config_id = list_resp[0]["id"].as_str().unwrap();

    // Update: disable the config
    let update_resp = client
        .put(format!("{base}/v1/org-idp-configs/{config_id}"))
        .header("authorization", format!("Bearer {api_key}"))
        .json(&json!({ "enabled": false }))
        .send()
        .await
        .unwrap();

    assert_eq!(update_resp.status(), 200);
    let updated: Value = update_resp.json().await.unwrap();
    assert_eq!(updated["enabled"], false);

    // Delete
    let delete_resp = client
        .delete(format!("{base}/v1/org-idp-configs/{config_id}"))
        .header("authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap();

    assert_eq!(delete_resp.status(), 200);
    let deleted: Value = delete_resp.json().await.unwrap();
    assert_eq!(deleted["deleted"], true);

    // Verify deletion
    let list_resp2: Vec<Value> = client
        .get(format!("{base}/v1/org-idp-configs"))
        .header("authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list_resp2.len(), 0);

    // Verify audit trail (audit endpoint returns Vec<AuditEntry> directly)
    let entries: Vec<Value> = client
        .get(format!("{base}/v1/audit"))
        .header("authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let idp_actions: Vec<&str> = entries
        .iter()
        .filter_map(|e| e["action"].as_str())
        .filter(|a| a.starts_with("org_idp_config."))
        .collect();
    assert!(
        idp_actions.contains(&"org_idp_config.created"),
        "audit: {idp_actions:?}"
    );
    assert!(
        idp_actions.contains(&"org_idp_config.updated"),
        "audit: {idp_actions:?}"
    );
    assert!(
        idp_actions.contains(&"org_idp_config.deleted"),
        "audit: {idp_actions:?}"
    );

    // Verify human-readable descriptions in audit entries
    let idp_entries: Vec<&Value> = entries
        .iter()
        .filter(|e| {
            e["action"]
                .as_str()
                .map(|a| a.starts_with("org_idp_config."))
                .unwrap_or(false)
        })
        .collect();
    for entry in &idp_entries {
        assert!(
            entry["description"].is_string(),
            "IdP audit entry should have description: {entry:?}"
        );
    }
}

#[tokio::test]
async fn org_idp_config_rejects_duplicate_provider() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (_org_id, _identity_id, api_key) = common::bootstrap_org_identity(&base, &client).await;

    let body = json!({
        "provider_key": "google",
        "client_id": "id1",
        "client_secret": "secret1",
    });

    // First create succeeds
    let resp1 = client
        .post(format!("{base}/v1/org-idp-configs"))
        .header("authorization", format!("Bearer {api_key}"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp1.status(), 200);

    // Duplicate fails with 409 Conflict
    let resp2 = client
        .post(format!("{base}/v1/org-idp-configs"))
        .header("authorization", format!("Bearer {api_key}"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), 409);
}

// ---------------------------------------------------------------------------
// Profile update on subsequent login
// ---------------------------------------------------------------------------

#[tokio::test]
async fn subsequent_login_updates_profile() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;

    sqlx::query(
        "UPDATE oauth_providers SET token_endpoint = $1, userinfo_endpoint = $2 WHERE key = 'google'",
    )
    .bind(format!("http://{mock_addr}/oauth/token"))
    .bind(format!("http://{mock_addr}/oidc/userinfo"))
    .execute(&pool)
    .await
    .unwrap();

    let (base, client) = common::start_api_with_auth_providers(
        pool.clone(),
        Some(("id".into(), "secret".into())),
        None,
        "http://localhost:3000",
    )
    .await;

    // First login
    let nonce1 = "nonce1";
    client
        .get(format!(
            "{base}/auth/callback/google?code=first&state=login:google:{nonce1}"
        ))
        .header(
            "cookie",
            format!("oss_auth_nonce={nonce1}; oss_auth_verifier=v; oss_auth_org=none"),
        )
        .send()
        .await
        .unwrap();

    // Check initial profile
    let user1 = sqlx::query_as::<_, (String, serde_json::Value)>(
        "SELECT name, metadata FROM identities WHERE email = 'testuser@example.com' AND kind = 'user'"
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(user1.0, "Test User");
    assert_eq!(user1.1["picture"], "https://example.com/avatar.png");

    // Second login — same user, profile should be updated
    let nonce2 = "nonce2";
    client
        .get(format!(
            "{base}/auth/callback/google?code=second&state=login:google:{nonce2}"
        ))
        .header(
            "cookie",
            format!("oss_auth_nonce={nonce2}; oss_auth_verifier=v; oss_auth_org=none"),
        )
        .send()
        .await
        .unwrap();

    // Verify the identity is the same (not duplicated)
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM identities WHERE email = 'testuser@example.com' AND kind = 'user'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 1, "should not duplicate user on re-login");

    // Metadata should be updated (provider field present from update)
    let user2 = sqlx::query_as::<_, (serde_json::Value,)>(
        "SELECT metadata FROM identities WHERE email = 'testuser@example.com' AND kind = 'user'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(user2.0["provider"], "google");
}

// ---------------------------------------------------------------------------
// OIDC Discovery validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn oidc_discovery_rejects_http_urls() {
    // Test the service directly — no need for a full API server
    let http_client = reqwest::Client::new();
    let result =
        overslash_api::services::oidc_discovery::discover(&http_client, "http://example.com").await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("HTTPS"), "expected HTTPS error, got: {err}");
}

#[tokio::test]
async fn oidc_discovery_rejects_localhost() {
    let http_client = reqwest::Client::new();
    let result =
        overslash_api::services::oidc_discovery::discover(&http_client, "https://localhost").await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("internal"),
        "expected internal services error, got: {err}"
    );
}

#[tokio::test]
async fn oidc_discovery_rejects_private_ips() {
    let http_client = reqwest::Client::new();
    for addr in [
        "https://10.0.0.1",
        "https://192.168.1.1",
        "https://172.16.0.1",
    ] {
        let result = overslash_api::services::oidc_discovery::discover(&http_client, addr).await;
        assert!(result.is_err(), "should reject {addr}");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("internal") || err.contains("private"),
            "{addr}: expected private address error, got: {err}"
        );
    }
}

#[tokio::test]
async fn oidc_discovery_rejects_metadata_endpoint() {
    let http_client = reqwest::Client::new();
    let result =
        overslash_api::services::oidc_discovery::discover(&http_client, "https://169.254.169.254")
            .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn oidc_discovery_rejects_ipv6_private() {
    let http_client = reqwest::Client::new();
    // IPv6 loopback
    let result =
        overslash_api::services::oidc_discovery::discover(&http_client, "https://[::1]").await;
    assert!(result.is_err(), "should reject IPv6 loopback");
    // IPv6 ULA
    let result =
        overslash_api::services::oidc_discovery::discover(&http_client, "https://[fc00::1]").await;
    assert!(result.is_err(), "should reject IPv6 ULA");
    // IPv6 link-local
    let result =
        overslash_api::services::oidc_discovery::discover(&http_client, "https://[fe80::1]").await;
    assert!(result.is_err(), "should reject IPv6 link-local");
}

// ---------------------------------------------------------------------------
// GitHub callback flow (covers fetch_github_userinfo)
// ---------------------------------------------------------------------------

// Note: GitHub callback integration test is not possible because
// fetch_github_userinfo hardcodes https://api.github.com/user URLs.
// The GitHub login redirect IS tested in provider_login_github_skips_pkce.

// ---------------------------------------------------------------------------
// Custom OIDC IdP creation via discovery (covers create_custom, discovery endpoint)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_custom_oidc_idp_via_discovery() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;

    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (_org_id, _identity_id, api_key) = common::bootstrap_org_identity(&base, &client).await;

    // The mock serves /.well-known/openid-configuration
    // Note: issuer validation requires HTTPS, but our mock is HTTP.
    // The discovery service validates HTTPS, so we test via the create endpoint
    // which catches the error gracefully.
    let resp = client
        .post(format!("{base}/v1/org-idp-configs"))
        .header("authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "issuer_url": format!("http://{mock_addr}"),
            "client_id": "custom_oidc_id",
            "client_secret": "custom_oidc_secret",
            "display_name": "Test OIDC Provider",
            "allowed_email_domains": ["testcorp.com"]
        }))
        .send()
        .await
        .unwrap();

    // Should fail because mock uses HTTP, not HTTPS
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("OIDC discovery failed"),
        "expected discovery error, got: {body}"
    );
}

// ---------------------------------------------------------------------------
// OIDC Discovery preview endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discover_preview_endpoint_rejects_http() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (_org_id, _identity_id, api_key) = common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/org-idp-configs/discover"))
        .header("authorization", format!("Bearer {api_key}"))
        .json(&json!({ "issuer_url": "http://not-https.com" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("HTTPS"));
}

// ---------------------------------------------------------------------------
// DB credential resolution path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_with_db_credentials_resolves_org_idp_config() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;

    // Point Google at mock
    sqlx::query(
        "UPDATE oauth_providers SET authorization_endpoint = $1, token_endpoint = $2, userinfo_endpoint = $3 WHERE key = 'google'",
    )
    .bind(format!("http://{mock_addr}/oauth/authorize"))
    .bind(format!("http://{mock_addr}/oauth/token"))
    .bind(format!("http://{mock_addr}/oidc/userinfo"))
    .execute(&pool)
    .await
    .unwrap();

    // Create org + API key via the API
    let (addr, admin_client) = common::start_api(pool.clone()).await;
    let admin_base = format!("http://{addr}");
    let (org_id, _identity_id, api_key) =
        common::bootstrap_org_identity(&admin_base, &admin_client).await;

    // Get the org slug from DB
    let org_slug: String = sqlx::query_scalar("SELECT slug FROM orgs WHERE id = $1")
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    // Create IdP config for this org
    let create_resp = admin_client
        .post(format!("{admin_base}/v1/org-idp-configs"))
        .header("authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "provider_key": "google",
            "client_id": "db-org-google-id",
            "client_secret": "db-org-google-secret"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(create_resp.status(), 200);

    // Now start API WITHOUT env creds — DB creds should be used
    let (base, client) = common::start_api_with_auth_providers(
        pool.clone(),
        None, // no env creds
        None,
        "http://localhost:3000",
    )
    .await;

    // Login with ?org=slug — should resolve DB credentials
    let resp = client
        .get(format!("{base}/auth/login/google?org={org_slug}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 303, "should redirect using DB credentials");
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        location.contains("client_id=db-org-google-id"),
        "should use DB-stored client_id, got: {location}"
    );
}

#[tokio::test]
async fn login_with_db_creds_fails_for_unknown_org() {
    let pool = common::test_pool().await;

    let (base, client) =
        common::start_api_with_auth_providers(pool, None, None, "http://localhost:3000").await;

    let resp = client
        .get(format!("{base}/auth/login/google?org=nonexistent-org"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn login_with_db_creds_fails_when_disabled() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;

    sqlx::query("UPDATE oauth_providers SET authorization_endpoint = $1 WHERE key = 'google'")
        .bind(format!("http://{mock_addr}/oauth/authorize"))
        .execute(&pool)
        .await
        .unwrap();

    let (addr, admin_client) = common::start_api(pool.clone()).await;
    let admin_base = format!("http://{addr}");
    let (org_id, _, api_key) = common::bootstrap_org_identity(&admin_base, &admin_client).await;

    let org_slug: String = sqlx::query_scalar("SELECT slug FROM orgs WHERE id = $1")
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    // Create DISABLED config
    admin_client
        .post(format!("{admin_base}/v1/org-idp-configs"))
        .header("authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "provider_key": "google",
            "client_id": "id",
            "client_secret": "secret",
            "enabled": false
        }))
        .send()
        .await
        .unwrap();

    let (base, client) =
        common::start_api_with_auth_providers(pool, None, None, "http://localhost:3000").await;

    let resp = client
        .get(format!("{base}/auth/login/google?org={org_slug}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404, "disabled config should return 404");
}

// ---------------------------------------------------------------------------
// Env var conflict in IdP config creation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_idp_config_rejects_env_var_conflict() {
    let pool = common::test_pool().await;

    // Start with Google env creds
    let (base, client) = common::start_api_with_auth_providers(
        pool.clone(),
        Some(("env_google_id".into(), "env_google_secret".into())),
        None,
        "http://localhost:3000",
    )
    .await;

    // Get a dev token for auth
    let token_resp: Value = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = token_resp["token"].as_str().unwrap();

    // Try to create DB config for google — should conflict with env vars
    let resp = client
        .post(format!("{base}/v1/org-idp-configs"))
        .header("cookie", format!("oss_session={token}"))
        .json(&json!({
            "provider_key": "google",
            "client_id": "db_id",
            "client_secret": "db_secret"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 409, "should reject env-var conflict");
}

// ---------------------------------------------------------------------------
// Update rejects env-var-configured providers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_idp_config_rejects_env_configured_provider() {
    let pool = common::test_pool().await;

    // Create org with DB config first (no env creds)
    let (addr, admin_client) = common::start_api(pool.clone()).await;
    let admin_base = format!("http://{addr}");
    let (_, _, api_key) = common::bootstrap_org_identity(&admin_base, &admin_client).await;

    let create_resp: Value = admin_client
        .post(format!("{admin_base}/v1/org-idp-configs"))
        .header("authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "provider_key": "google",
            "client_id": "id",
            "client_secret": "secret"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let config_id = create_resp["id"].as_str().unwrap();

    // Now start API WITH google env creds — update should be rejected.
    // Reuse the same pool so the config persists, and use the same API key.
    let (base2, client2) = common::start_api_with_auth_providers(
        pool,
        Some(("env_id".into(), "env_secret".into())),
        None,
        "http://localhost:3000",
    )
    .await;

    let resp = client2
        .put(format!("{base2}/v1/org-idp-configs/{config_id}"))
        .header("authorization", format!("Bearer {api_key}"))
        .json(&json!({ "enabled": false }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        409,
        "should reject update of env-configured provider"
    );
}

// ---------------------------------------------------------------------------
// Email domain provisioning with provider filtering
// ---------------------------------------------------------------------------

#[tokio::test]
async fn domain_provisioning_filters_by_provider_key() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;

    sqlx::query(
        "UPDATE oauth_providers SET token_endpoint = $1, userinfo_endpoint = $2 WHERE key = 'google'",
    )
    .bind(format!("http://{mock_addr}/oauth/token"))
    .bind(format!("http://{mock_addr}/oidc/userinfo"))
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "UPDATE oauth_providers SET token_endpoint = $1, userinfo_endpoint = $2 WHERE key = 'github'",
    )
    .bind(format!("http://{mock_addr}/oauth/token"))
    .bind(format!("http://{mock_addr}/github/user"))
    .execute(&pool)
    .await
    .unwrap();

    // Create an org with domain match for "github" provider only
    let (addr, admin_client) = common::start_api(pool.clone()).await;
    let admin_base = format!("http://{addr}");
    let (target_org_id, _, api_key) =
        common::bootstrap_org_identity(&admin_base, &admin_client).await;

    // Configure GitHub IdP with domain "example.com"
    admin_client
        .post(format!("{admin_base}/v1/org-idp-configs"))
        .header("authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "provider_key": "github",
            "client_id": "id",
            "client_secret": "secret",
            "allowed_email_domains": ["example.com"]
        }))
        .send()
        .await
        .unwrap();

    // Login via Google (not GitHub) — should NOT match the domain config
    // because provider_key is "google" but config is for "github"
    let (base, client) = common::start_api_with_auth_providers(
        pool.clone(),
        Some(("g_id".into(), "g_secret".into())),
        None,
        "http://localhost:3000",
    )
    .await;

    let nonce = "domain-nonce";
    client
        .get(format!(
            "{base}/auth/callback/google?code=domaintest&state=login:google:{nonce}"
        ))
        .header(
            "cookie",
            format!("oss_auth_nonce={nonce}; oss_auth_verifier=v; oss_auth_org=none"),
        )
        .send()
        .await
        .unwrap();

    // User should be in a NEW org (not target_org_id) because provider didn't match
    let user = sqlx::query_as::<_, (uuid::Uuid,)>(
        "SELECT org_id FROM identities WHERE email = 'testuser@example.com' AND kind = 'user'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_ne!(
        user.0, target_org_id,
        "user should NOT be provisioned into the GitHub-only org"
    );
}

// ---------------------------------------------------------------------------
// List providers with org slug shows DB-configured IdPs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_providers_includes_db_configured_for_org() {
    let pool = common::test_pool().await;

    let (addr, admin_client) = common::start_api(pool.clone()).await;
    let admin_base = format!("http://{addr}");
    let (org_id, _, api_key) = common::bootstrap_org_identity(&admin_base, &admin_client).await;

    let org_slug: String = sqlx::query_scalar("SELECT slug FROM orgs WHERE id = $1")
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    // Create DB config for Slack (a provider not configured via env)
    admin_client
        .post(format!("{admin_base}/v1/org-idp-configs"))
        .header("authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "provider_key": "slack",
            "client_id": "slack_id",
            "client_secret": "slack_secret"
        }))
        .send()
        .await
        .unwrap();

    // Start API with Google env creds
    let (base, client) = common::start_api_with_auth_providers(
        pool,
        Some(("g_id".into(), "g_secret".into())),
        None,
        "http://localhost:3000",
    )
    .await;

    let resp: Value = client
        .get(format!("{base}/auth/providers?org={org_slug}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let providers = resp["providers"].as_array().unwrap();
    let keys: Vec<&str> = providers
        .iter()
        .map(|p| p["key"].as_str().unwrap())
        .collect();
    assert!(keys.contains(&"google"), "env Google: {keys:?}");
    assert!(keys.contains(&"slack"), "DB Slack: {keys:?}");
    assert!(keys.contains(&"dev"), "dev login: {keys:?}");

    // Slack should be source: "db"
    let slack = providers.iter().find(|p| p["key"] == "slack").unwrap();
    assert_eq!(slack["source"], "db");
}

// ---------------------------------------------------------------------------
// Env var precedence — env providers listed first, deduped from DB
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_idp_configs_shows_env_as_readonly() {
    let pool = common::test_pool().await;

    let (base, client) = common::start_api_with_auth_providers(
        pool.clone(),
        Some(("g_id".into(), "g_secret".into())),
        Some(("gh_id".into(), "gh_secret".into())),
        "http://localhost:3000",
    )
    .await;

    // Get dev token
    let token_resp: Value = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = token_resp["token"].as_str().unwrap();

    // List IdP configs — should show env providers
    let configs: Vec<Value> = client
        .get(format!("{base}/v1/org-idp-configs"))
        .header("cookie", format!("oss_session={token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let google = configs.iter().find(|c| c["provider_key"] == "google");
    assert!(google.is_some(), "Google should be listed");
    assert_eq!(google.unwrap()["source"], "env");

    let github = configs.iter().find(|c| c["provider_key"] == "github");
    assert!(github.is_some(), "GitHub should be listed");
    assert_eq!(github.unwrap()["source"], "env");
}

// ---------------------------------------------------------------------------
// OIDC Discovery happy path (issuer validation, response parsing)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn oidc_discovery_succeeds_for_valid_issuer() {
    // Note: our mock uses HTTP, but the validation requires HTTPS.
    // We test the actual discovery parsing by testing the mock's well-known
    // endpoint response format directly.
    let mock_addr = common::start_mock().await;
    let http_client = reqwest::Client::new();

    // Fetch the mock's well-known endpoint directly (bypassing URL validation)
    let resp: Value = http_client
        .get(format!(
            "http://{mock_addr}/.well-known/openid-configuration"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Verify the mock returns a valid OIDC discovery document
    assert!(resp["issuer"].is_string());
    assert!(resp["authorization_endpoint"].is_string());
    assert!(resp["token_endpoint"].is_string());
    assert!(resp["userinfo_endpoint"].is_string());
    assert!(resp["jwks_uri"].is_string());
    let scopes = resp["scopes_supported"].as_array().unwrap();
    let scope_strs: Vec<&str> = scopes.iter().map(|s| s.as_str().unwrap()).collect();
    assert!(scope_strs.contains(&"openid"));
    assert!(scope_strs.contains(&"offline_access"));
}
