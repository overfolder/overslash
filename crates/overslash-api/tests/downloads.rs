//! Deferred downloads: `deliver: "url"` on `POST /v1/actions/call` plus
//! redemption via `GET /v1/downloads/{token}`.
//!
//! The property under test throughout is the one the feature exists for: the
//! bytes never appear in the call response. What comes back is a descriptor;
//! the file only materializes on a second, unauthenticated request.

use crate::common;

use serde_json::json;

/// Grant the agent raw-HTTP access and return `(base, api_key)`.
async fn setup(pool: sqlx::PgPool) -> (String, String, reqwest::Client, std::net::SocketAddr) {
    let mock_addr = common::start_mock().await;
    // 1 KB buffered ceiling: any test body over that proves the deferred path
    // bypasses the cap the same way `prefer_stream` does.
    let (api_addr, client) = common::start_api_with_body_limit(pool, 1024).await;
    let base = format!("http://{api_addr}");

    let (_org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "identity_id": ident_id,
            "action_pattern": "http:**",
            "effect": "allow",
        }))
        .send()
        .await
        .unwrap();

    (base, api_key, client, mock_addr)
}

#[tokio::test]
async fn deliver_url_returns_descriptor_not_bytes() {
    let pool = common::test_pool().await;
    let (base, api_key, client, mock_addr) = setup(pool).await;

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "service": "http",
            "method": "GET",
            "url": format!("http://{mock_addr}/large-file?size=102400"),
            "deliver": "url",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");

    let result: serde_json::Value =
        serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let url = result["download_url"].as_str().expect("download_url");
    assert!(
        url.starts_with(&base),
        "descriptor url should be ours: {url}"
    );
    assert!(result["expires_at"].as_str().is_some());

    // The whole point: 100 KB of payload, and the response the caller (an LLM,
    // typically) sees is a few hundred bytes with no file content in it.
    let envelope = serde_json::to_string(&body).unwrap();
    assert!(
        envelope.len() < 2048,
        "descriptor response should be tiny, was {} bytes",
        envelope.len()
    );

    // Redeem — unauthenticated, deliberately.
    let file = client.get(url).send().await.unwrap();
    assert_eq!(file.status(), 200);
    assert_eq!(
        file.headers().get("content-type").unwrap(),
        "application/octet-stream",
        "upstream content-type should be forwarded"
    );
    let bytes = file.bytes().await.unwrap();
    assert_eq!(bytes.len(), 102400, "all 100 KB, past the 1 KB buffer cap");
    assert!(bytes.iter().all(|&b| b == 0xAB));
}

#[tokio::test]
async fn download_token_is_multi_use_until_expiry() {
    let pool = common::test_pool().await;
    let (base, api_key, client, mock_addr) = setup(pool).await;

    let body: serde_json::Value = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "service": "http",
            "method": "GET",
            "url": format!("http://{mock_addr}/large-file?size=2048"),
            "deliver": "url",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let result: serde_json::Value =
        serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let url = result["download_url"].as_str().unwrap().to_string();

    // A resumed or retried transfer re-requests the same URL. Single-use would
    // turn every dropped connection into an unrecoverable failure, which for a
    // large video is the common case rather than the edge case.
    for attempt in 0..3 {
        let r = client.get(&url).send().await.unwrap();
        assert_eq!(r.status(), 200, "attempt {attempt} should still redeem");
        assert_eq!(r.bytes().await.unwrap().len(), 2048);
    }
}

#[tokio::test]
async fn expired_and_unknown_tokens_are_indistinguishable() {
    let pool = common::test_pool().await;
    let (base, api_key, client, mock_addr) = setup(pool.clone()).await;

    let body: serde_json::Value = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "service": "http",
            "method": "GET",
            "url": format!("http://{mock_addr}/large-file?size=512"),
            "deliver": "url",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let result: serde_json::Value =
        serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let url = result["download_url"].as_str().unwrap().to_string();

    assert_eq!(client.get(&url).send().await.unwrap().status(), 200);

    // Age the row out rather than sleeping through a real TTL.
    sqlx::query!("UPDATE download_tokens SET expires_at = now() - interval '1 second'")
        .execute(&pool)
        .await
        .unwrap();

    let expired = client.get(&url).send().await.unwrap();
    let unknown = client
        .get(format!("{base}/v1/downloads/definitely-not-a-real-token"))
        .send()
        .await
        .unwrap();

    // Same status for both: a distinguishable "expired" would confirm to
    // someone probing that a given token string was once real.
    assert_eq!(expired.status(), 404);
    assert_eq!(unknown.status(), 404);
}

#[tokio::test]
async fn credentials_are_resolved_at_fetch_and_never_leak() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let (api_addr, client) = common::start_api_with_body_limit(pool.clone(), 1024).await;
    let base = format!("http://{api_addr}");

    let (_org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    client
        .put(format!("{base}/v1/secrets/dl_token"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"value": "super-secret-token"}))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "identity_id": ident_id,
            "action_pattern": "http:**",
            "effect": "allow",
        }))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "service": "http",
            "method": "GET",
            "url": format!("http://{mock_addr}/large-file?size=2048"),
            "deliver": "url",
            "secrets": [{
                "name": "dl_token",
                "inject_as": "header",
                "header_name": "X-Token",
                "prefix": "Bearer "
            }]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let result: serde_json::Value =
        serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let url = result["download_url"].as_str().unwrap().to_string();

    // The token row must name the secret, never hold its value — the whole
    // reason credentials are re-resolved at fetch time instead of captured.
    let stored: String =
        sqlx::query_scalar!("SELECT request::text || credential_ref::text FROM download_tokens")
            .fetch_one(&pool)
            .await
            .unwrap()
            .expect("token row exists");
    assert!(
        !stored.contains("super-secret-token"),
        "the plaintext secret must not be persisted on the token row: {stored}"
    );
    assert!(
        stored.contains("dl_token"),
        "the token row should reference the secret by name"
    );

    // And the fetch still works, which is what proves re-resolution happened.
    let file = client.get(&url).send().await.unwrap();
    assert_eq!(file.status(), 200);
    let bytes = file.bytes().await.unwrap();
    assert_eq!(bytes.len(), 2048);
    assert!(!String::from_utf8_lossy(&bytes).contains("super-secret-token"));
}

#[tokio::test]
async fn deleting_the_secret_after_mint_fails_the_fetch_closed() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let (api_addr, client) = common::start_api_with_body_limit(pool.clone(), 1024).await;
    let base = format!("http://{api_addr}");

    let (_org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    client
        .put(format!("{base}/v1/secrets/ephemeral_token"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"value": "will-be-revoked"}))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "identity_id": ident_id,
            "action_pattern": "http:**",
            "effect": "allow",
        }))
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "service": "http",
            "method": "GET",
            "url": format!("http://{mock_addr}/large-file?size=512"),
            "deliver": "url",
            "secrets": [{
                "name": "ephemeral_token",
                "inject_as": "header",
                "header_name": "X-Token",
            }]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let result: serde_json::Value =
        serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let url = result["download_url"].as_str().unwrap().to_string();

    // Revoke between mint and redeem. Because nothing was captured, the fetch
    // has nothing to fall back on and must fail rather than serve.
    sqlx::query!("DELETE FROM secrets WHERE name = 'ephemeral_token'")
        .execute(&pool)
        .await
        .unwrap();

    let after = client.get(&url).send().await.unwrap();
    assert!(
        after.status().is_client_error() || after.status().is_server_error(),
        "revoking the secret must fail the deferred fetch closed, got {}",
        after.status()
    );
}

#[tokio::test]
async fn deliver_url_rejects_filter_and_prefer_stream() {
    let pool = common::test_pool().await;
    let (base, api_key, client, mock_addr) = setup(pool).await;
    let url = format!("http://{mock_addr}/large-file?size=512");

    // A filter has nothing to read: the body never passes through the gateway
    // at call time. Silently dropping it would let a caller believe it had
    // narrowed a response it will actually receive whole.
    let with_filter = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "service": "http", "method": "GET", "url": url,
            "deliver": "url",
            "filter": {"lang": "jq", "expr": "."},
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(with_filter.status(), 400);

    // The two flags are contradictory instructions about where bytes go.
    let with_stream = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "service": "http", "method": "GET", "url": url,
            "deliver": "url",
            "prefer_stream": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(with_stream.status(), 400);
}

#[tokio::test]
async fn inline_credential_headers_are_rejected_rather_than_persisted() {
    let pool = common::test_pool().await;
    let (base, api_key, client, mock_addr) = setup(pool.clone()).await;

    // Raw HTTP is the one shape whose headers come straight from the caller,
    // so it's the one shape that could put a plaintext credential in the token
    // row. `secrets` exists for this and works on the deferred path; an inline
    // header does not, and saying so now beats a 401 on redemption later.
    for header in ["Authorization", "x-api-key", "Cookie"] {
        let resp = client
            .post(format!("{base}/v1/actions/call"))
            .header("Authorization", format!("Bearer {api_key}"))
            .json(&json!({
                "service": "http",
                "method": "GET",
                "url": format!("http://{mock_addr}/large-file?size=512"),
                "deliver": "url",
                "headers": { header: "hunter2" },
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "`{header}` should be refused inline");
    }

    let rows = sqlx::query_scalar!("SELECT count(*) FROM download_tokens")
        .fetch_one(&pool)
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(rows, 0, "no token should have been minted");

    // A non-credential header is still fine — this is a credential guard, not
    // a blanket ban on customizing the request.
    let ok = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "service": "http",
            "method": "GET",
            "url": format!("http://{mock_addr}/large-file?size=512"),
            "deliver": "url",
            "headers": { "Accept": "application/octet-stream" },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
}

/// An OAuth-backed service must refuse deferral even when it builds no
/// `Authorization` header.
///
/// A template declaring `x-overslash-token_injection: {as: query}` resolves
/// OAuth successfully but produces `auth_header: None` — `auth_resolve.rs:133`
/// maps over `token_injection.header_name`, which is absent for query
/// injection, while `oauth_injected` stays `true`. Gating on
/// `auth_header.is_some()` therefore reads as "no credential needed" and mints
/// a token whose deferred fetch carries nothing: a URL that 401s minutes later
/// instead of an error now. The gate reads `oauth_injected` instead.
///
/// The connection has to be seeded for this to bite — without one, resolution
/// short-circuits to `needs_authentication` long before the deferred branch,
/// and the test would pass against the broken guard too.
#[tokio::test]
async fn oauth_with_query_token_injection_is_refused_not_silently_minted() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api_with_body_limit(pool.clone(), 1024).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "openapi": "openapi: 3.1.0\n\
                info:\n  title: Query OAuth Svc\n  key: queryoauth\n\
                servers:\n  - url: https://queryoauth.example.com\n\
                components:\n  securitySchemes:\n    oauth:\n      type: oauth2\n      provider: google\n      x-overslash-token_injection:\n        as: query\n        query_param: access_token\n      flows:\n        authorizationCode:\n          authorizationUrl: https://accounts.google.com/o/oauth2/v2/auth\n          tokenUrl: https://oauth2.googleapis.com/token\n          scopes:\n            openid: \"\"\n\
                security:\n  - oauth: []\n\
                paths:\n  /file:\n    get:\n      operationId: get_file\n      summary: Get file\n      risk: read\n",
            "user_level": false,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "template: {:?}", resp.text().await);

    client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "identity_id": ident_id,
            "action_pattern": "queryoauth:**",
            "effect": "allow",
        }))
        .send()
        .await
        .unwrap();

    // The group ceiling gates services independently of permission rules, and
    // the owner user is what it attaches to (not the calling agent).
    let owner_id = common::owner_user_id(&pool, org_id).await;
    let groups: serde_json::Value = client
        .get(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admins = groups
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["name"] == "Admins")
        .expect("Admins group")["id"]
        .as_str()
        .unwrap()
        .to_string();
    client
        .post(format!("{base}/v1/groups/{admins}/members"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "identity_id": owner_id }))
        .send()
        .await
        .unwrap();

    // The ceiling grants per service *instance*, so the template needs one.
    let inst: serde_json::Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "name": "queryoauth", "template_key": "queryoauth" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let inst_id = inst["id"].as_str().expect("instance id").to_string();
    client
        .post(format!("{base}/v1/groups/{admins}/grants"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "service_instance_id": inst_id, "access_level": "write" }))
        .send()
        .await
        .unwrap();

    // Org-level client credentials, or OAuth resolution refuses before the
    // deferred branch with "no OAuth client credentials configured".
    let put = client
        .put(format!("{base}/v1/org-oauth-credentials/google"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "client_id": "test_id.apps.googleusercontent.com",
            "client_secret": "GOCSPX-test_secret",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 200, "org oauth creds: {:?}", put.text().await);

    // Live, non-expired token so OAuth resolution *succeeds* and execution
    // reaches the deferred branch. Connections resolve at the owner identity
    // (D22), not the calling agent.
    let enc_key = overslash_core::crypto::Keyring::test();
    let access = overslash_core::crypto::encrypt(&enc_key, b"live_access_token").unwrap();
    sqlx::query!(
        "INSERT INTO connections (org_id, identity_id, provider_key,
         encrypted_access_token, token_expires_at, scopes, account_email)
         VALUES ($1, $2, 'google', $3, now() + interval '1 hour', $4, 'mock@example.com')",
        org_id,
        owner_id,
        &access,
        &vec!["openid".to_string()][..],
    )
    .execute(&pool)
    .await
    .unwrap();

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "service": "queryoauth",
            "action": "get_file",
            "deliver": "url",
        }))
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let body = resp.text().await.unwrap();
    assert_eq!(status, 400, "OAuth deferral must be refused: {body}");
    assert!(
        !body.contains("download_url"),
        "must not mint a credential-less capability: {body}"
    );

    let rows = sqlx::query_scalar!("SELECT count(*) FROM download_tokens")
        .fetch_one(&pool)
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(rows, 0, "no token should exist for an OAuth-backed service");
}

#[tokio::test]
async fn redemption_is_audited() {
    let pool = common::test_pool().await;
    let (base, api_key, client, mock_addr) = setup(pool.clone()).await;

    let body: serde_json::Value = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "service": "http",
            "method": "GET",
            "url": format!("http://{mock_addr}/large-file?size=512"),
            "deliver": "url",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let result: serde_json::Value =
        serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let url = result["download_url"].as_str().unwrap().to_string();

    // Minting is recorded even though no upstream call happened — otherwise a
    // deferred call would leave no trace between "agent asked" and the fetch.
    let deferred =
        sqlx::query_scalar!("SELECT count(*) FROM audit_log WHERE action = 'action.deferred'")
            .fetch_one(&pool)
            .await
            .unwrap()
            .unwrap_or(0);
    assert_eq!(deferred, 1, "mint should write an action.deferred row");

    client.get(&url).send().await.unwrap();

    let downloaded =
        sqlx::query_scalar!("SELECT count(*) FROM audit_log WHERE action = 'action.downloaded'")
            .fetch_one(&pool)
            .await
            .unwrap()
            .unwrap_or(0);
    assert_eq!(downloaded, 1, "redemption should write an audit row");
}
