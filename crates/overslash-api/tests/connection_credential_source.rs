//! Integration tests for the `credential_source` field on
//! `GET /v1/connections/{id}` and for the soft-pin fallback behaviour of
//! `client_credentials::resolve()` when a connection's stored BYOC has been
//! deleted out from under it.

#![allow(clippy::disallowed_methods)]

mod common;

use overslash_core::crypto;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// Register a fresh `oauth_providers` row so connections / BYOC / org-secret
/// inserts referencing it don't trip the FK. Using a per-test provider key
/// keeps the env-var-globals from one test out of another's cascade.
async fn seed_provider(pool: &PgPool, key: &str) {
    sqlx::query(
        "INSERT INTO oauth_providers
         (key, display_name, authorization_endpoint, token_endpoint)
         VALUES ($1, $1, 'https://example.test/authorize', 'https://example.test/token')
         ON CONFLICT (key) DO NOTHING",
    )
    .bind(key)
    .execute(pool)
    .await
    .unwrap();
}

/// Seed a connection that points at an optional BYOC credential. Mirrors the
/// helper in `oauth_connections_ux.rs` but adds the `byoc_credential_id`
/// column — necessary for exercising the BYOC tiers of `describe_source`.
async fn seed_connection_with_byoc(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    provider_key: &str,
    byoc_credential_id: Option<Uuid>,
) -> Uuid {
    let enc_key = crypto::Keyring::test();
    let access = crypto::encrypt(&enc_key, b"mock_access_token").unwrap();
    let scopes: Vec<String> = vec!["openid".into()];
    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO connections (org_id, identity_id, provider_key,
         encrypted_access_token, scopes, account_email, byoc_credential_id, is_default)
         VALUES ($1, $2, $3, $4, $5, $6, $7,
                 NOT EXISTS (
                     SELECT 1 FROM connections
                     WHERE identity_id = $2 AND provider_key = $3 AND is_default
                 )) RETURNING id",
    )
    .bind(org_id)
    .bind(identity_id)
    .bind(provider_key)
    .bind(&access)
    .bind(&scopes)
    .bind(Option::<&str>::None)
    .bind(byoc_credential_id)
    .fetch_one(pool)
    .await
    .unwrap();
    row.0
}

/// Seed a BYOC credential row directly. Bypasses the public API to avoid
/// pulling in identity-bound API-key plumbing the source-kind tests don't
/// need.
async fn seed_byoc(pool: &PgPool, org_id: Uuid, identity_id: Uuid, provider_key: &str) -> Uuid {
    let enc_key = crypto::Keyring::test();
    let client_id_enc = crypto::encrypt(&enc_key, b"fake-client-id").unwrap();
    let client_secret_enc = crypto::encrypt(&enc_key, b"fake-client-secret").unwrap();
    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO byoc_credentials
         (org_id, identity_id, provider_key, encrypted_client_id, encrypted_client_secret)
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(org_id)
    .bind(identity_id)
    .bind(provider_key)
    .bind(&client_id_enc)
    .bind(&client_secret_enc)
    .fetch_one(pool)
    .await
    .unwrap();
    row.0
}

/// Helper: GET /v1/connections/{id} and extract `credential_source.kind`.
async fn get_source_kind(base: &str, client: &reqwest::Client, api_key: &str, id: Uuid) -> Value {
    let detail: Value = client
        .get(format!("{base}/v1/connections/{id}"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    detail["credential_source"].clone()
}

#[tokio::test]
async fn credential_source_byoc_when_row_present() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    seed_provider(&pool, "credsrc-byoc-a").await;
    let byoc_id = seed_byoc(&pool, org_id, ident_id, "credsrc-byoc-a").await;
    let conn_id =
        seed_connection_with_byoc(&pool, org_id, ident_id, "credsrc-byoc-a", Some(byoc_id)).await;

    let source = get_source_kind(&base, &client, &api_key, conn_id).await;
    assert_eq!(source["kind"], "byoc", "source: {source}");
}

#[tokio::test]
async fn credential_source_org_secret_when_org_secrets_set() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    seed_provider(&pool, "credsrc-org-b").await;
    // Use the public endpoint to write both OAUTH_*_CLIENT_ID/_SECRET secrets.
    let resp = client
        .put(format!("{base}/v1/org-oauth-credentials/credsrc-org-b"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&serde_json::json!({
            "client_id": "org-id-value",
            "client_secret": "org-secret-value",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let conn_id = seed_connection_with_byoc(&pool, org_id, ident_id, "credsrc-org-b", None).await;

    let source = get_source_kind(&base, &client, &api_key, conn_id).await;
    assert_eq!(source["kind"], "org_secret", "source: {source}");
}

#[tokio::test]
async fn credential_source_after_pinned_byoc_deleted() {
    // FK `connections.byoc_credential_id ON DELETE SET NULL` auto-clears the
    // pin when the BYOC row is deleted, so the cascade just continues. With
    // no other tier configured for this provider, the connection now reports
    // `missing` — the dashboard escalates that to "next refresh will fail".
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    seed_provider(&pool, "credsrc-fb-c").await;
    let byoc_id = seed_byoc(&pool, org_id, ident_id, "credsrc-fb-c").await;
    let conn_id =
        seed_connection_with_byoc(&pool, org_id, ident_id, "credsrc-fb-c", Some(byoc_id)).await;

    sqlx::query("DELETE FROM byoc_credentials WHERE id = $1")
        .bind(byoc_id)
        .execute(&pool)
        .await
        .unwrap();

    // FK should have cleared the pin on the connection row.
    let pin: Option<Uuid> =
        sqlx::query_scalar("SELECT byoc_credential_id FROM connections WHERE id = $1")
            .bind(conn_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        pin.is_none(),
        "FK ON DELETE SET NULL should clear the pin (got {pin:?})"
    );

    let source = get_source_kind(&base, &client, &api_key, conn_id).await;
    assert_eq!(source["kind"], "missing", "source: {source}");
}

#[tokio::test]
async fn credential_source_system_when_env_vars_set() {
    // Env vars are process-global; use a unique provider key so this test
    // doesn't interfere with the org-secret / missing tests when run under
    // `--test-threads=4`. The same pattern is used in `org_oauth_credentials.rs`.
    // SAFETY: required by the modern `set_var` signature — the test harness
    // is single-process and the unique key avoids cross-test contention.
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_CREDSRCSYSX_CLIENT_ID", "env-id");
        std::env::set_var("OAUTH_CREDSRCSYSX_CLIENT_SECRET", "env-secret");
    }

    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Provider key in the DB is lowercase; the env-var scheme uppercases it.
    seed_provider(&pool, "credsrcsysx").await;
    let conn_id = seed_connection_with_byoc(&pool, org_id, ident_id, "credsrcsysx", None).await;

    let source = get_source_kind(&base, &client, &api_key, conn_id).await;

    // Clean up before asserting so a failure doesn't leak env into the next test.
    unsafe {
        std::env::remove_var("OAUTH_CREDSRCSYSX_CLIENT_ID");
        std::env::remove_var("OAUTH_CREDSRCSYSX_CLIENT_SECRET");
    }

    assert_eq!(source["kind"], "system", "source: {source}");
}

#[tokio::test]
async fn credential_source_missing_when_nothing_configured() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    seed_provider(&pool, "credsrc-missing-d").await;
    let conn_id =
        seed_connection_with_byoc(&pool, org_id, ident_id, "credsrc-missing-d", None).await;

    let source = get_source_kind(&base, &client, &api_key, conn_id).await;
    assert_eq!(source["kind"], "missing", "source: {source}");
}

#[tokio::test]
async fn resolve_soft_pin_falls_back_when_byoc_id_is_dangling() {
    // The DB FK `connections.byoc_credential_id ON DELETE SET NULL` normally
    // prevents a real dangling reference, but `resolve()` should still be
    // robust if it ever encounters one (cross-org filter mismatch, manual
    // schema repair, an old replica). The soft-pin change makes it fall
    // through the cascade instead of erroring. Construct a `ConnectionRow`
    // in-memory pointing at a UUID that doesn't exist, then call `resolve()`
    // directly and check it lands on the org-secret tier — exercising the
    // tier-1a branch which is otherwise unreachable through DB-mediated tests.
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, _api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    seed_provider(&pool, "credsrc-fb-e").await;
    let resp = client
        .put(format!("{base}/v1/org-oauth-credentials/credsrc-fb-e"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&serde_json::json!({
            "client_id": "fb-org-id",
            "client_secret": "fb-org-secret",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let dangling = overslash_db::repos::connection::ConnectionRow {
        id: Uuid::new_v4(),
        org_id,
        identity_id: ident_id,
        provider_key: "credsrc-fb-e".to_string(),
        encrypted_access_token: vec![0u8; 1],
        encrypted_refresh_token: None,
        token_expires_at: None,
        scopes: Some(vec![]),
        account_email: None,
        byoc_credential_id: Some(Uuid::new_v4()),
        is_default: true,
        integration_managed: false,
        created_at: time::OffsetDateTime::now_utc(),
        updated_at: time::OffsetDateTime::now_utc(),
    };

    let enc_key = crypto::Keyring::test();
    let creds = overslash_api::services::client_credentials::resolve(
        &pool,
        &enc_key,
        org_id,
        Some(ident_id),
        "credsrc-fb-e",
        Some(&dangling),
        None,
    )
    .await
    .expect("resolve should fall through the cascade, not error");

    assert_eq!(creds.client_id, "fb-org-id");
    assert_eq!(creds.client_secret, "fb-org-secret");
    assert!(creds.byoc_credential_id.is_none());
}

#[tokio::test]
async fn resolve_explicit_pin_still_errors_when_missing() {
    // The explicit `pinned_byoc_id` argument keeps its hard-pin semantics —
    // a caller that named a specific credential gets a clear error rather
    // than a silent credential switch.
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, _api_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    seed_provider(&pool, "credsrc-fb-f").await;
    let enc_key = crypto::Keyring::test();
    let result = overslash_api::services::client_credentials::resolve(
        &pool,
        &enc_key,
        org_id,
        Some(ident_id),
        "credsrc-fb-f",
        None,
        Some(Uuid::new_v4()),
    )
    .await;
    let err = match result {
        Ok(_) => panic!("explicit pin should still error when the BYOC is missing"),
        Err(e) => e,
    };
    assert!(
        format!("{err:?}").contains("pinned BYOC credential"),
        "expected hard-pin error, got: {err:?}"
    );
}
