//! White-label token-vault import tests (`POST /v1/connections/import`).
//!
//! These exercise the full surface of `docs/design/white-label-token-vault.md`
//! with a *fake integration partner* — the test itself plays the partner: it
//! holds already-minted OAuth tokens (the partner ran its own OAuth dance) and
//! POSTs them to `/v1/connections/import`. Overslash then stores, injects, and
//! (for self-refresh connections) would refresh them. No `redirect_uri` is ever
//! issued.
//!
//! Coverage:
//!   - integration-managed import (null BYOC): token injected on action calls
//!     until expiry, then `reauth_required` flagged integration-managed with no
//!     reconnect link — and NO refresh attempt / no org-env client fallback;
//!   - self-refresh import (pinned BYOC): `integration_managed = false`, and a
//!     missing BYOC id 400s at import time;
//!   - idempotent re-import (same identity+provider+email updates in place) vs
//!     multi-account (distinct emails create distinct connections);
//!   - `expires_at` / `expires_in` expiry resolution;
//!   - `on_behalf_of` owner binding;
//!   - input validation (`access_token` required).

// Test setup seeds rows + reads identities via direct SQL.
#![allow(clippy::disallowed_methods)]

mod common;

use serde_json::{Value, json};
use uuid::Uuid;

const CAL_SCOPE: &str = "https://www.googleapis.com/auth/calendar";

fn auth_header(key: &str) -> (&'static str, String) {
    common::auth(key)
}

async fn import(
    client: &reqwest::Client,
    base: &str,
    key: &str,
    body: Value,
) -> (reqwest::StatusCode, Value) {
    let resp = client
        .post(format!("{base}/v1/connections/import"))
        .header(auth_header(key).0, auth_header(key).1)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    (status, body)
}

/// End-to-end: import an integration-managed Google connection (no BYOC), then
/// drive a real action call through the mock upstream. A fresh token is
/// injected verbatim; once the token expires, the action call returns
/// `reauth_required` flagged `integration_managed` with no reconnect link —
/// proving Overslash never attempted a refresh nor borrowed the org/env client.
#[tokio::test]
async fn integration_managed_import_injects_then_reauths_on_expiry() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let mock_host = format!("http://{mock_addr}");

    // Point google's token endpoint at the mock so an *accidental* refresh
    // attempt would be observable (it must NOT happen for integration-managed).
    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'google'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();

    let (base, client) =
        common::start_api_with_registry(pool.clone(), Some(("google_calendar", mock_host))).await;
    let (_org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;

    for pattern in ["http:**", "google_calendar:*:*"] {
        client
            .post(format!("{base}/v1/permissions"))
            .header(auth_header(&admin_key).0, auth_header(&admin_key).1)
            .json(&json!({"identity_id": ident_id, "action_pattern": pattern}))
            .send()
            .await
            .unwrap();
    }
    common::grant_service_to_everyone(&base, &client, &admin_key, "google_calendar").await;

    // --- Import an integration-managed connection (no byoc_credential_id) ---
    let (status, body) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "vault-access-token-1",
            "scopes": [CAL_SCOPE],
            "account_email": "partner-user@example.com",
            "expires_in": 3600
        }),
    )
    .await;
    assert_eq!(status, 200, "import should succeed: {body}");
    assert_eq!(body["integration_managed"], true);
    assert_eq!(body["provider"], "google");
    assert_eq!(body["account_email"], "partner-user@example.com");
    let connection_id = body["connection_id"].as_str().unwrap().to_string();

    // GET the connection: integration-managed posture is surfaced.
    let detail: Value = client
        .get(format!("{base}/v1/connections/{connection_id}"))
        .header(auth_header(&key).0, auth_header(&key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["integration_managed"], true);
    assert_eq!(detail["credential_source"]["kind"], "integration_managed");

    // --- Action call: the vaulted token is injected verbatim ---
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth_header(&key).0, auth_header(&key).1)
        .json(&json!({
            "service": "google_calendar",
            "action": "list_events",
            "params": {"calendarId": "primary"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(
        echo["headers"]["authorization"], "Bearer vault-access-token-1",
        "integration-managed token must be injected verbatim"
    );

    // --- Re-import the same account with an already-expired token ---
    let past = (time::OffsetDateTime::now_utc() - time::Duration::hours(1)).unix_timestamp();
    let (status, _) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "vault-access-token-expired",
            "scopes": [CAL_SCOPE],
            "account_email": "partner-user@example.com",
            "expires_at": past
        }),
    )
    .await;
    assert_eq!(status, 200);

    // The same action call now returns reauth_required, flagged
    // integration-managed, with NO reconnect link — Overslash never tried to
    // refresh (it has no client) and never fell back to org/env credentials.
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth_header(&key).0, auth_header(&key).1)
        .json(&json!({
            "service": "google_calendar",
            "action": "list_events",
            "params": {"calendarId": "primary"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "expired integration-managed token must surface reauth_required"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "reauth_required");
    assert_eq!(body["integration_managed"], true);
    assert_eq!(body["provider"], "google");
    assert_eq!(body["reason"], "integration_token_expired");
    assert!(
        body.get("auth_url").is_none_or(Value::is_null),
        "integration-managed reauth must NOT carry a reconnect auth_url: {body}"
    );
    // Same connection id (re-import updated in place, no orphan row).
    assert_eq!(body["connection_id"], json!(connection_id));
}

/// Self-refresh import pins a BYOC client (`integration_managed = false`); a
/// missing BYOC id is rejected at import time, not deferred to first refresh.
#[tokio::test]
async fn self_refresh_import_validates_byoc() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (_org_id, ident_id, key, _admin_key) = common::bootstrap_org_identity(&base, &client).await;

    // Register a BYOC client (self-service, bound to the caller identity — the
    // same identity the import lands on) the partner used to mint the tokens.
    let byoc: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header(auth_header(&key).0, auth_header(&key).1)
        .json(&json!({
            "provider": "google",
            "client_id": "partner-client-id",
            "client_secret": "partner-client-secret",
            "identity_id": ident_id
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let byoc_id = byoc["id"].as_str().unwrap();

    // Valid pin → self-refresh connection.
    let (status, body) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "tok",
            "refresh_token": "refresh-tok",
            "byoc_credential_id": byoc_id,
            "scopes": [CAL_SCOPE]
        }),
    )
    .await;
    assert_eq!(status, 200, "valid byoc import should succeed: {body}");
    assert_eq!(body["integration_managed"], false);

    // Refresh mode is fixed at first import. Import an integration-managed
    // connection for a distinct account, then re-import the SAME account with a
    // BYOC pin — this must be rejected (not silently validated-then-discarded),
    // otherwise the caller would believe self-refresh is active when it isn't.
    let (status, body) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "im-tok",
            "account_email": "switch@example.com"
        }),
    )
    .await;
    assert_eq!(
        status, 200,
        "integration-managed import should succeed: {body}"
    );
    assert_eq!(body["integration_managed"], true);

    let (status, body) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "im-tok-2",
            "account_email": "switch@example.com",
            "byoc_credential_id": byoc_id
        }),
    )
    .await;
    assert_eq!(
        status, 400,
        "re-import must not silently switch refresh mode: {body}"
    );

    // Unknown pin → 400 at import time.
    let (status, body) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "tok2",
            "byoc_credential_id": Uuid::new_v4(),
        }),
    )
    .await;
    assert_eq!(status, 400, "unknown byoc id must 400: {body}");
}

/// An emailless import must never overwrite an existing *orchestrated*
/// connection that the `(identity, provider)` fallback happens to match (e.g.
/// one whose userinfo fetch left `account_email` NULL). It creates a fresh
/// vault connection instead — the orchestrated row is left untouched.
#[tokio::test]
async fn emailless_import_does_not_overwrite_orchestrated_connection() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, ident_id, key, _admin_key) = common::bootstrap_org_identity(&base, &client).await;

    // Seed an orchestrated connection (integration_managed = false, NULL email),
    // exactly what the OAuth callback would create when userinfo returns no email.
    let enc_key = overslash_core::crypto::Keyring::test();
    let orchestrated_token =
        overslash_core::crypto::encrypt(&enc_key, b"orchestrated-token").unwrap();
    let orchestrated = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: ident_id,
            provider_key: "google",
            encrypted_access_token: &orchestrated_token,
            encrypted_refresh_token: None,
            token_expires_at: None,
            scopes: &[],
            account_email: None,
            byoc_credential_id: None,
            integration_managed: false,
        })
        .await
        .unwrap();

    // Emailless integration-managed import — the fallback would match the
    // orchestrated row, but the mode differs, so it must create a new row.
    let (status, body) = import(
        &client,
        &base,
        &key,
        json!({ "provider": "google", "access_token": "vault-token" }),
    )
    .await;
    assert_eq!(status, 200, "import should succeed: {body}");
    assert_eq!(body["integration_managed"], true);
    let imported_id: Uuid = body["connection_id"].as_str().unwrap().parse().unwrap();
    assert_ne!(
        imported_id, orchestrated.id,
        "import must not reuse the orchestrated connection"
    );

    // The orchestrated row is untouched: still integration_managed = false and
    // its original (distinct) token.
    let row = sqlx::query_as::<_, (bool, Vec<u8>)>(
        "SELECT integration_managed, encrypted_access_token FROM connections WHERE id = $1",
    )
    .bind(orchestrated.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!row.0, "orchestrated connection mode must stay false");
    assert_eq!(
        row.1, orchestrated_token,
        "orchestrated connection token must be untouched"
    );

    // Two connections now exist for the provider.
    let conns: Value = client
        .get(format!("{base}/v1/connections"))
        .header(auth_header(&key).0, auth_header(&key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let google = conns
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["provider_key"] == "google")
        .count();
    assert_eq!(google, 2, "expected orchestrated + imported, got: {conns}");
}

/// `access_token` is required.
#[tokio::test]
async fn import_requires_access_token() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let (status, _) = import(
        &client,
        &base,
        &key,
        json!({ "provider": "google", "access_token": "" }),
    )
    .await;
    assert_eq!(status, 400, "empty access_token must 400");

    // Unknown provider → 404.
    let (status, _) = import(
        &client,
        &base,
        &key,
        json!({ "provider": "not_a_provider", "access_token": "x" }),
    )
    .await;
    assert_eq!(status, 404, "unknown provider must 404");
}

/// Re-import for the same (identity, provider, account_email) updates the
/// existing row in place; a *different* account_email creates a second
/// connection (multi-account vaulting).
#[tokio::test]
async fn reimport_is_idempotent_per_account() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let first: Value = {
        let (s, b) = import(
            &client,
            &base,
            &key,
            json!({
                "provider": "google",
                "access_token": "a1",
                "account_email": "a@example.com",
                "scopes": ["s1"]
            }),
        )
        .await;
        assert_eq!(s, 200);
        b
    };
    let first_id = first["connection_id"].clone();

    // Re-import same account: same connection id, scopes updated in place.
    let (s, again) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "a2",
            "account_email": "a@example.com",
            "scopes": ["s1", "s2"]
        }),
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(
        again["connection_id"], first_id,
        "re-import must update in place"
    );

    // Different account: a new connection.
    let (s, other) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "b1",
            "account_email": "b@example.com"
        }),
    )
    .await;
    assert_eq!(s, 200);
    assert_ne!(
        other["connection_id"], first_id,
        "distinct email → distinct connection"
    );

    // The list shows exactly the two connections (no duplicate from re-import).
    let conns: Value = client
        .get(format!("{base}/v1/connections"))
        .header(auth_header(&key).0, auth_header(&key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let google: Vec<&Value> = conns
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["provider_key"] == "google")
        .collect();
    assert_eq!(
        google.len(),
        2,
        "expected 2 google connections, got: {conns}"
    );
}

/// `expires_in` resolves to an absolute future expiry; `expires_at` is taken
/// verbatim as a Unix timestamp.
#[tokio::test]
async fn import_resolves_expiry_fields() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, ident_id, key, _admin_key) = common::bootstrap_org_identity(&base, &client).await;

    // expires_in → token_expires_at ≈ now + 3600s.
    let (s, _) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "tok",
            "account_email": "exp-in@example.com",
            "expires_in": 3600
        }),
    )
    .await;
    assert_eq!(s, 200);

    // expires_at (absolute unix ts) → stored verbatim.
    let absolute = (time::OffsetDateTime::now_utc() + time::Duration::days(30)).unix_timestamp();
    let (s, _) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "tok2",
            "account_email": "exp-at@example.com",
            "expires_at": absolute
        }),
    )
    .await;
    assert_eq!(s, 200);

    let rows = sqlx::query_as::<_, (String, Option<time::OffsetDateTime>)>(
        "SELECT account_email, token_expires_at FROM connections
         WHERE org_id = $1 AND identity_id = $2 AND provider_key = 'google'
         ORDER BY account_email",
    )
    .bind(org_id)
    .bind(ident_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    let by_email: std::collections::HashMap<_, _> = rows.into_iter().collect();

    let now = time::OffsetDateTime::now_utc();
    let exp_in = by_email["exp-in@example.com"].expect("expires_in sets expiry");
    assert!(
        exp_in > now + time::Duration::minutes(50) && exp_in < now + time::Duration::minutes(70),
        "expires_in should land ~1h out, got {exp_in}"
    );
    let exp_at = by_email["exp-at@example.com"].expect("expires_at sets expiry");
    assert_eq!(
        exp_at.unix_timestamp(),
        absolute,
        "expires_at stored verbatim"
    );
}

/// An agent importing `on_behalf_of` its owner user binds the connection to the
/// user identity (so every agent under the user shares it), not the agent.
#[tokio::test]
async fn import_on_behalf_of_binds_to_user() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, agent_id, key, _admin_key) = common::bootstrap_org_identity(&base, &client).await;

    // `bootstrap_org_identity` makes the agent a child of a "test-user".
    let user_id = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM identities WHERE org_id = $1 AND kind = 'user' AND name = 'test-user'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    let (status, body) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "shared-tok",
            "account_email": "shared@example.com",
            "on_behalf_of": user_id,
        }),
    )
    .await;
    assert_eq!(status, 200, "on_behalf_of import should succeed: {body}");
    let connection_id: Uuid = body["connection_id"].as_str().unwrap().parse().unwrap();

    let owner = sqlx::query_scalar::<_, Uuid>("SELECT identity_id FROM connections WHERE id = $1")
        .bind(connection_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        owner, user_id,
        "connection must bind to the owner user, not the agent"
    );
    assert_ne!(owner, agent_id);
}
