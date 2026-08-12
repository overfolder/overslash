//! White-label token-vault import tests (`POST /v1/connections/import`).
//!
//! These exercise the import surface of `docs/design/white-label-token-vault.md`
//! with a *fake integration partner* — the test itself plays the partner: it
//! holds already-minted OAuth tokens (the partner ran its own OAuth dance) and
//! POSTs them to `/v1/connections/import`. Overslash then stores, injects, and
//! self-refreshes them via the **required** pinned BYOC client. No `redirect_uri`
//! is ever issued.
//!
//! Every import now pins a `byoc_credential_id` (the no-client "integration-
//! managed" mode was removed): a null pin 400s. URL-less auth-recovery for
//! headless orgs is covered separately in `headless_oauth.rs`.
//!
//! Coverage:
//!   - import requires a `byoc_credential_id` (400 when null) and validates it
//!     (404 provider / 400 unknown pin / 400 empty access_token);
//!   - imported tokens are injected verbatim on action calls;
//!   - idempotent re-import (same identity+provider+email updates in place) vs
//!     multi-account (distinct emails create distinct connections);
//!   - `expires_at` / `expires_in` expiry resolution and preservation on
//!     token-only re-import; scope preservation on re-import;
//!   - `on_behalf_of` owner binding;
//!   - `upgrade_scopes` is rejected for headless orgs.

// Test setup seeds rows + reads identities via direct SQL.
#![allow(clippy::disallowed_methods)]

use crate::common;

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

/// Register a self-service BYOC client bound to `ident_id` and return its id.
/// Every import pins one — Overslash self-refreshes via the pinned client.
async fn register_byoc(client: &reqwest::Client, base: &str, key: &str, ident_id: Uuid) -> String {
    let byoc: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header(auth_header(key).0, auth_header(key).1)
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
    byoc["id"].as_str().unwrap().to_string()
}

/// End-to-end: import a Google connection pinned to a BYOC client, then drive a
/// real action call through the mock upstream. The vaulted token is injected
/// verbatim (it is still valid, so no refresh fires).
#[tokio::test]
async fn import_injects_token_verbatim() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let mock_host = format!("http://{mock_addr}");

    let (base, client) =
        common::start_api_with_registry(pool.clone(), Some(("google_calendar", mock_host))).await;
    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    // Connections resolve at the owner identity (D22), so the agent must import
    // its shared connection `on_behalf_of` its owner user — exactly how a
    // white-label partner (Overfolder) binds connections — for the agent's own
    // action call below to resolve it.
    let owner_id = common::owner_user_id(&pool, org_id).await;

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

    let byoc_id = register_byoc(&client, &base, &key, ident_id).await;

    let (status, body) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "vault-access-token-1",
            "refresh_token": "vault-refresh-1",
            "byoc_credential_id": byoc_id,
            "scopes": [CAL_SCOPE],
            "account_email": "partner-user@example.com",
            "expires_in": 3600,
            "on_behalf_of": owner_id,
        }),
    )
    .await;
    assert_eq!(status, 200, "import should succeed: {body}");
    assert_eq!(body["provider"], "google");
    assert_eq!(body["account_email"], "partner-user@example.com");
    // No `integration_managed` discriminator on the response anymore.
    assert!(
        body.get("integration_managed").is_none(),
        "integration_managed must not appear on the import response: {body}"
    );

    // The vaulted token is injected verbatim on the action call.
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
        "imported token must be injected verbatim"
    );
}

/// An import that omits `scopes` records `null` (unknown), and the scope-gate
/// gives such a connection the benefit of the doubt — a scope-gated action call
/// is injected and executes rather than 403ing.
#[tokio::test]
async fn import_without_scopes_gets_benefit_of_the_doubt() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let mock_host = format!("http://{mock_addr}");

    let (base, client) =
        common::start_api_with_registry(pool.clone(), Some(("google_calendar", mock_host))).await;
    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    // Connections resolve at the owner identity (D22), so the agent must import
    // its shared connection `on_behalf_of` its owner user — exactly how a
    // white-label partner (Overfolder) binds connections — for the agent's own
    // action call below to resolve it.
    let owner_id = common::owner_user_id(&pool, org_id).await;

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

    let byoc_id = register_byoc(&client, &base, &key, ident_id).await;

    // Import with NO scopes declared → recorded as null (unknown).
    let (status, body) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "vault-token",
            "byoc_credential_id": byoc_id,
            "account_email": "unknown-scopes@example.com",
            "on_behalf_of": owner_id,
        }),
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        body["scopes"].is_null(),
        "omitted scopes must be recorded as null, not []: {body}"
    );

    // The scope-gated action call is given the benefit of the doubt and executes.
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
        200,
        "unknown scopes must not 403 — benefit of the doubt"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
}

/// Import requires a `byoc_credential_id`: a null pin is rejected with 400, an
/// unknown pin is rejected with 400, and the pin is validated at import time
/// (not deferred to first refresh).
#[tokio::test]
async fn import_requires_and_validates_byoc() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (_org_id, ident_id, key, _admin_key) = common::bootstrap_org_identity(&base, &client).await;

    // Null BYOC → 400 (the core invariant).
    let (status, body) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "tok",
            "scopes": [CAL_SCOPE]
        }),
    )
    .await;
    assert_eq!(
        status, 400,
        "import without byoc_credential_id must 400: {body}"
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

    // Valid pin → succeeds.
    let byoc_id = register_byoc(&client, &base, &key, ident_id).await;
    let (status, body) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "tok3",
            "refresh_token": "refresh-tok",
            "byoc_credential_id": byoc_id,
            "scopes": [CAL_SCOPE]
        }),
    )
    .await;
    assert_eq!(status, 200, "valid byoc import should succeed: {body}");
}

/// `POST /v1/connections/{id}/upgrade_scopes` is rejected for a **headless** org
/// — its end users can't open the gated upgrade flow; the integration broadens
/// the grant and re-imports. Non-headless orgs keep the orchestrated flow.
#[tokio::test]
async fn upgrade_scopes_rejected_for_headless_org() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;

    let byoc_id = register_byoc(&client, &base, &key, ident_id).await;
    let (status, body) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "vault-token",
            "byoc_credential_id": byoc_id,
            "account_email": "up@example.com"
        }),
    )
    .await;
    assert_eq!(status, 200, "import should succeed: {body}");
    let connection_id = body["connection_id"].as_str().unwrap();

    // Flip the org to headless.
    let resp = client
        .patch(format!("{base}/v1/orgs/{org_id}/headless"))
        .header(auth_header(&admin_key).0, auth_header(&admin_key).1)
        .json(&json!({ "headless": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "patch headless should succeed");

    let resp = client
        .post(format!(
            "{base}/v1/connections/{connection_id}/upgrade_scopes"
        ))
        .header(auth_header(&key).0, auth_header(&key).1)
        .json(&json!({ "scopes": [CAL_SCOPE] }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        400,
        "upgrade_scopes must reject headless orgs"
    );
}

/// An emailless import must never overwrite an existing connection that the
/// `(identity, provider)` fallback happens to match but pins a *different*
/// client (e.g. an orchestrated row with no BYOC). It creates a fresh vault
/// connection instead — the original row is left untouched.
#[tokio::test]
async fn emailless_import_does_not_overwrite_differently_pinned_connection() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, ident_id, key, _admin_key) = common::bootstrap_org_identity(&base, &client).await;
    // Both the seeded orchestrated row (as the OAuth callback would create it,
    // at the owner per D22) and the agent's emailless import (D23) land on the
    // owner identity, so the fallback-match scenario is exercised there.
    let owner_id = common::owner_user_id(&pool, org_id).await;

    // Seed an orchestrated connection (no BYOC pin, NULL email), exactly what the
    // OAuth callback would create when userinfo returns no email.
    let enc_key = overslash_core::crypto::Keyring::test();
    let orchestrated_token =
        overslash_core::crypto::encrypt(&enc_key, b"orchestrated-token").unwrap();
    let orchestrated = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: owner_id,
            provider_key: "google",
            encrypted_access_token: &orchestrated_token,
            encrypted_refresh_token: None,
            token_expires_at: None,
            scopes: Some(&[]),
            account_email: None,
            account_picture: None,
            byoc_credential_id: None,
        })
        .await
        .unwrap();

    // Emailless import pinned to a BYOC — the fallback would match the
    // orchestrated row, but the pinned client differs, so it must create a new row.
    let byoc_id = register_byoc(&client, &base, &key, ident_id).await;
    let (status, body) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "vault-token",
            "byoc_credential_id": byoc_id
        }),
    )
    .await;
    assert_eq!(status, 200, "import should succeed: {body}");
    let imported_id: Uuid = body["connection_id"].as_str().unwrap().parse().unwrap();
    assert_ne!(
        imported_id, orchestrated.id,
        "import must not reuse the differently-pinned connection"
    );

    // The orchestrated row is untouched: still no BYOC pin and its original token.
    let row = sqlx::query_as::<_, (Option<Uuid>, Vec<u8>)>(
        "SELECT byoc_credential_id, encrypted_access_token FROM connections WHERE id = $1",
    )
    .bind(orchestrated.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        row.0.is_none(),
        "orchestrated connection pin must stay null"
    );
    assert_eq!(
        row.1, orchestrated_token,
        "orchestrated connection token must be untouched"
    );

    // Two connections now exist for the provider on the owner.
    let google = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM connections
         WHERE org_id = $1 AND identity_id = $2 AND provider_key = 'google'",
    )
    .bind(org_id)
    .bind(owner_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(google, 2, "expected orchestrated + imported on the owner");
}

/// `access_token` is required; an unknown provider 404s. Both checks fire before
/// the BYOC requirement, so no pin is needed to exercise them.
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

/// A token-only re-import that carries no fresh expiry must preserve the
/// existing `token_expires_at` — nulling it would make the connection look
/// perpetually valid and never surface reauth.
#[tokio::test]
async fn reimport_without_expiry_preserves_existing_expiry() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, ident_id, key, _admin_key) = common::bootstrap_org_identity(&base, &client).await;
    // Imports bind to the owner identity (D23), so the stored row lands there.
    let owner_id = common::owner_user_id(&pool, org_id).await;

    let byoc_id = register_byoc(&client, &base, &key, ident_id).await;

    // First import sets an expiry.
    let (status, _) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "tok",
            "byoc_credential_id": byoc_id,
            "account_email": "exp@example.com",
            "expires_in": 3600
        }),
    )
    .await;
    assert_eq!(status, 200);
    let original = sqlx::query_scalar::<_, Option<time::OffsetDateTime>>(
        "SELECT token_expires_at FROM connections
         WHERE org_id = $1 AND identity_id = $2 AND provider_key = 'google'",
    )
    .bind(org_id)
    .bind(owner_id)
    .fetch_one(&pool)
    .await
    .unwrap()
    .expect("first import sets an expiry");

    // Re-import the same account with NO expiry — must not null it.
    let (status, _) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "tok2",
            "byoc_credential_id": byoc_id,
            "account_email": "exp@example.com"
        }),
    )
    .await;
    assert_eq!(status, 200);
    let after = sqlx::query_scalar::<_, Option<time::OffsetDateTime>>(
        "SELECT token_expires_at FROM connections
         WHERE org_id = $1 AND identity_id = $2 AND provider_key = 'google'",
    )
    .bind(org_id)
    .bind(owner_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        after,
        Some(original),
        "re-import without expiry must preserve the existing token_expires_at"
    );
}

/// A token-only re-import that omits `scopes` must preserve the existing granted
/// scopes — wiping them would 403 every subsequent scope-gated call.
#[tokio::test]
async fn reimport_without_scopes_preserves_existing_scopes() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (_org_id, ident_id, key, _admin_key) = common::bootstrap_org_identity(&base, &client).await;

    let byoc_id = register_byoc(&client, &base, &key, ident_id).await;

    let (status, _) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "tok",
            "byoc_credential_id": byoc_id,
            "account_email": "scoped@example.com",
            "scopes": [CAL_SCOPE]
        }),
    )
    .await;
    assert_eq!(status, 200);

    // Re-import the same account with NO scopes — must keep the existing set.
    let (status, body) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "tok2",
            "byoc_credential_id": byoc_id,
            "account_email": "scoped@example.com"
        }),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        body["scopes"],
        json!([CAL_SCOPE]),
        "re-import without scopes must preserve the existing scopes: {body}"
    );
}

/// Bug A guard: a re-import that BROADENS the recorded scopes but carries NO
/// fresh refresh token (while the existing connection has one) is rejected.
/// This is the source of the metadata-refresh-token-behind-readonly-scopes
/// divergence (connection `85844f1a`): advancing scopes to `gmail.readonly`
/// while COALESCE-preserving a metadata-only refresh token makes every call
/// 403 forever and the self-refresh can't heal it. The partner must re-consent
/// to obtain a refresh token that backs the wider grant.
#[tokio::test]
async fn reimport_broadening_scopes_without_refresh_token_is_rejected() {
    const GMAIL_READONLY: &str = "https://www.googleapis.com/auth/gmail.readonly";
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (_org_id, ident_id, key, _admin_key) = common::bootstrap_org_identity(&base, &client).await;

    let byoc_id = register_byoc(&client, &base, &key, ident_id).await;

    // First import: metadata-era grant WITH a refresh token (the vault self-
    // refreshes via it).
    let (status, _) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "meta-access",
            "refresh_token": "meta-refresh",
            "byoc_credential_id": byoc_id,
            "account_email": "loopy@example.com",
            "scopes": [CAL_SCOPE]
        }),
    )
    .await;
    assert_eq!(status, 200);

    // Re-consent re-import: broadens scopes to include gmail.readonly but
    // Google returned no new refresh token, so the partner omits it. Must be
    // rejected rather than silently preserving the metadata refresh token
    // behind the wider recorded scopes.
    let (status, body) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "readonly-access",
            "byoc_credential_id": byoc_id,
            "account_email": "loopy@example.com",
            "scopes": [CAL_SCOPE, GMAIL_READONLY]
        }),
    )
    .await;
    assert_eq!(
        status, 400,
        "broadening re-import with no fresh refresh token must be rejected: {body}"
    );

    // The same re-import that DOES carry a fresh refresh token is accepted —
    // the new token backs the wider grant.
    let (status, body) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "readonly-access",
            "refresh_token": "readonly-refresh",
            "byoc_credential_id": byoc_id,
            "account_email": "loopy@example.com",
            "scopes": [CAL_SCOPE, GMAIL_READONLY]
        }),
    )
    .await;
    assert_eq!(status, 200, "re-import with a fresh refresh token succeeds");
    let mut got: Vec<String> = serde_json::from_value(body["scopes"].clone()).unwrap();
    got.sort();
    let mut want = vec![CAL_SCOPE.to_string(), GMAIL_READONLY.to_string()];
    want.sort();
    assert_eq!(
        got, want,
        "wider scopes recorded once a fresh token backs them"
    );
}

/// Re-import for the same (identity, provider, account_email) updates the
/// existing row in place; a *different* account_email creates a second
/// connection (multi-account vaulting).
#[tokio::test]
async fn reimport_is_idempotent_per_account() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, ident_id, key, _admin_key) = common::bootstrap_org_identity(&base, &client).await;
    // Imports bind to the owner identity (D23); count rows there, not on the agent.
    let owner_id = common::owner_user_id(&pool, org_id).await;

    let byoc_id = register_byoc(&client, &base, &key, ident_id).await;

    let first: Value = {
        let (s, b) = import(
            &client,
            &base,
            &key,
            json!({
                "provider": "google",
                "access_token": "a1",
                "byoc_credential_id": byoc_id,
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
            "byoc_credential_id": byoc_id,
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
            "byoc_credential_id": byoc_id,
            "account_email": "b@example.com"
        }),
    )
    .await;
    assert_eq!(s, 200);
    assert_ne!(
        other["connection_id"], first_id,
        "distinct email → distinct connection"
    );

    // The owner holds exactly the two connections (no duplicate from re-import).
    let google = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM connections
         WHERE org_id = $1 AND identity_id = $2 AND provider_key = 'google'",
    )
    .bind(org_id)
    .bind(owner_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(google, 2, "expected 2 google connections on the owner");
}

/// `expires_in` resolves to an absolute future expiry; `expires_at` is taken
/// verbatim as a Unix timestamp.
#[tokio::test]
async fn import_resolves_expiry_fields() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, ident_id, key, _admin_key) = common::bootstrap_org_identity(&base, &client).await;
    // Imports bind to the owner identity (D23), so the stored rows land there.
    let owner_id = common::owner_user_id(&pool, org_id).await;

    let byoc_id = register_byoc(&client, &base, &key, ident_id).await;

    // expires_in → token_expires_at ≈ now + 3600s.
    let (s, _) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "tok",
            "byoc_credential_id": byoc_id,
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
            "byoc_credential_id": byoc_id,
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
    .bind(owner_id)
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
    let user_id = common::owner_user_id(&pool, org_id).await;

    // The pinned BYOC resolve is org-scoped, so a credential registered on the
    // agent resolves for the on-behalf-of import landing on the user.
    let byoc_id = register_byoc(&client, &base, &key, agent_id).await;

    let (status, body) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "shared-tok",
            "byoc_credential_id": byoc_id,
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

/// An agent importing **without** `on_behalf_of` still binds the connection to
/// its owner user by default (ceiling root). This is the storage complement to
/// D22: the write path lands on the owner so the read path can resolve it, and
/// connections stop accreting on agent identities.
#[tokio::test]
async fn import_without_on_behalf_of_binds_to_owner() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, agent_id, key, _admin_key) = common::bootstrap_org_identity(&base, &client).await;

    let user_id = common::owner_user_id(&pool, org_id).await;
    let byoc_id = register_byoc(&client, &base, &key, agent_id).await;

    let (status, body) = import(
        &client,
        &base,
        &key,
        json!({
            "provider": "google",
            "access_token": "shared-tok",
            "byoc_credential_id": byoc_id,
            "account_email": "shared@example.com",
            // No `on_behalf_of` — the agent imports for itself, but the
            // connection must still land on the owner.
        }),
    )
    .await;
    assert_eq!(status, 200, "import should succeed: {body}");
    let connection_id: Uuid = body["connection_id"].as_str().unwrap().parse().unwrap();

    let owner = sqlx::query_scalar::<_, Uuid>("SELECT identity_id FROM connections WHERE id = $1")
        .bind(connection_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        owner, user_id,
        "connection must bind to the owner user even without on_behalf_of"
    );
    assert_ne!(
        owner, agent_id,
        "connection must NOT accrete on the calling agent (the reported bug)"
    );
}
