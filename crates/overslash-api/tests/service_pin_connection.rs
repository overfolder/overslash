//! `use_default_connection` opt-out + atomic `pin_service_ids` on connection
//! creation.
//!
//! Two features that let a white-label partner mint a *service* and its
//! *connection* coherently:
//!   - a per-instance `use_default_connection` flag (default `true`); when
//!     `false`, an unbound OAuth instance must NOT borrow the identity's default
//!     connection — it reports `needs_authentication` until one is pinned;
//!   - `pin_service_ids` on `POST /v1/connections/import`, binding the new
//!     connection to the named instances in the *same transaction* — a bad id
//!     rolls the whole import back so no orphan connection is left behind.

// Test setup reads/asserts rows via direct SQL.
#![allow(clippy::disallowed_methods)]

use crate::common;

use serde_json::{Value, json};
use uuid::Uuid;

fn ensure_oauth_env() {
    // SAFETY: test-only, ahead of API boot.
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_GOOGLE_CLIENT_ID", "test_client_id");
        std::env::set_var("OAUTH_GOOGLE_CLIENT_SECRET", "test_client_secret");
    }
}

async fn seed_oauth_template(base: &str, client: &reqwest::Client, admin_key: &str, key: &str) {
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "openapi": common::render_openapi(
                include_str!("fixtures/openapi/oauth_google_multi_scoped.yaml.tmpl"),
                &[("key", key), ("display_name", "GCal Pin")],
            ),
            "user_level": false,
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "template seed failed: {} {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// The scopes the multi-scoped Google template declares on its actions — grant
/// these on an imported connection so a bound/borrowed instance classifies `ok`.
const TEMPLATE_SCOPES: &[&str] = &[
    "https://www.googleapis.com/auth/calendar.events",
    "https://www.googleapis.com/auth/calendar.readonly",
];

async fn register_byoc(client: &reqwest::Client, base: &str, key: &str, ident_id: Uuid) -> String {
    let byoc: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {key}"))
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

async fn import(client: &reqwest::Client, base: &str, key: &str, body: Value) -> (u16, Value) {
    let resp = client
        .post(format!("{base}/v1/connections/import"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    (status, body)
}

async fn create_service(
    client: &reqwest::Client,
    base: &str,
    key: &str,
    template_key: &str,
    name: &str,
    use_default_connection: bool,
) -> Value {
    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({
            "template_key": template_key,
            "name": name,
            // Skip the auto-initiated OAuth flow so the instance lands unbound.
            "skip_connect": true,
            "use_default_connection": use_default_connection,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "create_service failed: {}",
        resp.text().await.unwrap_or_default()
    );
    resp.json().await.unwrap()
}

async fn get_service(client: &reqwest::Client, base: &str, key: &str, name: &str) -> Value {
    client
        .get(format!("{base}/v1/services/{name}"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// An unbound instance with `use_default_connection = false` must NOT borrow the
/// owner's default connection: it classifies `needs_authentication` even though
/// a covering connection exists. The `true` sibling still classifies `ok`.
#[tokio::test]
async fn use_default_connection_false_blocks_default_fallback() {
    ensure_oauth_env();
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    seed_oauth_template(&base, &client, &admin_key, "gcal-pin").await;
    let byoc_id = register_byoc(&client, &base, &api_key, ident_id).await;

    // Import a default Google connection covering the template's scopes.
    let (status, imported) = import(
        &client,
        &base,
        &api_key,
        json!({
            "provider": "google",
            "access_token": "vault-access-token",
            "refresh_token": "vault-refresh-token",
            "scopes": TEMPLATE_SCOPES,
            "byoc_credential_id": byoc_id,
        }),
    )
    .await;
    assert_eq!(status, 200, "import failed: {imported}");

    // Two unbound instances of the same template, differing only in the flag.
    create_service(&client, &base, &api_key, "gcal-pin", "borrows", true).await;
    create_service(&client, &base, &api_key, "gcal-pin", "isolated", false).await;

    let borrows = get_service(&client, &base, &api_key, "borrows").await;
    assert!(
        borrows["connection_id"].is_null(),
        "borrows must be unbound"
    );
    assert_eq!(
        borrows["credentials_status"], "ok",
        "use_default_connection=true must borrow the default connection; got {borrows}"
    );

    let isolated = get_service(&client, &base, &api_key, "isolated").await;
    assert!(
        isolated["connection_id"].is_null(),
        "isolated must be unbound"
    );
    assert_eq!(
        isolated["use_default_connection"], false,
        "flag must round-trip on the detail response; got {isolated}"
    );
    assert_eq!(
        isolated["credentials_status"], "needs_authentication",
        "use_default_connection=false must NOT borrow the default; got {isolated}"
    );
}

/// `pin_service_ids` on import binds the new connection to the instance in one
/// transaction: the instance ends up pointing at the imported connection and the
/// response echoes the pinned id.
#[tokio::test]
async fn import_pin_service_ids_binds_atomically() {
    ensure_oauth_env();
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    seed_oauth_template(&base, &client, &admin_key, "gcal-pin").await;
    let byoc_id = register_byoc(&client, &base, &api_key, ident_id).await;

    // Isolated (no default fallback) unbound instance.
    let svc = create_service(&client, &base, &api_key, "gcal-pin", "wl-svc", false).await;
    let instance_id = svc["id"].as_str().unwrap().to_string();

    let (status, imported) = import(
        &client,
        &base,
        &api_key,
        json!({
            "provider": "google",
            "access_token": "vault-access-token",
            "refresh_token": "vault-refresh-token",
            "scopes": TEMPLATE_SCOPES,
            "byoc_credential_id": byoc_id,
            "pin_service_ids": [instance_id],
        }),
    )
    .await;
    assert_eq!(status, 200, "pinned import failed: {imported}");
    let connection_id = imported["connection_id"].as_str().unwrap().to_string();
    assert_eq!(
        imported["pinned_service_ids"],
        json!([instance_id]),
        "response must echo the pinned instance; got {imported}"
    );

    // The instance now points at the imported connection and, being bound,
    // classifies ok despite use_default_connection=false.
    let detail = get_service(&client, &base, &api_key, "wl-svc").await;
    assert_eq!(
        detail["connection_id"].as_str().unwrap(),
        connection_id,
        "instance must be bound to the imported connection; got {detail}"
    );
    assert_eq!(
        detail["credentials_status"], "ok",
        "a pinned+covering connection classifies ok; got {detail}"
    );
}

/// A bad pin id rolls the whole import back: the response is a 400 AND no
/// connection row is created (contrast the OAuth callback's orphan-tolerant
/// best-effort bind).
#[tokio::test]
async fn import_pin_bad_id_rolls_back_connection() {
    ensure_oauth_env();
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let byoc_id = register_byoc(&client, &base, &api_key, ident_id).await;

    let (status, body) = import(
        &client,
        &base,
        &api_key,
        json!({
            "provider": "google",
            "access_token": "vault-access-token",
            "refresh_token": "vault-refresh-token",
            "scopes": TEMPLATE_SCOPES,
            "byoc_credential_id": byoc_id,
            // Nonexistent instance id.
            "pin_service_ids": [Uuid::new_v4()],
        }),
    )
    .await;
    assert_eq!(status, 400, "bad pin id must 400; got {status} {body}");

    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM connections WHERE org_id = $1 AND provider_key = 'google'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        count, 0,
        "a failed atomic pin must leave NO connection behind; found {count}"
    );
}
