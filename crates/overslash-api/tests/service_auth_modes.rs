//! A template may accept either an OAuth connection or a vaulted token
//! against the same host and paths; the instance picks one at creation.
//!
//! What is worth covering here is not that both credentials *can* be stored —
//! they always could — but that the choice actually steers the four surfaces
//! that used to guess: which handshake `create_service` mints, what the
//! credentials badge reports, whether the instance is gated on its probe, and
//! which credential the executor injects.
#![allow(clippy::disallowed_methods)]

use crate::common;

use serde_json::{Value, json};

/// The connect kernel needs mock Google OAuth client credentials to resolve.
/// Mirrors `services_auto_connect.rs`.
fn ensure_oauth_env() {
    // SAFETY: test-only, ahead of API boot.
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_GOOGLE_CLIENT_ID", "test_client_id");
        std::env::set_var("OAUTH_GOOGLE_CLIENT_SECRET", "test_client_secret");
    }
}

async fn seed_dual_mode_template(base: &str, client: &reqwest::Client, admin_key: &str, key: &str) {
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "openapi": common::render_openapi(
                include_str!("fixtures/openapi/dual_mode.yaml.tmpl"),
                &[("key", key), ("display_name", "Dual Mode")],
            ),
            "user_level": false,
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "dual-mode template seed failed: {} {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

/// Mint an API key bound to `identity_id`.
///
/// The switch tests need one for the instance's *owner*. The fixture's plain
/// key belongs to an agent, and an instance an agent creates is owned by that
/// agent's user (the "agents create at owner-user level" rule) — so the agent
/// is neither owner nor admin for `PUT /manage`, and an org admin, while
/// admitted there, cannot start an OAuth flow on behalf of a user it does not
/// own. The owner is the one principal that can do both, which is also the
/// dashboard's case: a person switching their own service.
async fn key_for_identity(
    base: &str,
    client: &reqwest::Client,
    admin_key: &str,
    org_id: uuid::Uuid,
    identity_id: &str,
) -> String {
    let body: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "org_id": org_id,
            "identity_id": identity_id,
            "name": "owner-key",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    body["key"].as_str().expect("api key minted").to_string()
}

async fn create_service(
    base: &str,
    client: &reqwest::Client,
    api_key: &str,
    body: Value,
) -> (u16, Value) {
    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// The template advertises both alternatives, with one of them the default.
#[tokio::test]
async fn the_template_detail_lists_both_modes() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org, _ident, _key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    seed_dual_mode_template(&base, &client, &admin_key, "dm-detail").await;

    let body: Value = client
        .get(format!("{base}/v1/templates/dm-detail"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let modes = body["auth_modes"].as_array().expect("auth_modes present");
    assert_eq!(modes.len(), 2, "{body}");
    let oauth = modes.iter().find(|m| m["key"] == "oauth").unwrap();
    assert_eq!(oauth["default"], true);
    assert_eq!(oauth["label"], "Sign in");
    let token = modes.iter().find(|m| m["key"] == "token").unwrap();
    assert!(token.get("default").is_none() || token["default"] == false);
    assert_eq!(token["schemes"], json!(["token"]));
}

/// A single-mode template still reports one mode, so no caller has to
/// special-case "this template has no modes".
#[tokio::test]
async fn a_single_mode_template_still_reports_one_mode() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org, _ident, _key, admin_key) = common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "openapi": common::minimal_openapi("dm-single"), "user_level": false }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let body: Value = client
        .get(format!("{base}/v1/templates/dm-single"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let modes = body["auth_modes"].as_array().expect("auth_modes present");
    assert_eq!(modes.len(), 1, "{body}");
}

/// The OAuth mode behaves exactly as an OAuth-only template always did.
#[tokio::test]
async fn the_default_mode_mints_the_oauth_handshake() {
    ensure_oauth_env();
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org, _ident, api_key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    seed_dual_mode_template(&base, &client, &admin_key, "dm-oauth").await;

    // No `auth_mode` at all: the template's declared default answers.
    let (status, body) = create_service(
        &base,
        &client,
        &api_key,
        json!({ "template_key": "dm-oauth", "name": "svc-oauth" }),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    assert_eq!(body["auth_mode"], "oauth", "{body}");
    assert!(
        body.get("connect").is_some(),
        "the oauth mode must mint an OAuth handshake: {body}"
    );
    assert!(
        body.get("setup").is_none(),
        "the oauth mode owes no vault secret, so it must mint no setup link: {body}"
    );
    // An OAuth create is left live: the callback is server-side, with no
    // caller to run a probe as.
    assert_eq!(body["status"], "active", "{body}");
}

/// The token mode is the one every surface used to get wrong.
#[tokio::test]
async fn the_token_mode_mints_a_setup_link_and_no_oauth_flow() {
    ensure_oauth_env();
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org, _ident, api_key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    seed_dual_mode_template(&base, &client, &admin_key, "dm-token").await;

    let (status, body) = create_service(
        &base,
        &client,
        &api_key,
        json!({ "template_key": "dm-token", "name": "svc-token", "auth_mode": "token" }),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    assert_eq!(body["auth_mode"], "token", "{body}");
    assert!(
        body.get("connect").is_none(),
        "a token-mode create must not mint an OAuth link nobody asked for: {body}"
    );
    assert!(
        body.get("setup").is_some(),
        "a token-mode create must mint the setup link for its slot: {body}"
    );
    // Gated on its probe (D86), because a setup link was minted.
    assert_eq!(body["status"], "pending_setup", "{body}");

    // And no OAuth flow row was started for it.
    let instance_id: uuid::Uuid = body["id"].as_str().unwrap().parse().unwrap();
    let flows: i64 = sqlx::query_scalar!(
        "SELECT count(*) FROM oauth_connection_flows WHERE service_instance_id = $1",
        instance_id
    )
    .fetch_one(&pool)
    .await
    .unwrap()
    .unwrap_or(0);
    assert_eq!(flows, 0, "a token-mode create started an OAuth flow");
}

/// The regression this whole feature turns on: read template-wide, a
/// dual-mode template always "has OAuth", so a token instance reported
/// `needs_authentication` forever and could never pass the go-live gate.
#[tokio::test]
async fn a_bound_token_instance_reports_ok_rather_than_needing_authentication() {
    ensure_oauth_env();
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org, _ident, api_key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    seed_dual_mode_template(&base, &client, &admin_key, "dm-bound").await;

    let (status, body) = create_service(
        &base,
        &client,
        &api_key,
        json!({
            "template_key": "dm-bound",
            "name": "svc-bound",
            "auth_mode": "token",
            // Bound up front, so nothing is outstanding.
            "credentials": { "token": "my_vault_token" },
        }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["credentials_status"], "ok",
        "a token-mode instance with its slot bound is not missing a connection: {body}"
    );

    // The same template in its OAuth mode, with nothing connected, *is*
    // missing one — the classifier still says so, per mode.
    let (status, oauth_body) = create_service(
        &base,
        &client,
        &api_key,
        json!({
            "template_key": "dm-bound",
            "name": "svc-bound-oauth",
            "auth_mode": "oauth",
            "skip_connect": true,
        }),
    )
    .await;
    assert_eq!(status, 200, "{oauth_body}");
    assert_eq!(
        oauth_body["credentials_status"], "needs_authentication",
        "an oauth-mode instance with no connection still needs one: {oauth_body}"
    );
}

/// A caller that guesses gets told what would have worked.
#[tokio::test]
async fn an_unknown_mode_is_rejected_naming_the_valid_ones() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org, _ident, api_key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    seed_dual_mode_template(&base, &client, &admin_key, "dm-bad").await;

    let (status, body) = create_service(
        &base,
        &client,
        &api_key,
        json!({ "template_key": "dm-bad", "name": "svc-bad", "auth_mode": "nope" }),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    let msg = body.to_string();
    assert!(msg.contains("nope"), "{msg}");
    assert!(msg.contains("oauth") && msg.contains("token"), "{msg}");

    // Nothing was written for the refused create.
    let rows: i64 = sqlx::query_scalar!(
        "SELECT count(*) FROM service_instances WHERE name = $1",
        "svc-bad"
    )
    .fetch_one(&pool)
    .await
    .unwrap()
    .unwrap_or(0);
    assert_eq!(rows, 0, "a refused create left a row behind");
}

/// Switching re-opens the handshake for the mode being switched *to*, and
/// keeps the credential of the one being left.
#[tokio::test]
async fn switching_mode_regates_and_keeps_the_other_credential() {
    ensure_oauth_env();
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, _ident, api_key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    seed_dual_mode_template(&base, &client, &admin_key, "dm-switch").await;

    let (status, created) = create_service(
        &base,
        &client,
        &api_key,
        json!({
            "template_key": "dm-switch",
            "name": "svc-switch",
            "auth_mode": "token",
            "credentials": { "token": "my_vault_token" },
        }),
    )
    .await;
    assert_eq!(status, 200, "{created}");
    assert_eq!(created["auth_mode"], "token");
    let id = created["id"].as_str().unwrap().to_string();
    let owner_key = key_for_identity(
        &base,
        &client,
        &admin_key,
        org_id,
        created["owner_identity_id"].as_str().unwrap(),
    )
    .await;

    // Switch to OAuth, as the owner.
    let resp = client
        .put(format!("{base}/v1/services/{id}/manage"))
        .header("Authorization", format!("Bearer {owner_key}"))
        .json(&json!({ "auth_mode": "oauth" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let switched: Value = resp.json().await.unwrap();

    assert_eq!(switched["auth_mode"], "oauth", "{switched}");
    assert!(
        switched.get("connect").is_some(),
        "switching into an OAuth mode must mint the OAuth handshake: {switched}"
    );
    assert_eq!(
        switched["status"], "pending_setup",
        "a switched instance is not live until its new credential is proven: {switched}"
    );

    // The token binding survives, so switching back costs no re-entry.
    let creds = sqlx::query_scalar!(
        "SELECT credentials FROM service_instances WHERE id = $1",
        uuid::Uuid::parse_str(&id).unwrap()
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        creds["token"], "my_vault_token",
        "switching away destroyed the credential it was leaving: {creds}"
    );
}

/// Re-sending the mode an instance is already on is not a switch, so it must
/// not knock a live service back into setup.
#[tokio::test]
async fn resending_the_current_mode_is_not_a_switch() {
    ensure_oauth_env();
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org, _ident, api_key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    seed_dual_mode_template(&base, &client, &admin_key, "dm-noop").await;

    let (status, created) = create_service(
        &base,
        &client,
        &api_key,
        json!({
            "template_key": "dm-noop",
            "name": "svc-noop",
            "auth_mode": "token",
            "credentials": { "token": "my_vault_token" },
        }),
    )
    .await;
    assert_eq!(status, 200, "{created}");
    assert_eq!(created["status"], "active", "{created}");
    let id = created["id"].as_str().unwrap().to_string();

    let resp = client
        .put(format!("{base}/v1/services/{id}/manage"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "auth_mode": "token" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let same: Value = resp.json().await.unwrap();
    assert_eq!(same["auth_mode"], "token");
    assert_eq!(
        same["status"], "active",
        "re-sending the current mode must not re-gate a live service: {same}"
    );
    assert!(same.get("setup").is_none(), "{same}");
}

/// A switched instance keeps its old `connection_id` on purpose — that is what
/// makes switching back free. The status path must therefore not read it while
/// the instance is in a token mode.
///
/// Regression: `resolve_effective_scopes` used the pinned connection
/// unconditionally, so it answered `Known(scopes)` for a token-mode instance.
/// `derive_credentials_status` then fell through its `!has_oauth` guard and
/// returned `None` — dropping the credentials badge entirely rather than
/// reporting on the token the instance actually authenticates with.
#[tokio::test]
async fn a_stale_connection_does_not_blank_the_badge_after_switching_to_a_token() {
    ensure_oauth_env();
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, _ident, api_key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    seed_dual_mode_template(&base, &client, &admin_key, "dm-stale").await;

    // An OAuth-mode instance with a connection actually pinned.
    let (status, created) = create_service(
        &base,
        &client,
        &api_key,
        json!({
            "template_key": "dm-stale",
            "name": "svc-stale",
            "auth_mode": "oauth",
            "skip_connect": true,
        }),
    )
    .await;
    assert_eq!(status, 200, "{created}");
    let id = created["id"].as_str().unwrap().to_string();
    let instance_id = uuid::Uuid::parse_str(&id).unwrap();
    let owner_id: uuid::Uuid = created["owner_identity_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let connection_id = uuid::Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO connections \
         (id, org_id, identity_id, provider_key, encrypted_access_token, scopes, account_email, is_default) \
         VALUES ($1, $2, $3, 'google', $4, ARRAY['openid']::TEXT[], 'someone@example.com', false)",
        connection_id,
        org_id,
        owner_id,
        b"fake_token".as_ref(),
    )
    .execute(&pool)
    .await
    .expect("seed connection");
    sqlx::query!(
        "UPDATE service_instances SET connection_id = $2 WHERE id = $1",
        instance_id,
        connection_id
    )
    .execute(&pool)
    .await
    .expect("pin connection");

    let owner_key =
        key_for_identity(&base, &client, &admin_key, org_id, &owner_id.to_string()).await;

    // Switch to the token mode and bind its slot in the same call.
    let resp = client
        .put(format!("{base}/v1/services/{id}/manage"))
        .header("Authorization", format!("Bearer {owner_key}"))
        .json(&json!({ "auth_mode": "token", "credentials": { "token": "my_vault_token" } }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let switched: Value = resp.json().await.unwrap();
    assert_eq!(switched["auth_mode"], "token", "{switched}");

    // The connection is deliberately still there…
    let still_pinned: Option<uuid::Uuid> = sqlx::query_scalar!(
        "SELECT connection_id FROM service_instances WHERE id = $1",
        instance_id
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        still_pinned,
        Some(connection_id),
        "switching must not drop the old connection — that is what makes switching back free"
    );

    // …and the badge reports on the token, rather than vanishing.
    let detail: Value = client
        .get(format!("{base}/v1/services/svc-stale"))
        .header("Authorization", format!("Bearer {owner_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        detail["credentials_status"], "ok",
        "a token-mode instance with its slot bound must report ok, not lose its badge to a \
         stale connection: {detail}"
    );
}
