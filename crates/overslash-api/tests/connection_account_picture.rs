//! The avatar of the account behind an OAuth connection (`account_picture`).
//!
//! The connect callback already calls the provider's userinfo endpoint to
//! label the connection; these tests pin the three things that fall out of
//! also reading the picture from that same response: it lands on connect, a
//! provider that names no picture still connects, and a userinfo failure on a
//! later reconnect leaves an already-stored avatar alone rather than blanking
//! it.
#![allow(clippy::disallowed_methods)]

use crate::common;

use serde_json::Value;
use uuid::Uuid;

/// The fixed avatar the OAuth fake's `/oidc/userinfo` returns alongside
/// `testuser@example.com` (crates/overslash-fakes/src/oauth.rs).
const FAKE_AVATAR: &str = "https://example.com/avatar.png";

/// Point the `x` provider at the fake for both the token exchange and the
/// userinfo lookup. `userinfo` is a full URL so a caller can aim it at a
/// deliberately broken path.
async fn point_x_provider_at(pool: &sqlx::PgPool, token_endpoint: &str, userinfo: &str) {
    sqlx::query!(
        "UPDATE oauth_providers SET token_endpoint = $1, userinfo_endpoint = $2 WHERE key = 'x'",
        token_endpoint,
        userinfo,
    )
    .execute(pool)
    .await
    .unwrap();
}

/// The connection row as the API reports it, found by id in `GET /v1/connections`.
async fn connection_summary(
    client: &reqwest::Client,
    base: &str,
    api_key: &str,
    connection_id: &str,
) -> Value {
    let rows: Value = client
        .get(format!("{base}/v1/connections"))
        .header(common::auth(api_key).0, common::auth(api_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    rows.as_array()
        .expect("connections list should be an array")
        .iter()
        .find(|c| c["id"] == connection_id)
        .unwrap_or_else(|| panic!("connection {connection_id} missing from {rows}"))
        .clone()
}

#[tokio::test]
async fn oauth_connect_stores_the_account_avatar() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;

    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client_id");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_client_secret");
    }
    point_x_provider_at(
        &pool,
        &format!("http://{mock_addr}/oauth/token"),
        &format!("http://{mock_addr}/oidc/userinfo"),
    )
    .await;

    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let state_param = common::seed_oauth_flow(&pool, org_id, ident_id, "x", None).await;
    let callback: Value = client
        .get(format!(
            "{base}/v1/oauth/callback?code=x_auth_code&state={state_param}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(callback["status"], "connected");
    let connection_id = callback["connection_id"].as_str().unwrap().to_string();

    // The list and the detail endpoint must agree — the dashboard reads the
    // avatar from both.
    let summary = connection_summary(&client, &base, &api_key, &connection_id).await;
    assert_eq!(summary["account_email"], "testuser@example.com");
    assert_eq!(summary["account_picture"], FAKE_AVATAR);

    let detail: Value = client
        .get(format!("{base}/v1/connections/{connection_id}"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["account_picture"], FAKE_AVATAR);
}

#[tokio::test]
async fn a_provider_with_no_avatar_still_connects() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;

    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client_id");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_client_secret");
    }
    // `/github/user/emails` answers a list of addresses and names no picture —
    // a stand-in for any provider whose userinfo carries no avatar field.
    point_x_provider_at(
        &pool,
        &format!("http://{mock_addr}/oauth/token"),
        &format!("http://{mock_addr}/github/user/emails"),
    )
    .await;

    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let state_param = common::seed_oauth_flow(&pool, org_id, ident_id, "x", None).await;
    let callback: Value = client
        .get(format!(
            "{base}/v1/oauth/callback?code=x_auth_code&state={state_param}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        callback["status"], "connected",
        "a missing avatar must not fail the connect: {callback}"
    );

    let summary = connection_summary(
        &client,
        &base,
        &api_key,
        callback["connection_id"].as_str().unwrap(),
    )
    .await;
    assert_eq!(summary["account_picture"], Value::Null);
}

#[tokio::test]
async fn a_failed_userinfo_on_reconnect_keeps_the_stored_avatar() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;

    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client_id");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_client_secret");
    }
    point_x_provider_at(
        &pool,
        &format!("http://{mock_addr}/oauth/token"),
        &format!("http://{mock_addr}/oidc/userinfo"),
    )
    .await;

    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let state_param = common::seed_oauth_flow(&pool, org_id, ident_id, "x", None).await;
    let callback: Value = client
        .get(format!(
            "{base}/v1/oauth/callback?code=x_auth_code&state={state_param}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let connection_id: Uuid = callback["connection_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(
        connection_summary(&client, &base, &api_key, &connection_id.to_string()).await["account_picture"],
        FAKE_AVATAR
    );

    // Now break userinfo and re-run OAuth against the *same* connection, the
    // way an incremental scope upgrade does.
    point_x_provider_at(
        &pool,
        &format!("http://{mock_addr}/oauth/token"),
        &format!("http://{mock_addr}/does-not-exist"),
    )
    .await;

    let upgrade_state = seed_upgrade_flow(&pool, org_id, ident_id, connection_id).await;
    let upgrade: Value = client
        .get(format!(
            "{base}/v1/oauth/callback?code=x_auth_code&state={upgrade_state}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        upgrade["connection_id"].as_str().unwrap(),
        connection_id.to_string(),
        "the upgrade must land on the same row: {upgrade}"
    );

    let after = connection_summary(&client, &base, &api_key, &connection_id.to_string()).await;
    assert_eq!(
        after["account_picture"], FAKE_AVATAR,
        "a userinfo failure must COALESCE, not blank the stored avatar"
    );
    assert_eq!(
        after["account_email"], "testuser@example.com",
        "the same must hold for the label it sits beside"
    );
}

/// An OAuth flow row that re-authorizes an existing connection in place —
/// what `POST /v1/connections/{id}/upgrade-scopes` seeds. `common` has no
/// helper for this because only this test needs the upgrade branch.
async fn seed_upgrade_flow(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    upgrade_connection_id: Uuid,
) -> String {
    use overslash_db::repos::oauth_connection_flow::{self, CreateOauthConnectionFlow};
    use time::{Duration, OffsetDateTime};

    let flow_id = format!("flow_{}", &Uuid::new_v4().simple().to_string()[..16]);
    oauth_connection_flow::create(
        pool,
        &CreateOauthConnectionFlow {
            id: &flow_id,
            org_id,
            identity_id,
            actor_identity_id: identity_id,
            provider_key: "x",
            byoc_credential_id: None,
            scopes: &[],
            pkce_code_verifier: None,
            upstream_authorize_url: "https://example.test/authorize",
            expires_at: OffsetDateTime::now_utc() + Duration::minutes(10),
            created_ip: None,
            created_user_agent: None,
            return_url: None,
            upgrade_connection_id: Some(upgrade_connection_id),
            service_instance_id: None,
            pin_service_instance_ids: &[],
        },
    )
    .await
    .unwrap();
    flow_id
}
