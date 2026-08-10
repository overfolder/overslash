//! OAuth connections resolve at the OWNER identity, not the calling agent (D22).
//!
//! A child agent shares its owner user's connection: the action-execution auth
//! resolver looks connections up at the ceiling user (owner), so one credential
//! per `(user, provider)` is enough and a single reauth heals every agent.
//!
//! Each test drives a typed auth-recovery envelope (`reauth_required` /
//! `needs_authentication`), all of which are produced *before* any upstream
//! call, so the assertions are deterministic and need no mock upstream. The
//! discriminator against the old per-calling-identity behavior is sharp:
//!
//! - Old: agent with no own connection → `needs_authentication`.
//! - New: agent with no own connection but an owner-level one → the owner's
//!   connection is found and used (here it's expired → `reauth_required`
//!   referencing the *owner's* connection id).
//!
//! See `routes/actions/auth.rs` and DECISIONS.md D22.

// Seeds connections + reads flow rows via direct SQL.
#![allow(clippy::disallowed_methods)]

use crate::common;

use overslash_core::crypto;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

fn set_x_oauth_env() {
    // SAFETY: test-only, ahead of API boot. Same values every call.
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_secret");
    }
}

/// Seed an OAuth connection. `expired_no_refresh` produces an expired access
/// token with no refresh token (drives `reauth_required`); otherwise a
/// long-lived token. `scopes` is the recorded granted set.
async fn seed_connection(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    provider_key: &str,
    scopes: &[&str],
    account_email: &str,
    expired_no_refresh: bool,
) -> Uuid {
    let enc_key = crypto::Keyring::test();
    let access = crypto::encrypt(&enc_key, b"mock_access_token").unwrap();
    let expires_at = if expired_no_refresh {
        time::OffsetDateTime::now_utc() - time::Duration::hours(1)
    } else {
        time::OffsetDateTime::now_utc() + time::Duration::hours(1)
    };
    let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO connections (org_id, identity_id, provider_key,
         encrypted_access_token, token_expires_at, scopes, account_email)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(org_id)
    .bind(identity_id)
    .bind(provider_key)
    .bind(&access)
    .bind(expires_at)
    .bind(scopes)
    .bind(account_email)
    .fetch_one(pool)
    .await
    .unwrap();
    row.0
}

/// Create the org-level `x` service (no pinned connection — auto-resolve) and
/// grant `caller_id` permission to call it.
async fn setup_x_service(base: &str, client: &reqwest::Client, caller_id: Uuid, admin_key: &str) {
    let (h, v) = common::auth(admin_key);
    let resp = client
        .post(format!("{base}/v1/services"))
        .header(h, v.clone())
        .json(&json!({
            "template_key": "x",
            "name": "x",
            "user_level": false,
            "groups": common::everyone_grant(base, client, admin_key).await,
            "status": "active",
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "x service create failed");

    client
        .post(format!("{base}/v1/permissions"))
        .header(h, v)
        .json(&json!({"identity_id": caller_id, "action_pattern": "x:*:*"}))
        .send()
        .await
        .unwrap();
}

async fn call_get_me(base: &str, client: &reqwest::Client, api_key: &str) -> (u16, Value) {
    let (h, v) = common::auth(api_key);
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(h, v)
        .json(&json!({ "service": "x", "action": "get_me", "params": {} }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap())
}

/// A child agent with NO connection of its own resolves the owner user's
/// connection. The owner's token is expired-no-refresh, so the call surfaces
/// `reauth_required` keyed to the **owner's** connection — proving the agent
/// inherited it. Under the old per-calling-identity behavior the agent had no
/// connection at all and the call would have been `needs_authentication`.
#[tokio::test]
async fn agent_inherits_owner_connection() {
    set_x_oauth_env();
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, agent_id, agent_key, org_key) =
        common::bootstrap_org_identity(&base, &client).await;
    let owner_id = common::owner_user_id(&pool, org_id).await;

    // Connection lives on the OWNER, expired with no refresh token.
    let owner_conn = seed_connection(
        &pool,
        org_id,
        owner_id,
        "x",
        &["tweet.read", "users.read"],
        "owner@x",
        true,
    )
    .await;

    setup_x_service(&base, &client, agent_id, &org_key).await;

    let (status, body) = call_get_me(&base, &client, &agent_key).await;
    assert_eq!(status, 401, "expected reauth_required: {body}");
    assert_eq!(body["error"], "reauth_required");
    assert_eq!(
        body["connection_id"].as_str().unwrap(),
        owner_conn.to_string(),
        "reauth must reference the OWNER's connection the agent inherited",
    );
}

/// The exact reported-bug shape: the owner holds a connection AND the calling
/// agent holds its own separate connection for the same provider. The resolver
/// must pick the **owner's** connection, never the agent's — otherwise an agent
/// with a broken self-bound connection enters a reauth loop the user's flow can
/// never heal (dev trace d57fe333).
#[tokio::test]
async fn owner_connection_wins_over_agents_own() {
    set_x_oauth_env();
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, agent_id, agent_key, org_key) =
        common::bootstrap_org_identity(&base, &client).await;
    let owner_id = common::owner_user_id(&pool, org_id).await;

    let owner_conn = seed_connection(
        &pool,
        org_id,
        owner_id,
        "x",
        &["tweet.read", "users.read"],
        "owner@x",
        true,
    )
    .await;
    // The agent's own (stale) connection — must NOT be the one resolved.
    let agent_conn = seed_connection(
        &pool,
        org_id,
        agent_id,
        "x",
        &["tweet.read", "users.read"],
        "agent@x",
        true,
    )
    .await;
    assert_ne!(owner_conn, agent_conn);

    setup_x_service(&base, &client, agent_id, &org_key).await;

    let (status, body) = call_get_me(&base, &client, &agent_key).await;
    assert_eq!(status, 401, "expected reauth_required: {body}");
    assert_eq!(body["error"], "reauth_required");
    let referenced = body["connection_id"].as_str().unwrap();
    assert_eq!(
        referenced,
        owner_conn.to_string(),
        "must resolve the owner's connection",
    );
    assert_ne!(
        referenced,
        agent_conn.to_string(),
        "must NOT resolve the agent's own connection (the reported bug)",
    );
}

/// With no connection anywhere, the call is `needs_authentication` and the
/// minted OAuth flow is keyed to the **owner** identity — so the connection the
/// user creates lands on the owner and is shared by every agent, not stranded
/// on the calling agent.
#[tokio::test]
async fn needs_authentication_mints_flow_at_owner() {
    set_x_oauth_env();
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, agent_id, agent_key, org_key) =
        common::bootstrap_org_identity(&base, &client).await;
    let owner_id = common::owner_user_id(&pool, org_id).await;
    assert_ne!(owner_id, agent_id);

    setup_x_service(&base, &client, agent_id, &org_key).await;

    let (status, body) = call_get_me(&base, &client, &agent_key).await;
    assert_eq!(status, 401, "expected needs_authentication: {body}");
    assert_eq!(body["error"], "needs_authentication");

    // The minted flow (org-scoped so it can't collide with other tests) must
    // be owned by the owner identity, not the calling agent.
    let (flow_identity, flow_actor): (Uuid, Uuid) = sqlx::query_as(
        "SELECT identity_id, actor_identity_id FROM oauth_connection_flows WHERE org_id = $1",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        flow_identity, owner_id,
        "minted flow must be keyed to the owner so the new connection lands on the owner",
    );
    assert_eq!(flow_actor, owner_id, "flow actor should be the owner too");
}
