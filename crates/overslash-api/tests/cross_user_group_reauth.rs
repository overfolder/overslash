//! Regression test for the cross-user / group-granted re-auth bug.
//!
//! Scenario (matches the live `overfolder-dev` repro on `google_calendar_angel`):
//!
//! - User A owns the calling agent.
//! - User B owns a user-level service instance with an expired, no-refresh
//!   OAuth connection.
//! - A group contains both users, with a `write` grant on the instance.
//!
//! `resolve_by_name` step 5 (group-granted) correctly resolves the instance,
//! so the call reaches the OAuth recovery path. There, `mint_upgrade_auth_url`
//! sees `conn.identity_id (B) != caller_identity_id (A's agent)` and sets
//! `on_behalf_of = Some(B)`. `validate_on_behalf_of` then rejects the call
//! because the caller's ceiling user (A) is not the target (B), surfacing
//! a 403 "caller may only act on_behalf_of its owner user" instead of the
//! expected typed 401 `reauth_required` envelope.
//!
//! The fix should either:
//!   1) Skip `on_behalf_of` (or refuse the mint) for cross-user group-granted
//!      connections, returning a clear typed error that names the owner; OR
//!   2) Loosen `validate_on_behalf_of` for the upgrade-flow path when the
//!      caller has a group grant on the connection's service instance.
//!
//! Today (HEAD on the `fix-...-reauth` branch base) this test fails: the
//! call returns 403 with the misleading body instead of the structured 401.

#![allow(clippy::disallowed_methods)]

mod common;

use axum::http::StatusCode;
use overslash_core::crypto;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_connection_no_refresh_expired(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    provider_key: &str,
) -> Uuid {
    let enc_key = crypto::Keyring::test();
    let access = crypto::encrypt(&enc_key, b"mock_expired_access_token").unwrap();
    let expired_at = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO connections (org_id, identity_id, provider_key,
         encrypted_access_token, token_expires_at, scopes, account_email)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(org_id)
    .bind(identity_id)
    .bind(provider_key)
    .bind(&access)
    .bind(expired_at)
    .bind::<Vec<String>>(vec!["tweet.read".into(), "users.read".into()])
    .bind(Some("user-b@example.com"))
    .fetch_one(pool)
    .await
    .unwrap();
    row.0
}

/// The call from A's agent against a connection owned by B (group-granted)
/// must NOT 403 with "caller may only act on_behalf_of its owner user". The
/// honest answer here is the standard typed 401 `reauth_required` — A's
/// agent legitimately reached the instance through the group grant, and the
/// only thing wrong is the expired token. (A 403 with a "connection owned
/// by another user" structured body would also be acceptable; what's not
/// acceptable is leaking the internal cross-identity validator message.)
#[tokio::test]
async fn group_granted_cross_user_reauth_does_not_403() {
    let pool = common::test_pool().await;

    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_secret");
    }

    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    // bootstrap creates "test-user" (user_a_id) plus "test-agent" under it,
    // and returns the agent's api key + the org-admin key.
    let (org_id, _agent_a_id, agent_a_key, org_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // User B — distinct user, separate identity. Will own the connection
    // and the service instance.
    let user_b: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"name": "user-b", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_b_id: Uuid = user_b["id"].as_str().unwrap().parse().unwrap();

    // Connection: expired, no refresh token. Owned by user B.
    let connection_id = seed_connection_no_refresh_expired(&pool, org_id, user_b_id, "x").await;

    // User-B-owned user-level instance bound to that connection. We mint a
    // user-B-bound API key to create it so ownership lands on B rather than
    // requiring `on_behalf_of` smuggling at setup time.
    let user_b_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({
            "org_id": org_id,
            "identity_id": user_b_id,
            "name": "user-b-key",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_b_key = user_b_key_resp["key"].as_str().unwrap();

    let svc_resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {user_b_key}"))
        .json(&json!({
            "template_key": "x",
            "name": "x_shared",
            "user_level": true,
            "status": "active",
            "connection_id": connection_id,
        }))
        .send()
        .await
        .unwrap();
    assert!(
        svc_resp.status().is_success(),
        "service create failed: {} {:?}",
        svc_resp.status(),
        svc_resp.text().await,
    );
    let svc: Value = svc_resp.json().await.unwrap();
    let svc_id: Uuid = svc["id"].as_str().unwrap().parse().unwrap();

    // Bootstrap created "test-user" (user A). Pull its id back from the
    // identity tree by querying — the helper returns the agent id, not
    // the parent user id.
    let identities: Value = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_a_id: Uuid = identities
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"].as_str() == Some("test-user"))
        .and_then(|r| r["id"].as_str())
        .unwrap()
        .parse()
        .unwrap();

    // Group containing both users, with a write grant on the instance.
    let group: Value = client
        .post(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"name": "Shared"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let group_id = group["id"].as_str().unwrap();
    for member in [user_a_id, user_b_id] {
        let r = client
            .post(format!("{base}/v1/groups/{group_id}/members"))
            .header("Authorization", format!("Bearer {org_key}"))
            .json(&json!({"identity_id": member}))
            .send()
            .await
            .unwrap();
        assert!(
            r.status().is_success(),
            "add member failed: {} {:?}",
            r.status(),
            r.text().await,
        );
    }
    let grant = client
        .post(format!("{base}/v1/groups/{group_id}/grants"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"service_instance_id": svc_id, "access_level": "write"}))
        .send()
        .await
        .unwrap();
    assert!(
        grant.status().is_success(),
        "grant failed: {} {:?}",
        grant.status(),
        grant.text().await,
    );

    // Call from A's agent against the B-owned, group-granted instance.
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_a_key}"))
        .json(&json!({
            "service": "x_shared",
            "action": "get_me",
            "params": {},
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body_text = resp.text().await.unwrap();

    // The bug: we currently get 403 with the on_behalf_of validator's message.
    // What we want: the call surfaces an OAuth-recovery error (typed envelope,
    // 401 reauth_required is the natural one). Either way, NOT a 403 leaking
    // the internal cross-identity check message.
    assert!(
        !(status == StatusCode::FORBIDDEN
            && body_text.contains("caller may only act on_behalf_of its owner user")),
        "cross-user group-granted call leaked the on_behalf_of validator's \
         403 instead of returning a typed OAuth-recovery envelope. \
         status={status} body={body_text}"
    );
    // Positive expectation: the right answer for an expired-no-refresh
    // connection reached via group grant is the same as for the owner —
    // a 401 reauth_required envelope.
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "expected 401 reauth_required, got status={status} body={body_text}"
    );
    let body: Value = serde_json::from_str(&body_text).unwrap();
    assert_eq!(body["error"], "reauth_required");
    assert_eq!(
        body["connection_id"].as_str().unwrap(),
        connection_id.to_string()
    );
}
