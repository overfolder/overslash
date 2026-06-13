//! Tests for admin-initiated removal of a human user from an org via
//! `DELETE /v1/identities/{id}` when the target is a `user`-kind identity.
//!
//! Removal is a cascade-archive of the user's subtree (revoking API keys) plus
//! a drop of their `user_org_memberships` row and a detach of the archived
//! identity from the user (so the same human can be re-invited later). Guards:
//! you can't remove yourself, and you can't remove the org's last admin.
//! Non-admin callers get 403.

#![allow(clippy::disallowed_methods)] // direct SQL seeding

mod common;

use overslash_api::services::jwt;
use overslash_db::repos::{identity, membership, org_bootstrap, user as user_repo};
use reqwest::StatusCode;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

/// Mint a session JWT (same signing key as `common::start_api`) bound to an
/// identity + user, so the caller authenticates as a real org member.
fn session_cookie(org_id: Uuid, identity_id: Uuid, user_id: Uuid) -> String {
    let secret = hex::decode("cd".repeat(32)).unwrap();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = jwt::Claims {
        sub: identity_id,
        org: org_id,
        email: "remove-user-test@example.com".into(),
        aud: jwt::AUD_SESSION.into(),
        iat: now,
        exp: now + 3600,
        user_id: Some(user_id),
        mcp_client_id: None,
    };
    format!("oss_session={}", jwt::mint(&secret, &claims).expect("mint"))
}

/// Seed a member user: `users` row + `user`-kind identity (linked via user_id)
/// + membership with the given role. Returns (user_id, identity_id).
async fn seed_member(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    name: &str,
    role: &str,
    is_org_admin: bool,
) -> (Uuid, Uuid) {
    let user = user_repo::create_overslash_backed(
        pool,
        Some(&format!("{name}@remove.test")),
        Some(name),
        "google",
        &format!("sub-{}", Uuid::new_v4()),
    )
    .await
    .unwrap();

    let ident = identity::create_with_email(
        pool,
        org_id,
        name,
        "user",
        None,
        Some(&format!("{name}@remove.test")),
        json!({}),
    )
    .await
    .unwrap();
    identity::set_user_id(pool, org_id, ident.id, Some(user.id))
        .await
        .unwrap();
    if is_org_admin {
        identity::set_is_org_admin(pool, org_id, ident.id, true)
            .await
            .unwrap();
    }
    membership::create(pool, user.id, org_id, role)
        .await
        .unwrap();

    (user.id, ident.id)
}

async fn fresh_org(pool: &sqlx::PgPool) -> Uuid {
    let org_id: Uuid = sqlx::query_scalar(
        "INSERT INTO orgs (name, slug) VALUES ('RemoveUserOrg', $1) RETURNING id",
    )
    .bind(format!("rm-user-{}", Uuid::new_v4().simple()))
    .fetch_one(pool)
    .await
    .unwrap();
    org_bootstrap::bootstrap_org(pool, org_id, None)
        .await
        .unwrap();
    org_id
}

#[tokio::test]
async fn admin_removes_member_cascades_and_drops_membership() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let org_id = fresh_org(&pool).await;
    let (admin_uid, admin_iid) =
        seed_member(&pool, org_id, "admin", membership::ROLE_ADMIN, true).await;
    let (member_uid, member_iid) =
        seed_member(&pool, org_id, "bob", membership::ROLE_MEMBER, false).await;

    // The member owns an agent with a bound API key.
    let agent = identity::create_with_parent(
        &pool, org_id, "bot", "agent", None, member_iid, 1, member_iid, false,
    )
    .await
    .unwrap();
    let key_prefix = format!("rmkey_{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO api_keys (org_id, identity_id, name, key_hash, key_prefix)
         VALUES ($1, $2, 'agent-key', 'hash', $3)",
    )
    .bind(org_id)
    .bind(agent.id)
    .bind(&key_prefix)
    .execute(&pool)
    .await
    .unwrap();

    // Admin removes the member.
    let resp = client
        .delete(format!("{base}/v1/identities/{member_iid}"))
        .header("cookie", session_cookie(org_id, admin_iid, admin_uid))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Membership dropped.
    assert!(
        membership::find(&pool, member_uid, org_id)
            .await
            .unwrap()
            .is_none(),
        "membership should be gone"
    );

    // Member identity archived + detached from the user.
    let member_row = identity::get_by_id(&pool, org_id, member_iid)
        .await
        .unwrap()
        .unwrap();
    assert!(member_row.archived_at.is_some(), "member identity archived");
    assert!(member_row.user_id.is_none(), "identity detached from user");

    // The owned agent is archived too.
    let agent_row = identity::get_by_id(&pool, org_id, agent.id)
        .await
        .unwrap()
        .unwrap();
    assert!(agent_row.archived_at.is_some(), "agent subtree archived");

    // The agent's API key was revoked, tagged identity_archived.
    let revoked: (Option<OffsetDateTime>, Option<String>) =
        sqlx::query_as("SELECT revoked_at, revoked_reason FROM api_keys WHERE key_prefix = $1")
            .bind(&key_prefix)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(revoked.0.is_some(), "key revoked");
    assert_eq!(revoked.1.as_deref(), Some("identity_archived"));

    // Regression: the (org_id, user_id) unique slot is freed — the same human
    // can be re-provisioned a fresh user identity in this org.
    let reprovisioned = identity::create_with_email(
        &pool,
        org_id,
        "bob",
        "user",
        None,
        Some("bob@remove.test"),
        json!({}),
    )
    .await
    .unwrap();
    identity::set_user_id(&pool, org_id, reprovisioned.id, Some(member_uid))
        .await
        .expect("re-inviting the same user must not collide on the unique index");
}

#[tokio::test]
async fn admin_cannot_remove_self() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let org_id = fresh_org(&pool).await;
    let (admin_uid, admin_iid) =
        seed_member(&pool, org_id, "admin", membership::ROLE_ADMIN, true).await;
    // A second admin so the last-admin guard wouldn't fire first.
    seed_member(&pool, org_id, "admin2", membership::ROLE_ADMIN, true).await;

    let resp = client
        .delete(format!("{base}/v1/identities/{admin_iid}"))
        .header("cookie", session_cookie(org_id, admin_iid, admin_uid))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Still a member.
    assert!(
        membership::find(&pool, admin_uid, org_id)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn cannot_remove_last_admin() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let org_id = fresh_org(&pool).await;
    // Caller passes AdminAcl via the is_org_admin flag but holds only a
    // `member` membership; the target is the org's sole admin membership.
    let (caller_uid, caller_iid) =
        seed_member(&pool, org_id, "flagadmin", membership::ROLE_MEMBER, true).await;
    let (sole_admin_uid, sole_admin_iid) =
        seed_member(&pool, org_id, "soleadmin", membership::ROLE_ADMIN, false).await;

    let resp = client
        .delete(format!("{base}/v1/identities/{sole_admin_iid}"))
        .header("cookie", session_cookie(org_id, caller_iid, caller_uid))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Sole admin retains membership.
    assert!(
        membership::find(&pool, sole_admin_uid, org_id)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn non_admin_cannot_remove_member() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let org_id = fresh_org(&pool).await;
    let (caller_uid, caller_iid) =
        seed_member(&pool, org_id, "plainmember", membership::ROLE_MEMBER, false).await;
    let (victim_uid, victim_iid) =
        seed_member(&pool, org_id, "victim", membership::ROLE_MEMBER, false).await;
    // Keep an admin around so the org is otherwise well-formed.
    seed_member(&pool, org_id, "admin", membership::ROLE_ADMIN, true).await;

    let resp = client
        .delete(format!("{base}/v1/identities/{victim_iid}"))
        .header("cookie", session_cookie(org_id, caller_iid, caller_uid))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Victim untouched.
    assert!(
        membership::find(&pool, victim_uid, org_id)
            .await
            .unwrap()
            .is_some()
    );
    let _ = caller_uid;
}
