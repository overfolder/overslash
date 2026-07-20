//! Tests for admin-initiated promotion/demotion of an existing org member via
//! `PATCH /v1/org-members/{identity_id}` with `{ "role": "admin" | "member" }`.
//!
//! Promotion must confer REAL admin authorization — not just a
//! `user_org_memberships.role='admin'` row, but the `is_org_admin` flag AND
//! `Admins`-group membership that `AdminAcl` actually reads. Demotion reverses
//! all three. Guards: only admins can call it, and the org's last admin can't
//! be demoted (including self-demotion).

#![allow(clippy::disallowed_methods)] // direct SQL seeding

use crate::common;

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
        email: "member-role-test@example.com".into(),
        aud: jwt::AUD_SESSION.into(),
        iat: now,
        exp: now + 3600,
        user_id: Some(user_id),
        mcp_client_id: None,
    };
    format!("oss_session={}", jwt::mint(&secret, &claims).expect("mint"))
}

/// Seed a member user: a `users` row, a `user`-kind identity (linked via
/// user_id), and a membership with the given role. When `is_org_admin`, also
/// sets the flag and Admins-group membership so the identity passes `AdminAcl`.
/// Returns (user_id, identity_id).
async fn seed_member(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    name: &str,
    role: &str,
    is_org_admin: bool,
) -> (Uuid, Uuid) {
    let user = user_repo::create_overslash_backed(
        pool,
        Some(&format!("{name}@role.test")),
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
        Some(&format!("{name}@role.test")),
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
        "INSERT INTO orgs (name, slug) VALUES ('MemberRoleOrg', $1) RETURNING id",
    )
    .bind(format!("member-role-{}", Uuid::new_v4().simple()))
    .fetch_one(pool)
    .await
    .unwrap();
    org_bootstrap::bootstrap_org(pool, org_id, None)
        .await
        .unwrap();
    org_id
}

/// True iff the identity sits in the org's `Admins` system group.
async fn in_admins_group(pool: &sqlx::PgPool, org_id: Uuid, identity_id: Uuid) -> bool {
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_groups ig
         JOIN groups g ON g.id = ig.group_id
         WHERE ig.identity_id = $1 AND g.org_id = $2 AND g.system_kind = 'admins'",
    )
    .bind(identity_id)
    .bind(org_id)
    .fetch_one(pool)
    .await
    .unwrap();
    n > 0
}

async fn membership_role(pool: &sqlx::PgPool, org_id: Uuid, user_id: Uuid) -> String {
    membership::find(pool, user_id, org_id)
        .await
        .unwrap()
        .unwrap()
        .role
}

#[tokio::test]
async fn admin_promotes_member_to_real_admin() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let org_id = fresh_org(&pool).await;
    let (admin_uid, admin_iid) =
        seed_member(&pool, org_id, "admin", membership::ROLE_ADMIN, true).await;
    let (member_uid, member_iid) =
        seed_member(&pool, org_id, "bob", membership::ROLE_MEMBER, false).await;

    // Sanity: the plain member can't reach an AdminAcl endpoint yet.
    let pre = client
        .get(format!("{base}/v1/org-invites"))
        .header("cookie", session_cookie(org_id, member_iid, member_uid))
        .send()
        .await
        .unwrap();
    assert_eq!(pre.status(), StatusCode::FORBIDDEN);

    // Admin promotes the member.
    let resp = client
        .patch(format!("{base}/v1/org-members/{member_iid}"))
        .header("cookie", session_cookie(org_id, admin_iid, admin_uid))
        .json(&json!({ "role": "admin" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // All three admin signals flipped.
    assert_eq!(membership_role(&pool, org_id, member_uid).await, "admin");
    let row = identity::get_by_id(&pool, org_id, member_iid)
        .await
        .unwrap()
        .unwrap();
    assert!(row.is_org_admin, "is_org_admin flag set");
    assert!(
        in_admins_group(&pool, org_id, member_iid).await,
        "identity added to Admins group"
    );

    // The promoted member now passes AdminAcl.
    let post = client
        .get(format!("{base}/v1/org-invites"))
        .header("cookie", session_cookie(org_id, member_iid, member_uid))
        .send()
        .await
        .unwrap();
    assert_eq!(
        post.status(),
        StatusCode::OK,
        "promoted member must pass AdminAcl"
    );
}

#[tokio::test]
async fn admin_demotes_admin_removes_authorization() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let org_id = fresh_org(&pool).await;
    let (admin_uid, admin_iid) =
        seed_member(&pool, org_id, "admin", membership::ROLE_ADMIN, true).await;
    // A second admin so the last-admin guard doesn't fire.
    let (admin2_uid, admin2_iid) =
        seed_member(&pool, org_id, "admin2", membership::ROLE_ADMIN, true).await;

    let resp = client
        .patch(format!("{base}/v1/org-members/{admin2_iid}"))
        .header("cookie", session_cookie(org_id, admin_iid, admin_uid))
        .json(&json!({ "role": "member" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    assert_eq!(membership_role(&pool, org_id, admin2_uid).await, "member");
    let row = identity::get_by_id(&pool, org_id, admin2_iid)
        .await
        .unwrap()
        .unwrap();
    assert!(!row.is_org_admin, "is_org_admin flag cleared");
    assert!(
        !in_admins_group(&pool, org_id, admin2_iid).await,
        "identity removed from Admins group"
    );

    // The demoted admin no longer passes AdminAcl.
    let post = client
        .get(format!("{base}/v1/org-invites"))
        .header("cookie", session_cookie(org_id, admin2_iid, admin2_uid))
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn cannot_demote_last_admin() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let org_id = fresh_org(&pool).await;
    let (admin_uid, admin_iid) =
        seed_member(&pool, org_id, "soleadmin", membership::ROLE_ADMIN, true).await;

    // Self-demotion of the sole admin is refused by the last-admin guard.
    let resp = client
        .patch(format!("{base}/v1/org-members/{admin_iid}"))
        .header("cookie", session_cookie(org_id, admin_iid, admin_uid))
        .json(&json!({ "role": "member" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Still a real admin.
    assert_eq!(membership_role(&pool, org_id, admin_uid).await, "admin");
    let row = identity::get_by_id(&pool, org_id, admin_iid)
        .await
        .unwrap()
        .unwrap();
    assert!(row.is_org_admin, "sole admin retains the flag");
    assert!(in_admins_group(&pool, org_id, admin_iid).await);
}

#[tokio::test]
async fn non_admin_cannot_change_role() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let org_id = fresh_org(&pool).await;
    let (caller_uid, caller_iid) =
        seed_member(&pool, org_id, "plainmember", membership::ROLE_MEMBER, false).await;
    let (target_uid, target_iid) =
        seed_member(&pool, org_id, "target", membership::ROLE_MEMBER, false).await;
    // Keep an admin around so the org is well-formed.
    seed_member(&pool, org_id, "admin", membership::ROLE_ADMIN, true).await;

    let resp = client
        .patch(format!("{base}/v1/org-members/{target_iid}"))
        .header("cookie", session_cookie(org_id, caller_iid, caller_uid))
        .json(&json!({ "role": "admin" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Target untouched.
    assert_eq!(membership_role(&pool, org_id, target_uid).await, "member");
    let _ = caller_uid;
}

#[tokio::test]
async fn rejects_invalid_role() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let org_id = fresh_org(&pool).await;
    let (admin_uid, admin_iid) =
        seed_member(&pool, org_id, "admin", membership::ROLE_ADMIN, true).await;
    let (_member_uid, member_iid) =
        seed_member(&pool, org_id, "bob", membership::ROLE_MEMBER, false).await;

    let resp = client
        .patch(format!("{base}/v1/org-members/{member_iid}"))
        .header("cookie", session_cookie(org_id, admin_iid, admin_uid))
        .json(&json!({ "role": "owner" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
