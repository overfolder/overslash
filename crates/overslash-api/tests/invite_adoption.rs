// Test setup requires dynamic SQL for provider endpoint overrides + DB seeding.
#![allow(clippy::disallowed_methods)]
//! End-to-end for the "identities are members" convergence: a member
//! pre-created by name-based impersonation (or by an invite) and their first
//! real SSO sign-in must land on the SAME identity — with its pre-created
//! agents and audit history — not a fresh duplicate.
//!
//! The mocked IdP (`overslash_fakes`) returns `email=testuser@example.com`,
//! so the pre-created identity matches the callback's verified email verbatim.

use crate::common;

use serde_json::{Value, json};
use uuid::Uuid;

/// Point the `google` provider at a fresh mock and start an API that trusts
/// env Google creds (so `resolve_auth_credentials` falls through to them for
/// a managed-signin org). Returns `(base, client, pool)`.
async fn api_with_google_mock() -> (String, reqwest::Client, sqlx::PgPool) {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    sqlx::query(
        "UPDATE oauth_providers SET authorization_endpoint = $1, token_endpoint = $2, userinfo_endpoint = $3 WHERE key = 'google'",
    )
    .bind(format!("http://{mock_addr}/oauth/authorize"))
    .bind(format!("http://{mock_addr}/oauth/token"))
    .bind(format!("http://{mock_addr}/oidc/userinfo"))
    .execute(&pool)
    .await
    .unwrap();

    let (base, client) = common::start_api_with_auth_providers(
        pool.clone(),
        Some(("env_id".into(), "env_secret".into())),
        None,
        "http://localhost:3000",
    )
    .await;
    (base, client, pool)
}

/// The whole story: impersonation pre-creates `testuser@example.com` and an
/// agent `henry` beneath her; she then signs in for the first time and lands
/// on the same identity, now a full member, still owning `henry`.
#[tokio::test]
async fn impersonation_provisioned_member_is_adopted_at_first_signin() {
    let (base, client, pool) = api_with_google_mock().await;

    // Bootstrap a corp org (managed sign-in defaults on) with an admin key.
    let (org_id, _, _, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    let org_slug = sqlx::query_scalar::<_, String>("SELECT slug FROM orgs WHERE id = $1")
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    // The bootstrap admin identity id — bind the impersonation key to it so
    // the ACL cap (target member <= caller admin) is satisfied.
    let admin_identity_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM identities WHERE org_id = $1 AND is_org_admin = true ORDER BY created_at LIMIT 1",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    let imp_key: String = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "org_id": org_id,
            "identity_id": admin_identity_id,
            "name": "provisioner",
            "scopes": ["impersonate"],
        }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["key"]
        .as_str()
        .unwrap()
        .to_string();

    // Impersonation provisions the user + agent chain. The leaf we act as is
    // `henry`; the user identity is created as a side effect.
    let whoami: Value = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {imp_key}"))
        .header("X-Overslash-As", "testuser@example.com/henry")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(whoami["kind"], "agent");

    let pre_user_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM identities WHERE org_id = $1 AND kind = 'user' AND email = 'testuser@example.com'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    // Pre-sign-in she is a pending member: no external_id, no users row.
    let (pre_ext, pre_user): (Option<String>, Option<Uuid>) =
        sqlx::query_as("SELECT external_id, user_id FROM identities WHERE id = $1")
            .bind(pre_user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(pre_ext.is_none() && pre_user.is_none());

    // She signs in for the first time via the Google mock on the corp slug.
    let nonce = "adopt-nonce-1";
    let state_param = format!("login:google:{nonce}");
    let resp = client
        .get(format!(
            "{base}/auth/callback/google?code=ac1&state={state_param}"
        ))
        .header(
            "cookie",
            format!("oss_auth_nonce={nonce}; oss_auth_verifier=v; oss_auth_org={org_slug}"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303, "first sign-in must be admitted");

    // Same identity, now adopted: external_id + user_id set, exactly one row.
    let identity_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identities WHERE org_id = $1 AND kind = 'user' AND email = 'testuser@example.com'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(identity_count, 1, "sign-in must adopt, not fork");

    let (post_ext, post_user): (Option<String>, Option<Uuid>) =
        sqlx::query_as("SELECT external_id, user_id FROM identities WHERE id = $1")
            .bind(pre_user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(post_ext.is_some(), "adopted identity gets the IdP subject");
    let user_id = post_user.expect("adopted identity gets a users row");

    // Membership now exists.
    let membership_role: String = sqlx::query_scalar(
        "SELECT role FROM user_org_memberships WHERE org_id = $1 AND user_id = $2",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(membership_role, "member");

    // And `henry` is still hers — her pre-created agent survived adoption.
    let henry_owner: Option<Uuid> = sqlx::query_scalar(
        "SELECT owner_id FROM identities WHERE org_id = $1 AND parent_id = $2 AND name = 'henry'",
    )
    .bind(org_id)
    .bind(pre_user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        henry_owner,
        Some(pre_user_id),
        "henry still owned by the same user"
    );

    // The adoption is audited, and records that this identity came from
    // impersonation rather than an explicit invite — the admission path is
    // legitimate (the `impersonate` scope is admin-minted) but must be
    // distinguishable after the fact.
    let (adopted_count, provisioned_by): (i64, Option<String>) = sqlx::query_as(
        "SELECT count(*), max(detail->>'provisioned_by') FROM audit_log
         WHERE org_id = $1 AND action = 'identity.adopted' AND resource_id = $2",
    )
    .bind(org_id)
    .bind(pre_user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(adopted_count, 1, "first sign-in must log identity.adopted");
    assert_eq!(
        provisioned_by.as_deref(),
        Some("impersonation"),
        "audit must record the identity was impersonation-provisioned"
    );
}

/// Invite-required admission is now "a user identity with this email exists":
/// with no pre-created identity, a first sign-in is rejected `not_invited`.
#[tokio::test]
async fn uninvited_email_is_rejected_when_invite_required() {
    let (base, client, pool) = api_with_google_mock().await;
    let (org_id, _, _, _) = common::bootstrap_org_identity(&base, &client).await;
    let org_slug = sqlx::query_scalar::<_, String>("SELECT slug FROM orgs WHERE id = $1")
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    let nonce = "adopt-nonce-2";
    let state_param = format!("login:google:{nonce}");
    let resp = client
        .get(format!(
            "{base}/auth/callback/google?code=ac2&state={state_param}"
        ))
        .header(
            "cookie",
            format!("oss_auth_nonce={nonce}; oss_auth_verifier=v; oss_auth_org={org_slug}"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "no pre-created identity => not_invited");
    let body = resp.text().await.unwrap();
    assert!(body.contains("not_invited"), "got: {body}");
}

/// An invite created as `admin` (a pre-created identity carrying
/// `is_org_admin`) becomes a real admin member at first sign-in.
#[tokio::test]
async fn admin_invite_signs_in_as_admin() {
    let (base, client, pool) = api_with_google_mock().await;
    let (org_id, _, _, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    let org_slug = sqlx::query_scalar::<_, String>("SELECT slug FROM orgs WHERE id = $1")
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    // Invite testuser as admin via the (identity-backed) invite endpoint.
    let resp = client
        .post(format!("{base}/v1/org-invites"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "email": "testuser@example.com", "role": "admin" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let nonce = "adopt-nonce-3";
    let state_param = format!("login:google:{nonce}");
    let resp = client
        .get(format!(
            "{base}/auth/callback/google?code=ac3&state={state_param}"
        ))
        .header(
            "cookie",
            format!("oss_auth_nonce={nonce}; oss_auth_verifier=v; oss_auth_org={org_slug}"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);

    let (is_admin, user_id): (bool, Option<Uuid>) = sqlx::query_as(
        "SELECT is_org_admin, user_id FROM identities
         WHERE org_id = $1 AND kind = 'user' AND email = 'testuser@example.com'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(is_admin, "admin invite must sign in as org admin");

    let membership_role: String = sqlx::query_scalar(
        "SELECT role FROM user_org_memberships WHERE org_id = $1 AND user_id = $2",
    )
    .bind(org_id)
    .bind(user_id.unwrap())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        membership_role, "admin",
        "membership must honor the admin invite"
    );
}
