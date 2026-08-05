//! The invitee's side of org invitations: `/v1/account/invitations`.
//!
//! These are the only endpoints that answer "which orgs invited *me*", so
//! they deliberately read across org boundaries. The tests here pin the two
//! things that make that safe: the caller's email comes from their `users`
//! row (IdP-verified, not admin-writable), and only genuinely-pending,
//! genuinely-invited identities are ever surfaced.
//!
//! Sessions are forged JWTs with a `user_id` claim, the same pattern as
//! `multi_org.rs`.

#![allow(clippy::disallowed_methods)] // seeding needs raw SQL

use crate::common;

use overslash_api::services::jwt;
use overslash_db::repos::{identity, membership, user as user_repo};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

const INVITEE_EMAIL: &str = "invitee@acct-invites.test";

fn mint_session(org_id: Uuid, identity_id: Uuid, user_id: Option<Uuid>, email: &str) -> String {
    let secret = hex::decode("cd".repeat(32)).unwrap();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    jwt::mint(
        &secret,
        &jwt::Claims {
            sub: identity_id,
            org: org_id,
            email: email.into(),
            aud: jwt::AUD_SESSION.into(),
            iat: now,
            exp: now + 3600,
            user_id,
            mcp_client_id: None,
        },
    )
    .expect("mint")
}

/// The signed-in human: a `users` row carrying the IdP-verified email, plus
/// their own org, identity, and membership — i.e. the session they hold
/// while the invitation is sitting in another org.
struct Caller {
    org_id: Uuid,
    identity_id: Uuid,
    user_id: Uuid,
    cookie: String,
}

async fn seed_caller(pool: &PgPool, email: &str) -> Caller {
    let org_id: Uuid =
        sqlx::query_scalar("INSERT INTO orgs (name, slug) VALUES ('Home', $1) RETURNING id")
            .bind(format!("home-{}", Uuid::new_v4().simple()))
            .fetch_one(pool)
            .await
            .unwrap();
    overslash_db::repos::org_bootstrap::bootstrap_org(pool, org_id, None)
        .await
        .unwrap();

    let user = user_repo::create_overslash_backed(
        pool,
        Some(email),
        Some("Invitee"),
        "google",
        &format!("sub-{}", Uuid::new_v4()),
    )
    .await
    .unwrap();

    let ident = identity::create_with_email(
        pool,
        org_id,
        "Invitee",
        "user",
        None,
        Some(email),
        json!({}),
    )
    .await
    .unwrap();
    identity::set_user_id(pool, org_id, ident.id, Some(user.id))
        .await
        .unwrap();
    membership::create(pool, user.id, org_id, membership::ROLE_MEMBER)
        .await
        .unwrap();

    let cookie = mint_session(org_id, ident.id, Some(user.id), email);
    Caller {
        org_id,
        identity_id: ident.id,
        user_id: user.id,
        cookie,
    }
}

/// A corp org with an admin API key. `POST /v1/orgs` flips
/// `allow_overslash_managed_signin` on, so this org can admit in place.
async fn seed_inviting_org(base: &str, client: &reqwest::Client) -> (Uuid, String) {
    let (org_id, _, _, admin_key) = common::bootstrap_org_identity(base, client).await;
    (org_id, admin_key)
}

async fn invite(base: &str, client: &reqwest::Client, admin_key: &str, email: &str, role: &str) {
    let resp = client
        .post(format!("{base}/v1/org-invites"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "email": email, "role": role }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "invite create failed");
}

async fn list_invitations(base: &str, client: &reqwest::Client, cookie: &str) -> Vec<Value> {
    let resp = client
        .get(format!("{base}/v1/account/invitations"))
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    resp.json::<Vec<Value>>().await.unwrap()
}

#[tokio::test]
async fn lists_pending_invitations_from_another_org() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let caller = seed_caller(&pool, INVITEE_EMAIL).await;
    let (acme_id, admin_key) = seed_inviting_org(&base, &client).await;
    invite(&base, &client, &admin_key, INVITEE_EMAIL, "admin").await;

    let items = list_invitations(&base, &client, &caller.cookie).await;
    assert_eq!(items.len(), 1, "one invitation, got {items:?}");
    assert_eq!(items[0]["org_id"].as_str().unwrap(), acme_id.to_string());
    assert_eq!(items[0]["role"], "admin");
    assert_eq!(
        items[0]["can_accept_in_place"],
        Value::Bool(true),
        "orgs created through POST /v1/orgs have managed sign-in on"
    );
    assert!(items[0]["org_name"].is_string());
    assert!(items[0]["sign_in_url"].is_string());

    // The shell reads the same list off its universal auth call.
    let me: Value = client
        .get(format!("{base}/auth/me/identity"))
        .header("cookie", format!("oss_session={}", caller.cookie))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        me["invitations"].as_array().map(|a| a.len()),
        Some(1),
        "me/identity embeds the invitations: {me}"
    );
}

/// Case-insensitivity, and the negative space: an invitation addressed to
/// someone else must never surface, and neither must the caller's own
/// pending rows in orgs they already belong to.
#[tokio::test]
async fn matches_email_case_insensitively_and_ignores_other_recipients() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let caller = seed_caller(&pool, INVITEE_EMAIL).await;
    let (_acme_id, admin_key) = seed_inviting_org(&base, &client).await;
    invite(
        &base,
        &client,
        &admin_key,
        "SOMEONE.ELSE@acct-invites.test",
        "member",
    )
    .await;

    assert!(
        list_invitations(&base, &client, &caller.cookie)
            .await
            .is_empty(),
        "another recipient's invite must not surface"
    );

    // Upper-cased invite for *this* caller still matches.
    let mixed = INVITEE_EMAIL.to_uppercase();
    let (_, admin_key2) = seed_inviting_org(&base, &client).await;
    // `validate_email` lower-cases on write, so force the mixed casing that
    // pre-103 rows can carry.
    invite(&base, &client, &admin_key2, &mixed, "member").await;
    sqlx::query("UPDATE identities SET email = $1 WHERE lower(email) = lower($1)")
        .bind(&mixed)
        .execute(&pool)
        .await
        .unwrap();

    let items = list_invitations(&base, &client, &caller.cookie).await;
    assert_eq!(items.len(), 1, "mixed-case email still matches: {items:?}");
}

/// Impersonation-provisioned rows, archived rows, and orgs the caller is
/// already a member of are all excluded. None of them is an invitation the
/// caller can act on, and the first would leak the existence of any org that
/// ever impersonated this email.
#[tokio::test]
async fn excludes_impersonation_archived_and_existing_memberships() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let caller = seed_caller(&pool, INVITEE_EMAIL).await;

    // 1. Impersonation-provisioned pending identity.
    let (imp_org, _, _, _) = common::bootstrap_org_identity(&base, &client).await;
    identity::create_with_email(
        &pool,
        imp_org,
        "invitee",
        "user",
        None,
        Some(INVITEE_EMAIL),
        json!({ "provisioned_by": "impersonation" }),
    )
    .await
    .unwrap();

    // 2. Archived (e.g. previously declined) pending identity.
    let (archived_org, archived_key) = seed_inviting_org(&base, &client).await;
    invite(&base, &client, &archived_key, INVITEE_EMAIL, "member").await;
    sqlx::query(
        "UPDATE identities SET archived_at = now(), archived_reason = 'invite_declined' WHERE org_id = $1 AND lower(email) = lower($2)",
    )
    .bind(archived_org)
    .bind(INVITEE_EMAIL)
    .execute(&pool)
    .await
    .unwrap();

    // 3. A pending row in an org the caller already belongs to.
    let (member_org, member_key) = seed_inviting_org(&base, &client).await;
    invite(&base, &client, &member_key, INVITEE_EMAIL, "member").await;
    membership::create(&pool, caller.user_id, member_org, membership::ROLE_MEMBER)
        .await
        .unwrap();

    // 4. The caller's own personal-org identity is not an invitation either.
    sqlx::query("UPDATE orgs SET is_personal = true WHERE id = $1")
        .bind(caller.org_id)
        .execute(&pool)
        .await
        .unwrap();

    assert!(
        list_invitations(&base, &client, &caller.cookie)
            .await
            .is_empty(),
        "none of these are actionable invitations"
    );
}

#[tokio::test]
async fn accept_joins_the_org_and_clears_the_invite_everywhere() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let caller = seed_caller(&pool, INVITEE_EMAIL).await;
    let (acme_id, admin_key) = seed_inviting_org(&base, &client).await;
    invite(&base, &client, &admin_key, INVITEE_EMAIL, "admin").await;

    let items = list_invitations(&base, &client, &caller.cookie).await;
    let invitation_id = items[0]["id"].as_str().unwrap().to_string();

    let resp = client
        .post(format!(
            "{base}/v1/account/invitations/{invitation_id}/accept"
        ))
        .header("cookie", format!("oss_session={}", caller.cookie))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["org_id"].as_str().unwrap(), acme_id.to_string());

    // Membership with the invited role.
    let m = membership::find(&pool, caller.user_id, acme_id)
        .await
        .unwrap()
        .expect("membership created");
    assert_eq!(m.role, membership::ROLE_ADMIN, "invite role is honored");

    // The identity is now linked to the human.
    let linked: Option<Uuid> =
        sqlx::query_scalar("SELECT user_id FROM identities WHERE id = $1::uuid")
            .bind(Uuid::parse_str(&invitation_id).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(linked, Some(caller.user_id));

    // Gone from the invitee's list...
    assert!(
        list_invitations(&base, &client, &caller.cookie)
            .await
            .is_empty()
    );

    // ...and from the admin's Invites card: a member is not a revocable
    // invite, even though no `external_id` was ever minted for this org.
    let admin_view: Vec<Value> = client
        .get(format!("{base}/v1/org-invites"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        admin_view.is_empty(),
        "accepted invite still listed as pending: {admin_view:?}"
    );

    // The Members page must stop badging them "pending".
    let identities: Vec<Value> = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = identities
        .iter()
        .find(|i| i["id"].as_str() == Some(invitation_id.as_str()))
        .expect("member identity");
    assert_eq!(row["pending"], Value::Bool(false));

    // Accepting twice is not a way to re-run adoption.
    let again = client
        .post(format!(
            "{base}/v1/account/invitations/{invitation_id}/accept"
        ))
        .header("cookie", format!("oss_session={}", caller.cookie))
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), StatusCode::NOT_FOUND);
}

/// The email match is the whole authorization story, so a session belonging
/// to someone else must not be able to spend an invitation it can see the id
/// of — and the answer must be 404, not 403, so the probe learns nothing.
#[tokio::test]
async fn accept_by_a_different_user_is_not_found() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let invitee = seed_caller(&pool, INVITEE_EMAIL).await;
    let attacker = seed_caller(&pool, "attacker@acct-invites.test").await;
    let (_acme_id, admin_key) = seed_inviting_org(&base, &client).await;
    invite(&base, &client, &admin_key, INVITEE_EMAIL, "member").await;

    let items = list_invitations(&base, &client, &invitee.cookie).await;
    let invitation_id = items[0]["id"].as_str().unwrap().to_string();

    assert!(
        list_invitations(&base, &client, &attacker.cookie)
            .await
            .is_empty()
    );

    for verb in ["accept", "decline"] {
        let resp = client
            .post(format!(
                "{base}/v1/account/invitations/{invitation_id}/{verb}"
            ))
            .header("cookie", format!("oss_session={}", attacker.cookie))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{verb} leaked");
    }
}

/// A session whose JWT carries an admin-chosen `email` claim must not be able
/// to claim invitations for that address: the lookup uses `users.email`.
#[tokio::test]
async fn jwt_email_claim_does_not_grant_invitations() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let attacker = seed_caller(&pool, "attacker@acct-invites.test").await;
    let (_acme_id, admin_key) = seed_inviting_org(&base, &client).await;
    invite(&base, &client, &admin_key, INVITEE_EMAIL, "member").await;

    // Same session, but the claim says they are the invitee.
    let forged = mint_session(
        attacker.org_id,
        attacker.identity_id,
        Some(attacker.user_id),
        INVITEE_EMAIL,
    );
    assert!(
        list_invitations(&base, &client, &forged).await.is_empty(),
        "the email claim must not be the lookup key"
    );
}

/// An org that never opted into Overslash-managed sign-in gates admission on
/// its own IdP. The invitation is still visible — the invitee should know it
/// exists — but it has to be accepted on that org's sign-in page.
#[tokio::test]
async fn org_with_its_own_idp_cannot_be_accepted_in_place() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let caller = seed_caller(&pool, INVITEE_EMAIL).await;
    let (org_id, admin_key) = seed_inviting_org(&base, &client).await;
    invite(&base, &client, &admin_key, INVITEE_EMAIL, "member").await;
    sqlx::query("UPDATE orgs SET allow_overslash_managed_signin = false WHERE id = $1")
        .bind(org_id)
        .execute(&pool)
        .await
        .unwrap();

    let items = list_invitations(&base, &client, &caller.cookie).await;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["can_accept_in_place"], Value::Bool(false));

    let invitation_id = items[0]["id"].as_str().unwrap();
    let resp = client
        .post(format!(
            "{base}/v1/account/invitations/{invitation_id}/accept"
        ))
        .header("cookie", format!("oss_session={}", caller.cookie))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "org_requires_idp_signin", "body={body}");

    assert!(
        membership::find(&pool, caller.user_id, org_id)
            .await
            .unwrap()
            .is_none(),
        "no membership on a rejected accept"
    );
}

#[tokio::test]
async fn decline_archives_the_invite_and_frees_the_email() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let caller = seed_caller(&pool, INVITEE_EMAIL).await;
    let (org_id, admin_key) = seed_inviting_org(&base, &client).await;
    invite(&base, &client, &admin_key, INVITEE_EMAIL, "member").await;

    let items = list_invitations(&base, &client, &caller.cookie).await;
    let invitation_id = items[0]["id"].as_str().unwrap().to_string();

    let resp = client
        .post(format!(
            "{base}/v1/account/invitations/{invitation_id}/decline"
        ))
        .header("cookie", format!("oss_session={}", caller.cookie))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["declined"], Value::Bool(true));

    let reason: Option<String> =
        sqlx::query_scalar("SELECT archived_reason FROM identities WHERE id = $1::uuid")
            .bind(Uuid::parse_str(&invitation_id).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(reason.as_deref(), Some("invite_declined"));

    assert!(
        list_invitations(&base, &client, &caller.cookie)
            .await
            .is_empty()
    );

    // Declining must not create a membership, and must leave the admin free
    // to invite the same address again.
    assert!(
        membership::find(&pool, caller.user_id, org_id)
            .await
            .unwrap()
            .is_none()
    );
    invite(&base, &client, &admin_key, INVITEE_EMAIL, "member").await;
    assert_eq!(
        list_invitations(&base, &client, &caller.cookie).await.len(),
        1,
        "re-invite reaches the same person"
    );
}

/// A legacy session (no `user_id` claim) has no `users` row to resolve an
/// email from, so it sees nothing rather than falling back to the
/// admin-writable identity email.
#[tokio::test]
async fn legacy_session_without_user_claim_sees_nothing() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let caller = seed_caller(&pool, INVITEE_EMAIL).await;
    let (_acme_id, admin_key) = seed_inviting_org(&base, &client).await;
    invite(&base, &client, &admin_key, INVITEE_EMAIL, "member").await;

    let legacy = mint_session(caller.org_id, caller.identity_id, None, INVITEE_EMAIL);
    assert!(list_invitations(&base, &client, &legacy).await.is_empty());
}
