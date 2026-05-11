// Test setup requires dynamic SQL for provider endpoint overrides and DB seeding.
#![allow(clippy::disallowed_methods)]
//! Integration tests for the Overslash-managed sign-in feature
//! (migration 066). Covers:
//!
//! * New corp orgs default to `allow_overslash_managed_signin = true`.
//! * Toggle GET/PATCH endpoint round-trip.
//! * Invite CRUD: create, duplicate rejection, role validation, revoke.
//! * Invite-gated callback admission: a verified email with a pending
//!   invite is admitted; without an invite, the callback responds with
//!   `not_invited`.
//!
//! Mocked OAuth IdP from `overslash_fakes` returns
//! `email=testuser@example.com` so the invite fixture below matches that
//! value verbatim.

mod common;

use serde_json::{Value, json};

#[tokio::test]
async fn new_corp_org_defaults_managed_signin_on() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (org_id, _, _, org_admin_key) = common::bootstrap_org_identity(&base, &client).await;

    let settings: Value = client
        .get(format!("{base}/v1/orgs/{org_id}/managed-signin"))
        .header("authorization", format!("Bearer {org_admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        settings["allow_overslash_managed_signin"], true,
        "new corp orgs should default to managed-signin = true"
    );
}

#[tokio::test]
async fn managed_signin_toggle_round_trip() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (org_id, _, _, org_admin_key) = common::bootstrap_org_identity(&base, &client).await;

    let resp: Value = client
        .patch(format!("{base}/v1/orgs/{org_id}/managed-signin"))
        .header("authorization", format!("Bearer {org_admin_key}"))
        .json(&json!({ "allow_overslash_managed_signin": false }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["allow_overslash_managed_signin"], false);

    let resp: Value = client
        .patch(format!("{base}/v1/orgs/{org_id}/managed-signin"))
        .header("authorization", format!("Bearer {org_admin_key}"))
        .json(&json!({ "allow_overslash_managed_signin": true }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["allow_overslash_managed_signin"], true);
}

#[tokio::test]
async fn invite_create_list_revoke_round_trip() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_, _, _, org_admin_key) = common::bootstrap_org_identity(&base, &client).await;

    let created: Value = client
        .post(format!("{base}/v1/org-invites"))
        .header("authorization", format!("Bearer {org_admin_key}"))
        .json(&json!({ "email": "Alice@Example.com", "role": "member" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        created["email"], "alice@example.com",
        "email must be lower-cased server-side"
    );
    assert_eq!(created["role"], "member");
    assert_eq!(created["status"], "pending");
    let invite_id = created["id"].as_str().unwrap().to_string();

    let list: Vec<Value> = client
        .get(format!("{base}/v1/org-invites"))
        .header("authorization", format!("Bearer {org_admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["email"], "alice@example.com");

    // Duplicate (with different casing) is rejected as pending-invite conflict.
    let resp = client
        .post(format!("{base}/v1/org-invites"))
        .header("authorization", format!("Bearer {org_admin_key}"))
        .json(&json!({ "email": "alice@example.com", "role": "admin" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);

    let resp = client
        .delete(format!("{base}/v1/org-invites/{invite_id}"))
        .header("authorization", format!("Bearer {org_admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["deleted"], true);

    // After revoke the same email can be re-invited.
    let resp = client
        .post(format!("{base}/v1/org-invites"))
        .header("authorization", format!("Bearer {org_admin_key}"))
        .json(&json!({ "email": "alice@example.com", "role": "admin" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn invite_create_rejects_invalid_role() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_, _, _, org_admin_key) = common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/org-invites"))
        .header("authorization", format!("Bearer {org_admin_key}"))
        .json(&json!({ "email": "bob@example.com", "role": "owner" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn invite_create_rejects_invalid_email() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_, _, _, org_admin_key) = common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/org-invites"))
        .header("authorization", format!("Bearer {org_admin_key}"))
        .json(&json!({ "email": "not-an-email", "role": "member" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn callback_admits_invited_email_on_corp_subdomain() {
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

    // Provision a corp org (managed-signin defaults on) and pre-create an
    // invite for the email the mock will return.
    let (org_id, _, _, org_admin_key) = common::bootstrap_org_identity(&base, &client).await;
    let org_slug = sqlx::query_scalar::<_, String>("SELECT slug FROM orgs WHERE id = $1")
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    let invite_resp = client
        .post(format!("{base}/v1/org-invites"))
        .header("authorization", format!("Bearer {org_admin_key}"))
        .json(&json!({ "email": "testuser@example.com", "role": "admin" }))
        .send()
        .await
        .unwrap();
    assert_eq!(invite_resp.status(), 200);

    // Hit the callback with the corp slug cookie. resolve_auth_credentials
    // falls through to env creds (managed-signin = true, no dedicated IdP);
    // provision_org_subdomain admits via the invite.
    let nonce = "managed-nonce-1";
    let state_param = format!("login:google:{nonce}");
    let resp = client
        .get(format!(
            "{base}/auth/callback/google?code=mc1&state={state_param}"
        ))
        .header(
            "cookie",
            format!("oss_auth_nonce={nonce}; oss_auth_verifier=v; oss_auth_org={org_slug}"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303, "expected redirect on admitted login");

    // Invite is marked accepted; membership exists with the invite's role.
    let invite: (Option<time::OffsetDateTime>, String) = sqlx::query_as(
        "SELECT accepted_at, role FROM org_invites WHERE org_id = $1 AND email = 'testuser@example.com'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(invite.0.is_some(), "invite should be marked accepted");
    assert_eq!(invite.1, "admin");

    let membership_role: String = sqlx::query_scalar(
        "SELECT role FROM user_org_memberships m
         JOIN users u ON u.id = m.user_id
         WHERE m.org_id = $1 AND u.email = 'testuser@example.com'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        membership_role, "admin",
        "membership role should honor invite role"
    );
}

#[tokio::test]
async fn invite_gate_applies_to_dedicated_idp_when_flag_on() {
    // Flow 2b in docs/design/multi_org_auth.md: when
    // `allow_overslash_managed_signin = true`, the invite gate applies to
    // *every* sign-in into the org — including authentications via a
    // dedicated `org_idp_configs` row, not just the env-var path. Without
    // an invite, even a domain-matching email is rejected with
    // `not_invited` (the `allowed_email_domains` whitelist is bypassed).
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

    // Boot WITHOUT env creds so the only path to credentials is the
    // dedicated `org_idp_configs` row we'll create below.
    let (base, client) =
        common::start_api_with_auth_providers(pool.clone(), None, None, "http://localhost:3000")
            .await;

    let (org_id, _, _, org_admin_key) = common::bootstrap_org_identity(&base, &client).await;
    let org_slug = sqlx::query_scalar::<_, String>("SELECT slug FROM orgs WHERE id = $1")
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    // Configure a dedicated google IdP with allowed_email_domains that
    // *would* admit testuser@example.com under the legacy path. Then leave
    // the managed-signin flag on (the default for new corp orgs) and
    // confirm the invite gate still wins — no invite, no admission.
    let resp = client
        .post(format!("{base}/v1/org-idp-configs"))
        .header("authorization", format!("Bearer {org_admin_key}"))
        .json(&json!({
            "provider_key": "google",
            "client_id": "dedicated_id",
            "client_secret": "dedicated_secret",
            "allowed_email_domains": ["example.com"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "dedicated IdP create should succeed");

    let nonce = "managed-nonce-3";
    let state_param = format!("login:google:{nonce}");
    let resp = client
        .get(format!(
            "{base}/auth/callback/google?code=mc3&state={state_param}"
        ))
        .header(
            "cookie",
            format!("oss_auth_nonce={nonce}; oss_auth_verifier=v; oss_auth_org={org_slug}"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "invite gate must block admission via dedicated IdP when flag is on"
    );
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap().contains("not_invited"),
        "expected not_invited, got: {body:?}"
    );
}

#[tokio::test]
async fn callback_rejects_uninvited_email_on_managed_signin_org() {
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

    let (org_id, _, _, _) = common::bootstrap_org_identity(&base, &client).await;
    let org_slug = sqlx::query_scalar::<_, String>("SELECT slug FROM orgs WHERE id = $1")
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    // No invite for testuser@example.com.
    let nonce = "managed-nonce-2";
    let state_param = format!("login:google:{nonce}");
    let resp = client
        .get(format!(
            "{base}/auth/callback/google?code=mc2&state={state_param}"
        ))
        .header(
            "cookie",
            format!("oss_auth_nonce={nonce}; oss_auth_verifier=v; oss_auth_org={org_slug}"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap().contains("not_invited"),
        "expected not_invited, got: {body:?}"
    );
}
