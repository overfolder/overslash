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
//! * Domain-allowlist admission (migration 092): with managed sign-in on and
//!   `require_invite_admission = false`, a verified email whose domain is on
//!   `orgs.managed_signin_allowed_domains` JIT-provisions with no invite;
//!   an empty allowlist rejects `domain_admission_not_configured` and an
//!   off-list domain rejects `domain_not_allowed`.
//!
//! Mocked OAuth IdP from `overslash_fakes` returns
//! `email=testuser@example.com` so the invite fixture below matches that
//! value verbatim.

use crate::common;

use overslash_api::services::jwt;
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

/// Mint a session JWT (same signing key as `common::start_api`) so a test can
/// authenticate as a freshly-provisioned identity and probe `AdminAcl`.
fn session_cookie(org_id: Uuid, identity_id: Uuid, user_id: Uuid) -> String {
    let secret = hex::decode("cd".repeat(32)).unwrap();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = jwt::Claims {
        sub: identity_id,
        org: org_id,
        email: "testuser@example.com".into(),
        aud: jwt::AUD_SESSION.into(),
        iat: now,
        exp: now + 3600,
        user_id: Some(user_id),
        mcp_client_id: None,
    };
    format!("oss_session={}", jwt::mint(&secret, &claims).expect("mint"))
}

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
async fn invite_endpoints_reject_non_admin() {
    // PII guard — pending invites carry invitee emails + roles + inviter
    // identity. Every endpoint (list, get, create, delete) is `AdminAcl`,
    // so a non-admin org member must get 403 across the board.
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_, _, agent_key, org_admin_key) = common::bootstrap_org_identity(&base, &client).await;

    let created: Value = client
        .post(format!("{base}/v1/org-invites"))
        .header("authorization", format!("Bearer {org_admin_key}"))
        .json(&json!({ "email": "secret@example.com", "role": "member" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let invite_id = created["id"].as_str().unwrap().to_string();

    for path in ["/v1/org-invites", &format!("/v1/org-invites/{invite_id}")] {
        let resp = client
            .get(format!("{base}{path}"))
            .header("authorization", format!("Bearer {agent_key}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            403,
            "non-admin must not read invite data at {path}"
        );
    }

    let resp = client
        .post(format!("{base}/v1/org-invites"))
        .header("authorization", format!("Bearer {agent_key}"))
        .json(&json!({ "email": "x@example.com", "role": "member" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let resp = client
        .delete(format!("{base}/v1/org-invites/{invite_id}"))
        .header("authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn auth_providers_lists_managed_when_flag_on() {
    // The login page hits `GET /auth/providers?org=<slug>`. When the org
    // opts in to managed-signin, env-var providers (Google/GitHub) must
    // appear in the response so users have a button to click. Without
    // this, a new corp org with no dedicated IdP would render an empty
    // login page even though the backend is wired to admit them.
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_auth_providers(
        pool.clone(),
        Some(("env_id".into(), "env_secret".into())),
        Some(("gh_id".into(), "gh_secret".into())),
        "http://localhost:3000",
    )
    .await;
    let (org_id, _, _, _) = common::bootstrap_org_identity(&base, &client).await;
    let org_slug = sqlx::query_scalar::<_, String>("SELECT slug FROM orgs WHERE id = $1")
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    let resp: Value = client
        .get(format!("{base}/auth/providers?org={org_slug}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let keys: Vec<&str> = resp["providers"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p["key"].as_str())
        .collect();
    assert!(
        keys.contains(&"google"),
        "google must be listed when managed-signin is on; got {keys:?}"
    );
    assert!(
        keys.contains(&"github"),
        "github must be listed when managed-signin is on; got {keys:?}"
    );

    // With the flag flipped off, env providers disappear (D12 default).
    overslash_db::repos::org::set_allow_overslash_managed_signin(&pool, org_id, false)
        .await
        .unwrap();
    let resp: Value = client
        .get(format!("{base}/auth/providers?org={org_slug}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let keys: Vec<&str> = resp["providers"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p["key"].as_str())
        .collect();
    assert!(
        !keys.contains(&"google") && !keys.contains(&"github"),
        "env providers must not leak when flag is off; got {keys:?}"
    );
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

    // The pre-created invite identity is now "accepted": adopting it at
    // sign-in stamps `external_id` (the IdP subject) onto the same row.
    let external_id: Option<String> = sqlx::query_scalar(
        "SELECT external_id FROM identities WHERE org_id = $1 AND email = 'testuser@example.com' AND kind = 'user'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        external_id.is_some(),
        "invite identity should be adopted (external_id set) after sign-in"
    );

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

    // Regression (bug fix): an invited *admin* must get REAL admin
    // authorization — the `is_org_admin` flag AND `Admins`-group membership,
    // not merely a `role='admin'` membership row. Pre-fix the acceptance path
    // only wrote the membership role, so the invited admin failed `AdminAcl`.
    let (new_iid, new_uid, is_admin): (Uuid, Uuid, bool) = sqlx::query_as(
        "SELECT id, user_id, is_org_admin FROM identities
         WHERE org_id = $1 AND email = 'testuser@example.com' AND kind = 'user'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(is_admin, "invited admin must have is_org_admin = true");

    let in_admins_group: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_groups ig
         JOIN groups g ON g.id = ig.group_id
         WHERE ig.identity_id = $1 AND g.org_id = $2 AND g.system_kind = 'admins'",
    )
    .bind(new_iid)
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        in_admins_group, 1,
        "invited admin must join the Admins group"
    );

    // End-to-end: the invited admin's session passes an AdminAcl-gated request.
    let admin_probe = client
        .get(format!("{base}/v1/org-invites"))
        .header("cookie", session_cookie(org_id, new_iid, new_uid))
        .send()
        .await
        .unwrap();
    assert_eq!(
        admin_probe.status(),
        200,
        "invited admin must pass AdminAcl on a real request"
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
async fn existing_member_admitted_when_new_idp_subject_misses_invite() {
    // Regression test for Seer 1268323: after alice@acme.com accepts an
    // invite, signing in with a different IdP (or any flow that produces
    // a fresh external_id for the same email) must NOT 403 with
    // `not_invited`. Models that case directly by pre-seeding an
    // existing membership for `testuser@example.com` under a synthetic
    // external_id, then letting the Google mock callback flow run — the
    // (org, external_id) lookup misses, no pending invite exists, and
    // the only path to admission is the existing-member short-circuit.
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

    // Seed an existing member — user + membership + identity — matching the
    // mock's email but whose identity is bound to a *different* external_id
    // than the mock will return. The `(org_id, external_id)` lookup in
    // `provision_org_subdomain` therefore misses; adopt-by-email finds the
    // identity by email and re-points it at the new subject.
    let existing_user_id: uuid::Uuid =
        sqlx::query_scalar("INSERT INTO users (email, display_name) VALUES ($1, $2) RETURNING id")
            .bind("testuser@example.com")
            .bind("Original")
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query(
        "INSERT INTO user_org_memberships (user_id, org_id, role) VALUES ($1, $2, 'member')",
    )
    .bind(existing_user_id)
    .bind(org_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO identities (org_id, name, kind, external_id, email, user_id)
         VALUES ($1, 'Original', 'user', 'original-idp-subject', 'testuser@example.com', $2)",
    )
    .bind(org_id)
    .bind(existing_user_id)
    .execute(&pool)
    .await
    .unwrap();
    // Crucially: no invite identity beyond this already-signed-in one. Without
    // adopt-by-email the callback would 403 not_invited.

    let nonce = "second-idp-1";
    let state_param = format!("login:google:{nonce}");
    let resp = client
        .get(format!(
            "{base}/auth/callback/google?code=g1&state={state_param}"
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
        303,
        "existing member must be admitted when (org, external_id) misses but email already has a membership"
    );

    // Still exactly one membership row — the new identity attached to
    // the existing user, no duplicate (user_id, org_id) row was created.
    let member_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM user_org_memberships m
         JOIN users u ON u.id = m.user_id
         WHERE m.org_id = $1 AND lower(u.email) = 'testuser@example.com'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        member_count, 1,
        "no duplicate membership for the same email"
    );
}

#[tokio::test]
async fn existing_admin_keeps_admin_via_second_idp() {
    // Regression test for Seer 1268697 HIGH: an existing admin signing
    // in via a second IdP must NOT be silently downgraded to a member.
    //
    // Under the identities-are-members model, a second IdP no longer forks
    // a fresh identity: adopt-by-email finds the admin's existing identity
    // and re-points its `external_id` at the new subject. Admin powers are
    // preserved trivially because it is the same row — one human, one
    // identity per org.
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

    // Pre-seed an admin user with an existing user-kind identity in this
    // org. Different external_id than the mock will return — that's the
    // whole point: the new IdP subject doesn't match, the
    // (org, external_id) lookup misses, we fall through to the existing-
    // member short-circuit, and the new identity must inherit admin.
    let existing_user_id: uuid::Uuid =
        sqlx::query_scalar("INSERT INTO users (email, display_name) VALUES ($1, $2) RETURNING id")
            .bind("testuser@example.com")
            .bind("Existing Admin")
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query(
        "INSERT INTO user_org_memberships (user_id, org_id, role) VALUES ($1, $2, 'admin')",
    )
    .bind(existing_user_id)
    .bind(org_id)
    .execute(&pool)
    .await
    .unwrap();
    let prior_identity_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO identities (org_id, name, kind, external_id, email, user_id, is_org_admin, metadata)
         VALUES ($1, 'Existing Admin', 'user', 'prior-subject', 'testuser@example.com', $2, true, '{}'::jsonb)
         RETURNING id",
    )
    .bind(org_id)
    .bind(existing_user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    // A real admin identity is always in the Admins group (kept in lock-step
    // with `is_org_admin` by `set_is_org_admin`). Mirror that so the seed is
    // a consistent starting state.
    sqlx::query(
        "INSERT INTO identity_groups (identity_id, group_id)
         SELECT $1, g.id FROM groups g WHERE g.org_id = $2 AND g.system_kind = 'admins'",
    )
    .bind(prior_identity_id)
    .bind(org_id)
    .execute(&pool)
    .await
    .unwrap();

    let nonce = "admin-second-idp-1";
    let state_param = format!("login:google:{nonce}");
    let resp = client
        .get(format!(
            "{base}/auth/callback/google?code=adm1&state={state_param}"
        ))
        .header(
            "cookie",
            format!("oss_auth_nonce={nonce}; oss_auth_verifier=v; oss_auth_org={org_slug}"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303, "second IdP login must admit");

    // Exactly one user identity for this email — the prior one was adopted,
    // not forked.
    let identity_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identities
         WHERE org_id = $1 AND kind = 'user' AND email = 'testuser@example.com'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        identity_count, 1,
        "second IdP must adopt, not fork a new identity"
    );

    // The adopted identity keeps `is_org_admin = true` and had its
    // `external_id` re-pointed away from the seeded 'prior-subject'.
    let (is_admin, external_id): (bool, Option<String>) =
        sqlx::query_as("SELECT is_org_admin, external_id FROM identities WHERE id = $1")
            .bind(prior_identity_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(is_admin, "adopted identity must keep is_org_admin = true");
    assert_ne!(
        external_id.as_deref(),
        Some("prior-subject"),
        "external_id should be re-pointed to the new IdP subject"
    );

    // Still in the Admins group so ACL extractors see admin powers.
    let in_admins_group: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_groups ig
         JOIN groups g ON g.id = ig.group_id
         WHERE ig.identity_id = $1 AND g.org_id = $2 AND g.system_kind = 'admins'",
    )
    .bind(prior_identity_id)
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        in_admins_group, 1,
        "adopted admin identity must stay in the Admins group"
    );
}

#[tokio::test]
async fn re_invite_of_current_member_is_rejected_and_resignin_is_idempotent() {
    // Under the identities-are-members model, inviting is creating a user
    // identity for an email. Re-inviting an email that is already a member
    // (or already invited) is a 409 — there is only ever one identity per
    // email per org. And a second sign-in by that member must not fork a
    // second identity or a duplicate membership.
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
    let (org_id, _, _, org_admin_key) = common::bootstrap_org_identity(&base, &client).await;
    let org_slug = sqlx::query_scalar::<_, String>("SELECT slug FROM orgs WHERE id = $1")
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    client
        .post(format!("{base}/v1/org-invites"))
        .header("authorization", format!("Bearer {org_admin_key}"))
        .json(&json!({ "email": "testuser@example.com", "role": "member" }))
        .send()
        .await
        .unwrap();

    // First sign-in: consumes the invite.
    let nonce = "consume-nonce-1";
    let state_param = format!("login:google:{nonce}");
    client
        .get(format!(
            "{base}/auth/callback/google?code=c1&state={state_param}"
        ))
        .header(
            "cookie",
            format!("oss_auth_nonce={nonce}; oss_auth_verifier=v; oss_auth_org={org_slug}"),
        )
        .send()
        .await
        .unwrap();

    // Re-inviting the same email now that they're a member is a 409 — the
    // identity already exists.
    let resp = client
        .post(format!("{base}/v1/org-invites"))
        .header("authorization", format!("Bearer {org_admin_key}"))
        .json(&json!({ "email": "testuser@example.com", "role": "admin" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        409,
        "re-inviting a current member must conflict"
    );

    // A second sign-in re-points the same identity; it must not fork.
    let nonce = "consume-nonce-2";
    let state_param = format!("login:google:{nonce}");
    client
        .get(format!(
            "{base}/auth/callback/google?code=c2&state={state_param}"
        ))
        .header(
            "cookie",
            format!("oss_auth_nonce={nonce}; oss_auth_verifier=v; oss_auth_org={org_slug}"),
        )
        .send()
        .await
        .unwrap();

    let identity_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identities WHERE org_id = $1 AND kind = 'user' AND email = 'testuser@example.com'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        identity_count, 1,
        "re-sign-in must not fork a second identity"
    );

    let membership_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM user_org_memberships m
         JOIN users u ON u.id = m.user_id
         WHERE m.org_id = $1 AND lower(u.email) = 'testuser@example.com'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        membership_count, 1,
        "re-sign-in must not duplicate membership"
    );
}

#[tokio::test]
async fn single_org_mode_bypasses_invite_gate() {
    // CRITICAL: self-hosted SINGLE_ORG_MODE deployments pin every request
    // to one org slug. New orgs default `allow_overslash_managed_signin =
    // true`, which gates on invites — but in single-org mode the operator
    // IS the org admin and there's nobody to mint an invite for them.
    // The bypass must skip the invite gate (and the legacy domain gate)
    // when the configured slug matches.
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

    // Bootstrap a corp org first (managed-signin defaults on) so we know
    // the slug to pin SINGLE_ORG_MODE to.
    let (boot_addr, boot_client) = common::start_api(pool.clone()).await;
    let boot_base = format!("http://{boot_addr}");
    let (org_id, _, _, _) = common::bootstrap_org_identity(&boot_base, &boot_client).await;
    let org_slug = sqlx::query_scalar::<_, String>("SELECT slug FROM orgs WHERE id = $1")
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    // Re-boot with SINGLE_ORG_MODE pinned and env creds set. No invite
    // exists for testuser@example.com — without the bypass this would
    // 403 not_invited.
    let (addr, _) = common::start_api_with(pool.clone(), |cfg| {
        cfg.single_org_mode = Some(org_slug.clone());
        cfg.google_auth_client_id = Some("env_id".into());
        cfg.google_auth_client_secret = Some("env_secret".into());
    })
    .await;
    let base = format!("http://{addr}");
    // Inspect the 303 directly instead of following it to a dead end.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // Repoint Google's endpoints at the mock for the token / userinfo
    // exchange so the callback can complete end-to-end.
    sqlx::query(
        "UPDATE oauth_providers SET token_endpoint = $1, userinfo_endpoint = $2 WHERE key = 'google'",
    )
    .bind(format!("http://{mock_addr}/oauth/token"))
    .bind(format!("http://{mock_addr}/oidc/userinfo"))
    .execute(&pool)
    .await
    .unwrap();

    let nonce = "som-nonce-1";
    let state_param = format!("login:google:{nonce}");
    let resp = client
        .get(format!(
            "{base}/auth/callback/google?code=som1&state={state_param}"
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
        303,
        "SINGLE_ORG_MODE must bypass the invite gate; got {}",
        resp.status(),
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

/// Boot the API with env creds + a google mock, provision a corp org, and
/// point the google provider at the mock (which returns
/// `testuser@example.com`). Returns `(base, client, pool, org_id, org_slug,
/// org_admin_key)` for the domain-admission tests below.
async fn setup_managed_org_with_google_mock() -> (
    String,
    reqwest::Client,
    sqlx::PgPool,
    uuid::Uuid,
    String,
    String,
) {
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

    let (org_id, _, _, org_admin_key) = common::bootstrap_org_identity(&base, &client).await;
    let org_slug = sqlx::query_scalar::<_, String>("SELECT slug FROM orgs WHERE id = $1")
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    (base, client, pool, org_id, org_slug, org_admin_key)
}

#[tokio::test]
async fn callback_admits_by_domain_when_invite_not_required() {
    // Managed sign-in ON + require_invite OFF + domain allowlist. The mock
    // IdP returns testuser@example.com; with `example.com` on the allowlist
    // the user JIT-provisions on first login *without* any invite. Models
    // the Reveni case: any @reveni.io Workspace user self-provisions.
    let (base, client, pool, org_id, org_slug, org_admin_key) =
        setup_managed_org_with_google_mock().await;

    // Open domain admission for example.com via the settings PATCH.
    let resp: Value = client
        .patch(format!("{base}/v1/orgs/{org_id}/managed-signin"))
        .header("authorization", format!("Bearer {org_admin_key}"))
        .json(&json!({
            "require_invite_admission": false,
            "managed_signin_allowed_domains": ["Example.COM", "@example.com", ""],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["require_invite_admission"], false);
    // Normalized: lowercased, leading `@` stripped, empties dropped, deduped.
    assert_eq!(
        resp["managed_signin_allowed_domains"],
        json!(["example.com"]),
        "domains should be normalized + deduped, got: {resp:?}"
    );

    let nonce = "managed-nonce-domain-ok";
    let state_param = format!("login:google:{nonce}");
    let resp = client
        .get(format!(
            "{base}/auth/callback/google?code=mc-domain-ok&state={state_param}"
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
        303,
        "domain-matching email should be admitted without an invite"
    );

    // Membership created with the default `member` role (domain admission
    // never confers admin). The provisioned identity is a plain member.
    let membership_role: String = sqlx::query_scalar(
        "SELECT role FROM user_org_memberships m
         JOIN users u ON u.id = m.user_id
         WHERE m.org_id = $1 AND u.email = 'testuser@example.com'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(membership_role, "member");

    let is_admin: bool = sqlx::query_scalar(
        "SELECT is_org_admin FROM identities
         WHERE org_id = $1 AND kind = 'user' AND email = 'testuser@example.com'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!is_admin, "domain admission must not confer admin");
}

#[tokio::test]
async fn callback_rejects_when_domain_admission_unconfigured() {
    // require_invite OFF but an EMPTY allowlist is a misconfiguration, not
    // "admit everyone" — reject with `domain_admission_not_configured`.
    let (base, client, _pool, org_id, org_slug, org_admin_key) =
        setup_managed_org_with_google_mock().await;

    client
        .patch(format!("{base}/v1/orgs/{org_id}/managed-signin"))
        .header("authorization", format!("Bearer {org_admin_key}"))
        .json(&json!({ "require_invite_admission": false }))
        .send()
        .await
        .unwrap();

    let nonce = "managed-nonce-domain-empty";
    let state_param = format!("login:google:{nonce}");
    let resp = client
        .get(format!(
            "{base}/auth/callback/google?code=mc-domain-empty&state={state_param}"
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
        body["error"]
            .as_str()
            .unwrap()
            .contains("domain_admission_not_configured"),
        "expected domain_admission_not_configured, got: {body:?}"
    );
}

#[tokio::test]
async fn callback_rejects_domain_not_on_allowlist() {
    // require_invite OFF with a non-empty allowlist that does NOT include the
    // user's domain — reject with `domain_not_allowed`.
    let (base, client, _pool, org_id, org_slug, org_admin_key) =
        setup_managed_org_with_google_mock().await;

    client
        .patch(format!("{base}/v1/orgs/{org_id}/managed-signin"))
        .header("authorization", format!("Bearer {org_admin_key}"))
        .json(&json!({
            "require_invite_admission": false,
            "managed_signin_allowed_domains": ["other.com"],
        }))
        .send()
        .await
        .unwrap();

    let nonce = "managed-nonce-domain-mismatch";
    let state_param = format!("login:google:{nonce}");
    let resp = client
        .get(format!(
            "{base}/auth/callback/google?code=mc-domain-mismatch&state={state_param}"
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
        body["error"]
            .as_str()
            .unwrap()
            .contains("domain_not_allowed"),
        "expected domain_not_allowed, got: {body:?}"
    );
}

#[tokio::test]
async fn managed_signin_settings_partial_patch_round_trip() {
    // The PATCH is partial: each field defaults to None and leaves the
    // stored value untouched. Flip fields independently and confirm the
    // others survive.
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (org_id, _, _, org_admin_key) = common::bootstrap_org_identity(&base, &client).await;

    // Set domains only; the two booleans keep their defaults (true/true).
    let resp: Value = client
        .patch(format!("{base}/v1/orgs/{org_id}/managed-signin"))
        .header("authorization", format!("Bearer {org_admin_key}"))
        .json(&json!({ "managed_signin_allowed_domains": ["acme.io"] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["allow_overslash_managed_signin"], true);
    assert_eq!(resp["require_invite_admission"], true);
    assert_eq!(resp["managed_signin_allowed_domains"], json!(["acme.io"]));

    // Flip require_invite only; domains must survive.
    let resp: Value = client
        .patch(format!("{base}/v1/orgs/{org_id}/managed-signin"))
        .header("authorization", format!("Bearer {org_admin_key}"))
        .json(&json!({ "require_invite_admission": false }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["require_invite_admission"], false);
    assert_eq!(
        resp["managed_signin_allowed_domains"],
        json!(["acme.io"]),
        "domains must survive an unrelated partial patch"
    );

    // A fresh GET reflects the persisted state.
    let got: Value = client
        .get(format!("{base}/v1/orgs/{org_id}/managed-signin"))
        .header("authorization", format!("Bearer {org_admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(got["require_invite_admission"], false);
    assert_eq!(got["managed_signin_allowed_domains"], json!(["acme.io"]));
}
