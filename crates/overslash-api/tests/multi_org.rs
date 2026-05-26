//! Integration tests for the multi-org auth surface introduced by this PR.
//!
//! Covers the paths that don't need a live IdP:
//!   * POST /v1/orgs → creator becomes a regular admin member
//!   * POST /auth/switch-org — membership guard + cross-org switch
//!   * GET /v1/account/memberships
//!   * DELETE /v1/account/memberships/{org_id} — personal-org guard,
//!     last-admin guard, normal self-drop
//!   * ALLOW_ORG_CREATION=false → 403 org_creation_disabled
//!   * Subdomain middleware + extractor `org_mismatch` behavior
//!
//! The OAuth callback path (find_or_provision_user → root / subdomain) is
//! exercised indirectly via the HTTP surface once we have an IdP mock; here
//! we use direct DB seeding + forged session cookies (same pattern as
//! `dashboard_only_endpoints.rs`).

#![allow(clippy::disallowed_methods)] // seeding needs raw SQL

mod common;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use overslash_api::services::jwt;
use overslash_db::repos::{identity, membership, org_bootstrap, user as user_repo};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// Mint a session JWT with a `user_id` claim — what the multi-org login
/// flow produces after this PR. Uses the same signing key as `common::start_api`.
fn mint_session_cookie_with_user(org_id: Uuid, identity_id: Uuid, user_id: Option<Uuid>) -> String {
    let secret = hex::decode("cd".repeat(32)).unwrap();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = jwt::Claims {
        sub: identity_id,
        org: org_id,
        email: "multi-org-test@example.com".into(),
        aud: jwt::AUD_SESSION.into(),
        iat: now,
        exp: now + 3600,
        user_id,
        mcp_client_id: None,
    };
    jwt::mint(&secret, &claims).expect("mint")
}

/// Minimal seed: a pair of orgs + a users row + an identity for the caller
/// in the first org, linked via user_id + membership.
async fn seed_user_with_single_org(pool: &PgPool) -> (Uuid, Uuid, Uuid) {
    let org_id: Uuid =
        sqlx::query_scalar("INSERT INTO orgs (name, slug) VALUES ('Primary', $1) RETURNING id")
            .bind(format!("primary-{}", Uuid::new_v4().simple()))
            .fetch_one(pool)
            .await
            .unwrap();
    overslash_db::repos::org_bootstrap::bootstrap_org(pool, org_id, None)
        .await
        .unwrap();

    let user = user_repo::create_overslash_backed(
        pool,
        Some("alice@multiorg.test"),
        Some("Alice"),
        "google",
        &format!("sub-{}", Uuid::new_v4()),
    )
    .await
    .unwrap();

    let ident = identity::create_with_email(
        pool,
        org_id,
        "Alice",
        "user",
        None,
        Some("alice@multiorg.test"),
        json!({}),
    )
    .await
    .unwrap();
    identity::set_is_org_admin(pool, org_id, ident.id, true)
        .await
        .unwrap();
    identity::set_user_id(pool, org_id, ident.id, Some(user.id))
        .await
        .unwrap();

    membership::create(pool, user.id, org_id, membership::ROLE_ADMIN)
        .await
        .unwrap();

    (org_id, ident.id, user.id)
}

#[tokio::test]
async fn post_v1_orgs_attaches_admin_membership_when_session_present() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (_, identity_id, user_id) = seed_user_with_single_org(&pool).await;
    let primary_org: Uuid = sqlx::query_scalar("SELECT org_id FROM identities WHERE id = $1")
        .bind(identity_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    let cookie = mint_session_cookie_with_user(primary_org, identity_id, Some(user_id));
    let slug = format!("acme-{}", Uuid::new_v4().simple());
    let resp = client
        .post(format!("{base}/v1/orgs"))
        .header("cookie", format!("oss_session={cookie}"))
        .json(&json!({ "name": "Acme", "slug": slug }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .map(|v| v.to_str().unwrap().to_string());
    let body: Value = resp.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "body={body}");

    let new_org_id: Uuid = serde_json::from_value(body["id"].clone()).unwrap();
    assert_eq!(body["is_personal"], Value::Bool(false));
    assert!(body["redirect_to"].is_string() || body["redirect_to"].is_null());

    let m = membership::find(&pool, user_id, new_org_id)
        .await
        .unwrap()
        .expect("creator membership");
    assert_eq!(
        m.role, "admin",
        "creator is a regular admin — no special flag"
    );

    // The response must re-mint the session cookie scoped to the NEW org;
    // without this the dashboard lands on the new subdomain carrying the
    // old JWT and trips the subdomain↔JWT guard. The new JWT's `org` and
    // `sub` must point at the new org + its bootstrap identity.
    let raw_cookie = set_cookie.expect("create_org must Set-Cookie the new session");
    let token = raw_cookie
        .split(';')
        .next()
        .and_then(|kv| kv.trim().strip_prefix("oss_session="))
        .expect("Set-Cookie carries an oss_session token");
    let secret = hex::decode("cd".repeat(32)).unwrap();
    let claims = overslash_api::services::jwt::verify(
        &secret,
        token,
        overslash_api::services::jwt::AUD_SESSION,
    )
    .expect("new session JWT verifies");
    assert_eq!(claims.org, new_org_id);
    assert_eq!(claims.user_id, Some(user_id));
    // `sub` must be the bootstrap-admin identity in the new org, not the
    // caller's identity from the old org.
    assert_ne!(claims.sub, identity_id);
    let bootstrap_ident: Uuid =
        sqlx::query_scalar("SELECT id FROM identities WHERE org_id = $1 AND kind = 'user'")
            .bind(new_org_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(claims.sub, bootstrap_ident);
}

#[tokio::test]
async fn post_v1_orgs_without_session_creates_orphan_org() {
    // Legacy bootstrap path (test harness, provisioning scripts): anonymous
    // POST /v1/orgs creates the org with NO memberships. Subsequent members
    // join through the org's IdP once it's configured.
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let slug = format!("orphan-{}", Uuid::new_v4().simple());
    let resp = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({ "name": "Orphan", "slug": slug }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    let new_org_id: Uuid = serde_json::from_value(body["id"].clone()).unwrap();

    // Zero memberships for this org.
    let rows: Vec<overslash_db::repos::membership::MembershipRow> =
        membership::list_for_org(&pool, new_org_id).await.unwrap();
    assert!(
        rows.is_empty(),
        "anonymous create must not attach a bootstrap admin"
    );
}

#[tokio::test]
async fn check_slug_and_collision() {
    // Live-validation endpoint used by the create-org modal:
    //   * malformed slug → not available, reason=slug_*
    //   * reserved slug  → not available, reason=slug_reserved
    //   * free slug      → available
    //   * taken slug     → not available, reason=slug_taken
    // And: POST /v1/orgs on a taken slug must return 409 slug_taken
    // rather than a generic 500 from the sqlx unique-violation.
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    // Malformed (uppercase) → slug_invalid_chars.
    let resp: Value = client
        .get(format!("{base}/v1/orgs/check-slug?slug=BadSlug"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["available"], Value::Bool(false));
    assert_eq!(resp["reason"], "slug_invalid_chars");

    // Reserved.
    let resp: Value = client
        .get(format!("{base}/v1/orgs/check-slug?slug=admin"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["available"], Value::Bool(false));
    assert_eq!(resp["reason"], "slug_reserved");

    // Fresh slug → available.
    let fresh = format!("fresh-{}", Uuid::new_v4().simple());
    let resp: Value = client
        .get(format!("{base}/v1/orgs/check-slug?slug={fresh}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["available"], Value::Bool(true));

    // Create it, then re-check → slug_taken.
    let create = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({ "name": "Fresh", "slug": fresh }))
        .send()
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::OK);

    let resp: Value = client
        .get(format!("{base}/v1/orgs/check-slug?slug={fresh}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["available"], Value::Bool(false));
    assert_eq!(resp["reason"], "slug_taken");

    // POST collision → 409 with stable error code.
    let dupe = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({ "name": "Duplicate", "slug": fresh }))
        .send()
        .await
        .unwrap();
    assert_eq!(dupe.status(), StatusCode::CONFLICT);
    let body: Value = dupe.json().await.unwrap();
    assert_eq!(body["error"], "slug_taken");
}

#[tokio::test]
async fn allow_org_creation_false_returns_403() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api_with(pool.clone(), |cfg| {
        cfg.allow_org_creation = false;
    })
    .await;
    let base = format!("http://{addr}");
    let (_, identity_id, user_id) = seed_user_with_single_org(&pool).await;
    let primary_org: Uuid = sqlx::query_scalar("SELECT org_id FROM identities WHERE id = $1")
        .bind(identity_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    let cookie = mint_session_cookie_with_user(primary_org, identity_id, Some(user_id));
    let resp = client
        .post(format!("{base}/v1/orgs"))
        .header("cookie", format!("oss_session={cookie}"))
        .json(&json!({ "name": "Blocked", "slug": format!("blk-{}", Uuid::new_v4().simple()) }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("org_creation_disabled")
            || body["message"]
                .as_str()
                .unwrap_or_default()
                .contains("org_creation_disabled")
    );
}

#[tokio::test]
async fn switch_org_requires_membership() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_a, identity_id, user_id) = seed_user_with_single_org(&pool).await;

    // A second org the user is NOT a member of.
    let org_b: Uuid =
        sqlx::query_scalar("INSERT INTO orgs (name, slug) VALUES ('B', $1) RETURNING id")
            .bind(format!("b-{}", Uuid::new_v4().simple()))
            .fetch_one(&pool)
            .await
            .unwrap();

    let cookie = mint_session_cookie_with_user(org_a, identity_id, Some(user_id));
    let resp = client
        .post(format!("{base}/auth/switch-org"))
        .header("cookie", format!("oss_session={cookie}"))
        .json(&json!({ "org_id": org_b }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn list_and_drop_memberships_round_trip() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, identity_id, user_id) = seed_user_with_single_org(&pool).await;

    // Add a second, non-personal org membership we can freely drop.
    let org_b: Uuid =
        sqlx::query_scalar("INSERT INTO orgs (name, slug) VALUES ('Second', $1) RETURNING id")
            .bind(format!("second-{}", Uuid::new_v4().simple()))
            .fetch_one(&pool)
            .await
            .unwrap();
    // Add another admin so dropping user's own membership doesn't trip the
    // last-admin guard.
    let other = user_repo::create_org_only(&pool, Some("other@x.test"), Some("Other"))
        .await
        .unwrap();
    membership::create(&pool, other.id, org_b, membership::ROLE_ADMIN)
        .await
        .unwrap();
    membership::create(&pool, user_id, org_b, membership::ROLE_ADMIN)
        .await
        .unwrap();

    let cookie = mint_session_cookie_with_user(org_id, identity_id, Some(user_id));

    // LIST shows both
    let resp = client
        .get(format!("{base}/v1/account/memberships"))
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    let memberships = body["memberships"].as_array().unwrap();
    assert_eq!(memberships.len(), 2);

    // DELETE the second org's membership — should succeed (another admin exists).
    let del = client
        .delete(format!("{base}/v1/account/memberships/{org_b}"))
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(del.status(), StatusCode::OK, "body={:?}", del.text().await);

    // And now only one membership remains.
    let after: Value = client
        .get(format!("{base}/v1/account/memberships"))
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(after["memberships"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn cannot_drop_last_admin() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, identity_id, user_id) = seed_user_with_single_org(&pool).await;

    // The seed's admin membership IS the only admin of this (non-personal) org.
    let cookie = mint_session_cookie_with_user(org_id, identity_id, Some(user_id));
    let resp = client
        .delete(format!("{base}/v1/account/memberships/{org_id}"))
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    let msg = body["error"]
        .as_str()
        .or_else(|| body["message"].as_str())
        .unwrap_or_default();
    assert!(
        msg.contains("last admin"),
        "expected last-admin error, got: {msg}"
    );
}

#[tokio::test]
async fn cannot_drop_personal_org_membership() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (_, identity_id, user_id) = seed_user_with_single_org(&pool).await;
    // Promote the seed's org into a personal org for this test — same
    // machinery as what the root-login provisioning produces.
    let primary_org: Uuid = sqlx::query_scalar("SELECT org_id FROM identities WHERE id = $1")
        .bind(identity_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE orgs SET is_personal = true WHERE id = $1")
        .bind(primary_org)
        .execute(&pool)
        .await
        .unwrap();

    let cookie = mint_session_cookie_with_user(primary_org, identity_id, Some(user_id));
    let resp = client
        .delete(format!("{base}/v1/account/memberships/{primary_org}"))
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn subdomain_mismatch_returns_401() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api_with(pool.clone(), |cfg| {
        cfg.app_host_suffix = Some("app.test".into());
    })
    .await;
    let base = format!("http://{addr}");
    let (org_a, identity_id, user_id) = seed_user_with_single_org(&pool).await;

    // A second org with a known slug the subdomain middleware can resolve.
    let other_slug = format!("other-{}", Uuid::new_v4().simple());
    let _org_b: Uuid =
        sqlx::query_scalar("INSERT INTO orgs (name, slug) VALUES ('Other', $1) RETURNING id")
            .bind(&other_slug)
            .fetch_one(&pool)
            .await
            .unwrap();

    // Session scoped to org_a, but Host announces <other_slug>.app.test.
    let cookie = mint_session_cookie_with_user(org_a, identity_id, Some(user_id));
    let resp = client
        .get(format!("{base}/v1/account/memberships"))
        .header("host", format!("{other_slug}.app.test"))
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn single_org_mode_pins_every_request_to_one_org() {
    let pool = common::test_pool().await;
    // Seed the org we'll pin to BEFORE starting the server, then thread its
    // slug into the config so the middleware resolves it at request time.
    let (org_id, identity_id, user_id) = seed_user_with_single_org(&pool).await;
    let slug: String = sqlx::query_scalar("SELECT slug FROM orgs WHERE id = $1")
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    let (addr, client) = common::start_api_with(pool.clone(), move |cfg| {
        cfg.single_org_mode = Some(slug.clone());
        // app_host_suffix unset → subdomain middleware would normally return
        // Root; SINGLE_ORG_MODE overrides both paths.
    })
    .await;
    let base = format!("http://{addr}");

    let cookie = mint_session_cookie_with_user(org_id, identity_id, Some(user_id));
    // Any host, including a would-be-other subdomain, must resolve to org_id
    // without the extractor flagging mismatch.
    let resp = client
        .get(format!("{base}/v1/account/memberships"))
        .header("host", "anything.app.invalid")
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "body={:?}",
        resp.text().await
    );
}

#[tokio::test]
async fn subdomain_middleware_routes_known_slug_and_rejects_noise() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api_with(pool.clone(), |cfg| {
        cfg.app_host_suffix = Some("app.test".into());
    })
    .await;
    let base = format!("http://{addr}");

    let (org_id, _identity_id, _user_id) = seed_user_with_single_org(&pool).await;
    let slug: String = sqlx::query_scalar("SELECT slug FROM orgs WHERE id = $1")
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    // Known slug → health endpoint still answers 200 (middleware resolves org).
    let ok = client
        .get(format!("{base}/health"))
        .header("host", format!("{slug}.app.test"))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);

    // Unknown subdomain → 404 org_not_found.
    let bad = client
        .get(format!("{base}/health"))
        .header("host", "never-existed.app.test")
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::NOT_FOUND);
    let body: Value = bad.json().await.unwrap();
    assert_eq!(body["error"], "org_not_found");

    // Dotted sub-sub-domain → 404 (slugs are single DNS labels).
    let dotted = client
        .get(format!("{base}/health"))
        .header("host", "foo.bar.app.test")
        .send()
        .await
        .unwrap();
    assert_eq!(dotted.status(), StatusCode::NOT_FOUND);

    // Personal org subdomain → 404 personal_org_unreachable. Flip the seeded
    // org to personal to exercise the branch.
    sqlx::query("UPDATE orgs SET is_personal = true WHERE id = $1")
        .bind(org_id)
        .execute(&pool)
        .await
        .unwrap();
    let personal = client
        .get(format!("{base}/health"))
        .header("host", format!("{slug}.app.test"))
        .send()
        .await
        .unwrap();
    assert_eq!(personal.status(), StatusCode::NOT_FOUND);
    let personal_body: Value = personal.json().await.unwrap();
    assert_eq!(personal_body["error"], "personal_org_unreachable");
}

#[tokio::test]
async fn list_auth_providers_scope_on_org_subdomain() {
    // /auth/providers honors RequestOrgContext. On a corp subdomain we
    // should get `scope: "org"` and only the org's IdPs (none here, so
    // an empty list — the dashboard renders an explanatory state for this).
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api_with(pool.clone(), |cfg| {
        cfg.app_host_suffix = Some("app.test".into());
    })
    .await;
    let base = format!("http://{addr}");

    let (org_id, _identity_id, _user_id) = seed_user_with_single_org(&pool).await;
    let slug: String = sqlx::query_scalar("SELECT slug FROM orgs WHERE id = $1")
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    let resp: Value = client
        .get(format!("{base}/auth/providers"))
        .header("host", format!("{slug}.app.test"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["scope"], "org");
    assert_eq!(resp["providers"].as_array().unwrap().len(), 0);

    // On root it's scope: "root" (no env creds configured in tests → empty list).
    let resp_root: Value = client
        .get(format!("{base}/auth/providers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp_root["scope"], "root");
}

#[tokio::test]
async fn concurrent_drops_do_not_deadlock_and_preserve_last_admin() {
    // Two admins racing to leave the same org: one must succeed, the other
    // must fail with the "last admin" guard. Neither may 500 with a
    // deadlock_detected (40P01) from the prior two-step lock order.
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let (org_id, _, user_a) = seed_user_with_single_org(&pool).await;
    let identity_a: Uuid = sqlx::query_scalar(
        "SELECT id FROM identities WHERE user_id = $1 AND org_id = $2 AND kind = 'user'",
    )
    .bind(user_a)
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Add a second admin to the same org.
    let user_b_row = user_repo::create_org_only(&pool, Some("b@x.test"), Some("Bob"))
        .await
        .unwrap();
    let identity_b = identity::create_with_email(
        &pool,
        org_id,
        "Bob",
        "user",
        None,
        Some("b@x.test"),
        json!({}),
    )
    .await
    .unwrap();
    identity::set_is_org_admin(&pool, org_id, identity_b.id, true)
        .await
        .unwrap();
    identity::set_user_id(&pool, org_id, identity_b.id, Some(user_b_row.id))
        .await
        .unwrap();
    membership::create(&pool, user_b_row.id, org_id, membership::ROLE_ADMIN)
        .await
        .unwrap();

    let cookie_a = mint_session_cookie_with_user(org_id, identity_a, Some(user_a));
    let cookie_b = mint_session_cookie_with_user(org_id, identity_b.id, Some(user_b_row.id));

    let fut_a = client
        .delete(format!("{base}/v1/account/memberships/{org_id}"))
        .header("cookie", format!("oss_session={cookie_a}"))
        .send();
    let fut_b = client
        .delete(format!("{base}/v1/account/memberships/{org_id}"))
        .header("cookie", format!("oss_session={cookie_b}"))
        .send();

    let (resp_a, resp_b) = tokio::join!(fut_a, fut_b);
    let (status_a, status_b) = (resp_a.unwrap().status(), resp_b.unwrap().status());

    let statuses = [status_a, status_b];
    assert!(
        statuses.contains(&StatusCode::OK),
        "one must succeed: {statuses:?}"
    );
    assert!(
        statuses.contains(&StatusCode::BAD_REQUEST),
        "the other must fail with last-admin guard: {statuses:?}"
    );
    // Neither path should produce a 500 deadlock_detected error.
    for s in statuses {
        assert_ne!(s, StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Exactly one admin remains.
    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_org_memberships WHERE org_id = $1 AND role = 'admin'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(remaining, 1);
}

// ---------------------------------------------------------------------------
// Creator-admin lifecycle audit events (migration 067)
// ---------------------------------------------------------------------------
//
// Three facts the audit page now surfaces:
//   * `org.creator_admin_added` — fires on POST /v1/orgs WITH a session;
//     skipped when the org is created anonymously (no admin to record).
//   * `membership.removed` — fires on every DELETE /v1/account/memberships/{id},
//     carrying `was_original_creator: bool` derived from `orgs.creator_user_id`.
//   * `orgs.creator_user_id` is populated idempotently — retry paths can't
//     silently rewrite history.

async fn fetch_audit_actions(pool: &PgPool, org_id: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT action FROM audit_log WHERE org_id = $1 ORDER BY created_at, id")
        .bind(org_id)
        .fetch_all(pool)
        .await
        .unwrap()
}

async fn fetch_audit_detail(
    pool: &PgPool,
    org_id: Uuid,
    action: &str,
) -> Option<serde_json::Value> {
    sqlx::query_scalar(
        "SELECT detail FROM audit_log WHERE org_id = $1 AND action = $2 ORDER BY created_at LIMIT 1",
    )
    .bind(org_id)
    .bind(action)
    .fetch_optional(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn post_v1_orgs_with_session_records_creator_and_emits_audit() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (_, identity_id, user_id) = seed_user_with_single_org(&pool).await;
    let primary_org: Uuid = sqlx::query_scalar("SELECT org_id FROM identities WHERE id = $1")
        .bind(identity_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    let cookie = mint_session_cookie_with_user(primary_org, identity_id, Some(user_id));
    let slug = format!("creator-audit-{}", Uuid::new_v4().simple());
    let resp = client
        .post(format!("{base}/v1/orgs"))
        .header("cookie", format!("oss_session={cookie}"))
        .json(&json!({ "name": "CreatorAudit", "slug": slug }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    let new_org_id: Uuid = serde_json::from_value(body["id"].clone()).unwrap();

    // `creator_user_id` is recorded on the org row.
    let creator_user_id: Option<Uuid> =
        sqlx::query_scalar("SELECT creator_user_id FROM orgs WHERE id = $1")
            .bind(new_org_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(creator_user_id, Some(user_id));

    // Both `org.created` and `org.creator_admin_added` are in the audit log.
    let actions = fetch_audit_actions(&pool, new_org_id).await;
    assert!(
        actions.contains(&"org.created".to_string()),
        "expected org.created in {actions:?}"
    );
    assert!(
        actions.contains(&"org.creator_admin_added".to_string()),
        "expected org.creator_admin_added in {actions:?}"
    );

    // Detail carries the user_id and role so the audit page can render WHO
    // got admin without joining further tables.
    let detail = fetch_audit_detail(&pool, new_org_id, "org.creator_admin_added")
        .await
        .expect("audit detail");
    assert_eq!(
        detail["user_id"].as_str(),
        Some(user_id.to_string().as_str())
    );
    assert_eq!(detail["role"], Value::String("admin".into()));
}

#[tokio::test]
async fn post_v1_orgs_anonymous_skips_creator_admin_audit() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let slug = format!("orphan-audit-{}", Uuid::new_v4().simple());
    let resp = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({ "name": "OrphanAudit", "slug": slug }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    let new_org_id: Uuid = serde_json::from_value(body["id"].clone()).unwrap();

    let creator_user_id: Option<Uuid> =
        sqlx::query_scalar("SELECT creator_user_id FROM orgs WHERE id = $1")
            .bind(new_org_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        creator_user_id.is_none(),
        "anonymous create must leave creator_user_id NULL"
    );

    let actions = fetch_audit_actions(&pool, new_org_id).await;
    assert!(
        actions.contains(&"org.created".to_string()),
        "org.created always fires"
    );
    assert!(
        !actions.contains(&"org.creator_admin_added".to_string()),
        "creator_admin_added must NOT fire when there's no admin to record: {actions:?}"
    );
}

#[tokio::test]
async fn drop_membership_emits_audit_with_creator_flag_true() {
    // Founder leaves their own org (after promoting a second admin so the
    // last-admin guard doesn't fire). `membership.removed` audit row must
    // carry `was_original_creator: true`.
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (_, identity_id, user_id) = seed_user_with_single_org(&pool).await;

    // Create a fresh org via the HTTP surface so `creator_user_id` is set
    // by the production code path (not by the seed helper).
    let cookie = mint_session_cookie_with_user(
        sqlx::query_scalar("SELECT org_id FROM identities WHERE id = $1")
            .bind(identity_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        identity_id,
        Some(user_id),
    );
    let slug = format!("founder-leave-{}", Uuid::new_v4().simple());
    let create = client
        .post(format!("{base}/v1/orgs"))
        .header("cookie", format!("oss_session={cookie}"))
        .json(&json!({ "name": "FounderLeave", "slug": slug }))
        .send()
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::OK);
    let create_body: Value = create.json().await.unwrap();
    let new_org_id: Uuid = serde_json::from_value(create_body["id"].clone()).unwrap();

    // Promote a second admin so the founder can actually drop their seat
    // (last-admin guard would otherwise block the DELETE). POST /v1/orgs
    // already created the founder's membership in the new org.
    let other = user_repo::create_org_only(&pool, Some("other@founder.test"), Some("Other"))
        .await
        .unwrap();
    membership::create(&pool, other.id, new_org_id, membership::ROLE_ADMIN)
        .await
        .unwrap();

    // Mint a session for the founder in the new org. We need the bootstrap
    // identity in this org (different from the seed's identity_id).
    let bootstrap_ident: Uuid =
        sqlx::query_scalar("SELECT id FROM identities WHERE org_id = $1 AND kind = 'user'")
            .bind(new_org_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let cookie_in_new = mint_session_cookie_with_user(new_org_id, bootstrap_ident, Some(user_id));
    let drop = client
        .delete(format!("{base}/v1/account/memberships/{new_org_id}"))
        .header("cookie", format!("oss_session={cookie_in_new}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        drop.status(),
        StatusCode::OK,
        "drop: {:?}",
        drop.text().await
    );

    let detail = fetch_audit_detail(&pool, new_org_id, "membership.removed")
        .await
        .expect("membership.removed must be logged");
    assert_eq!(detail["was_original_creator"], Value::Bool(true));
    assert_eq!(detail["was_admin"], Value::Bool(true));
    assert_eq!(
        detail["user_id"].as_str(),
        Some(user_id.to_string().as_str())
    );
}

#[tokio::test]
async fn drop_membership_emits_audit_with_creator_flag_false_for_non_creator() {
    // A regular member (not the founder) leaves. `was_original_creator` must
    // be false; `was_admin` reflects whether they held the admin role.
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (_, identity_id, user_id) = seed_user_with_single_org(&pool).await;

    // Seed-helper creates org_id with creator_user_id=NULL (it bypasses the
    // route layer). Set it explicitly to a non-`user_id` so the leaver is
    // clearly NOT the founder.
    let org_id: Uuid = sqlx::query_scalar("SELECT org_id FROM identities WHERE id = $1")
        .bind(identity_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let founder = user_repo::create_org_only(&pool, Some("founder@x.test"), Some("Founder"))
        .await
        .unwrap();
    sqlx::query("UPDATE orgs SET creator_user_id = $2 WHERE id = $1")
        .bind(org_id)
        .bind(founder.id)
        .execute(&pool)
        .await
        .unwrap();
    membership::create(&pool, founder.id, org_id, membership::ROLE_ADMIN)
        .await
        .unwrap();

    // The seed user is already an admin; downgrade to plain member so
    // `was_admin: false` is also exercised on the same path.
    sqlx::query(
        "UPDATE user_org_memberships SET role = 'member' WHERE user_id = $1 AND org_id = $2",
    )
    .bind(user_id)
    .bind(org_id)
    .execute(&pool)
    .await
    .unwrap();

    let cookie = mint_session_cookie_with_user(org_id, identity_id, Some(user_id));
    let drop = client
        .delete(format!("{base}/v1/account/memberships/{org_id}"))
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(drop.status(), StatusCode::OK);

    let detail = fetch_audit_detail(&pool, org_id, "membership.removed")
        .await
        .expect("membership.removed must be logged");
    assert_eq!(detail["was_original_creator"], Value::Bool(false));
    assert_eq!(detail["was_admin"], Value::Bool(false));
    assert_eq!(
        detail["user_id"].as_str(),
        Some(user_id.to_string().as_str())
    );
}

#[tokio::test]
async fn set_creator_user_id_is_idempotent() {
    // `org::set_creator_user_id` MUST only set when NULL — a retry path
    // (e.g. POST /v1/orgs called twice on the same org_id) must not silently
    // rewrite the founder.
    let pool = common::test_pool().await;
    let org_id: Uuid =
        sqlx::query_scalar("INSERT INTO orgs (name, slug) VALUES ('Idem', $1) RETURNING id")
            .bind(format!("idem-{}", Uuid::new_v4().simple()))
            .fetch_one(&pool)
            .await
            .unwrap();

    let first = user_repo::create_org_only(&pool, Some("first@idem.test"), Some("First"))
        .await
        .unwrap();
    let second = user_repo::create_org_only(&pool, Some("second@idem.test"), Some("Second"))
        .await
        .unwrap();

    let set1 = overslash_db::repos::org::set_creator_user_id(&pool, org_id, first.id)
        .await
        .unwrap();
    assert!(set1, "first call sets the field");

    let set2 = overslash_db::repos::org::set_creator_user_id(&pool, org_id, second.id)
        .await
        .unwrap();
    assert!(!set2, "second call must NOT overwrite an existing creator");

    let actual: Option<Uuid> = sqlx::query_scalar("SELECT creator_user_id FROM orgs WHERE id = $1")
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(actual, Some(first.id));
}

// ---------------------------------------------------------------------------
// Org switching from the OAuth consent page
//
// The consent flow is org-locked at /oauth/authorize time, so switching can't
// be a cookie flip — POST /v1/oauth/consent/{request_id}/switch-org clones the
// pending request into the target org and re-mints the session cookie.
// ---------------------------------------------------------------------------

fn pkce() -> (String, String) {
    let verifier = URL_SAFE_NO_PAD.encode(b"pkce-verifier-0123456789abcdefghij");
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

async fn register_mcp_client(client: &reqwest::Client, base: &str, redirect_uri: &str) -> String {
    let resp = client
        .post(format!("{base}/oauth/register"))
        .json(&json!({
            "client_name": "switch-org-client",
            "redirect_uris": [redirect_uri],
            "token_endpoint_auth_method": "none",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "DCR must return 201");
    let body: Value = resp.json().await.unwrap();
    body["client_id"].as_str().unwrap().to_string()
}

/// Seed a second org for an existing user: bootstrap it, create the user-kind
/// identity, link it via user_id, and add an admin membership.
async fn seed_extra_org(pool: &PgPool, user_id: Uuid, label: &str) -> (Uuid, Uuid) {
    let org_id: Uuid =
        sqlx::query_scalar("INSERT INTO orgs (name, slug) VALUES ($1, $2) RETURNING id")
            .bind(label)
            .bind(format!(
                "{}-{}",
                label.to_lowercase(),
                Uuid::new_v4().simple()
            ))
            .fetch_one(pool)
            .await
            .unwrap();
    org_bootstrap::bootstrap_org(pool, org_id, None)
        .await
        .unwrap();
    let ident = identity::create_with_email(
        pool,
        org_id,
        "Alice",
        "user",
        None,
        Some("alice@multiorg.test"),
        json!({}),
    )
    .await
    .unwrap();
    identity::set_user_id(pool, org_id, ident.id, Some(user_id))
        .await
        .unwrap();
    membership::create(pool, user_id, org_id, membership::ROLE_ADMIN)
        .await
        .unwrap();
    (org_id, ident.id)
}

/// Drive /oauth/authorize with a forged session cookie and return the
/// `request_id` from the consent redirect.
async fn authorize_to_request_id(
    base: &str,
    cookie: &str,
    client_id: &str,
    redirect: &str,
    challenge: &str,
) -> String {
    let no_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let url = format!(
        "{base}/oauth/authorize?response_type=code&client_id={}\
         &redirect_uri={}&code_challenge={}&code_challenge_method=S256&scope=mcp&state=abc",
        urlencoding::encode(client_id),
        urlencoding::encode(redirect),
        urlencoding::encode(challenge),
    );
    let resp = no_redirect
        .get(&url)
        .header("cookie", format!("oss_session={cookie}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "authorize → consent");
    let loc = resp.headers()[reqwest::header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    let request_id = loc
        .split(&['?', '&'][..])
        .find_map(|p| p.strip_prefix("request_id="))
        .expect("consent redirect missing request_id");
    urlencoding::decode(request_id).unwrap().into_owned()
}

#[tokio::test]
async fn consent_switch_org_rebinds_to_target_org() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_a, ident_a, user_id) = seed_user_with_single_org(&pool).await;
    let (org_b, _ident_b) = seed_extra_org(&pool, user_id, "Beta").await;

    let redirect = "http://127.0.0.1:9999/callback";
    let client_id = register_mcp_client(&client, &base, redirect).await;
    let (_v, challenge) = pkce();
    let cookie_a = mint_session_cookie_with_user(org_a, ident_a, Some(user_id));

    let request_id =
        authorize_to_request_id(&base, &cookie_a, &client_id, redirect, &challenge).await;

    // Switch to org B.
    let resp = client
        .post(format!("{base}/v1/oauth/consent/{request_id}/switch-org"))
        .header("cookie", format!("oss_session={cookie_a}"))
        .json(&json!({ "org_id": org_b }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let new_cookie = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|c| c.split(';').next())
        .and_then(|kv| kv.trim().strip_prefix("oss_session="))
        .expect("switch-org must re-mint the session cookie")
        .to_string();
    let body: Value = resp.json().await.unwrap();
    let new_request_id = body["request_id"]
        .as_str()
        .expect("new request_id")
        .to_string();
    assert_ne!(
        new_request_id, request_id,
        "switch issues a fresh request_id"
    );
    assert!(
        body["redirect_to"]
            .as_str()
            .unwrap()
            .contains("/oauth/consent?request_id="),
        "redirect_to points back to the consent page"
    );

    // The fresh request, fetched with the new cookie, is bound to org B.
    let ctx: Value = client
        .get(format!("{base}/v1/oauth/consent/{new_request_id}"))
        .header("cookie", format!("oss_session={new_cookie}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ctx["org_id"].as_str().unwrap(), org_b.to_string());
}

#[tokio::test]
async fn consent_switch_org_rejects_non_member() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_a, ident_a, user_id) = seed_user_with_single_org(&pool).await;

    // An org the user is NOT a member of.
    let stranger_org: Uuid =
        sqlx::query_scalar("INSERT INTO orgs (name, slug) VALUES ('Stranger', $1) RETURNING id")
            .bind(format!("stranger-{}", Uuid::new_v4().simple()))
            .fetch_one(&pool)
            .await
            .unwrap();

    let redirect = "http://127.0.0.1:9999/callback";
    let client_id = register_mcp_client(&client, &base, redirect).await;
    let (_v, challenge) = pkce();
    let cookie_a = mint_session_cookie_with_user(org_a, ident_a, Some(user_id));
    let request_id =
        authorize_to_request_id(&base, &cookie_a, &client_id, redirect, &challenge).await;

    let resp = client
        .post(format!("{base}/v1/oauth/consent/{request_id}/switch-org"))
        .header("cookie", format!("oss_session={cookie_a}"))
        .json(&json!({ "org_id": stranger_org }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn consent_switch_org_rejects_different_user() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_a, ident_a, user_id) = seed_user_with_single_org(&pool).await;
    let (org_b, _ident_b) = seed_extra_org(&pool, user_id, "Beta").await;

    let redirect = "http://127.0.0.1:9999/callback";
    let client_id = register_mcp_client(&client, &base, redirect).await;
    let (_v, challenge) = pkce();
    let cookie_a = mint_session_cookie_with_user(org_a, ident_a, Some(user_id));
    let request_id =
        authorize_to_request_id(&base, &cookie_a, &client_id, redirect, &challenge).await;

    // A session for a different identity (sub) in the same org tries to switch
    // the pending request — rejected before any org work.
    let other_cookie = mint_session_cookie_with_user(org_a, Uuid::new_v4(), Some(user_id));
    let resp = client
        .post(format!("{base}/v1/oauth/consent/{request_id}/switch-org"))
        .header("cookie", format!("oss_session={other_cookie}"))
        .json(&json!({ "org_id": org_b }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
