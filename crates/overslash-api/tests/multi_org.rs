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

use overslash_api::services::jwt;
use overslash_db::repos::{identity, membership, user as user_repo};
use reqwest::StatusCode;
use serde_json::{Value, json};
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
