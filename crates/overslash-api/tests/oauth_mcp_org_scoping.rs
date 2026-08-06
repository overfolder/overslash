//! Integration tests for MCP enrollment org-scoping
//! (`docs/design/mcp-enrollment-org-scoping.md`).
//!
//! The invariant under test: on a corp subdomain
//! (`<slug>.api.overslash.com`), an MCP client always enrolls its agent into
//! *that* org — never into whatever org a stale session happens to hold. Root
//! (`app.overslash.com`) stays the multi-org hub: enrollment follows the
//! session org there, which may itself be a corp org.
//!
//! We drive the real HTTP surface with forged session cookies (signed with the
//! test signing key) and an `x-forwarded-host` header to select the subdomain
//! context — the same pattern as `subdomain_oauth_as.rs` and `multi_org.rs`.

#![allow(clippy::disallowed_methods)] // seeding needs raw SQL

use crate::common;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use overslash_api::services::jwt;
use overslash_db::repos::{identity, mcp_client_agent_binding, membership, org_bootstrap, user};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

const SUFFIX: &str = "api.test";

fn signing_secret() -> Vec<u8> {
    hex::decode("cd".repeat(32)).unwrap()
}

fn mint_session(org_id: Uuid, identity_id: Uuid, user_id: Uuid, email: &str) -> String {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = jwt::Claims {
        sub: identity_id,
        org: org_id,
        email: email.into(),
        aud: jwt::AUD_SESSION.into(),
        iat: now,
        exp: now + 3600,
        user_id: Some(user_id),
        mcp_client_id: None,
    };
    jwt::mint(&signing_secret(), &claims).expect("mint session")
}

fn pkce() -> (String, String) {
    let verifier = URL_SAFE_NO_PAD.encode(b"pkce-verifier-0123456789abcdefghij");
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

struct OrgSeed {
    org_id: Uuid,
    slug: String,
    host: String,
    ident_id: Uuid,
    user_id: Uuid,
    email: String,
}

/// Seed a subdomain-resolvable corp org (is_personal=false) with an admin user
/// identity linked via a `users` row + membership.
async fn seed_corp_org(pool: &PgPool, name: &str) -> OrgSeed {
    let slug = format!("{}-{}", name.to_lowercase(), Uuid::new_v4().simple());
    let org_id: Uuid = sqlx::query_scalar(
        "INSERT INTO orgs (name, slug, is_personal) VALUES ($1, $2, false) RETURNING id",
    )
    .bind(name)
    .bind(&slug)
    .fetch_one(pool)
    .await
    .unwrap();
    org_bootstrap::bootstrap_org(pool, org_id, None)
        .await
        .unwrap();

    let email = format!(
        "alice-{}@{}.test",
        Uuid::new_v4().simple(),
        name.to_lowercase()
    );
    let u = user::create_overslash_backed(
        pool,
        Some(&email),
        Some("Alice"),
        "google",
        &format!("sub-{}", Uuid::new_v4()),
    )
    .await
    .unwrap();
    let ident =
        identity::create_with_email(pool, org_id, "Alice", "user", None, Some(&email), json!({}))
            .await
            .unwrap();
    identity::set_is_org_admin(pool, org_id, ident.id, true)
        .await
        .unwrap();
    identity::set_user_id(pool, org_id, ident.id, Some(u.id))
        .await
        .unwrap();
    membership::create(pool, u.id, org_id, membership::ROLE_ADMIN)
        .await
        .unwrap();

    OrgSeed {
        org_id,
        host: format!("{slug}.{SUFFIX}"),
        slug,
        ident_id: ident.id,
        user_id: u.id,
        email,
    }
}

/// Attach an existing user to a second corp org, returning that org's identity.
async fn add_user_to_corp_org(pool: &PgPool, user_id: Uuid, email: &str, name: &str) -> OrgSeed {
    let slug = format!("{}-{}", name.to_lowercase(), Uuid::new_v4().simple());
    let org_id: Uuid = sqlx::query_scalar(
        "INSERT INTO orgs (name, slug, is_personal) VALUES ($1, $2, false) RETURNING id",
    )
    .bind(name)
    .bind(&slug)
    .fetch_one(pool)
    .await
    .unwrap();
    org_bootstrap::bootstrap_org(pool, org_id, None)
        .await
        .unwrap();
    let ident =
        identity::create_with_email(pool, org_id, "Alice", "user", None, Some(email), json!({}))
            .await
            .unwrap();
    identity::set_user_id(pool, org_id, ident.id, Some(user_id))
        .await
        .unwrap();
    membership::create(pool, user_id, org_id, membership::ROLE_ADMIN)
        .await
        .unwrap();
    OrgSeed {
        org_id,
        host: format!("{slug}.{SUFFIX}"),
        slug,
        ident_id: ident.id,
        user_id,
        email: email.to_string(),
    }
}

/// Give an org a default IdP so a cold/mismatched authorize bounces through it.
async fn add_default_idp(pool: &PgPool, org_id: Uuid) {
    sqlx::query(
        "INSERT INTO org_idp_configs (org_id, provider_key, enabled, is_default)
         VALUES ($1, 'google', true, true)",
    )
    .bind(org_id)
    .execute(pool)
    .await
    .unwrap();
}

/// Opt the org into Overslash-managed sign-in — the "Allow Overslash-managed
/// sign-in" toggle in Org Settings. `seed_corp_org` INSERTs the org directly,
/// so it starts at the column default (`false`) rather than the `true` that
/// `POST /v1/orgs` flips on.
async fn enable_managed_signin(pool: &PgPool, org_id: Uuid) {
    sqlx::query("UPDATE orgs SET allow_overslash_managed_signin = true WHERE id = $1")
        .bind(org_id)
        .execute(pool)
        .await
        .unwrap();
}

/// The app-host origin `org_app_url` builds for a corp org: the dashboard
/// apex, port mirrored from `public_url` (the harness binds a random one).
fn app_origin(slug: &str, addr: &std::net::SocketAddr) -> String {
    format!("http://{slug}.app.test:{}", addr.port())
}

/// DCR register. `host = Some(..)` stamps the client to that subdomain's org;
/// `None` (root) leaves `org_id` NULL (multi-org).
async fn register_client(base: &str, redirect: &str, host: Option<&str>) -> String {
    let client = reqwest::Client::new();
    let mut req = client.post(format!("{base}/oauth/register")).json(&json!({
        "client_name": "org-scope-test",
        "redirect_uris": [redirect],
        "token_endpoint_auth_method": "none",
    }));
    if let Some(h) = host {
        req = req.header("x-forwarded-host", h);
    }
    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "DCR must return 201");
    let body: Value = resp.json().await.unwrap();
    body["client_id"].as_str().unwrap().to_string()
}

/// GET /oauth/authorize (no auto-redirect). `cookie`/`host` optional.
async fn authorize(
    base: &str,
    client_id: &str,
    redirect: &str,
    challenge: &str,
    cookie: Option<&str>,
    host: Option<&str>,
) -> reqwest::Response {
    let nr = reqwest::Client::builder()
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
    let mut req = nr.get(&url);
    if let Some(c) = cookie {
        req = req.header("cookie", format!("oss_session={c}"));
    }
    if let Some(h) = host {
        req = req.header("x-forwarded-host", h);
    }
    req.send().await.unwrap()
}

fn location(resp: &reqwest::Response) -> String {
    resp.headers()[reqwest::header::LOCATION]
        .to_str()
        .unwrap()
        .to_string()
}

fn request_id_from(loc: &str) -> String {
    let raw = loc
        .split(&['?', '&'][..])
        .find_map(|p| p.strip_prefix("request_id="))
        .expect("consent redirect missing request_id");
    urlencoding::decode(raw).unwrap().into_owned()
}

/// Fetch the consent context's locked org for a parked request.
async fn consent_org(base: &str, request_id: &str, cookie: &str, host: Option<&str>) -> String {
    let client = reqwest::Client::new();
    let mut req = client
        .get(format!("{base}/v1/oauth/consent/{request_id}"))
        .header("cookie", format!("oss_session={cookie}"));
    if let Some(h) = host {
        req = req.header("x-forwarded-host", h);
    }
    let ctx: Value = req.send().await.unwrap().json().await.unwrap();
    ctx["org_id"].as_str().unwrap().to_string()
}

const REDIRECT: &str = "http://127.0.0.1:9/callback";

// ---------------------------------------------------------------------------
// 1. A stale personal/other-org session on a corp subdomain is bounced through
//    the org IdP, never enrolled into the session org.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn personal_session_on_corp_subdomain_bounces_not_enrolls() {
    let pool = common::test_pool().await;
    let (addr, _c) = common::start_api_with(pool.clone(), |cfg| {
        cfg.api_host_suffix = Some(SUFFIX.to_string());
    })
    .await;
    let base = format!("http://{addr}");

    let personal = seed_corp_org(&pool, "Personal").await;
    let acme = seed_corp_org(&pool, "Acme").await;
    add_default_idp(&pool, acme.org_id).await;

    // Root-registered (NULL) client so the client-org gate is not what stops us.
    let client_id = register_client(&base, REDIRECT, None).await;
    let (_v, challenge) = pkce();
    let cookie = mint_session(
        personal.org_id,
        personal.ident_id,
        personal.user_id,
        &personal.email,
    );

    let resp = authorize(
        &base,
        &client_id,
        REDIRECT,
        &challenge,
        Some(&cookie),
        Some(&acme.host),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = location(&resp);
    assert!(
        loc.starts_with("/auth/login/") || loc.starts_with("/login"),
        "must bounce through the corp IdP, got: {loc}"
    );
    assert!(
        !loc.contains("/oauth/consent"),
        "must NOT proceed to consent in the stale session's org, got: {loc}"
    );
    assert!(loc.contains("next="), "bounce preserves next=, got: {loc}");
}

// ---------------------------------------------------------------------------
// 2. A matching corp session on the corp subdomain proceeds to consent, and the
//    parked request is locked to the corp org.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn corp_session_on_corp_subdomain_enrolls_in_corp_org() {
    let pool = common::test_pool().await;
    let (addr, _c) = common::start_api_with(pool.clone(), |cfg| {
        cfg.api_host_suffix = Some(SUFFIX.to_string());
    })
    .await;
    let base = format!("http://{addr}");

    let acme = seed_corp_org(&pool, "Acme").await;
    let client_id = register_client(&base, REDIRECT, Some(&acme.host)).await;
    let (_v, challenge) = pkce();
    let cookie = mint_session(acme.org_id, acme.ident_id, acme.user_id, &acme.email);

    let resp = authorize(
        &base,
        &client_id,
        REDIRECT,
        &challenge,
        Some(&cookie),
        Some(&acme.host),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = location(&resp);
    assert!(
        loc.contains("/oauth/consent"),
        "matching session → consent, got: {loc}"
    );

    let org = consent_org(&base, &request_id_from(&loc), &cookie, Some(&acme.host)).await;
    assert_eq!(
        org,
        acme.org_id.to_string(),
        "agent must enroll into the corp org"
    );
}

// ---------------------------------------------------------------------------
// 3. A binding formed under one org does not short-circuit authorize on
//    another org's subdomain. Same NULL client, two orgs the user belongs to:
//    reuse fires on beta, but acme falls through to a fresh consent.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn binding_in_other_org_does_not_short_circuit() {
    let pool = common::test_pool().await;
    let (addr, _c) = common::start_api_with(pool.clone(), |cfg| {
        cfg.api_host_suffix = Some(SUFFIX.to_string());
    })
    .await;
    let base = format!("http://{addr}");

    let acme = seed_corp_org(&pool, "Acme").await;
    let beta = add_user_to_corp_org(&pool, acme.user_id, &acme.email, "Beta").await;

    // NULL (root) client so it's accepted on both subdomains.
    let client_id = register_client(&base, REDIRECT, None).await;
    let (_v, challenge) = pkce();

    // Seed a completed enrollment under Beta: an agent + a binding.
    let agent = identity::create_with_email(
        &pool,
        beta.org_id,
        "beta-agent",
        "agent",
        None,
        Some("beta-agent@beta.test"),
        json!({}),
    )
    .await
    .unwrap();
    mcp_client_agent_binding::upsert(&pool, beta.org_id, beta.ident_id, &client_id, agent.id)
        .await
        .unwrap();

    // On Beta's subdomain the binding is reused → straight to the client redirect.
    let beta_cookie = mint_session(beta.org_id, beta.ident_id, beta.user_id, &beta.email);
    let on_beta = authorize(
        &base,
        &client_id,
        REDIRECT,
        &challenge,
        Some(&beta_cookie),
        Some(&beta.host),
    )
    .await;
    assert_eq!(on_beta.status(), StatusCode::SEE_OTHER);
    let beta_loc = location(&on_beta);
    assert!(
        beta_loc.starts_with(REDIRECT) && beta_loc.contains("code="),
        "beta reuses its own binding, got: {beta_loc}"
    );

    // On Acme's subdomain the beta binding must NOT short-circuit → consent.
    let acme_cookie = mint_session(acme.org_id, acme.ident_id, acme.user_id, &acme.email);
    let on_acme = authorize(
        &base,
        &client_id,
        REDIRECT,
        &challenge,
        Some(&acme_cookie),
        Some(&acme.host),
    )
    .await;
    assert_eq!(on_acme.status(), StatusCode::SEE_OTHER);
    let acme_loc = location(&on_acme);
    assert!(
        acme_loc.contains("/oauth/consent"),
        "acme must not reuse beta's binding — fresh consent expected, got: {acme_loc}"
    );
}

// ---------------------------------------------------------------------------
// 4. A client stamped for one org is rejected on another org's subdomain
//    (cross-subdomain replay protection).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn client_registered_on_one_subdomain_rejected_on_another() {
    let pool = common::test_pool().await;
    let (addr, _c) = common::start_api_with(pool.clone(), |cfg| {
        cfg.api_host_suffix = Some(SUFFIX.to_string());
    })
    .await;
    let base = format!("http://{addr}");

    let acme = seed_corp_org(&pool, "Acme").await;
    let beta = seed_corp_org(&pool, "Beta").await;

    // Stamp the client to Acme.
    let client_id = register_client(&base, REDIRECT, Some(&acme.host)).await;
    let (_v, challenge) = pkce();

    // Authorize on Beta's subdomain — rejected before any session work.
    let resp = authorize(
        &base,
        &client_id,
        REDIRECT,
        &challenge,
        None,
        Some(&beta.host),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_client");
}

// ---------------------------------------------------------------------------
// 5 + 6. Root apex is the multi-org hub: enrollment follows the session org,
//        including a corp session — unchanged behavior, no forced bounce.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn root_apex_enrollment_follows_session_org() {
    let pool = common::test_pool().await;
    let (addr, _c) = common::start_api_with(pool.clone(), |cfg| {
        cfg.api_host_suffix = Some(SUFFIX.to_string());
    })
    .await;
    let base = format!("http://{addr}");

    let acme = seed_corp_org(&pool, "Acme").await;
    // Root-registered client, and NO x-forwarded-host on authorize → Root ctx.
    let client_id = register_client(&base, REDIRECT, None).await;
    let (_v, challenge) = pkce();
    let cookie = mint_session(acme.org_id, acme.ident_id, acme.user_id, &acme.email);

    let resp = authorize(&base, &client_id, REDIRECT, &challenge, Some(&cookie), None).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = location(&resp);
    assert!(
        loc.contains("/oauth/consent"),
        "root corp session → consent, got: {loc}"
    );

    let org = consent_org(&base, &request_id_from(&loc), &cookie, None).await;
    assert_eq!(
        org,
        acme.org_id.to_string(),
        "root enrollment lands in the session org (a corp org here)"
    );
}

// ---------------------------------------------------------------------------
// 7. A NULL/root-registered client is accepted on a corp subdomain and still
//    lands the agent in that subdomain's org (back-compat without a leak).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn null_client_accepted_on_corp_subdomain_lands_in_that_org() {
    let pool = common::test_pool().await;
    let (addr, _c) = common::start_api_with(pool.clone(), |cfg| {
        cfg.api_host_suffix = Some(SUFFIX.to_string());
    })
    .await;
    let base = format!("http://{addr}");

    let acme = seed_corp_org(&pool, "Acme").await;
    let client_id = register_client(&base, REDIRECT, None).await; // NULL org
    let (_v, challenge) = pkce();
    let cookie = mint_session(acme.org_id, acme.ident_id, acme.user_id, &acme.email);

    let resp = authorize(
        &base,
        &client_id,
        REDIRECT,
        &challenge,
        Some(&cookie),
        Some(&acme.host),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = location(&resp);
    assert!(
        loc.contains("/oauth/consent"),
        "NULL client accepted on subdomain, got: {loc}"
    );

    let org = consent_org(&base, &request_id_from(&loc), &cookie, Some(&acme.host)).await;
    assert_eq!(
        org,
        acme.org_id.to_string(),
        "NULL client still lands in the subdomain org"
    );
}

// ---------------------------------------------------------------------------
// 8. A client stamped for one org cannot bind an agent in another org via the
//    `switch-org` path: consent_finish re-checks the client stamp at the single
//    binding-creation site (regression for the Seer finding on #443).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn stamped_client_cannot_bind_in_switched_org() {
    let pool = common::test_pool().await;
    let (addr, _c) = common::start_api_with(pool.clone(), |cfg| {
        cfg.api_host_suffix = Some(SUFFIX.to_string());
    })
    .await;
    let base = format!("http://{addr}");

    let acme = seed_corp_org(&pool, "Acme").await;
    let beta = add_user_to_corp_org(&pool, acme.user_id, &acme.email, "Beta").await;

    // Client stamped for Acme.
    let client_id = register_client(&base, REDIRECT, Some(&acme.host)).await;
    let (_v, challenge) = pkce();
    let acme_cookie = mint_session(acme.org_id, acme.ident_id, acme.user_id, &acme.email);

    // Authorize on Acme → consent parked in Acme.
    let resp = authorize(
        &base,
        &client_id,
        REDIRECT,
        &challenge,
        Some(&acme_cookie),
        Some(&acme.host),
    )
    .await;
    let request_id = request_id_from(&location(&resp));

    // Switch the pending request to Beta (a legit member org).
    let http = reqwest::Client::new();
    let sw = http
        .post(format!("{base}/v1/oauth/consent/{request_id}/switch-org"))
        .header("cookie", format!("oss_session={acme_cookie}"))
        .json(&json!({ "org_id": beta.org_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        sw.status(),
        StatusCode::OK,
        "switch to a member org is allowed"
    );
    let beta_cookie = sw
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|c| c.split(';').next())
        .and_then(|kv| kv.trim().strip_prefix("oss_session="))
        .expect("switch-org re-mints the session cookie")
        .to_string();
    let sw_body: Value = sw.json().await.unwrap();
    let beta_request_id = sw_body["request_id"].as_str().unwrap().to_string();

    // Finishing in Beta with the Acme-stamped client must be rejected — the
    // stamp binds the client to Acme even after an org switch.
    let fin = http
        .post(format!("{base}/v1/oauth/consent/{beta_request_id}/finish"))
        .header("cookie", format!("oss_session={beta_cookie}"))
        .header("content-type", "application/json")
        .body(
            json!({
                "mode": "new",
                "agent_name": "cross-org-agent",
                "inherit_permissions": false,
                "group_names": [],
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        fin.status(),
        StatusCode::FORBIDDEN,
        "an Acme-stamped client must not bind an agent in Beta"
    );
}

// ---------------------------------------------------------------------------
// Overslash-managed sign-in on a corp subdomain.
//
// An org can enable "Allow Overslash-managed sign-in" instead of configuring
// its own IdP (D12's 2026-05 amendment, migration 066 / 092: authentication
// goes through Overslash's OAuth apps, membership is gated separately by
// invites or the domain allowlist). `/oauth/authorize` used to read only
// `org_idp_configs` and answered 503 `login_required` for those orgs, even
// though the same org's `/auth/providers` listed working Google/GitHub
// buttons. `services::org_signin` is now the single source of truth for both.
// ---------------------------------------------------------------------------

/// Both managed providers available and no designated default → the dashboard
/// login picker, absolute on the org's **app** host. Host-relative would land
/// on `<slug>.api.<apex>/login`, which is not a route.
#[tokio::test]
async fn managed_signin_with_no_idp_rows_bounces_to_picker() {
    let pool = common::test_pool().await;
    let (addr, _c) = common::start_api_with(pool.clone(), |cfg| {
        cfg.api_host_suffix = Some(SUFFIX.to_string());
        cfg.app_host_suffix = Some("app.test".to_string());
        cfg.google_auth_client_id = Some("google-id".into());
        cfg.google_auth_client_secret = Some("google-secret".into());
        cfg.github_auth_client_id = Some("github-id".into());
        cfg.github_auth_client_secret = Some("github-secret".into());
    })
    .await;
    let base = format!("http://{addr}");

    let acme = seed_corp_org(&pool, "Acme").await;
    enable_managed_signin(&pool, acme.org_id).await;

    let client_id = register_client(&base, REDIRECT, None).await;
    let (_v, challenge) = pkce();

    // Cold: no session cookie at all.
    let resp = authorize(
        &base,
        &client_id,
        REDIRECT,
        &challenge,
        None,
        Some(&acme.host),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = location(&resp);
    assert!(
        loc.starts_with(&format!("{}/login?", app_origin(&acme.slug, &addr))),
        "managed sign-in must bounce to the org's app-host login picker, got: {loc}"
    );
    assert!(
        loc.contains("next=%2Foauth%2Fauthorize"),
        "bounce preserves the authorize request as next=, got: {loc}"
    );
}

/// One managed provider configured on the deployment → skip the one-button
/// picker and go straight to it, matching the root-apex behavior.
#[tokio::test]
async fn managed_signin_with_single_provider_bounces_straight_to_it() {
    let pool = common::test_pool().await;
    let (addr, _c) = common::start_api_with(pool.clone(), |cfg| {
        cfg.api_host_suffix = Some(SUFFIX.to_string());
        cfg.app_host_suffix = Some("app.test".to_string());
        cfg.github_auth_client_id = Some("github-id".into());
        cfg.github_auth_client_secret = Some("github-secret".into());
    })
    .await;
    let base = format!("http://{addr}");

    let acme = seed_corp_org(&pool, "Acme").await;
    enable_managed_signin(&pool, acme.org_id).await;

    let client_id = register_client(&base, REDIRECT, None).await;
    let (_v, challenge) = pkce();

    let resp = authorize(
        &base,
        &client_id,
        REDIRECT,
        &challenge,
        None,
        Some(&acme.host),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = location(&resp);
    assert!(
        loc.starts_with(&format!(
            "{}/auth/login/github?",
            app_origin(&acme.slug, &addr)
        )),
        "a lone managed provider skips the picker, got: {loc}"
    );
}

/// The D12 boundary still holds: without the opt-in, env-var credentials do
/// not leak into a corp subdomain's sign-in.
#[tokio::test]
async fn managed_signin_off_and_no_idp_rows_still_503s() {
    let pool = common::test_pool().await;
    let (addr, _c) = common::start_api_with(pool.clone(), |cfg| {
        cfg.api_host_suffix = Some(SUFFIX.to_string());
        cfg.app_host_suffix = Some("app.test".to_string());
        cfg.google_auth_client_id = Some("google-id".into());
        cfg.google_auth_client_secret = Some("google-secret".into());
    })
    .await;
    let base = format!("http://{addr}");

    // No `enable_managed_signin` — the org opted into nothing.
    let acme = seed_corp_org(&pool, "Acme").await;

    let client_id = register_client(&base, REDIRECT, None).await;
    let (_v, challenge) = pkce();

    let resp = authorize(
        &base,
        &client_id,
        REDIRECT,
        &challenge,
        None,
        Some(&acme.host),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "login_required");
}

/// A designated default `org_idp_configs` row outranks managed sign-in — the
/// admin picked that IdP on purpose.
#[tokio::test]
async fn dedicated_default_idp_wins_over_managed_signin() {
    let pool = common::test_pool().await;
    let (addr, _c) = common::start_api_with(pool.clone(), |cfg| {
        cfg.api_host_suffix = Some(SUFFIX.to_string());
        cfg.app_host_suffix = Some("app.test".to_string());
        cfg.github_auth_client_id = Some("github-id".into());
        cfg.github_auth_client_secret = Some("github-secret".into());
    })
    .await;
    let base = format!("http://{addr}");

    let acme = seed_corp_org(&pool, "Acme").await;
    enable_managed_signin(&pool, acme.org_id).await;
    add_default_idp(&pool, acme.org_id).await; // google, is_default

    let client_id = register_client(&base, REDIRECT, None).await;
    let (_v, challenge) = pkce();

    let resp = authorize(
        &base,
        &client_id,
        REDIRECT,
        &challenge,
        None,
        Some(&acme.host),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = location(&resp);
    assert!(
        loc.starts_with(&format!(
            "{}/auth/login/google?",
            app_origin(&acme.slug, &addr)
        )),
        "the org's designated default must win, got: {loc}"
    );
}

/// Self-hosted single-host deployments have no separate app apex to name, so
/// the bounce stays host-relative there.
#[tokio::test]
async fn bounce_stays_relative_without_app_host_suffix() {
    let pool = common::test_pool().await;
    let (addr, _c) = common::start_api_with(pool.clone(), |cfg| {
        cfg.api_host_suffix = Some(SUFFIX.to_string());
        cfg.app_host_suffix = None;
        cfg.github_auth_client_id = Some("github-id".into());
        cfg.github_auth_client_secret = Some("github-secret".into());
    })
    .await;
    let base = format!("http://{addr}");

    let acme = seed_corp_org(&pool, "Acme").await;
    enable_managed_signin(&pool, acme.org_id).await;

    let client_id = register_client(&base, REDIRECT, None).await;
    let (_v, challenge) = pkce();

    let resp = authorize(
        &base,
        &client_id,
        REDIRECT,
        &challenge,
        None,
        Some(&acme.host),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = location(&resp);
    assert!(
        loc.starts_with("/auth/login/github?"),
        "no app apex configured → keep the relative path, got: {loc}"
    );
}
