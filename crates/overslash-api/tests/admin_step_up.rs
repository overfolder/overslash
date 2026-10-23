// Dynamic SQL ages and inspects session rows directly.
#![allow(clippy::disallowed_methods)]
//! Admin-class mutations need a fresh IdP sign-in (CASA 3.3.1, 2.4.1).
//!
//! `AdminAcl` refuses a non-GET from a dashboard session in a shared org
//! unless `user_sessions` says the session is an IdP sign-in, through a
//! provider the org signs in with, no older than the step-up window. The
//! answer is 403 `step_up_required` — a 401 would sign the dashboard out.

use crate::common;

use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

use overslash_api::services::jwt;
use overslash_db::repos::user_session;

fn cookie(token: &str) -> String {
    format!("__Host-oss_session={token}")
}

/// A deployment with a root IdP (Google), so a magic link is never enough.
/// The harness client does not follow redirects.
async fn start_with_google(pool: PgPool, dev_auth: bool) -> (String, Client) {
    common::start_api_with_auth_providers_customized(
        pool,
        Some(("test_google_id".into(), "test_google_secret".into())),
        None,
        "http://localhost:3000",
        |c| c.dev_auth_enabled = dev_auth,
    )
    .await
}

/// The session token a response sets, if any.
fn set_session(resp: &reqwest::Response) -> Option<String> {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| c.strip_prefix("__Host-oss_session="))
        .map(|rest| rest.split(';').next().unwrap().to_string())
        .filter(|t| !t.is_empty())
}

/// A shared (non-personal) org and its bootstrap admin key + identity.
async fn shared_org(base: &str, client: &Client) -> (Uuid, Uuid, String) {
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "StepUp", "slug": format!("stepup-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();
    let key = org["api_key"].as_str().unwrap().to_string();
    let me: Value = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let identity_id: Uuid = me["identity_id"].as_str().unwrap().parse().unwrap();
    (org_id, identity_id, key)
}

/// A live session row signed in by `method` (`provider` for `idp`)
/// `age_secs` ago, and a cookie naming it.
async fn session(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    method: Option<&str>,
    provider: Option<&str>,
    age_secs: i64,
) -> String {
    let row = user_session::create(
        pool,
        user_session::NewUserSession {
            user_id: None,
            identity_id,
            org_id,
            ttl_secs: 3600,
            user_agent: None,
            ip_address: None,
            auth_method: method,
            auth_provider: provider,
            idp_amr: None,
            idp_acr: None,
        },
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE user_sessions SET authenticated_at = now() - make_interval(secs => $2)
         WHERE id = $1 AND authenticated_at IS NOT NULL",
    )
    .bind(row.id)
    .bind(age_secs as f64)
    .execute(pool)
    .await
    .unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let token = jwt::mint(
        &common::signing_key_bytes(),
        &jwt::Claims {
            sub: identity_id,
            org: org_id,
            email: "admin@stepup.test".into(),
            aud: jwt::AUD_SESSION.into(),
            iat: now,
            exp: now + 3600,
            user_id: None,
            mcp_client_id: None,
            jti: Some(row.id),
        },
    )
    .unwrap();
    cookie(&token)
}

/// `POST /v1/groups` — an `AdminAcl` mutation.
async fn create_group(base: &str, client: &Client, auth: (&str, &str)) -> reqwest::Response {
    client
        .post(format!("{base}/v1/groups"))
        .header(auth.0, auth.1)
        .json(&json!({"name": format!("g-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
}

async fn step_up_reason(resp: reqwest::Response) -> (Option<String>, Value) {
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "step_up_required", "{body}");
    (body["reason"].as_str().map(str::to_owned), body)
}

#[tokio::test]
async fn a_fresh_idp_sign_in_can_mutate_and_a_stale_one_cannot() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, admin, _) = shared_org(&base, &client).await;

    let fresh = session(&pool, org_id, admin, Some("idp"), Some("google"), 60).await;
    let resp = create_group(&base, &client, ("cookie", &fresh)).await;
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());

    let stale = session(&pool, org_id, admin, Some("idp"), Some("google"), 7200).await;
    let (reason, body) =
        step_up_reason(create_group(&base, &client, ("cookie", &stale)).await).await;
    assert_eq!(reason.as_deref(), Some("stale"));
    assert_eq!(body["max_age_secs"], 3600);
}

#[tokio::test]
async fn magic_link_and_unrecorded_sessions_are_refused_but_can_still_read() {
    let pool = common::test_pool().await;
    let (base, client) = start_with_google(pool.clone(), false).await;
    let (org_id, admin, _) = shared_org(&base, &client).await;

    for method in [Some("magic_link"), None] {
        let c = session(&pool, org_id, admin, method, None, 0).await;
        let (reason, _) = step_up_reason(create_group(&base, &client, ("cookie", &c)).await).await;
        assert_eq!(reason.as_deref(), Some("idp_required"), "{method:?}");

        // Reading an admin surface is not an admin action.
        let resp = client
            .get(format!("{base}/v1/org-invites"))
            .header("cookie", &c)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{method:?}");
    }
}

#[tokio::test]
async fn the_idp_must_be_one_the_org_signs_in_with() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, admin, _) = shared_org(&base, &client).await;
    // The org signs in through its own GitHub app only.
    sqlx::query(
        "INSERT INTO org_idp_configs (org_id, provider_key, enabled) VALUES ($1, 'github', true)",
    )
    .bind(org_id)
    .execute(&pool)
    .await
    .unwrap();

    let google = session(&pool, org_id, admin, Some("idp"), Some("google"), 60).await;
    let (reason, body) =
        step_up_reason(create_group(&base, &client, ("cookie", &google)).await).await;
    assert_eq!(reason.as_deref(), Some("provider_not_allowed"));
    let offered: Vec<&str> = body["providers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["key"].as_str().unwrap())
        .collect();
    assert_eq!(offered, ["github"], "{body}");
    let login_path = body["providers"][0]["login_path"].as_str().unwrap();
    assert!(
        login_path.starts_with("/auth/login/github?step_up=true&org=stepup-"),
        "{login_path}"
    );

    let github = session(&pool, org_id, admin, Some("idp"), Some("github"), 60).await;
    let resp = create_group(&base, &client, ("cookie", &github)).await;
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
}

#[tokio::test]
async fn api_keys_and_dev_sessions_under_dev_auth_are_out_of_scope() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool.clone()).await;
    let (org_id, admin, key) = shared_org(&base, &client).await;

    let bearer = format!("Bearer {key}");
    let resp = create_group(&base, &client, ("authorization", &bearer)).await;
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());

    let dev = session(&pool, org_id, admin, Some("dev"), None, 60).await;
    let resp = create_group(&base, &client, ("cookie", &dev)).await;
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
}

#[tokio::test]
async fn a_dev_session_without_dev_auth_is_not_an_idp_sign_in() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, admin, _) = shared_org(&base, &client).await;

    let dev = session(&pool, org_id, admin, Some("dev"), None, 60).await;
    let (reason, _) = step_up_reason(create_group(&base, &client, ("cookie", &dev)).await).await;
    assert_eq!(reason.as_deref(), Some("idp_required"));
}

/// The bypass the gate exists for: a magic link lands in the personal org,
/// and the same session then re-scopes into a shared org it administers.
#[tokio::test]
async fn a_magic_link_session_carried_into_a_shared_org_needs_a_step_up() {
    let pool = common::test_pool().await;
    let (base, client) = start_with_google(pool.clone(), true).await;
    let email = format!("stepup-{}@example.com", Uuid::new_v4());

    let body: Value = client
        .post(format!("{base}/auth/magic-link/request"))
        .json(&json!({ "email": email }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let resp = client
        .get(body["dev_verify_url"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    let personal = cookie(&set_session(&resp).expect("verify sets a session"));

    // Its own personal org is out of scope.
    let resp = create_group(&base, &client, ("cookie", &personal)).await;
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());

    // Create a shared org; the response re-scopes the same session into it.
    let resp = client
        .post(format!("{base}/v1/orgs"))
        .header("cookie", &personal)
        .json(&json!({"name": "Corp", "slug": format!("corp-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let corp = cookie(&set_session(&resp).expect("create re-scopes the session"));

    let (reason, _) = step_up_reason(create_group(&base, &client, ("cookie", &corp)).await).await;
    assert_eq!(reason.as_deref(), Some("idp_required"));

    // The sessions list says why.
    let sessions: Value = client
        .get(format!("{base}/v1/account/sessions"))
        .header("cookie", &corp)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let current = sessions["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["current"] == true)
        .unwrap();
    assert_eq!(current["auth_method"], "magic_link");
    assert!(current["authenticated_at"].is_string());
}

/// A self-hosted, magic-link-only deployment has no IdP to defer to; refusing
/// would leave its admins unable to configure the first one.
#[tokio::test]
async fn a_deployment_without_any_idp_accepts_a_fresh_magic_link() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, admin, _) = shared_org(&base, &client).await;

    let fresh = session(&pool, org_id, admin, Some("magic_link"), None, 60).await;
    let resp = create_group(&base, &client, ("cookie", &fresh)).await;
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());

    let stale = session(&pool, org_id, admin, Some("magic_link"), None, 7200).await;
    let (reason, body) =
        step_up_reason(create_group(&base, &client, ("cookie", &stale)).await).await;
    assert_eq!(reason.as_deref(), Some("stale"));
    assert_eq!(body["providers"][0]["key"], "email", "{body}");
}

#[tokio::test]
async fn members_cannot_manage_identity_providers() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, _, admin_key) = shared_org(&base, &client).await;

    let member: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": "member", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let member_id: Uuid = member["id"].as_str().unwrap().parse().unwrap();
    let member_cookie = common::session_cookie(org_id, member_id);

    let resp = client
        .post(format!("{base}/v1/org-idp-configs"))
        .header("cookie", &member_cookie)
        .json(&json!({"provider_key": "github", "client_id": "x", "client_secret": "y"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "admin access required");

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM org_idp_configs WHERE org_id = $1")
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn an_idp_sign_in_is_recorded_and_step_up_asks_the_idp_to_reauthenticate() {
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
    // The harness client does not follow redirects.
    let (base, nr) = common::start_api_with_auth_providers(
        pool.clone(),
        Some(("test_google_id".into(), "test_google_secret".into())),
        None,
        "http://localhost:3000",
    )
    .await;

    let location =
        |resp: &reqwest::Response| resp.headers()["location"].to_str().unwrap().to_string();
    let plain = nr
        .get(format!("{base}/auth/login/google"))
        .send()
        .await
        .unwrap();
    assert_eq!(plain.status(), 303, "{:?}", plain.headers());
    assert!(!location(&plain).contains("max_age"));
    let step_up = nr
        .get(format!("{base}/auth/login/google?step_up=true"))
        .send()
        .await
        .unwrap();
    assert!(
        location(&step_up).contains("max_age=0"),
        "{}",
        location(&step_up)
    );

    let nonce = "step-up-nonce";
    let resp = nr
        .get(format!(
            "{base}/auth/callback/google?code=authcode&state=login:google:{nonce}"
        ))
        .header(
            "cookie",
            format!("__Host-oss_auth_nonce={nonce}; __Host-oss_auth_verifier=v; __Host-oss_auth_org=none"),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 303);
    let token = set_session(&resp).unwrap();
    let claims = jwt::verify(&common::signing_key_bytes(), &token, jwt::AUD_SESSION).unwrap();
    let row = user_session::get(&pool, claims.jti.unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.auth_method.as_deref(), Some("idp"));
    assert_eq!(row.auth_provider.as_deref(), Some("google"));
    assert!(row.authenticated_at.is_some());
}
