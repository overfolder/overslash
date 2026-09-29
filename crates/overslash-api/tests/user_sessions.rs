//! Server-side dashboard sessions (CASA 2.2.1–2.2.3): the `jti` in the session
//! JWT names a `user_sessions` row, and the session gate refuses a cookie
//! whose row is revoked, expired or gone.

use crate::common;

use std::net::SocketAddr;

use axum::{Router, routing::get};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio::net::TcpListener;
use uuid::Uuid;

use overslash_api::services::jwt;
use overslash_db::repos::user_session;

/// A dev login. Returns `(token, body)`.
async fn dev_login(base: &str, client: &Client, profile: &str) -> (String, Value) {
    let body: Value = client
        .get(format!("{base}/auth/dev/token?profile={profile}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (body["token"].as_str().unwrap().to_string(), body)
}

fn cookie(token: &str) -> String {
    format!("__Host-oss_session={token}")
}

async fn me(base: &str, client: &Client, token: &str) -> StatusCode {
    client
        .get(format!("{base}/auth/me/identity"))
        .header("cookie", cookie(token))
        .send()
        .await
        .unwrap()
        .status()
}

async fn list(base: &str, client: &Client, token: &str) -> Vec<Value> {
    let resp = client
        .get(format!("{base}/v1/account/sessions"))
        .header("cookie", cookie(token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    body["sessions"].as_array().unwrap().clone()
}

fn clears_session(resp: &reqwest::Response) -> bool {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|c| c.starts_with("__Host-oss_session=;") && c.contains("Max-Age=0"))
}

/// A session JWT signed with the harness key.
fn forge(org: Uuid, sub: Uuid, jti: Option<Uuid>, lifetime_secs: i64) -> String {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    jwt::mint(
        &common::signing_key_bytes(),
        &jwt::Claims {
            sub,
            org,
            email: "fixture@test.local".into(),
            aud: jwt::AUD_SESSION.into(),
            iat: now,
            exp: now + lifetime_secs,
            user_id: None,
            mcp_client_id: None,
            jti,
        },
    )
    .unwrap()
}

async fn session_row(pool: &PgPool, org_id: Uuid, identity_id: Uuid) -> Uuid {
    user_session::create(
        pool,
        user_session::NewUserSession {
            user_id: None,
            identity_id,
            org_id,
            ttl_secs: 3600,
            user_agent: None,
            ip_address: None,
        },
    )
    .await
    .unwrap()
    .id
}

// ── Logout and legacy tokens ────────────────────────────────────────

#[tokio::test]
async fn logout_revokes_the_session_not_just_the_cookie() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;
    let (token, _) = dev_login(&base, &client, "admin").await;
    // First use also warms the validation cache — logout must evict it.
    assert_eq!(me(&base, &client, &token).await, StatusCode::OK);

    let resp = client
        .post(format!("{base}/auth/logout"))
        .header("cookie", cookie(&token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // A copy of the cookie that survived the browser clear is worthless.
    let resp = client
        .get(format!("{base}/auth/me/identity"))
        .header("cookie", cookie(&token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(
        clears_session(&resp),
        "a dead session cookie is cleared on the response"
    );
}

#[tokio::test]
async fn a_stateless_token_is_accepted_only_under_24_hours() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;
    let (_, body) = dev_login(&base, &client, "admin").await;
    let org: Uuid = body["org_id"].as_str().unwrap().parse().unwrap();
    let sub: Uuid = body["identity_id"].as_str().unwrap().parse().unwrap();

    // Every cookie minted before this change: 7 days, no jti.
    let legacy = forge(org, sub, None, 7 * 24 * 3600);
    assert_eq!(me(&base, &client, &legacy).await, StatusCode::UNAUTHORIZED);

    // The API's own short-lived loopback tokens stay stateless.
    let short = forge(org, sub, None, 600);
    assert_eq!(me(&base, &client, &short).await, StatusCode::OK);
}

#[tokio::test]
async fn a_jti_with_no_row_is_no_session() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;
    let (_, body) = dev_login(&base, &client, "admin").await;
    let org: Uuid = body["org_id"].as_str().unwrap().parse().unwrap();
    let sub: Uuid = body["identity_id"].as_str().unwrap().parse().unwrap();

    let made_up = forge(org, sub, Some(Uuid::new_v4()), 3600);
    assert_eq!(me(&base, &client, &made_up).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_superseded_copy_is_refused_but_not_cleared() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool.clone()).await;
    let (_, admin) = dev_login(&base, &client, "admin").await;
    let (_, member) = dev_login(&base, &client, "member").await;
    let org: Uuid = admin["org_id"].as_str().unwrap().parse().unwrap();
    let admin_id: Uuid = admin["identity_id"].as_str().unwrap().parse().unwrap();
    let member_id: Uuid = member["identity_id"].as_str().unwrap().parse().unwrap();

    // The row now points at `member_id` (as after a switch-org); a cookie
    // still naming `admin_id` under the same jti is the older copy.
    let jti = session_row(&pool, org, member_id).await;
    let stale = forge(org, admin_id, Some(jti), 3600);
    let resp = client
        .get(format!("{base}/auth/me/identity"))
        .header("cookie", cookie(&stale))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(
        !clears_session(&resp),
        "clearing would wipe the browser's replacement cookie"
    );
    let current = forge(org, member_id, Some(jti), 3600);
    assert_eq!(me(&base, &client, &current).await, StatusCode::OK);
}

// ── Self-service: list, terminate one, terminate the others ─────────

#[tokio::test]
async fn terminate_all_other_sessions() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;
    let (laptop, _) = dev_login(&base, &client, "admin").await;
    let (phone, _) = dev_login(&base, &client, "admin").await;
    assert_eq!(me(&base, &client, &phone).await, StatusCode::OK);

    let sessions = list(&base, &client, &laptop).await;
    assert_eq!(sessions.len(), 2, "{sessions:?}");
    assert_eq!(
        sessions.iter().filter(|s| s["current"] == true).count(),
        1,
        "exactly one is the caller's"
    );
    assert!(sessions.iter().all(|s| s["org_name"].is_string()));

    let resp: Value = client
        .post(format!("{base}/v1/account/sessions/revoke-others"))
        .header("cookie", cookie(&laptop))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["revoked"], 1);

    assert_eq!(me(&base, &client, &phone).await, StatusCode::UNAUTHORIZED);
    assert_eq!(me(&base, &client, &laptop).await, StatusCode::OK);
    let left = list(&base, &client, &laptop).await;
    assert_eq!(left.len(), 1);
    assert_eq!(left[0]["current"], true);
}

#[tokio::test]
async fn terminate_one_session_of_your_own_and_none_of_anyone_elses() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;
    let (laptop, _) = dev_login(&base, &client, "admin").await;
    let (phone, _) = dev_login(&base, &client, "admin").await;
    let (member, _) = dev_login(&base, &client, "member").await;

    let phone_id = list(&base, &client, &phone)
        .await
        .into_iter()
        .find(|s| s["current"] == true)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let member_id = list(&base, &client, &member).await[0]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Another human's session id is a 404, and it stays alive.
    let resp = client
        .delete(format!("{base}/v1/account/sessions/{member_id}"))
        .header("cookie", cookie(&laptop))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(me(&base, &client, &member).await, StatusCode::OK);

    let resp = client
        .delete(format!("{base}/v1/account/sessions/{phone_id}"))
        .header("cookie", cookie(&laptop))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!clears_session(&resp), "ending another session keeps yours");
    assert_eq!(me(&base, &client, &phone).await, StatusCode::UNAUTHORIZED);
    assert_eq!(me(&base, &client, &laptop).await, StatusCode::OK);

    // Ending your current session is a sign-out.
    let laptop_id = list(&base, &client, &laptop).await[0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let resp = client
        .delete(format!("{base}/v1/account/sessions/{laptop_id}"))
        .header("cookie", cookie(&laptop))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(clears_session(&resp));
    assert_eq!(me(&base, &client, &laptop).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_new_sign_in_replaces_the_browsers_previous_session() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;
    let (first, _) = dev_login(&base, &client, "admin").await;

    // Same browser signs in again, presenting its current cookie.
    let second: Value = client
        .get(format!("{base}/auth/dev/token"))
        .header("cookie", cookie(&first))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let second = second["token"].as_str().unwrap();

    assert_eq!(me(&base, &client, &first).await, StatusCode::UNAUTHORIZED);
    assert_eq!(list(&base, &client, second).await.len(), 1);
}

#[tokio::test]
async fn sessions_are_not_reachable_with_an_api_key() {
    let pool = common::test_pool().await;
    let (org_id, user_id, key) =
        common::seed_org_user_key(&pool, common::SeedOptions::default()).await;
    let _ = (org_id, user_id);
    let (base, client) = common::start_api_with_dev_auth(pool).await;
    for req in [
        client.get(format!("{base}/v1/account/sessions")),
        client.post(format!("{base}/v1/account/sessions/revoke-others")),
    ] {
        let status = req.bearer_auth(&key).send().await.unwrap().status();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}

// ── Admin revocation and identity change ────────────────────────────

async fn identity_of(body: &Value) -> Uuid {
    body["identity_id"].as_str().unwrap().parse().unwrap()
}

#[tokio::test]
async fn removing_a_member_ends_their_sessions() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool.clone()).await;
    let (admin, _) = dev_login(&base, &client, "admin").await;
    let (member, member_body) = dev_login(&base, &client, "member").await;
    assert_eq!(me(&base, &client, &member).await, StatusCode::OK);

    let resp = client
        .delete(format!(
            "{base}/v1/identities/{}",
            identity_of(&member_body).await
        ))
        .header("cookie", cookie(&admin))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "{:?}",
        resp.text().await
    );

    assert_eq!(me(&base, &client, &member).await, StatusCode::UNAUTHORIZED);
    assert_eq!(me(&base, &client, &admin).await, StatusCode::OK);

    // Revoked inside the removal's own transaction, so the two cannot part:
    // a retry would find the member already detached and revoke nothing.
    let jti = jwt::verify(&common::signing_key_bytes(), &member, jwt::AUD_SESSION)
        .unwrap()
        .jti
        .unwrap();
    let row = user_session::get(&pool, jti).await.unwrap().unwrap();
    assert_eq!(row.revoked_reason.as_deref(), Some("member_removed"));
}

#[tokio::test]
async fn archiving_a_member_ends_their_sessions() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;
    let (admin, _) = dev_login(&base, &client, "admin").await;
    let (member, member_body) = dev_login(&base, &client, "member").await;
    assert_eq!(me(&base, &client, &member).await, StatusCode::OK);

    let resp = client
        .post(format!(
            "{base}/v1/identities/{}/archive",
            identity_of(&member_body).await
        ))
        .header("cookie", cookie(&admin))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "{:?}", resp.text().await);
    assert_eq!(me(&base, &client, &member).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rewriting_a_members_email_ends_their_sessions() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool.clone()).await;
    let (admin, admin_body) = dev_login(&base, &client, "admin").await;
    let org: Uuid = admin_body["org_id"].as_str().unwrap().parse().unwrap();

    // A pre-created member — the only kind whose email an admin may rewrite.
    let created: Value = client
        .post(format!("{base}/v1/identities"))
        .header("cookie", cookie(&admin))
        .json(&json!({"name": "Pat", "kind": "user", "email": "pat@example.com"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let pat: Uuid = created["id"].as_str().unwrap().parse().unwrap();
    let jti = session_row(&pool, org, pat).await;
    let pat_token = forge(org, pat, Some(jti), 3600);
    assert_eq!(me(&base, &client, &pat_token).await, StatusCode::OK);

    // A name-only patch is not an identity change.
    let resp = client
        .patch(format!("{base}/v1/identities/{pat}"))
        .header("cookie", cookie(&admin))
        .json(&json!({"name": "Pat Smith"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(me(&base, &client, &pat_token).await, StatusCode::OK);

    let resp = client
        .patch(format!("{base}/v1/identities/{pat}"))
        .header("cookie", cookie(&admin))
        .json(&json!({"email": "pat@elsewhere.example"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "{:?}", resp.text().await);
    assert_eq!(
        me(&base, &client, &pat_token).await,
        StatusCode::UNAUTHORIZED
    );
    let row = user_session::get(&pool, jti).await.unwrap().unwrap();
    assert_eq!(row.revoked_reason.as_deref(), Some("identity_changed"));
}

// ── Rate limits (#695) ──────────────────────────────────────────────

/// `/v1/echo` behind the gate and the `/v1` limiter, in production order.
async fn spawn_v1_echo(pool: PgPool) -> SocketAddr {
    async fn echo() -> &'static str {
        "ok"
    }
    let state = common::make_app_state(pool).await;
    let app = Router::new()
        .route("/v1/echo", get(echo))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            overslash_api::middleware::rate_limit::rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            overslash_api::middleware::session_gate::session_gate,
        ))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// The gate runs before the limiter, so a revoked cookie — say, a stolen one
/// the owner has since signed out — is anonymous by the time the limiter
/// looks, and cannot drain the owner's dashboard bucket.
#[tokio::test]
async fn a_revoked_session_does_not_spend_its_owners_bucket() {
    let pool = common::test_pool().await;
    let (org_id, user_id, _key) =
        common::seed_org_user_key(&pool, common::SeedOptions::default()).await;
    overslash_db::OrgScope::new(org_id, pool.clone())
        .upsert_rate_limit("user", Some(user_id), None, 2, 60)
        .await
        .unwrap();
    let live_jti = session_row(&pool, org_id, user_id).await;
    let dead_jti = session_row(&pool, org_id, user_id).await;
    user_session::revoke(&pool, dead_jti, None, "logout")
        .await
        .unwrap();
    let addr = spawn_v1_echo(pool).await;
    let client = Client::new();
    let url = format!("http://{addr}/v1/echo");

    let dead = forge(org_id, user_id, Some(dead_jti), 3600);
    for _ in 0..5 {
        let resp = client
            .get(&url)
            .header("cookie", cookie(&dead))
            .send()
            .await
            .unwrap();
        assert!(
            resp.headers().get("x-ratelimit-limit").is_none(),
            "a dead session is never metered as its owner"
        );
    }

    let live = forge(org_id, user_id, Some(live_jti), 3600);
    for i in 0..2 {
        let resp = client
            .get(&url)
            .header("cookie", cookie(&live))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "request {i}");
        assert_eq!(resp.headers()["x-ratelimit-limit"], "2");
    }
    let resp = client
        .get(&url)
        .header("cookie", cookie(&live))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

// ── Valkey cache ────────────────────────────────────────────────────

/// Two replicas sharing Valkey: a revocation on one evicts the other's cached
/// "live". Runs only where `REDIS_URL` points at a server (CI, `make
/// local-db`).
#[tokio::test]
async fn a_revocation_evicts_the_shared_cache_for_every_replica() {
    let Ok(url) = std::env::var("REDIS_URL") else {
        eprintln!("REDIS_URL unset; skipping");
        return;
    };
    let a = overslash_api::services::user_sessions::cache::redis(&url)
        .await
        .expect("REDIS_URL reachable");
    let b = overslash_api::services::user_sessions::cache::redis(&url)
        .await
        .unwrap();
    let (jti, identity) = (Uuid::new_v4(), Uuid::new_v4());
    a.put(jti, identity, std::time::Duration::from_secs(30))
        .await;
    assert_eq!(b.get(jti).await, Some(identity));
    b.invalidate(&[jti]).await;
    assert_eq!(a.get(jti).await, None);
}
