// Dynamic SQL points the Google provider row at the fake IdP.
#![allow(clippy::disallowed_methods)]
//! The admin step-up's freshness comes from the IdP's `auth_time`, never the
//! callback time (D136 and its amendment).
//!
//! An OIDC IdP that omits `auth_time` — Google unless asked for it and
//! enabled, or any IdP answering a `max_age=0` step-up from its own session
//! without saying so — leaves the session with no `authenticated_at`, so it
//! cannot reach admin mutations: 403 `step_up_required` with reason
//! `auth_time_missing`. Only `ADMIN_STEP_UP_CALLBACK_TIME_PROVIDERS` (GitHub
//! by default, which is not OIDC) stand the callback time in for it.

use crate::common;

use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;
use std::net::SocketAddr;
use uuid::Uuid;

use overslash_api::services::jwt;
use overslash_db::repos::user_session;

/// A deployment whose Google sign-in goes to the fake IdP. `callback_time`
/// overrides `ADMIN_STEP_UP_CALLBACK_TIME_PROVIDERS`.
async fn start(callback_time: Option<Vec<String>>) -> (PgPool, SocketAddr, String, Client) {
    let pool = common::test_pool().await;
    let mock = common::start_mock().await;
    sqlx::query(
        "UPDATE oauth_providers SET authorization_endpoint = $1, token_endpoint = $2, userinfo_endpoint = $3 WHERE key = 'google'",
    )
    .bind(format!("http://{mock}/oauth/authorize"))
    .bind(format!("http://{mock}/oauth/token"))
    .bind(format!("http://{mock}/oidc/userinfo"))
    .execute(&pool)
    .await
    .unwrap();
    let (base, client) = common::start_api_with_auth_providers_customized(
        pool.clone(),
        Some(("test_google_id".into(), "test_google_secret".into())),
        None,
        "http://localhost:3000",
        |c| {
            if let Some(keys) = callback_time {
                c.admin_step_up_callback_time_providers = keys;
            }
        },
    )
    .await;
    (pool, mock, base, client)
}

/// What the fake IdP reports as `auth_time` on the next sign-in (`null`
/// for nothing).
async fn idp_reports(mock: SocketAddr, auth_time: Value) {
    let claims = if auth_time.is_null() {
        json!({})
    } else {
        json!({ "auth_time": auth_time })
    };
    let resp = Client::new()
        .post(format!("http://{mock}/control/userinfo-claims"))
        .json(&claims)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
}

fn set_session(resp: &reqwest::Response) -> Option<String> {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| c.strip_prefix("__Host-oss_session="))
        .map(|rest| rest.split(';').next().unwrap().to_string())
        .filter(|t| !t.is_empty())
}

fn cookie(token: &str) -> String {
    format!("__Host-oss_session={token}")
}

/// A Google sign-in at the root, through the callback; `extra` is appended
/// to its cookies (a session to replace, a step-up org).
async fn google_callback(base: &str, client: &Client, extra: &str) -> reqwest::Response {
    let nonce = Uuid::new_v4().simple().to_string();
    client
        .get(format!(
            "{base}/auth/callback/google?code=c&state=login:google:{nonce}"
        ))
        .header(
            "cookie",
            format!(
                "__Host-oss_auth_nonce={nonce}; __Host-oss_auth_verifier=v; __Host-oss_auth_org=none{}",
                extra.replace("{nonce}", &nonce)
            ),
        )
        .send()
        .await
        .unwrap()
}

async fn row(pool: &PgPool, token: &str) -> user_session::UserSessionRow {
    let claims = jwt::verify(&common::signing_key_bytes(), token, jwt::AUD_SESSION).unwrap();
    user_session::get(pool, claims.jti.unwrap())
        .await
        .unwrap()
        .unwrap()
}

/// Sign in, then create a shared org with no IdP of its own; returns its id
/// and the session re-scoped into it.
async fn shared_org(base: &str, client: &Client) -> (Uuid, String) {
    let resp = google_callback(base, client, "").await;
    assert_eq!(resp.status(), 303);
    let personal = cookie(&set_session(&resp).unwrap());
    let resp = client
        .post(format!("{base}/v1/orgs"))
        .header("cookie", &personal)
        .json(&json!({"name": "Corp", "slug": format!("corp-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let corp = cookie(&set_session(&resp).unwrap());
    let org: Value = resp.json().await.unwrap();
    (org["id"].as_str().unwrap().parse().unwrap(), corp)
}

/// A root step-up into `org_id`, replacing the session in `current`.
async fn step_up(base: &str, client: &Client, org_id: Uuid, current: &str) -> String {
    let resp = google_callback(
        base,
        client,
        &format!("; __Host-oss_auth_step_up_org={{nonce}}.{org_id}; {current}"),
    )
    .await;
    assert_eq!(resp.status(), 303);
    cookie(&set_session(&resp).unwrap())
}

/// `POST /v1/groups` — an `AdminAcl` mutation. `None` when it went through,
/// else the step-up reason.
async fn admin_change(base: &str, client: &Client, session: &str) -> Option<String> {
    let resp = client
        .post(format!("{base}/v1/groups"))
        .header("cookie", session)
        .json(&json!({"name": format!("g-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap();
    if resp.status().is_success() {
        return None;
    }
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "step_up_required", "{body}");
    Some(body["reason"].as_str().unwrap().to_owned())
}

/// Google sends `auth_time` only when the login asks for it.
#[tokio::test]
async fn a_google_login_asks_for_auth_time() {
    let (_, _, base, client) = start(None).await;
    for path in ["/auth/login/google", "/auth/login/google?step_up=true"] {
        let resp = client.get(format!("{base}{path}")).send().await.unwrap();
        let location = resp.headers()["location"].to_str().unwrap();
        let url = reqwest::Url::parse(location).unwrap();
        let claims = url
            .query_pairs()
            .find(|(k, _)| k == "claims")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_else(|| panic!("{path}: no claims in {location}"));
        let claims: Value = serde_json::from_str(&claims).unwrap();
        assert_eq!(claims["id_token"]["auth_time"]["essential"], true);
    }
}

/// The IdP did not say when it authenticated the human: the session has no
/// sign-in time, a step-up through the same silent IdP does not fix that, and
/// the 403 says why rather than claiming the sign-in is merely old.
#[tokio::test]
async fn an_idp_without_auth_time_cannot_pass_the_step_up() {
    let (pool, mock, base, client) = start(None).await;
    idp_reports(mock, Value::Null).await;
    let (org_id, corp) = shared_org(&base, &client).await;

    let session = step_up(&base, &client, org_id, &corp).await;
    let r = row(&pool, session.strip_prefix("__Host-oss_session=").unwrap()).await;
    assert_eq!(r.auth_method.as_deref(), Some("idp"));
    assert_eq!(r.org_id, org_id);
    assert_eq!(
        r.authenticated_at, None,
        "the callback time is not a sign-in time"
    );
    assert_eq!(
        admin_change(&base, &client, &session).await.as_deref(),
        Some("auth_time_missing")
    );
}

/// `auth_time` as an integer, a fraction or a numeric string all count; an
/// old one is stale, not fresh.
#[tokio::test]
async fn the_idps_auth_time_decides_freshness_in_any_numeric_shape() {
    let (pool, mock, base, client) = start(None).await;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    idp_reports(mock, json!(now)).await;
    let (org_id, mut session) = shared_org(&base, &client).await;

    for (auth_time, expect) in [
        (json!(now - 7200), Some("stale")),
        (json!(now as f64 + 0.5), None),
        (json!((now - 30).to_string()), None),
        (json!("not a time"), Some("auth_time_missing")),
    ] {
        idp_reports(mock, auth_time.clone()).await;
        session = step_up(&base, &client, org_id, &session).await;
        assert_eq!(
            admin_change(&base, &client, &session).await.as_deref(),
            expect,
            "auth_time {auth_time}"
        );
    }
    let r = row(&pool, session.strip_prefix("__Host-oss_session=").unwrap()).await;
    assert_eq!(r.authenticated_at, None);
}

/// A provider listed in `ADMIN_STEP_UP_CALLBACK_TIME_PROVIDERS` — GitHub by
/// default, Google here so the fake can drive it — has its callback time
/// recorded when it reports no `auth_time`. One that does report it is still
/// taken at its word.
#[tokio::test]
async fn a_callback_time_provider_counts_the_callback() {
    let (_, mock, base, client) = start(Some(vec!["google".into()])).await;
    idp_reports(mock, Value::Null).await;
    let (org_id, corp) = shared_org(&base, &client).await;
    let session = step_up(&base, &client, org_id, &corp).await;
    assert_eq!(admin_change(&base, &client, &session).await, None);

    let old = time::OffsetDateTime::now_utc().unix_timestamp() - 7200;
    idp_reports(mock, json!(old)).await;
    let session = step_up(&base, &client, org_id, &session).await;
    assert_eq!(
        admin_change(&base, &client, &session).await.as_deref(),
        Some("stale")
    );
}
