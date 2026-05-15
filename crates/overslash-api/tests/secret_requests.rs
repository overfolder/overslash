//! Integration tests for the standalone "Provide Secret" flow.
//!
//! Mint via authenticated `POST /v1/secrets/requests`, then exercise the
//! public `GET`/`POST /public/secrets/provide/{req_id}` endpoints.

#![allow(clippy::disallowed_methods)]

mod common;

use overslash_api::services::jwt;
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

async fn mint(base: &str, client: &reqwest::Client, api_key: &str, name: &str) -> Value {
    client
        .post(format!("{base}/v1/secrets/requests"))
        .header(common::auth(api_key).0, common::auth(api_key).1)
        .json(&json!({"secret_name": name, "ttl_seconds": 3600}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Build the public provide URL with the token as a query param.
fn provide_url(base: &str, req_id: &str, token: &str) -> String {
    format!(
        "{base}/public/secrets/provide/{req_id}?token={token}",
        token = urlencoding::encode(token)
    )
}

#[tokio::test]
async fn happy_path_mint_get_submit_stored() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org, _ident, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let req = mint(&base, &client, &agent_key, "openai_api_key").await;
    let req_id = req["id"].as_str().unwrap();
    let token = req["token"].as_str().unwrap();

    // GET metadata (no auth)
    let resp = client
        .get(provide_url(&base, req_id, token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let meta: Value = resp.json().await.unwrap();
    assert_eq!(meta["secret_name"], "openai_api_key");
    assert!(meta["identity_label"].as_str().is_some());

    // Submit value
    let resp = client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
        .json(&json!({"token": token, "value": "sk-real-value"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["version"], 1);

    // Confirm secret exists by writing a second version (PUT uses WriteAcl,
    // which accepts bearer tokens, unlike GET which is dashboard-only).
    let resp = client
        .put(format!("{base}/v1/secrets/openai_api_key"))
        .header(common::auth(&agent_key).0, common::auth(&agent_key).1)
        .json(&json!({"value": "sk-updated-value"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let got: Value = resp.json().await.unwrap();
    assert_eq!(got["name"], "openai_api_key");
    assert_eq!(got["version"], 2);
}

#[tokio::test]
async fn single_use_second_submit_rejected() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org, _ident, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let req = mint(&base, &client, &agent_key, "k1").await;
    let req_id = req["id"].as_str().unwrap();
    let token = req["token"].as_str().unwrap();

    let r1 = client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
        .json(&json!({"token": token, "value": "v1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 200);

    let r2 = client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
        .json(&json!({"token": token, "value": "v2"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 410);
}

#[tokio::test]
async fn tampered_token_rejected() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org, _ident, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let req = mint(&base, &client, &agent_key, "k2").await;
    let req_id = req["id"].as_str().unwrap();
    let token = req["token"].as_str().unwrap();
    // Flip a character in the signature segment.
    let mut bad = token.to_string();
    let last = bad.pop().unwrap();
    bad.push(if last == 'a' { 'b' } else { 'a' });

    let r = client
        .get(provide_url(&base, req_id, &bad))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
}

#[tokio::test]
async fn mismatched_req_id_rejected() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org, _ident, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let a = mint(&base, &client, &agent_key, "ka").await;
    let b = mint(&base, &client, &agent_key, "kb").await;
    // Use a's request ID but b's token — should be rejected.
    let r = client
        .get(provide_url(
            &base,
            a["id"].as_str().unwrap(),
            b["token"].as_str().unwrap(),
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
}

#[tokio::test]
async fn empty_value_rejected() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org, _ident, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let req = mint(&base, &client, &agent_key, "k3").await;
    let r = client
        .post(format!(
            "{base}/public/secrets/provide/{}",
            req["id"].as_str().unwrap()
        ))
        .json(&json!({"token": req["token"], "value": ""}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
}

// ─── User Signed Mode tests ───────────────────────────────────────────

/// Signing key used by `common::start_api` — must stay in sync.
const TEST_SIGNING_KEY_HEX: &str = concat!(
    "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
    "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
);

fn signing_bytes() -> Vec<u8> {
    hex::decode(TEST_SIGNING_KEY_HEX).unwrap()
}

/// Mint a dashboard-shaped `oss_session` JWT for a given identity + org.
/// Matches what `POST /v1/auth/*` would issue on a successful login.
fn mint_session_cookie(identity_id: Uuid, org_id: Uuid, email: &str) -> String {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let claims = jwt::Claims {
        sub: identity_id,
        org: org_id,
        email: email.into(),
        aud: jwt::AUD_SESSION.into(),
        iat: now,
        exp: now + 3600,
        user_id: None,
        mcp_client_id: None,
    };
    let token = jwt::mint(&signing_bytes(), &claims).unwrap();
    format!("oss_session={token}")
}

async fn create_user(base: &str, client: &reqwest::Client, admin_key: &str, name: &str) -> Uuid {
    let v: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": name, "kind": "user", "email": format!("{name}@example.test")}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    v["id"].as_str().unwrap().parse().unwrap()
}

async fn patch_secret_request_settings(
    base: &str,
    client: &reqwest::Client,
    admin_key: &str,
    org_id: Uuid,
    allow_unsigned: bool,
) {
    let resp = client
        .patch(format!("{base}/v1/orgs/{org_id}/secret-request-settings"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"allow_unsigned_secret_provide": allow_unsigned}))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "patch secret-request-settings failed: {}",
        resp.status()
    );
}

#[tokio::test]
async fn secret_request_settings_get_defaults_to_allow_unsigned() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (org_id, _ident, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Fresh org: GET should return the default (true) without any prior PATCH.
    let r = client
        .get(format!("{base}/v1/orgs/{org_id}/secret-request-settings"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["allow_unsigned_secret_provide"], true);

    // After PATCH off, GET should reflect the new value.
    patch_secret_request_settings(&base, &client, &admin_key, org_id, false).await;
    let r = client
        .get(format!("{base}/v1/orgs/{org_id}/secret-request-settings"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["allow_unsigned_secret_provide"], false);
}

#[tokio::test]
async fn anonymous_fulfillment_records_no_provisioner() {
    let pool = common::test_pool().await;
    let q = pool.clone();
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org, _ident, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let req = mint(&base, &client, &agent_key, "k_anon").await;
    let req_id = req["id"].as_str().unwrap();
    let token = req["token"].as_str().unwrap();

    let r = client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
        .json(&json!({"token": token, "value": "anon-val"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // The version row should have provisioned_by_user_id = NULL for
    // anonymous submissions.
    let row = sqlx::query(
        "SELECT sv.provisioned_by_user_id \
         FROM secret_versions sv \
         JOIN secrets s ON sv.secret_id = s.id \
         WHERE s.name = 'k_anon'",
    )
    .fetch_one(&q)
    .await
    .unwrap();
    let v: Option<Uuid> = row.get(0);
    assert!(v.is_none(), "expected NULL provisioner, got {v:?}");
}

#[tokio::test]
async fn session_bound_fulfillment_records_user() {
    let pool = common::test_pool().await;
    let q = pool.clone();
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (org_id, _ident, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // The human who will paste the value. Distinct from the "target"
    // identity so we can assert the *session* identity is what ends up on
    // the version row.
    let provisioner_id = create_user(&base, &client, &admin_key, "jane").await;
    let cookie = mint_session_cookie(provisioner_id, org_id, "jane@example.test");

    let req = mint(&base, &client, &agent_key, "k_session").await;
    let req_id = req["id"].as_str().unwrap();
    let token = req["token"].as_str().unwrap();

    // GET should surface the viewer so the page can render the banner.
    let r = client
        .get(provide_url(&base, req_id, token))
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let meta: Value = r.json().await.unwrap();
    assert_eq!(meta["require_user_session"], false);
    assert_eq!(meta["viewer"]["identity_id"], provisioner_id.to_string());
    assert_eq!(meta["viewer"]["email"], "jane@example.test");

    // POST with the cookie records the provisioner.
    let r = client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
        .header("Cookie", &cookie)
        .json(&json!({"token": token, "value": "jane-val"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    let row = sqlx::query(
        "SELECT sv.provisioned_by_user_id \
         FROM secret_versions sv \
         JOIN secrets s ON sv.secret_id = s.id \
         WHERE s.name = 'k_session'",
    )
    .fetch_one(&q)
    .await
    .unwrap();
    let v: Option<Uuid> = row.get(0);
    assert_eq!(v, Some(provisioner_id));
}

#[tokio::test]
async fn org_disallows_unsigned_rejects_anonymous() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (org_id, _ident, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    patch_secret_request_settings(&base, &client, &admin_key, org_id, false).await;

    let req = mint(&base, &client, &agent_key, "k_strict").await;
    let req_id = req["id"].as_str().unwrap();
    let token = req["token"].as_str().unwrap();

    // GET metadata should still succeed (metadata isn't secret-bearing) but
    // must flag `require_user_session`.
    let r = client
        .get(provide_url(&base, req_id, token))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let meta: Value = r.json().await.unwrap();
    assert_eq!(meta["require_user_session"], true);
    assert!(meta["viewer"].is_null());

    // Anonymous POST: rejected with 401 + user_session_required.
    let r = client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
        .json(&json!({"token": token, "value": "nope"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let body: Value = r.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or("")
            .contains("user_session_required"),
        "unexpected body: {body}"
    );
}

#[tokio::test]
async fn org_disallows_unsigned_accepts_session() {
    let pool = common::test_pool().await;
    let q = pool.clone();
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (org_id, _ident, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    patch_secret_request_settings(&base, &client, &admin_key, org_id, false).await;

    let provisioner_id = create_user(&base, &client, &admin_key, "alex").await;
    let cookie = mint_session_cookie(provisioner_id, org_id, "alex@example.test");

    let req = mint(&base, &client, &agent_key, "k_strict_ok").await;
    let req_id = req["id"].as_str().unwrap();
    let token = req["token"].as_str().unwrap();

    let r = client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
        .header("Cookie", &cookie)
        .json(&json!({"token": token, "value": "sig-val"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    let row = sqlx::query(
        "SELECT sv.provisioned_by_user_id \
         FROM secret_versions sv \
         JOIN secrets s ON sv.secret_id = s.id \
         WHERE s.name = 'k_strict_ok'",
    )
    .fetch_one(&q)
    .await
    .unwrap();
    let v: Option<Uuid> = row.get(0);
    assert_eq!(v, Some(provisioner_id));
}

#[tokio::test]
async fn outstanding_url_unaffected_by_toggle() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (org_id, _ident, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Mint under the permissive default — this URL carries
    // require_user_session = false for its entire lifetime.
    let req = mint(&base, &client, &agent_key, "k_legacy").await;
    let req_id = req["id"].as_str().unwrap();
    let token = req["token"].as_str().unwrap();

    // Flip the org toggle off *after* minting.
    patch_secret_request_settings(&base, &client, &admin_key, org_id, false).await;

    // Old URL still redeems anonymously. Policy is forward-only.
    let r = client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
        .json(&json!({"token": token, "value": "legacy-val"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // A *new* request minted after the toggle should require a session.
    let req2 = mint(&base, &client, &agent_key, "k_post_flip").await;
    let r2 = client
        .post(format!(
            "{base}/public/secrets/provide/{}",
            req2["id"].as_str().unwrap()
        ))
        .json(&json!({"token": req2["token"], "value": "v"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 401);
}

#[tokio::test]
async fn expired_token_rejected() {
    // The provide page must reject a request whose `expires_at` is in the
    // past, even when the JWT signature is otherwise valid. Mint normally
    // (so the JWT is well-formed), then fast-forward `expires_at` past now
    // via SQL. Both GET (page metadata) and POST (submit) must return 410
    // `expired`.
    let pool = common::test_pool().await;
    let q = pool.clone();
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org, _ident, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let req = mint(&base, &client, &agent_key, "k_expired").await;
    let req_id = req["id"].as_str().unwrap();
    let token = req["token"].as_str().unwrap();

    // Fast-forward expiry. The JWT's own `exp` claim is also checked, but
    // the row's `expires_at` is the gate the test is locking — so set it
    // far enough in the past that the row check fires regardless.
    let past = time::OffsetDateTime::now_utc() - time::Duration::seconds(3600);
    sqlx::query("UPDATE secret_requests SET expires_at = $1 WHERE id = $2")
        .bind(past)
        .bind(req_id)
        .execute(&q)
        .await
        .unwrap();

    let r = client
        .get(provide_url(&base, req_id, token))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 410);
    let body: Value = r.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap_or("").contains("expired")
            || body["error"]
                .as_str()
                .unwrap_or("")
                .contains("invalid_token"),
        "unexpected GET body: {body}"
    );

    let r = client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
        .json(&json!({"token": token, "value": "v"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 410);
    let body: Value = r.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap_or("").contains("expired")
            || body["error"]
                .as_str()
                .unwrap_or("")
                .contains("invalid_token"),
        "unexpected POST body: {body}"
    );
}

#[tokio::test]
async fn cross_org_session_ignored() {
    let pool = common::test_pool().await;
    let q = pool.clone();
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    // Org A: where the request will be minted.
    let (_org_a, _ident_a, agent_key_a, _admin_key_a) =
        common::bootstrap_org_identity(&base, &client).await;

    // Org B: some *other* org. Any session for this org must be treated as
    // anonymous when redeeming an Org A request — we must never credit an
    // identity from another tenant.
    let (org_b, _ident_b, _agent_key_b, admin_key_b) =
        common::bootstrap_org_identity(&base, &client).await;
    let user_b = create_user(&base, &client, &admin_key_b, "mallory").await;
    let cookie_b = mint_session_cookie(user_b, org_b, "mallory@example.test");

    let req = mint(&base, &client, &agent_key_a, "k_xtenant").await;
    let req_id = req["id"].as_str().unwrap();
    let token = req["token"].as_str().unwrap();

    // GET with cross-org cookie — `viewer` must be null (not a leak).
    let r = client
        .get(provide_url(&base, req_id, token))
        .header("Cookie", &cookie_b)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let meta: Value = r.json().await.unwrap();
    assert!(
        meta["viewer"].is_null(),
        "cross-org session leaked into viewer: {meta}"
    );

    // POST succeeds (org A allows unsigned), but should credit no one —
    // the cross-org session is silently dropped.
    let r = client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
        .header("Cookie", &cookie_b)
        .json(&json!({"token": token, "value": "xt-val"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let row = sqlx::query(
        "SELECT sv.provisioned_by_user_id \
         FROM secret_versions sv \
         JOIN secrets s ON sv.secret_id = s.id \
         WHERE s.name = 'k_xtenant'",
    )
    .fetch_one(&q)
    .await
    .unwrap();
    let v: Option<Uuid> = row.get(0);
    assert!(v.is_none(), "cross-org user credited: {v:?}");
}

#[tokio::test]
async fn session_overrides_jwt_in_audit() {
    let pool = common::test_pool().await;
    let q = pool.clone();
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (org_id, target_ident, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let provisioner = create_user(&base, &client, &admin_key, "pat").await;
    let cookie = mint_session_cookie(provisioner, org_id, "pat@example.test");

    let req = mint(&base, &client, &agent_key, "k_audit").await;
    let req_id = req["id"].as_str().unwrap();
    let token = req["token"].as_str().unwrap();

    let r = client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
        .header("Cookie", &cookie)
        .json(&json!({"token": token, "value": "audit-val"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // The audit row for `secret_request.fulfilled` should be attributed to
    // the session user (not the target identity), and the detail JSON
    // should record `user_signed = true`.
    let row = sqlx::query(
        "SELECT identity_id, detail \
         FROM audit_log \
         WHERE action = 'secret_request.fulfilled' \
         ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_one(&q)
    .await
    .unwrap();
    let audit_identity: Option<Uuid> = row.get(0);
    let detail: serde_json::Value = row.get(1);
    assert_eq!(audit_identity, Some(provisioner));
    assert_ne!(
        audit_identity,
        Some(target_ident),
        "audit should attribute to session user, not target"
    );
    assert_eq!(detail["user_signed"], true);
    assert_eq!(
        detail["provisioned_by_user_id"].as_str().unwrap(),
        provisioner.to_string()
    );
}
