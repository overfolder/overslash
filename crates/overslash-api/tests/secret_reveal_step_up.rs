// Dynamic SQL configures org IdPs and counts audit rows.
#![allow(clippy::disallowed_methods)]
//! Revealing a secret needs a fresh sign-in (CASA 2.4.1).
//!
//! Reveal is a member's own read, so neither `AdminAcl` nor the method guard
//! would ever reach it: the handler calls `admin_step_up::require_fresh`. The
//! rule is otherwise the admin one, including what is exempt.

use crate::admin_step_up::{session, shared_org, start_with_google, step_up_reason};
use crate::common;

use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

const VALUE: &str = "sk_live_step_up_canary";

/// A non-admin user in the org, with `name` in their own vault.
async fn member_with_secret(
    base: &str,
    client: &Client,
    pool: &PgPool,
    org_id: Uuid,
    admin_key: &str,
    name: &str,
) -> Uuid {
    let member: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": format!("member-{}", Uuid::new_v4()), "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let member_id: Uuid = member["id"].as_str().unwrap().parse().unwrap();
    // A session that passes the gate, because writing is not what is tested.
    let writer = session(pool, org_id, member_id, Some("idp"), Some("google"), 0).await;
    let resp = client
        .put(format!("{base}/v1/secrets/{name}"))
        .header("cookie", writer)
        .json(&json!({"value": VALUE}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    member_id
}

async fn reveal(
    base: &str,
    client: &Client,
    auth: (&str, &str),
    name: &str,
    version: i32,
    query: &str,
) -> reqwest::Response {
    client
        .post(format!(
            "{base}/v1/secrets/{name}/versions/{version}/reveal{query}"
        ))
        .header(auth.0, auth.1)
        .send()
        .await
        .unwrap()
}

async fn assert_revealed(resp: reqwest::Response) {
    let status = resp.status();
    let body = resp.text().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    let body: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["value"], VALUE);
}

async fn revealed_rows(pool: &PgPool, org_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE org_id = $1 AND action = 'secret.revealed'",
    )
    .bind(org_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// The gap the gate closes: nothing about this caller is admin-class.
#[tokio::test]
async fn a_member_needs_a_fresh_idp_sign_in_to_reveal_their_own_secret() {
    let pool = common::test_pool().await;
    let (base, client) = start_with_google(pool.clone(), false).await;
    let (org_id, _, key) = shared_org(&base, &client).await;
    let member = member_with_secret(&base, &client, &pool, org_id, &key, "mine").await;

    for (method, provider, age, want) in [
        (Some("magic_link"), None, 60, "idp_required"),
        (None, None, 0, "idp_required"),
        (Some("idp"), Some("google"), 7200, "stale"),
    ] {
        let stale = session(&pool, org_id, member, method, provider, age).await;
        let resp = reveal(&base, &client, ("cookie", &stale), "mine", 1, "").await;
        let (reason, body) = step_up_reason(resp).await;
        assert_eq!(reason.as_deref(), Some(want), "{body}");
        assert!(!body.to_string().contains(VALUE), "{body}");
        assert_eq!(body["providers"][0]["key"], "google", "{body}");
    }
    assert_eq!(
        revealed_rows(&pool, org_id).await,
        0,
        "a refusal reveals nothing"
    );

    let fresh = session(&pool, org_id, member, Some("idp"), Some("google"), 60).await;
    assert_revealed(reveal(&base, &client, ("cookie", &fresh), "mine", 1, "").await).await;
    assert_eq!(revealed_rows(&pool, org_id).await, 1);
}

#[tokio::test]
async fn an_idp_sign_in_with_no_known_time_cannot_reveal() {
    let pool = common::test_pool().await;
    let (base, client) = start_with_google(pool.clone(), false).await;
    let (org_id, _, key) = shared_org(&base, &client).await;
    let member = member_with_secret(&base, &client, &pool, org_id, &key, "mine").await;

    let unknown = session(&pool, org_id, member, Some("idp"), Some("google"), 0).await;
    sqlx::query("UPDATE user_sessions SET authenticated_at = NULL WHERE identity_id = $1")
        .bind(member)
        .execute(&pool)
        .await
        .unwrap();
    let resp = reveal(&base, &client, ("cookie", &unknown), "mine", 1, "").await;
    let (reason, _) = step_up_reason(resp).await;
    assert_eq!(reason.as_deref(), Some("auth_time_missing"));
}

#[tokio::test]
async fn the_idp_must_be_one_the_org_signs_in_with() {
    let pool = common::test_pool().await;
    // No root IdP: with one, the org would accept managed Google as well.
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, _, key) = shared_org(&base, &client).await;
    let member = member_with_secret(&base, &client, &pool, org_id, &key, "mine").await;
    sqlx::query(
        "INSERT INTO org_idp_configs (org_id, provider_key, enabled) VALUES ($1, 'github', true)",
    )
    .bind(org_id)
    .execute(&pool)
    .await
    .unwrap();

    let google = session(&pool, org_id, member, Some("idp"), Some("google"), 60).await;
    let resp = reveal(&base, &client, ("cookie", &google), "mine", 1, "").await;
    let (reason, body) = step_up_reason(resp).await;
    assert_eq!(reason.as_deref(), Some("provider_not_allowed"));
    let login_path = body["providers"][0]["login_path"].as_str().unwrap();
    assert!(
        login_path.starts_with("/auth/login/github?step_up=true&org=stepup-"),
        "{login_path}"
    );

    let github = session(&pool, org_id, member, Some("idp"), Some("github"), 60).await;
    assert_revealed(reveal(&base, &client, ("cookie", &github), "mine", 1, "").await).await;
}

/// An admin reaches other vaults through the same gate, not around it.
#[tokio::test]
async fn an_admin_revealing_another_vault_is_gated_too() {
    let pool = common::test_pool().await;
    let (base, client) = start_with_google(pool.clone(), false).await;
    let (org_id, admin, key) = shared_org(&base, &client).await;
    let member = member_with_secret(&base, &client, &pool, org_id, &key, "theirs").await;
    let query = format!("?owner={member}");

    let magic = session(&pool, org_id, admin, Some("magic_link"), None, 60).await;
    let resp = reveal(&base, &client, ("cookie", &magic), "theirs", 1, &query).await;
    assert_eq!(
        step_up_reason(resp).await.0.as_deref(),
        Some("idp_required")
    );

    let fresh = session(&pool, org_id, admin, Some("idp"), Some("google"), 60).await;
    assert_revealed(reveal(&base, &client, ("cookie", &fresh), "theirs", 1, &query).await).await;
}

/// The 403 must not become an oracle for what is in the vault, and a vault
/// out of reach must not cost the human a pointless sign-in.
#[tokio::test]
async fn the_refusal_says_nothing_about_the_vault() {
    let pool = common::test_pool().await;
    let (base, client) = start_with_google(pool.clone(), false).await;
    let (org_id, _, key) = shared_org(&base, &client).await;
    let member = member_with_secret(&base, &client, &pool, org_id, &key, "mine").await;
    let other = member_with_secret(&base, &client, &pool, org_id, &key, "theirs").await;
    let magic = session(&pool, org_id, member, Some("magic_link"), None, 60).await;

    let mut bodies = Vec::new();
    for (name, version) in [("mine", 1), ("mine", 99), ("no_such_secret", 1)] {
        let resp = reveal(&base, &client, ("cookie", &magic), name, version, "").await;
        bodies.push(step_up_reason(resp).await.1);
    }
    assert_eq!(bodies[0], bodies[1]);
    assert_eq!(bodies[0], bodies[2]);

    let query = format!("?owner={other}");
    let resp = reveal(&base, &client, ("cookie", &magic), "theirs", 1, &query).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_session_with_no_jti_and_dev_sign_ins_under_dev_auth_are_exempt() {
    let pool = common::test_pool().await;
    let (base, client) = start_with_google(pool.clone(), true).await;
    let (org_id, _, key) = shared_org(&base, &client).await;
    let member = member_with_secret(&base, &client, &pool, org_id, &key, "mine").await;

    let stateless = common::session_cookie(org_id, member);
    assert_revealed(reveal(&base, &client, ("cookie", &stateless), "mine", 1, "").await).await;

    let dev = session(&pool, org_id, member, Some("dev"), None, 60).await;
    assert_revealed(reveal(&base, &client, ("cookie", &dev), "mine", 1, "").await).await;

    // Same freshness rule as `AdminAcl`: `dev` waives the IdP, not the window.
    let old = session(&pool, org_id, member, Some("dev"), None, 7200).await;
    let resp = reveal(&base, &client, ("cookie", &old), "mine", 1, "").await;
    assert_eq!(step_up_reason(resp).await.0.as_deref(), Some("stale"));
}

#[tokio::test]
async fn a_dev_session_without_dev_auth_cannot_reveal() {
    let pool = common::test_pool().await;
    let (base, client) = start_with_google(pool.clone(), false).await;
    let (org_id, _, key) = shared_org(&base, &client).await;
    let member = member_with_secret(&base, &client, &pool, org_id, &key, "mine").await;

    let dev = session(&pool, org_id, member, Some("dev"), None, 60).await;
    let resp = reveal(&base, &client, ("cookie", &dev), "mine", 1, "").await;
    assert_eq!(
        step_up_reason(resp).await.0.as_deref(),
        Some("idp_required")
    );
}

#[tokio::test]
async fn a_deployment_without_any_idp_accepts_a_fresh_magic_link() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, _, key) = shared_org(&base, &client).await;
    let member = member_with_secret(&base, &client, &pool, org_id, &key, "mine").await;

    let fresh = session(&pool, org_id, member, Some("magic_link"), None, 60).await;
    assert_revealed(reveal(&base, &client, ("cookie", &fresh), "mine", 1, "").await).await;

    let stale = session(&pool, org_id, member, Some("magic_link"), None, 7200).await;
    let resp = reveal(&base, &client, ("cookie", &stale), "mine", 1, "").await;
    let (reason, body) = step_up_reason(resp).await;
    assert_eq!(reason.as_deref(), Some("stale"));
    assert_eq!(body["providers"][0]["key"], "email", "{body}");
}

/// Personal orgs keep D136's exemption: nothing there reaches anyone else.
#[tokio::test]
async fn a_personal_org_is_exempt() {
    let pool = common::test_pool().await;
    let (base, client) = start_with_google(pool.clone(), false).await;
    let (org_id, identity, key) = shared_org(&base, &client).await;
    sqlx::query("UPDATE orgs SET is_personal = true WHERE id = $1")
        .bind(org_id)
        .execute(&pool)
        .await
        .unwrap();
    let resp = client
        .put(format!("{base}/v1/secrets/mine"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({"value": VALUE}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());

    let magic = session(&pool, org_id, identity, Some("magic_link"), None, 60).await;
    assert_revealed(reveal(&base, &client, ("cookie", &magic), "mine", 1, "").await).await;
}

/// Reveal was never a bearer path, and the step-up exemption for bearers must
/// not make it one.
#[tokio::test]
async fn an_api_key_still_cannot_reveal() {
    let pool = common::test_pool().await;
    let (base, client) = start_with_google(pool.clone(), false).await;
    let (org_id, _, key) = shared_org(&base, &client).await;
    member_with_secret(&base, &client, &pool, org_id, &key, "mine").await;

    let bearer = format!("Bearer {key}");
    let resp = reveal(&base, &client, ("authorization", &bearer), "mine", 1, "").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
