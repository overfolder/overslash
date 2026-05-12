// Test setup queries the DB directly to assert audit-row + token-state
// side effects of the routes under test. Dynamic queries are fine here.
#![allow(clippy::disallowed_methods)]
//! Per-user welcome-email unsubscribe state.
//!
//! Covers the surfaces shipped with TODO §1.1's "welcome / first-login email"
//! and "per-user unsubscribe state":
//!
//! * `GET/PUT /v1/account/email-preferences` — authenticated toggle exposed
//!   by the `/account` page, plus the audit rows it writes.
//! * `GET/POST /v1/unsubscribe?token=…` — public one-click endpoint
//!   embedded in welcome emails (RFC 8058 List-Unsubscribe-Post).
//! * The `welcome_email_sent_at IS NULL` gate that makes the welcome-send
//!   call site naturally idempotent for re-entered provisioning paths
//!   (corp-org returning members, second-IdP adds).

mod common;

use overslash_db::repos::{email_unsubscribe_token, user as user_repo};
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;

#[tokio::test]
async fn email_prefs_default_subscribed_then_toggle_roundtrip() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool.clone()).await;

    let token_resp: Value = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = token_resp["token"].as_str().unwrap();
    let org_id: Uuid = token_resp["org_id"].as_str().unwrap().parse().unwrap();

    let cookie = format!("oss_session={token}");

    let prefs: Value = client
        .get(format!("{base}/v1/account/email-preferences"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(prefs["welcome_emails"], true, "default is subscribed");

    let unsubbed: Value = client
        .put(format!("{base}/v1/account/email-preferences"))
        .header("cookie", &cookie)
        .json(&serde_json::json!({ "welcome_emails": false }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(unsubbed["welcome_emails"], false);

    let after: Value = client
        .get(format!("{base}/v1/account/email-preferences"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(after["welcome_emails"], false, "state persists");

    let resub: Value = client
        .put(format!("{base}/v1/account/email-preferences"))
        .header("cookie", &cookie)
        .json(&serde_json::json!({ "welcome_emails": true }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resub["welcome_emails"], true);

    // The toggle writes audit rows scoped to the caller's current org. Both
    // actions should be present after the round-trip.
    let rows = sqlx::query(
        "SELECT action FROM audit_log
         WHERE org_id = $1 AND action IN ('email.unsubscribed','email.resubscribed')
         ORDER BY created_at",
    )
    .bind(org_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    let actions: Vec<String> = rows.iter().map(|r| r.get::<String, _>("action")).collect();
    assert_eq!(
        actions,
        vec!["email.unsubscribed", "email.resubscribed"],
        "toggle writes one audit row per transition"
    );
}

#[tokio::test]
async fn unsubscribe_post_one_click_is_idempotent_and_opaque() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool.clone()).await;

    // Provision a user via the dev token route, then mint a token row pointing
    // at that user the same way `welcome_email::send_if_due` would.
    let token_resp: Value = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cookie = format!("oss_session={}", token_resp["token"].as_str().unwrap());
    let org_id: Uuid = token_resp["org_id"].as_str().unwrap().parse().unwrap();
    let me: Value = client
        .get(format!("{base}/auth/me/identity"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id: Uuid = me["user_id"].as_str().unwrap().parse().unwrap();

    let row = email_unsubscribe_token::create(&pool, user_id, org_id, "welcome")
        .await
        .unwrap();

    // First click flips unsubscribe + stamps redeemed_at + writes audit.
    let resp = client
        .post(format!("{base}/v1/unsubscribe?token={}", row.token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let user_row = sqlx::query("SELECT welcome_emails_unsubscribed_at FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        user_row
            .get::<Option<time::OffsetDateTime>, _>("welcome_emails_unsubscribed_at")
            .is_some(),
        "first click should stamp welcome_emails_unsubscribed_at"
    );
    let redeemed: Option<time::OffsetDateTime> =
        sqlx::query("SELECT redeemed_at FROM email_unsubscribe_tokens WHERE token = $1")
            .bind(row.token)
            .fetch_one(&pool)
            .await
            .unwrap()
            .get("redeemed_at");
    assert!(redeemed.is_some(), "first click stamps redeemed_at");

    let audit_count: i64 = sqlx::query(
        "SELECT COUNT(*) AS c FROM audit_log
         WHERE org_id = $1 AND action = 'email.unsubscribed'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap()
    .get("c");
    assert_eq!(audit_count, 1);

    // Second click on the same token: still 204, no extra audit row.
    let resp = client
        .post(format!("{base}/v1/unsubscribe?token={}", row.token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let audit_count: i64 = sqlx::query(
        "SELECT COUNT(*) AS c FROM audit_log
         WHERE org_id = $1 AND action = 'email.unsubscribed'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap()
    .get("c");
    assert_eq!(audit_count, 1, "replay must not duplicate audit rows");

    // RFC 8058 §3.1: an unknown / malformed token must still 204 on POST so
    // probes can't enumerate valid tokens.
    let resp = client
        .post(format!("{base}/v1/unsubscribe?token={}", Uuid::new_v4()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let resp = client
        .post(format!("{base}/v1/unsubscribe?token=not-a-uuid"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn unsubscribe_get_renders_html_on_hit_and_404s_on_miss() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool.clone()).await;

    let token_resp: Value = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cookie = format!("oss_session={}", token_resp["token"].as_str().unwrap());
    let org_id: Uuid = token_resp["org_id"].as_str().unwrap().parse().unwrap();
    let me: Value = client
        .get(format!("{base}/auth/me/identity"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id: Uuid = me["user_id"].as_str().unwrap().parse().unwrap();

    let row = email_unsubscribe_token::create(&pool, user_id, org_id, "welcome")
        .await
        .unwrap();
    let resp = client
        .get(format!("{base}/v1/unsubscribe?token={}", row.token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("You've been unsubscribed."),
        "GET should render the confirmation HTML: {body}"
    );

    // GET on an unknown token can surface 404 (browser users get a clear
    // signal); only POST has to stay opaque per RFC 8058.
    let resp = client
        .get(format!("{base}/v1/unsubscribe?token={}", Uuid::new_v4()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn welcome_email_sent_at_gate_is_one_shot() {
    // The gate that makes `welcome_email::send_if_due` idempotent across
    // re-entered provisioning paths (corp-org returning members, second-IdP
    // adds): `mark_welcome_sent` returns `true` exactly once per user, then
    // `false` forever after. Stand-in for the call-site gate the service
    // uses — `user.welcome_email_sent_at.is_some()` short-circuits before
    // any token is minted, so the second call would never reach the mailer.
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool.clone()).await;
    let token_resp: Value = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cookie = format!("oss_session={}", token_resp["token"].as_str().unwrap());
    let me: Value = client
        .get(format!("{base}/auth/me/identity"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id: Uuid = me["user_id"].as_str().unwrap().parse().unwrap();

    let user = user_repo::get_by_id(&pool, user_id).await.unwrap().unwrap();
    assert!(
        user.welcome_email_sent_at.is_none(),
        "fresh user has no welcome_email_sent_at"
    );

    let first = user_repo::mark_welcome_sent(&pool, user_id).await.unwrap();
    assert!(first, "first mark should succeed");

    let second = user_repo::mark_welcome_sent(&pool, user_id).await.unwrap();
    assert!(
        !second,
        "second mark must return false so the service short-circuits"
    );
}
