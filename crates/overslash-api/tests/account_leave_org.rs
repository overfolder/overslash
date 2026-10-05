//! Leaving an org (`DELETE /v1/account/memberships/{org_id}`) runs the same
//! removal as an admin evicting the member: the caller's identity subtree is
//! archived (API keys revoked), their sessions in the org are revoked, the
//! membership is dropped and the identity is detached so a re-invite gets a
//! clean slot. Leaving the org the session is scoped to re-points the session
//! at the personal org.
//!
//! The guards (personal org, last admin, concurrent leaves) and the audit row
//! are covered in `multi_org.rs`.

#![allow(clippy::disallowed_methods)] // direct SQL seeding

use crate::common;

use overslash_api::services::jwt;
use overslash_db::repos::{identity, membership, org_bootstrap, user as user_repo, user_session};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// A session JWT (harness signing key) for `user_id` acting as `identity_id`
/// in `org_id`. With `jti`, it names a real `user_sessions` row.
fn session_token(org_id: Uuid, identity_id: Uuid, user_id: Uuid, jti: Option<Uuid>) -> String {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    jwt::mint(
        &common::signing_key_bytes(),
        &jwt::Claims {
            sub: identity_id,
            org: org_id,
            email: "leaver@leave.test".into(),
            aud: jwt::AUD_SESSION.into(),
            iat: now,
            exp: now + 3600,
            user_id: Some(user_id),
            mcp_client_id: None,
            jti,
        },
    )
    .unwrap()
}

fn cookie(token: &str) -> String {
    format!("__Host-oss_session={token}")
}

async fn fresh_org(pool: &PgPool, personal: bool) -> Uuid {
    let org_id: Uuid = sqlx::query_scalar(
        "INSERT INTO orgs (name, slug, is_personal) VALUES ('LeaveOrg', $1, $2) RETURNING id",
    )
    .bind(format!("leave-{}", Uuid::new_v4().simple()))
    .bind(personal)
    .fetch_one(pool)
    .await
    .unwrap();
    org_bootstrap::bootstrap_org(pool, org_id, None)
        .await
        .unwrap();
    org_id
}

/// Give `user_id` a user identity + membership in `org_id`. Returns the identity.
async fn join(pool: &PgPool, org_id: Uuid, user_id: Uuid, name: &str, admin: bool) -> Uuid {
    let ident = identity::create_with_email(
        pool,
        org_id,
        name,
        "user",
        None,
        Some(&format!("{name}@leave.test")),
        json!({}),
    )
    .await
    .unwrap();
    identity::set_user_id(pool, org_id, ident.id, Some(user_id))
        .await
        .unwrap();
    if admin {
        identity::set_is_org_admin(pool, org_id, ident.id, true)
            .await
            .unwrap();
    }
    let role = if admin {
        membership::ROLE_ADMIN
    } else {
        membership::ROLE_MEMBER
    };
    membership::create(pool, user_id, org_id, role)
        .await
        .unwrap();
    ident.id
}

async fn new_user(pool: &PgPool, name: &str) -> Uuid {
    user_repo::create_overslash_backed(
        pool,
        Some(&format!("{name}@leave.test")),
        Some(name),
        "google",
        &format!("sub-{}", Uuid::new_v4()),
    )
    .await
    .unwrap()
    .id
}

/// An org with an admin (so the leaver is never the last one) and the
/// leaver as an admin too — the dangerous case: a departed admin's
/// credentials must stop working. Returns (org_id, leaver identity).
async fn org_with_leaver(pool: &PgPool, leaver: Uuid) -> (Uuid, Uuid) {
    let org_id = fresh_org(pool, false).await;
    let other = new_user(pool, "other").await;
    join(pool, org_id, other, "other", true).await;
    let ident = join(pool, org_id, leaver, "leaver", true).await;
    (org_id, ident)
}

async fn session_row(pool: &PgPool, org_id: Uuid, identity_id: Uuid, user_id: Uuid) -> Uuid {
    user_session::create(
        pool,
        user_session::NewUserSession {
            user_id: Some(user_id),
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

async fn leave(base: &str, client: &Client, token: &str, org_id: Uuid) -> reqwest::Response {
    client
        .delete(format!("{base}/v1/account/memberships/{org_id}"))
        .header("cookie", cookie(token))
        .send()
        .await
        .unwrap()
}

fn new_session_token(resp: &reqwest::Response) -> Option<String> {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| c.strip_prefix("__Host-oss_session="))
        .map(|c| c.split(';').next().unwrap().to_string())
        .filter(|t| !t.is_empty())
}

#[tokio::test]
async fn leaving_archives_identity_revokes_keys_and_frees_the_slot() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let user_id = new_user(&pool, "leaver").await;
    let home = fresh_org(&pool, false).await;
    let home_ident = join(&pool, home, user_id, "leaver", true).await;
    let (org_id, ident) = org_with_leaver(&pool, user_id).await;

    // The leaver owns an agent with a bound API key in the org they leave.
    let agent =
        identity::create_with_parent(&pool, org_id, "bot", "agent", None, ident, 1, ident, false)
            .await
            .unwrap();
    let key_prefix = format!("lvkey_{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO api_keys (org_id, identity_id, name, key_hash, key_prefix)
         VALUES ($1, $2, 'agent-key', 'hash', $3)",
    )
    .bind(org_id)
    .bind(agent.id)
    .bind(&key_prefix)
    .execute(&pool)
    .await
    .unwrap();

    // Leave from a session scoped to another org — no rescope needed.
    let token = session_token(home, home_ident, user_id, None);
    let resp = leave(&base, &client, &token, org_id).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        new_session_token(&resp).is_none(),
        "no cookie when not rescoped"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "dropped");
    assert!(body.get("redirect_to").is_none());

    assert!(
        membership::find(&pool, user_id, org_id)
            .await
            .unwrap()
            .is_none()
    );
    let row = identity::get_by_id(&pool, org_id, ident)
        .await
        .unwrap()
        .unwrap();
    assert!(row.archived_at.is_some(), "leaver identity archived");
    assert!(row.user_id.is_none(), "identity detached from the user");
    let agent_row = identity::get_by_id(&pool, org_id, agent.id)
        .await
        .unwrap()
        .unwrap();
    assert!(agent_row.archived_at.is_some(), "agent subtree archived");
    let revoked_at: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT revoked_at FROM api_keys WHERE key_prefix = $1")
            .bind(&key_prefix)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(revoked_at.is_some(), "agent key revoked");

    // The same human can be re-invited and join again.
    join(&pool, org_id, user_id, "leaver-again", false).await;
}

#[tokio::test]
async fn leaving_the_current_org_lands_on_the_personal_org() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let user_id = new_user(&pool, "leaver").await;
    let personal = fresh_org(&pool, true).await;
    join(&pool, personal, user_id, "leaver", true).await;
    user_repo::set_personal_org(&pool, user_id, personal)
        .await
        .unwrap();
    let (org_id, ident) = org_with_leaver(&pool, user_id).await;

    let jti = session_row(&pool, org_id, ident, user_id).await;
    let token = session_token(org_id, ident, user_id, Some(jti));

    let resp = leave(&base, &client, &token, org_id).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let fresh = new_session_token(&resp).expect("rescoped session cookie");
    let body: Value = resp.json().await.unwrap();
    assert!(body["redirect_to"].is_string(), "body={body}");

    // The new cookie works, and is scoped to the personal org.
    let me = client
        .get(format!("{base}/auth/me/identity"))
        .header("cookie", cookie(&fresh))
        .send()
        .await
        .unwrap();
    assert_eq!(me.status(), StatusCode::OK);
    let me: Value = me.json().await.unwrap();
    assert_eq!(me["org_id"], json!(personal));

    // The old cookie (scoped to the org just left) is dead.
    let old = client
        .get(format!("{base}/auth/me/identity"))
        .header("cookie", cookie(&token))
        .send()
        .await
        .unwrap();
    assert_eq!(old.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn leaving_the_current_org_without_a_personal_org_signs_out() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let user_id = new_user(&pool, "leaver").await;
    let (org_id, ident) = org_with_leaver(&pool, user_id).await;
    let jti = session_row(&pool, org_id, ident, user_id).await;
    let token = session_token(org_id, ident, user_id, Some(jti));

    let resp = leave(&base, &client, &token, org_id).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(new_session_token(&resp).is_none());
    let body: Value = resp.json().await.unwrap();
    assert!(body.get("redirect_to").is_none());

    let old = client
        .get(format!("{base}/auth/me/identity"))
        .header("cookie", cookie(&token))
        .send()
        .await
        .unwrap();
    assert_eq!(old.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn leaving_twice_is_not_found() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let user_id = new_user(&pool, "leaver").await;
    let home = fresh_org(&pool, false).await;
    let home_ident = join(&pool, home, user_id, "leaver", true).await;
    let (org_id, _) = org_with_leaver(&pool, user_id).await;
    let token = session_token(home, home_ident, user_id, None);

    assert_eq!(
        leave(&base, &client, &token, org_id).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        leave(&base, &client, &token, org_id).await.status(),
        StatusCode::NOT_FOUND
    );
}
