//! Integration coverage for the Vercel preview-deployment OAuth handoff
//! (`/auth/handoff` + the callback's preview-redirect branch).
//!
//! The full IdP round-trip is exercised by `auth_login.rs` and
//! `oidc_auth.rs`; here we focus on the new surface — feature gating,
//! one-time-code consumption, allowlist enforcement, host binding — and
//! drive the handoff endpoint directly with rows we plant in the DB,
//! avoiding the cost of mocking Google.

mod common;

use overslash_db::repos::oauth_preview_handoff;
use sqlx::PgPool;
use std::net::SocketAddr;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const ALLOWLIST_PATTERN: &str = r"^https://allowed\.preview\.test$";
const ALLOWED_ORIGIN: &str = "https://allowed.preview.test";
const ALLOWED_HOST: &str = "allowed.preview.test";

/// Spin up the API with the preview-handoff feature enabled (env=dev +
/// allowlist set) so we can exercise the success path.
async fn start_with_handoff_enabled(pool: PgPool) -> (SocketAddr, reqwest::Client) {
    common::start_api_with(pool, |cfg| {
        cfg.overslash_env = Some("dev".into());
        cfg.preview_origin_allowlist =
            Some(regex::Regex::new(ALLOWLIST_PATTERN).expect("valid regex"));
    })
    .await
}

/// Reqwest client that doesn't auto-follow 3xx so tests can inspect the
/// redirect target + Set-Cookie.
fn no_redirect_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

/// Plant a `oauth_handoff_codes` row directly so the handoff endpoint has
/// something to redeem without needing a working OAuth flow.
async fn plant_code(
    pool: &PgPool,
    code: &str,
    jwt: &str,
    origin: &str,
    next: Option<&str>,
    ttl_secs: i64,
) {
    oauth_preview_handoff::insert_handoff_code(pool, code, jwt, origin, next, ttl_secs)
        .await
        .expect("insert handoff code");
}

// ---------------------------------------------------------------------------
// Defense-in-depth gate
// ---------------------------------------------------------------------------

/// With the feature off (no env var, no allowlist), the redemption endpoint
/// must look like it doesn't exist — not 400, not 403, a flat 404. Anything
/// less leaks the feature's existence to a prod scanner.
#[tokio::test]
async fn handoff_endpoint_returns_404_when_feature_disabled() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let resp = client
        .get(format!("http://{addr}/auth/handoff?code=anything"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// Env says dev but no allowlist regex → still off. The two gates combine
/// AND-style; either missing keeps the door shut.
#[tokio::test]
async fn handoff_endpoint_404_when_env_dev_but_no_allowlist() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api_with(pool, |cfg| {
        cfg.overslash_env = Some("dev".into());
        cfg.preview_origin_allowlist = None;
    })
    .await;

    let resp = client
        .get(format!("http://{addr}/auth/handoff?code=anything"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// Symmetric defense: allowlist set but env != "dev" must also 404 — this
/// guards against a prod deploy that accidentally inherits the env var.
#[tokio::test]
async fn handoff_endpoint_404_when_allowlist_set_but_env_is_prod() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api_with(pool, |cfg| {
        cfg.overslash_env = Some("prod".into());
        cfg.preview_origin_allowlist = Some(regex::Regex::new(ALLOWLIST_PATTERN).unwrap());
    })
    .await;

    let resp = client
        .get(format!("http://{addr}/auth/handoff?code=anything"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ---------------------------------------------------------------------------
// Code redemption
// ---------------------------------------------------------------------------

/// Happy path: code present, host matches, allowlist matches → cookie set,
/// 303 to the stored next path, code marked consumed.
#[tokio::test]
async fn handoff_endpoint_sets_session_and_redirects_on_success() {
    let pool = common::test_pool().await;
    let code = "ok-code-1";
    plant_code(
        &pool,
        code,
        "fake.jwt.value",
        ALLOWED_ORIGIN,
        Some("/agents"),
        60,
    )
    .await;

    let (addr, _) = start_with_handoff_enabled(pool.clone()).await;
    let client = no_redirect_client();

    let resp = client
        .get(format!("http://{addr}/auth/handoff?code={code}"))
        .header("x-forwarded-host", ALLOWED_HOST)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 303);
    assert_eq!(
        resp.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/agents")
    );
    let cookies: Vec<_> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    let session = cookies
        .iter()
        .find(|c| c.starts_with("oss_session="))
        .expect("expected oss_session cookie");
    // Host-only: no `Domain=` attribute. Cross-tenant `.vercel.app` must
    // never inherit the cookie.
    assert!(
        !session.contains("Domain="),
        "cookie must be host-only: {session}"
    );
    assert!(session.contains("HttpOnly"));
    assert!(session.contains("SameSite=Lax"));
    assert!(session.contains("Secure"));

    // Replay-protection: row should now have consumed_at set.
    let consumed = oauth_preview_handoff::consume_handoff_code(&pool, code)
        .await
        .unwrap();
    assert!(consumed.is_none(), "second consume must be a no-op");
}

/// Replay protection: a successful redemption must invalidate the code.
#[tokio::test]
async fn handoff_endpoint_rejects_replayed_code() {
    let pool = common::test_pool().await;
    let code = "replay-code";
    plant_code(&pool, code, "fake.jwt", ALLOWED_ORIGIN, None, 60).await;

    let (addr, _) = start_with_handoff_enabled(pool).await;
    let client = no_redirect_client();
    let url = format!("http://{addr}/auth/handoff?code={code}");

    let first = client
        .get(&url)
        .header("x-forwarded-host", ALLOWED_HOST)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 303);

    let second = client
        .get(&url)
        .header("x-forwarded-host", ALLOWED_HOST)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), 400);
}

/// An expired code must not be redeemable — table stores expires_at, the
/// `UPDATE … WHERE expires_at > now()` filter must skip stale rows.
#[tokio::test]
async fn handoff_endpoint_rejects_expired_code() {
    let pool = common::test_pool().await;
    // Bypass the helper's TTL accounting: insert with an explicit past
    // expiry so the row is born stale.
    let past = OffsetDateTime::now_utc() - Duration::seconds(5);
    sqlx::query!(
        "INSERT INTO oauth_handoff_codes (code, jwt, origin, expires_at)
         VALUES ($1, $2, $3, $4)",
        "stale-code",
        "fake.jwt",
        ALLOWED_ORIGIN,
        past,
    )
    .execute(&pool)
    .await
    .unwrap();

    let (addr, _) = start_with_handoff_enabled(pool).await;
    let client = no_redirect_client();

    let resp = client
        .get(format!("http://{addr}/auth/handoff?code=stale-code"))
        .header("x-forwarded-host", ALLOWED_HOST)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

/// XFH host doesn't match the origin the code was minted for → reject.
/// This blocks an attacker who lured a user to a different host while
/// holding a sniffed code.
#[tokio::test]
async fn handoff_endpoint_rejects_host_mismatch() {
    let pool = common::test_pool().await;
    plant_code(&pool, "host-mismatch", "fake.jwt", ALLOWED_ORIGIN, None, 60).await;

    let (addr, _) = start_with_handoff_enabled(pool).await;
    let client = no_redirect_client();

    let resp = client
        .get(format!("http://{addr}/auth/handoff?code=host-mismatch"))
        .header("x-forwarded-host", "evil.preview.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

/// Live allowlist re-check: a code minted while the allowlist matched can
/// still be invalidated by a subsequent allowlist change. The endpoint
/// reads the current config, not a snapshot taken at mint time.
#[tokio::test]
async fn handoff_endpoint_rejects_when_origin_falls_off_allowlist() {
    let pool = common::test_pool().await;
    plant_code(&pool, "off-list", "fake.jwt", ALLOWED_ORIGIN, None, 60).await;

    // Boot with a *different* allowlist that excludes ALLOWED_ORIGIN.
    let (addr, _) = common::start_api_with(pool, |cfg| {
        cfg.overslash_env = Some("dev".into());
        cfg.preview_origin_allowlist =
            Some(regex::Regex::new(r"^https://other\.preview\.test$").unwrap());
    })
    .await;
    let client = no_redirect_client();

    let resp = client
        .get(format!("http://{addr}/auth/handoff?code=off-list"))
        .header("x-forwarded-host", ALLOWED_HOST)
        .send()
        .await
        .unwrap();
    // 403 — code consumed, but the origin no longer trusted; semantically
    // distinct from a malformed/expired code (400).
    assert_eq!(resp.status(), 403);
}

/// Bogus code (never minted) → 400. No information leak about whether the
/// feature is on; the 404 case is the off branch only.
#[tokio::test]
async fn handoff_endpoint_rejects_unknown_code() {
    let pool = common::test_pool().await;
    let (addr, _) = start_with_handoff_enabled(pool).await;
    let client = no_redirect_client();

    let resp = client
        .get(format!("http://{addr}/auth/handoff?code=never-existed"))
        .header("x-forwarded-host", ALLOWED_HOST)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

// ---------------------------------------------------------------------------
// Callback state-param defense
// ---------------------------------------------------------------------------

/// A 4-segment OAuth state param ("login:<provider>:<nonce>:<preview_id>")
/// must be rejected with 400 when the feature is off — even before the
/// callback gets to the nonce check or token exchange. A stale URL from a
/// dev session must not be replayable into a prod environment to coax it
/// into a strange code path.
#[tokio::test]
async fn callback_with_4_segment_state_returns_400_when_feature_off() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;

    // Forge what an in-flight dev login URL would look like, with a UUID
    // standing in for the preview_id segment.
    let state = format!("login:google:{}:{}", Uuid::new_v4(), Uuid::new_v4());
    let resp = client
        .get(format!(
            "http://{addr}/auth/callback/google?code=ignored&state={}",
            urlencoding::encode(&state)
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

// ---------------------------------------------------------------------------
// Repo-level coverage
// ---------------------------------------------------------------------------

/// Smoke-test the repo helpers in isolation: the lazy GC branch, the
/// "consume returns None on stale row" branch, and the round-trip insert
/// → get for preview origins.
#[tokio::test]
async fn preview_origin_round_trip_and_expiry() {
    let pool = common::test_pool().await;

    let id = Uuid::new_v4();
    oauth_preview_handoff::insert_preview_origin(&pool, id, "https://x.test", 60)
        .await
        .unwrap();
    let got = oauth_preview_handoff::get_preview_origin(&pool, id)
        .await
        .unwrap()
        .expect("row present");
    assert_eq!(got.origin, "https://x.test");

    // Insert an already-stale row, then a fresh insert should GC it.
    let past = OffsetDateTime::now_utc() - Duration::seconds(1);
    let stale_id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO oauth_preview_origins (preview_id, origin, expires_at)
         VALUES ($1, $2, $3)",
        stale_id,
        "https://stale.test",
        past,
    )
    .execute(&pool)
    .await
    .unwrap();
    // Trigger the lazy GC.
    oauth_preview_handoff::insert_preview_origin(&pool, Uuid::new_v4(), "https://y.test", 60)
        .await
        .unwrap();
    let after_gc = oauth_preview_handoff::get_preview_origin(&pool, stale_id)
        .await
        .unwrap();
    assert!(after_gc.is_none(), "stale row should have been GCed");
}
