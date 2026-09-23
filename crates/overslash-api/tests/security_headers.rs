//! The security-headers baseline (CASA 4.x / 6.x): every response carries
//! HSTS, nosniff, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`
//! and a CSP; `Cache-Control: no-store` is the default unless a handler opts
//! into caching; the HTML pages the API renders get a CSP they can render
//! under.

use crate::common;

use overslash_api::middleware::security_headers::{API_CSP, HSTS, HTML_CSP};
use reqwest::header::HeaderMap;
use serde_json::json;
use uuid::Uuid;

fn assert_baseline(h: &HeaderMap) {
    assert_eq!(h["strict-transport-security"], HSTS);
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["x-frame-options"], "DENY");
    assert_eq!(h["referrer-policy"], "no-referrer");
    let pp = h["permissions-policy"].to_str().unwrap();
    assert!(
        pp.contains("camera=()") && pp.contains("microphone=()"),
        "{pp}"
    );
    assert!(pp.contains("geolocation=()"), "{pp}");
}

#[tokio::test]
async fn json_responses_carry_the_baseline_and_no_store() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;

    let resp = client
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let h = resp.headers();
    assert_baseline(h);
    assert_eq!(h["content-security-policy"], API_CSP);
    assert_eq!(h["cache-control"], "no-store");
}

/// The layer wraps the router, so a response no handler produced — a 404 —
/// still carries the baseline.
#[tokio::test]
async fn unrouted_404_carries_the_baseline() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;

    let resp = client
        .get(format!("http://{addr}/definitely/not/a/route"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    assert_baseline(resp.headers());
    assert_eq!(resp.headers()["content-security-policy"], API_CSP);
}

/// `/icons/*` sets its own `Cache-Control`; the layer must not clobber it.
#[tokio::test]
async fn icons_keep_their_own_caching() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;

    let resp = client
        .get(format!("http://{addr}/icons/github.svg"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["cache-control"], "public, max-age=86400");
    assert_baseline(resp.headers());
}

#[tokio::test]
async fn secret_reveal_is_no_store() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let r = client
        .put(format!("{base}/v1/secrets/hdr_key"))
        .header("Authorization", format!("Bearer {}", fx.admin_key))
        .json(&json!({"value": "sk_live_should_not_be_cached"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    let cookie = common::session_cookie(fx.org_id, fx.user_ids[0]);
    let resp = client
        .post(format!("{base}/v1/secrets/hdr_key/versions/1/reveal"))
        .header("cookie", cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["cache-control"], "no-store");
    assert_baseline(resp.headers());
    assert_eq!(
        resp.json::<serde_json::Value>().await.unwrap()["value"],
        "sk_live_should_not_be_cached"
    );
}

/// An HTML page the API renders itself gets the HTML CSP — inline styles
/// render, no script runs — not the JSON one, which would blank it.
#[tokio::test]
async fn api_rendered_html_gets_a_renderable_csp() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;

    let resp = client
        .get(format!(
            "http://{addr}/connect-authorize?id={}",
            Uuid::new_v4()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 410);
    let h = resp.headers().clone();
    assert!(
        h["content-type"].to_str().unwrap().starts_with("text/html"),
        "{h:?}"
    );
    assert_eq!(h["content-security-policy"], HTML_CSP);
    assert!(HTML_CSP.contains("style-src 'unsafe-inline'"));
    assert!(!HTML_CSP.contains("script-src"));
    assert_eq!(h["cache-control"], "no-store");
    assert_baseline(&h);
    let body = resp.text().await.unwrap();
    assert!(body.contains("style='"), "the page relies on inline styles");
}
