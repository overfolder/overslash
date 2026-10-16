//! `GET /v1/oauth/callback` content negotiation: a browser (`Accept:
//! text/html`) with no `return_url` gets the "you're connected" page or a
//! friendly failure page; HTTP clients keep getting JSON.
// Test setup requires dynamic SQL for provider endpoint overrides.
#![allow(clippy::disallowed_methods)]

use crate::common;

use serde_json::{Value, json};

const BROWSER_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

/// Point X's token endpoint at the mock and give the identity a BYOC
/// credential (no env-var cascade, so no cross-test env leaks).
async fn setup() -> (
    sqlx::PgPool,
    reqwest::Client,
    String,
    uuid::Uuid,
    uuid::Uuid,
) {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'x'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, _api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    let resp = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "provider": "x",
            "client_id": "x_byoc_client_id",
            "client_secret": "x_byoc_client_secret",
            "identity_id": ident_id,
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    (pool, client, base, org_id, ident_id)
}

async fn display_name(pool: &sqlx::PgPool) -> String {
    sqlx::query_scalar("SELECT display_name FROM oauth_providers WHERE key = 'x'")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn browser_gets_connected_page() {
    let (pool, client, base, org_id, ident_id) = setup().await;
    let state = common::seed_oauth_flow(&pool, org_id, ident_id, "x", None).await;

    let resp = client
        .get(format!("{base}/v1/oauth/callback?code=c1&state={state}"))
        .header("Accept", BROWSER_ACCEPT)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let ct = resp.headers()["content-type"].to_str().unwrap().to_string();
    assert!(ct.starts_with("text/html"), "{ct}");
    let csp = resp.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        !csp.contains("script-src"),
        "page must run no script: {csp}"
    );
    let body = resp.text().await.unwrap();
    assert!(
        body.contains(&format!("Connected to {}", display_name(&pool).await)),
        "{body}"
    );
    assert!(body.contains("You can close this tab"), "{body}");
    assert!(!body.contains("connection_id"), "no JSON leaked: {body}");
}

#[tokio::test]
async fn http_client_still_gets_json() {
    let (pool, client, base, org_id, ident_id) = setup().await;
    let state = common::seed_oauth_flow(&pool, org_id, ident_id, "x", None).await;

    let resp: Value = client
        .get(format!("{base}/v1/oauth/callback?code=c2&state={state}"))
        .header("Accept", "*/*")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "connected");
    assert_eq!(resp["provider"], "x");
}

#[tokio::test]
async fn browser_gets_declined_page() {
    let (pool, client, base, org_id, ident_id) = setup().await;
    let state = common::seed_oauth_flow(&pool, org_id, ident_id, "x", None).await;

    let resp = client
        .get(format!(
            "{base}/v1/oauth/callback?error=access_denied&state={state}"
        ))
        .header("Accept", BROWSER_ACCEPT)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(body.contains("Access was not granted"), "{body}");
    assert!(body.contains("<code>access_denied</code>"), "{body}");
    assert!(!body.contains("authorization was not granted"), "{body}");
}

#[tokio::test]
async fn browser_gets_expired_page_for_unknown_state() {
    let (_pool, client, base, _org_id, _ident_id) = setup().await;

    let resp = client
        .get(format!("{base}/v1/oauth/callback?code=c3&state=nope"))
        .header("Accept", BROWSER_ACCEPT)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(body.contains("This link has expired"), "{body}");
}
