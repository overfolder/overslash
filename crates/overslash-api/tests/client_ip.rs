// Reads `oauth_mcp_clients.created_ip` back to check what `/oauth/register` stored.
#![allow(clippy::disallowed_methods)]
//! Client IP resolution against the trusted-proxy config, end to end.
//!
//! The harness serves with connect-info, so the socket peer is `127.0.0.1`.
//! With no proxy configured that is the client, whatever `X-Forwarded-For`
//! says; telling the server loopback is a trusted proxy makes it read the
//! header right to left. Both the per-IP throttle (magic-link) and audit
//! `ip_address` go through the same `ClientIp` extractor.

use crate::common::{self, auth, bootstrap_org_identity, start_api, start_api_with};

use overslash_api::services::client_ip::{PROXY_SECRET_HEADER, TrustedProxies};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

const SECRET: &str = "0123456789abcdef0123456789abcdef";

/// Mirrors `MAGIC_LINK_REQ_IP_MAX`.
const ML_IP_MAX: usize = 30;

fn loopback_proxy(secret: Option<&str>) -> TrustedProxies {
    TrustedProxies::parse(None, Some("127.0.0.1"), secret).unwrap()
}

async fn magic_link(base: &str, client: &Client, xff: &str) -> StatusCode {
    client
        .post(format!("{base}/auth/magic-link/request"))
        .header("x-forwarded-for", xff)
        // Fresh address each time so the per-email bucket never trips.
        .json(&json!({ "email": format!("ip-{}@example.com", Uuid::new_v4()) }))
        .send()
        .await
        .unwrap()
        .status()
}

/// `PUT /v1/secrets/<name>` with the given XFF, then the `ip_address` on the
/// resulting `secret.put` audit row.
async fn audited_ip(base: &str, client: &Client, xff: &str) -> Option<String> {
    let (_org, _ident, _agent_key, admin_key) = bootstrap_org_identity(base, client).await;
    let resp = client
        .put(format!("{base}/v1/secrets/ip_probe"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .header("x-forwarded-for", xff)
        .json(&json!({ "value": "v" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());
    let rows: Vec<Value> = client
        .get(format!("{base}/v1/audit?action=secret.put"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = rows
        .iter()
        .find(|r| r["action"] == "secret.put")
        .expect("secret.put audit row");
    row["ip_address"].as_str().map(str::to_string)
}

#[tokio::test]
async fn spoofed_xff_cannot_dodge_the_per_ip_throttle() {
    let (addr, client) = start_api(common::test_pool().await).await;
    let base = format!("http://{addr}");

    // A fresh forged address per request used to mint a fresh bucket each
    // time. Untrusted peer ⇒ the header is ignored ⇒ one bucket.
    for i in 0..ML_IP_MAX {
        let status = magic_link(&base, &client, &format!("10.9.{i}.1")).await;
        assert_eq!(status, StatusCode::OK, "request {i}");
    }
    let status = magic_link(&base, &client, "10.9.250.1").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn spoofed_xff_is_not_written_to_the_audit_log() {
    let (addr, client) = start_api(common::test_pool().await).await;
    let base = format!("http://{addr}");
    let ip = audited_ip(&base, &client, "203.0.113.9").await;
    assert_eq!(ip.as_deref(), Some("127.0.0.1"));
}

#[tokio::test]
async fn behind_a_trusted_proxy_the_client_is_the_rightmost_untrusted_entry() {
    let (addr, client) = start_api_with(common::test_pool().await, |c| {
        c.trusted_proxies = loopback_proxy(None);
    })
    .await;
    let base = format!("http://{addr}");

    // The leftmost entry is the client's own claim; the proxy appended
    // 203.0.113.9 and that is who we record.
    let ip = audited_ip(&base, &client, "198.51.100.1, 203.0.113.9").await;
    assert_eq!(ip.as_deref(), Some("203.0.113.9"));

    // And the throttle buckets per resolved client: A exhausts its own
    // allowance without touching B's.
    for i in 0..ML_IP_MAX {
        let status = magic_link(&base, &client, &format!("10.0.0.{i}, 203.0.113.10")).await;
        assert_eq!(status, StatusCode::OK, "request {i}");
    }
    let status = magic_link(&base, &client, "10.0.0.99, 203.0.113.10").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        magic_link(&base, &client, "203.0.113.11").await,
        StatusCode::OK
    );
}

/// `POST /oauth/register` with the given headers; returns the stored
/// `created_ip`.
async fn registered_ip(
    base: &str,
    client: &Client,
    pool: &sqlx::PgPool,
    xff: &str,
    secret: Option<&str>,
) -> Option<String> {
    let mut req = client
        .post(format!("{base}/oauth/register"))
        .header("x-forwarded-for", xff)
        .json(&json!({
            "client_name": "ip-probe",
            "redirect_uris": ["http://localhost:9/cb"],
            "token_endpoint_auth_method": "none",
        }));
    if let Some(s) = secret {
        req = req.header(PROXY_SECRET_HEADER, s);
    }
    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: Value = resp.json().await.unwrap();
    sqlx::query_scalar("SELECT created_ip FROM oauth_mcp_clients WHERE client_id = $1")
        .bind(body["client_id"].as_str().unwrap())
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn proxy_secret_vouches_for_exactly_one_more_hop() {
    let pool = common::test_pool().await;
    let (addr, client) = start_api_with(pool.clone(), |c| {
        c.trusted_proxies = loopback_proxy(Some(SECRET));
    })
    .await;
    let base = format!("http://{addr}");
    // 76.76.21.21 plays the Vercel egress: not in any trusted range.
    let xff = "198.51.100.1, 203.0.113.9, 76.76.21.21";

    let ip = registered_ip(&base, &client, &pool, xff, Some(SECRET)).await;
    assert_eq!(ip.as_deref(), Some("203.0.113.9"));

    let wrong = "ffffffffffffffffffffffffffffffff";
    let ip = registered_ip(&base, &client, &pool, xff, Some(wrong)).await;
    assert_eq!(ip.as_deref(), Some("76.76.21.21"));

    let ip = registered_ip(&base, &client, &pool, xff, None).await;
    assert_eq!(ip.as_deref(), Some("76.76.21.21"));
}

#[tokio::test]
async fn oauth_register_ignores_spoofed_xff_by_default() {
    let pool = common::test_pool().await;
    let (addr, client) = start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let ip = registered_ip(&base, &client, &pool, "203.0.113.9", Some(SECRET)).await;
    assert_eq!(ip.as_deref(), Some("127.0.0.1"));
}
