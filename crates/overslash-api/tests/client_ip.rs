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

use overslash_api::services::client_ip::{CLIENT_IP_HEADER, PROXY_SECRET_HEADER, TrustedProxies};
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
    named: Option<&str>,
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
    if let Some(n) = named {
        req = req.header(CLIENT_IP_HEADER, n);
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
async fn proxy_secret_makes_the_named_client_the_client() {
    let pool = common::test_pool().await;
    let (addr, client) = start_api_with(pool.clone(), |c| {
        c.trusted_proxies = loopback_proxy(Some(SECRET));
    })
    .await;
    let base = format!("http://{addr}");
    // 76.76.21.21 plays the Vercel egress: not in any trusted range. To its
    // left, what Vercel really forwards: the browser's own forged XFF.
    let xff = "203.0.113.66, 76.76.21.21";
    let named = Some("128.140.96.98");

    let ip = registered_ip(&base, &client, &pool, xff, Some(SECRET), named).await;
    assert_eq!(ip.as_deref(), Some("128.140.96.98"));

    // Vouched but naming nobody: stop at the egress, never read its left.
    let ip = registered_ip(&base, &client, &pool, xff, Some(SECRET), None).await;
    assert_eq!(ip.as_deref(), Some("76.76.21.21"));

    // A forged name without the secret buys nothing.
    let wrong = "ffffffffffffffffffffffffffffffff";
    let ip = registered_ip(&base, &client, &pool, xff, Some(wrong), named).await;
    assert_eq!(ip.as_deref(), Some("76.76.21.21"));
    let ip = registered_ip(&base, &client, &pool, xff, None, named).await;
    assert_eq!(ip.as_deref(), Some("76.76.21.21"));
}

#[tokio::test]
async fn oauth_register_ignores_spoofed_xff_by_default() {
    let pool = common::test_pool().await;
    let (addr, client) = start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let ip = registered_ip(
        &base,
        &client,
        &pool,
        "203.0.113.9",
        Some(SECRET),
        Some("203.0.113.8"),
    )
    .await;
    assert_eq!(ip.as_deref(), Some("127.0.0.1"));
}

#[tokio::test]
async fn the_edge_header_names_the_client_whatever_xff_says() {
    // Prod: the GCLB overwrites this header with the address it saw, and
    // Google's own hops land in XFF wherever they land.
    const EDGE: &str = "x-overslash-edge-client-ip";
    let pool = common::test_pool().await;
    let (addr, client) = start_api_with(pool.clone(), |c| {
        c.trusted_proxies = TrustedProxies::parse(Some("2"), Some("34.36.8.174/32"), Some(SECRET))
            .unwrap()
            .with_client_ip_header(Some(EDGE))
            .unwrap();
    })
    .await;
    let base = format!("http://{addr}");
    let resp = client
        .post(format!("{base}/oauth/register"))
        .header(
            "x-forwarded-for",
            "203.0.113.9, 82.213.253.53, 34.96.62.181, 34.36.8.174",
        )
        .header(EDGE, "82.213.253.53")
        .json(&json!({
            "client_name": "ip-probe",
            "redirect_uris": ["http://localhost:9/cb"],
            "token_endpoint_auth_method": "none",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: Value = resp.json().await.unwrap();
    let ip: Option<String> =
        sqlx::query_scalar("SELECT created_ip FROM oauth_mcp_clients WHERE client_id = $1")
            .bind(body["client_id"].as_str().unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(ip.as_deref(), Some("82.213.253.53"));
}

/// A read action on the shared mock, reachable by the returned agent key.
/// Returns `(base, client, agent_key, admin_key)`.
async fn mcp_setup(pool: sqlx::PgPool) -> (String, Client, String, String) {
    common::allow_loopback_ssrf();
    let mock_addr = common::start_mock().await;
    // Loopback is a trusted proxy, so the `/mcp` request's XFF names its
    // client — and so would the loopback's, if it carried one.
    let (addr, client) = start_api_with(pool.clone(), |c| {
        c.trusted_proxies = loopback_proxy(None);
    })
    .await;
    let base = format!("http://{addr}");
    let (org_id, ident_id, agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;
    let admin = |r: reqwest::RequestBuilder| r.header(auth(&admin_key).0, auth(&admin_key).1);

    let openapi = format!(
        "openapi: 3.1.0\n\
         info:\n  title: IP Probe\n  key: ipprobe\n\
         servers:\n  - url: http://{mock_addr}\n\
         paths:\n  /large-file:\n    get:\n      operationId: get_small\n      \
         summary: Get a small file\n      risk: read\n      parameters:\n        \
         - name: size\n          in: query\n          required: true\n          \
         description: Bytes to return\n          schema:\n            type: integer\n"
    );
    let resp = admin(client.post(format!("{base}/v1/templates")))
        .json(&json!({ "openapi": openapi, "user_level": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "template: {:?}", resp.text().await);
    admin(client.post(format!("{base}/v1/permissions")))
        .json(
            &json!({ "identity_id": ident_id, "action_pattern": "ipprobe:**", "effect": "allow" }),
        )
        .send()
        .await
        .unwrap();

    // The group ceiling attaches to the owner user, not the calling agent.
    let owner_id = common::owner_user_id(&pool, org_id).await;
    let groups: Value = admin(client.get(format!("{base}/v1/groups")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admins = groups
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["name"] == "Admins")
        .expect("Admins group")["id"]
        .as_str()
        .unwrap()
        .to_string();
    admin(client.post(format!("{base}/v1/groups/{admins}/members")))
        .json(&json!({ "identity_id": owner_id }))
        .send()
        .await
        .unwrap();
    let inst: Value = admin(client.post(format!("{base}/v1/services")))
        .json(&json!({
            "name": "ipprobe",
            "template_key": "ipprobe",
            "url": format!("http://{mock_addr}"),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let inst_id = inst["id"]
        .as_str()
        .unwrap_or_else(|| panic!("instance: {inst}"));
    admin(client.post(format!("{base}/v1/groups/{admins}/grants")))
        .json(&json!({ "service_instance_id": inst_id, "access_level": "write" }))
        .send()
        .await
        .unwrap();
    (base, client, agent_key, admin_key)
}

#[tokio::test]
async fn an_mcp_tool_call_audits_the_mcp_caller_not_the_loopback() {
    // `POST /mcp` re-issues the call to `/v1/actions/call` from this
    // process. That request used to be audited with its own source — in prod
    // Cloud Run's egress (34.96.x) — instead of the agent's address.
    let (base, client, agent_key, admin_key) = mcp_setup(common::test_pool().await).await;
    let frame: Value = client
        .post(format!("{base}/mcp"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .header("x-forwarded-for", "198.51.100.1, 203.0.113.9")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "overslash_read",
                "arguments": {
                    "service": "ipprobe",
                    "action": "get_small",
                    "params": { "size": 16 },
                },
            },
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(frame.get("error").is_none(), "{frame}");
    assert_ne!(frame["result"]["isError"], true, "{frame}");

    let rows: Vec<Value> = client
        .get(format!("{base}/v1/audit?action=action.executed"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = rows
        .iter()
        .find(|r| r["action"] == "action.executed")
        .unwrap_or_else(|| panic!("no action.executed row: {rows:?}"));
    assert_eq!(row["ip_address"], "203.0.113.9", "{row}");
    // `transport:` names the dispatch fork, not the surface: an HTTP template
    // reached over `/mcp` is still `transport:http`.
    let tags: Vec<&str> = row["tags"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(tags.contains(&"transport:http"), "{tags:?}");
    assert!(!tags.contains(&"transport:mcp"), "{tags:?}");
}

#[tokio::test]
async fn a_forged_loopback_header_buys_nothing() {
    // Without this process's token the loopback headers are just headers.
    let pool = common::test_pool().await;
    let (addr, client) = start_api_with(pool.clone(), |c| {
        c.trusted_proxies = loopback_proxy(None);
    })
    .await;
    let base = format!("http://{addr}");
    let resp = client
        .post(format!("{base}/oauth/register"))
        .header("x-forwarded-for", "203.0.113.9")
        .header("x-overslash-loopback-token", "0".repeat(64))
        .header("x-overslash-loopback-client-ip", "192.0.2.1")
        .json(&json!({
            "client_name": "ip-probe",
            "redirect_uris": ["http://localhost:9/cb"],
            "token_endpoint_auth_method": "none",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: Value = resp.json().await.unwrap();
    let ip: Option<String> =
        sqlx::query_scalar("SELECT created_ip FROM oauth_mcp_clients WHERE client_id = $1")
            .bind(body["client_id"].as_str().unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(ip.as_deref(), Some("203.0.113.9"));
}
