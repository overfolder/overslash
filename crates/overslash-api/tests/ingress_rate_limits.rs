//! Rate limiting beyond `osk_` API keys (CASA 1.1.1, 3.1.5, the residual of
//! 3.2.2): dashboard sessions and MCP bearers on `/v1`, and the per-IP /
//! per-MCP-client throttles on the `/oauth/*` + `/mcp` subrouter.
//!
//! The subrouter tests boot the harness, which mounts the same
//! `overslash_api::mcp_oauth_routes` production does, with the limits turned
//! on through `start_api_with`. The `/v1` tests mount the real middleware in
//! front of an echo handler, like `tests/rate_limits.rs`, because the harness
//! router carries no `/v1` rate-limit layer.

// Seeding identities uses dynamic SQL, as the neighbouring rate-limit tests do.
#![allow(clippy::disallowed_methods)]

use crate::common;

use std::net::SocketAddr;

use axum::{Router, routing::get};
use overslash_api::config::IngressRateLimits;
use overslash_api::services::client_ip::TrustedProxies;
use overslash_api::services::rate_limit::RateLimitConfig;
use reqwest::{Client, Response, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio::net::TcpListener;
use uuid::Uuid;

fn limit(max_requests: u32, window_seconds: u32) -> Option<RateLimitConfig> {
    Some(RateLimitConfig {
        max_requests,
        window_seconds,
    })
}

async fn start(limits: IngressRateLimits) -> (String, Client) {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api_with(pool, |c| c.ingress_rate_limits = limits).await;
    (format!("http://{addr}"), client)
}

async fn register(base: &str, client: &Client, xff: Option<&str>) -> Response {
    let mut req = client.post(format!("{base}/oauth/register")).json(&json!({
        "client_name": "ingress-rate-limit-test",
        "redirect_uris": ["http://127.0.0.1:33418/callback"],
        "token_endpoint_auth_method": "none",
    }));
    if let Some(xff) = xff {
        req = req.header("x-forwarded-for", xff);
    }
    req.send().await.unwrap()
}

async fn mcp_ping(base: &str, client: &Client, bearer: Option<&str>) -> StatusCode {
    let mut req = client
        .post(format!("{base}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}));
    if let Some(bearer) = bearer {
        req = req.bearer_auth(bearer);
    }
    req.send().await.unwrap().status()
}

/// A 429 from any of these limiters: `Retry-After` in seconds, within the
/// window, plus the same body `/v1` returns.
async fn assert_throttled(resp: Response, window_seconds: u64) {
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after: u64 = resp
        .headers()
        .get("retry-after")
        .expect("429 carries Retry-After")
        .to_str()
        .unwrap()
        .parse()
        .expect("Retry-After is delta-seconds");
    assert!(
        retry_after <= window_seconds,
        "Retry-After {retry_after} exceeds the {window_seconds}s window"
    );
    assert!(resp.headers().get("x-ratelimit-reset").is_some());
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "rate limit exceeded");
}

// ── POST /oauth/register ────────────────────────────────────────────

#[tokio::test]
async fn dcr_is_capped_per_ip() {
    let (base, client) = start(IngressRateLimits {
        oauth_register_ip: limit(2, 3600),
        ..IngressRateLimits::disabled()
    })
    .await;

    for i in 0..2 {
        let resp = register(&base, &client, None).await;
        assert_eq!(resp.status(), StatusCode::CREATED, "registration {i}");
    }
    assert_throttled(register(&base, &client, None).await, 3600).await;

    // The cap is on registration only: the rest of the handshake still works.
    let meta = client
        .get(format!("{base}/.well-known/oauth-authorization-server"))
        .send()
        .await
        .unwrap();
    assert_eq!(meta.status(), StatusCode::OK);
}

#[tokio::test]
async fn dcr_cap_keys_on_the_resolved_client_ip() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api_with(pool, |c| {
        c.ingress_rate_limits = IngressRateLimits {
            oauth_register_ip: limit(1, 3600),
            ..IngressRateLimits::disabled()
        };
        // Loopback plays the load balancer, so the address it appended is the
        // client's.
        c.trusted_proxies = TrustedProxies::parse(None, Some("127.0.0.1"), None).unwrap();
    })
    .await;
    let base = format!("http://{addr}");

    assert_eq!(
        register(&base, &client, Some("203.0.113.1")).await.status(),
        StatusCode::CREATED
    );
    assert_eq!(
        register(&base, &client, Some("203.0.113.1")).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    // A different client behind the same proxy has its own bucket…
    assert_eq!(
        register(&base, &client, Some("203.0.113.2")).await.status(),
        StatusCode::CREATED
    );
    // …and forging a leftmost entry does not buy a fresh one: the proxy's
    // appended address is still what counts.
    assert_eq!(
        register(&base, &client, Some("198.51.100.77, 203.0.113.1"))
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn ipv6_clients_are_bucketed_by_their_64() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api_with(pool, |c| {
        c.ingress_rate_limits = IngressRateLimits {
            oauth_register_ip: limit(1, 3600),
            ..IngressRateLimits::disabled()
        };
        c.trusted_proxies = TrustedProxies::parse(None, Some("127.0.0.1"), None).unwrap();
    })
    .await;
    let base = format!("http://{addr}");

    assert_eq!(
        register(&base, &client, Some("2001:db8:1:2::1"))
            .await
            .status(),
        StatusCode::CREATED
    );
    // Walking the rest of the /64 buys nothing…
    assert_eq!(
        register(&base, &client, Some("2001:db8:1:2:dead:beef:0:7"))
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    // …a different /64 is a different subscriber.
    assert_eq!(
        register(&base, &client, Some("2001:db8:1:3::1"))
            .await
            .status(),
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn spoofed_xff_without_a_trusted_proxy_shares_one_bucket() {
    let (base, client) = start(IngressRateLimits {
        oauth_register_ip: limit(1, 3600),
        ..IngressRateLimits::disabled()
    })
    .await;

    assert_eq!(
        register(&base, &client, Some("203.0.113.1")).await.status(),
        StatusCode::CREATED
    );
    // No proxy configured → the socket peer is the client, whatever the
    // header claims.
    assert_eq!(
        register(&base, &client, Some("203.0.113.2")).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn a_refused_registration_does_not_spend_the_handshake_budget() {
    let (base, client) = start(IngressRateLimits {
        oauth_ip: limit(3, 60),
        oauth_register_ip: limit(1, 3600),
        mcp_client: None,
    })
    .await;

    assert_eq!(
        register(&base, &client, None).await.status(),
        StatusCode::CREATED
    );
    for _ in 0..3 {
        assert_eq!(
            register(&base, &client, None).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    // One handshake request spent (the successful registration), two left.
    for _ in 0..2 {
        let resp = client
            .get(format!("{base}/.well-known/oauth-protected-resource"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

// ── /oauth/* and /.well-known/oauth-* ───────────────────────────────

#[tokio::test]
async fn the_oauth_subrouter_is_throttled_per_ip() {
    let (base, client) = start(IngressRateLimits {
        oauth_ip: limit(3, 60),
        ..IngressRateLimits::disabled()
    })
    .await;

    for path in [
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource",
    ] {
        let resp = client.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
    }
    // Same bucket across every endpoint: token is the third request.
    let token = client
        .post(format!("{base}/oauth/token"))
        .form(&[("grant_type", "authorization_code"), ("code", "nope")])
        .send()
        .await
        .unwrap();
    assert_ne!(token.status(), StatusCode::TOO_MANY_REQUESTS);

    let resp = client
        .get(format!("{base}/oauth/authorize"))
        .send()
        .await
        .unwrap();
    assert_throttled(resp, 60).await;
}

#[tokio::test]
async fn v1_is_not_behind_the_oauth_ip_throttle() {
    let (base, client) = start(IngressRateLimits {
        oauth_ip: limit(1, 60),
        ..IngressRateLimits::disabled()
    })
    .await;

    for _ in 0..3 {
        let resp = client.get(format!("{base}/health")).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

// ── /mcp ────────────────────────────────────────────────────────────

/// Org + user + an agent the user owns. Returns `(org, user, agent)`.
async fn seed_agent(pool: &PgPool) -> (Uuid, Uuid, Uuid) {
    let (org_id, user_id, _) =
        common::seed_org_user_key(pool, common::SeedOptions::default()).await;
    let agent_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO identities (id, org_id, name, kind, owner_id, parent_id, depth)
         VALUES ($1, $2, 'ingress-agent', 'agent', $3, $3, 1)",
    )
    .bind(agent_id)
    .bind(org_id)
    .bind(user_id)
    .execute(pool)
    .await
    .unwrap();
    (org_id, user_id, agent_id)
}

fn mcp_token(org_id: Uuid, agent_id: Uuid, client_id: Option<&str>) -> String {
    overslash_api::services::jwt::mint_mcp(
        &common::signing_key_bytes(),
        agent_id,
        org_id,
        "agent@test.local".into(),
        3600,
        client_id.map(str::to_string),
    )
    .unwrap()
}

#[tokio::test]
async fn mcp_is_throttled_per_client() {
    let pool = common::test_pool().await;
    let (org_id, _user, agent_id) = seed_agent(&pool).await;
    let (addr, client) = common::start_api_with(pool, |c| {
        c.ingress_rate_limits = IngressRateLimits {
            mcp_client: limit(2, 60),
            ..IngressRateLimits::disabled()
        };
    })
    .await;
    let base = format!("http://{addr}");

    let a = mcp_token(org_id, agent_id, Some("client-a"));
    for _ in 0..2 {
        assert_ne!(
            mcp_ping(&base, &client, Some(&a)).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    assert_eq!(
        mcp_ping(&base, &client, Some(&a)).await,
        StatusCode::TOO_MANY_REQUESTS
    );

    // A second client for the same agent is a separate bucket.
    let b = mcp_token(org_id, agent_id, Some("client-b"));
    assert_ne!(
        mcp_ping(&base, &client, Some(&b)).await,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn anonymous_mcp_probes_spend_the_ip_handshake_bucket() {
    let (base, client) = start(IngressRateLimits {
        oauth_ip: limit(2, 60),
        mcp_client: limit(1000, 60),
        ..IngressRateLimits::disabled()
    })
    .await;

    // No bearer → the 401 challenge, until the per-IP bucket runs out.
    for _ in 0..2 {
        assert_eq!(
            mcp_ping(&base, &client, None).await,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        mcp_ping(&base, &client, None).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    // A forged bearer is anonymous too.
    assert_eq!(
        mcp_ping(&base, &client, Some("not-a-token")).await,
        StatusCode::TOO_MANY_REQUESTS
    );
}

// ── /v1: sessions and MCP bearers ───────────────────────────────────

async fn spawn_v1_echo(pool: PgPool) -> SocketAddr {
    async fn echo() -> &'static str {
        "ok"
    }
    let state = common::make_app_state(pool).await;
    let app = Router::new()
        .route("/v1/echo", get(echo))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            overslash_api::middleware::rate_limit::rate_limit_middleware,
        ))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

async fn set_user_budget(pool: &PgPool, org_id: Uuid, user_id: Uuid, max: i32) {
    overslash_db::OrgScope::new(org_id, pool.clone())
        .upsert_rate_limit("user", Some(user_id), None, max, 60)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_session_is_throttled_on_its_identity() {
    let pool = common::test_pool().await;
    let (org_id, user_id, _key) =
        common::seed_org_user_key(&pool, common::SeedOptions::default()).await;
    set_user_budget(&pool, org_id, user_id, 2).await;
    let addr = spawn_v1_echo(pool).await;
    let client = Client::new();
    let cookie = common::session_cookie(org_id, user_id);

    for i in 0..2 {
        let resp = client
            .get(format!("http://{addr}/v1/echo"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "request {i}");
        assert_eq!(resp.headers()["x-ratelimit-limit"], "2");
    }
    let resp = client
        .get(format!("http://{addr}/v1/echo"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_throttled(resp, 60).await;
}

#[tokio::test]
async fn a_busy_agent_does_not_lock_its_owner_out_of_the_dashboard() {
    let pool = common::test_pool().await;
    let (org_id, user_id, key) =
        common::seed_org_user_key(&pool, common::SeedOptions::default()).await;
    set_user_budget(&pool, org_id, user_id, 1).await;
    let addr = spawn_v1_echo(pool).await;
    let client = Client::new();
    let url = format!("http://{addr}/v1/echo");

    // The API key spends the user bucket…
    let ok = client.get(&url).bearer_auth(&key).send().await.unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    let refused = client.get(&url).bearer_auth(&key).send().await.unwrap();
    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);

    // …and the session has its own, sized from the same budget.
    let resp = client
        .get(&url)
        .header("cookie", common::session_cookie(org_id, user_id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["x-ratelimit-limit"], "1");
}

#[tokio::test]
async fn an_mcp_bearer_spends_its_owners_budget() {
    let pool = common::test_pool().await;
    let (org_id, user_id, agent_id) = seed_agent(&pool).await;
    set_user_budget(&pool, org_id, user_id, 2).await;
    let addr = spawn_v1_echo(pool).await;
    let client = Client::new();
    let url = format!("http://{addr}/v1/echo");
    let token = mcp_token(org_id, agent_id, Some("client-a"));

    for i in 0..2 {
        let resp = client.get(&url).bearer_auth(&token).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "request {i}");
        assert_eq!(resp.headers()["x-ratelimit-limit"], "2");
    }
    // The owner's bucket, not a per-client one: a token for another client of
    // the same agent is refused as well.
    let other = mcp_token(org_id, agent_id, Some("client-b"));
    let resp = client.get(&url).bearer_auth(&other).send().await.unwrap();
    assert_throttled(resp, 60).await;
}

#[tokio::test]
async fn an_mcp_bearer_hits_its_identity_cap() {
    let pool = common::test_pool().await;
    let (org_id, _user, agent_id) = seed_agent(&pool).await;
    overslash_db::OrgScope::new(org_id, pool.clone())
        .upsert_rate_limit("identity_cap", Some(agent_id), None, 1, 60)
        .await
        .unwrap();
    let addr = spawn_v1_echo(pool).await;
    let client = Client::new();
    let url = format!("http://{addr}/v1/echo");
    let token = mcp_token(org_id, agent_id, None);

    let ok = client.get(&url).bearer_auth(&token).send().await.unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    let resp = client.get(&url).bearer_auth(&token).send().await.unwrap();
    assert_throttled(resp, 60).await;
}

#[tokio::test]
async fn forged_sessions_and_tokens_are_left_to_the_extractor() {
    let pool = common::test_pool().await;
    let addr = spawn_v1_echo(pool).await;
    let client = Client::new();
    let url = format!("http://{addr}/v1/echo");

    // Signed with the wrong key: nothing to attribute, so no bucket and no
    // headers. The real routes' extractor returns the 401.
    let forged = overslash_api::services::jwt::mint_mcp(
        b"not-the-signing-key",
        Uuid::new_v4(),
        Uuid::new_v4(),
        String::new(),
        3600,
        None,
    )
    .unwrap();
    let resp = client.get(&url).bearer_auth(&forged).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("x-ratelimit-limit").is_none());

    let resp = client
        .get(&url)
        .header("cookie", "__Host-oss_session=garbage")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("x-ratelimit-limit").is_none());
}
