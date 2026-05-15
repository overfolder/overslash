//! Integration tests for the nested-OAuth flow (Overslash as MCP client to
//! upstream MCP servers).
//!
//! The security boundary the test suite proves:
//!   1. The gate redirects to the upstream-AS authorize URL when the clicker's
//!      `oss_session` belongs to the identity that initiated the flow.
//!   2. The gate rejects clicks from any other identity.
//!   3. The callback re-validates the session vs. the flow's identity. Even
//!      if an attacker bypassed the gate by handing the victim the raw
//!      upstream URL, the victim's session must match here for the token to
//!      bind to the attacker's identity. **This is the test that proves the
//!      design's security guarantee.**
//!
//! Mocked upstream: a tiny in-process axum app exposing the discovery
//! (`/.well-known/oauth-authorization-server`), DCR (`/register`), and token
//! (`/token`) endpoints. The MCP "resource" is also served from the same
//! mock — it's only used for resource-metadata-URL discovery.
//!
//! `OVERSLASH_SSRF_ALLOW_PRIVATE=1` opens loopback for the SSRF guard so
//! the mock at 127.0.0.1 can be reached.

mod common;

use std::net::SocketAddr;

use axum::{
    Form, Json, Router,
    routing::{get, post},
};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use uuid::Uuid;

use overslash_api::services::jwt;

/// Spin up a mock upstream MCP authorization server.
///
/// Endpoints:
/// - `GET /.well-known/oauth-authorization-server` — RFC 8414 metadata
/// - `POST /register` — RFC 7591 DCR
/// - `POST /token` — code-grant exchange
async fn start_mock_upstream() -> SocketAddr {
    async fn metadata(axum::extract::State(issuer): axum::extract::State<String>) -> Json<Value> {
        Json(json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "registration_endpoint": format!("{issuer}/register"),
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["read"]
        }))
    }

    async fn register(Json(_body): Json<Value>) -> Json<Value> {
        Json(json!({
            "client_id": format!("upstream_client_{}", Uuid::new_v4().simple()),
        }))
    }

    async fn token(Form(params): Form<Vec<(String, String)>>) -> Json<Value> {
        let grant = params
            .iter()
            .find(|(k, _)| k == "grant_type")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        if grant == "authorization_code" {
            Json(json!({
                "access_token": "upstream_access_xyz",
                "refresh_token": "upstream_refresh_xyz",
                "expires_in": 3600,
                "token_type": "Bearer",
                "scope": "read"
            }))
        } else {
            Json(json!({"error": "unsupported_grant_type"}))
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let issuer = format!("http://{addr}");
    let app = Router::new()
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .route("/register", post(register))
        .route("/token", post(token))
        .with_state(issuer);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// Mint a session JWT for an arbitrary `(org, identity, user)` triple,
/// signed with the test config's signing_key. Lets us forge the
/// "wrong account clicker" scenario without standing up a second user
/// flow.
fn mint_session_for(signing_key: &[u8], org_id: Uuid, identity_id: Uuid, user_id: Uuid) -> String {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let claims = jwt::Claims {
        sub: identity_id,
        org: org_id,
        email: "imposter@test.local".into(),
        aud: jwt::AUD_SESSION.into(),
        iat: now,
        exp: now + 3600,
        user_id: Some(user_id),
        mcp_client_id: None,
    };
    jwt::mint(signing_key, &claims).unwrap()
}

/// Convert the test config's hex signing_key to bytes (matches what the
/// dev-auth API does at startup).
fn signing_key_bytes() -> Vec<u8> {
    let hex_str = "cd".repeat(32);
    hex::decode(&hex_str).unwrap()
}

/// Bootstrap a session via dev-auth and return (base_url, client, session_jwt,
/// identity_id, org_id).
async fn dev_session(pool: sqlx::PgPool) -> (String, reqwest::Client, String, Uuid, Uuid) {
    let (base, _client) = common::start_api_with_dev_auth(pool).await;
    // The `/auth/dev/token` route returns a session JWT and sets the cookie.
    // We use a non-redirecting client so 303s don't get followed during gate
    // tests.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let body: Value = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = body["token"].as_str().unwrap().to_string();
    // Decode without verification just to lift sub/org out — the test trusts
    // the locally-minted JWT.
    let claims = jwt::verify(&signing_key_bytes(), &token, jwt::AUD_SESSION).unwrap();
    (base, client, token, claims.sub, claims.org)
}

/// SSRF guard escape hatch — loopback addresses are blocked by default.
fn allow_loopback() {
    // Safe in tests: the env var is process-wide but each test runs in its
    // own process under cargo nextest / cargo test default.
    unsafe {
        std::env::set_var("OVERSLASH_SSRF_ALLOW_PRIVATE", "1");
    }
}

#[tokio::test]
async fn initiate_mints_flow_and_gate_redirects_for_owner() {
    allow_loopback();
    let upstream = start_mock_upstream().await;
    let pool = common::test_pool().await;
    let (base, client, session, _identity, _org) = dev_session(pool).await;

    let resp = client
        .post(format!("{base}/v1/mcp_upstream/initiate"))
        .header("cookie", format!("oss_session={session}"))
        .json(&json!({
            "as_issuer": format!("http://{upstream}"),
            "upstream_resource": format!("http://{upstream}/mcp"),
            "scopes": ["read"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "pending_auth");
    let proxied = body["authorize_urls"]["proxied"].as_str().unwrap();

    // Owner clicks the gate — should 302 to the upstream authorize URL.
    let r = client
        .get(proxied)
        .header("cookie", format!("oss_session={session}"))
        .send()
        .await
        .unwrap();
    assert!(
        r.status().is_redirection(),
        "gate must redirect for the owner; got {}",
        r.status()
    );
    let loc = r.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        loc.starts_with(&format!("http://{upstream}/authorize")),
        "expected redirect to upstream authorize, got {loc}"
    );
    // Sanity: state is the flow_id from the response, not echoed from the
    // attacker. Confirms the URL the gate emits is server-built.
    let flow_id = body["flow_id"].as_str().unwrap();
    assert!(loc.contains(&format!("state={flow_id}")));
}

#[tokio::test]
async fn gate_hard_rejects_when_session_belongs_to_different_identity() {
    allow_loopback();
    let upstream = start_mock_upstream().await;
    let pool = common::test_pool().await;
    let (base, client, owner_session, _identity, org) = dev_session(pool).await;

    // Owner mints a flow.
    let body: Value = client
        .post(format!("{base}/v1/mcp_upstream/initiate"))
        .header("cookie", format!("oss_session={owner_session}"))
        .json(&json!({
            "as_issuer": format!("http://{upstream}"),
            "upstream_resource": format!("http://{upstream}/mcp"),
            "scopes": ["read"],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let proxied = body["authorize_urls"]["proxied"].as_str().unwrap();

    // Attacker forges a session JWT for a different identity in the same org.
    let imposter_session =
        mint_session_for(&signing_key_bytes(), org, Uuid::new_v4(), Uuid::new_v4());

    let r = client
        .get(proxied)
        .header("cookie", format!("oss_session={imposter_session}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        403,
        "gate must hard-reject when session's identity is not in the flow's tree"
    );
    // No upstream redirect.
    assert!(r.headers().get("location").is_none());
}

#[tokio::test]
async fn callback_rejects_when_session_doesnt_match_flow_security_boundary() {
    // **The security-boundary test.** Even if an attacker hands the victim
    // the raw upstream URL (bypassing the gate), the callback at
    // /oauth/upstream/callback must check session-vs-flow before exchanging
    // the code. This test exercises that re-check.
    allow_loopback();
    let upstream = start_mock_upstream().await;
    let pool = common::test_pool().await;
    let (base, client, owner_session, _identity, org) = dev_session(pool).await;

    // Owner mints a flow.
    let body: Value = client
        .post(format!("{base}/v1/mcp_upstream/initiate"))
        .header("cookie", format!("oss_session={owner_session}"))
        .json(&json!({
            "as_issuer": format!("http://{upstream}"),
            "upstream_resource": format!("http://{upstream}/mcp"),
            "scopes": ["read"],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let flow_id = body["flow_id"].as_str().unwrap().to_string();

    // Imposter forges a session and hits the callback with a fake code as if
    // they had walked the upstream-AS flow with the victim's URL.
    let imposter_session =
        mint_session_for(&signing_key_bytes(), org, Uuid::new_v4(), Uuid::new_v4());

    let callback_url = format!("{base}/oauth/upstream/callback?code=anycode&state={flow_id}");
    let r = client
        .get(&callback_url)
        .header("cookie", format!("oss_session={imposter_session}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        403,
        "callback must reject when session.identity is outside the flow's identity tree"
    );

    // The flow row must remain unconsumed so the legitimate owner can still
    // complete it. Re-issue from owner's session and observe success.
    let owner_callback = client
        .get(&callback_url)
        .header("cookie", format!("oss_session={owner_session}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        owner_callback.status(),
        200,
        "owner must still be able to complete the flow after a rejected imposter callback"
    );
    let html = owner_callback.text().await.unwrap();
    assert!(
        html.contains("Connection ready"),
        "expected success page, got: {}",
        html.lines().take(5).collect::<Vec<_>>().join("\n")
    );
}

#[tokio::test]
async fn replay_returns_410_after_consume() {
    allow_loopback();
    let upstream = start_mock_upstream().await;
    let pool = common::test_pool().await;
    let (base, client, owner_session, _identity, _org) = dev_session(pool).await;

    let body: Value = client
        .post(format!("{base}/v1/mcp_upstream/initiate"))
        .header("cookie", format!("oss_session={owner_session}"))
        .json(&json!({
            "as_issuer": format!("http://{upstream}"),
            "upstream_resource": format!("http://{upstream}/mcp"),
            "scopes": ["read"],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let flow_id = body["flow_id"].as_str().unwrap().to_string();
    let callback_url = format!("{base}/oauth/upstream/callback?code=anycode&state={flow_id}");

    // Owner consumes the flow.
    let r1 = client
        .get(&callback_url)
        .header("cookie", format!("oss_session={owner_session}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 200);

    // Replay → 410.
    let r2 = client
        .get(&callback_url)
        .header("cookie", format!("oss_session={owner_session}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r2.status(),
        410,
        "second consume of the same flow must 410 Gone"
    );
}

#[tokio::test]
async fn initiate_rejects_foreign_identity_id() {
    allow_loopback();
    let upstream = start_mock_upstream().await;
    let pool = common::test_pool().await;
    let (base, client, owner_session, _identity, _org) = dev_session(pool).await;

    // Caller specifies a fake identity_id they don't own. Must 403/404 before
    // any I/O to the upstream AS happens — otherwise an attacker could
    // attribute connections to identities they don't own.
    let resp = client
        .post(format!("{base}/v1/mcp_upstream/initiate"))
        .header("cookie", format!("oss_session={owner_session}"))
        .json(&json!({
            "as_issuer": format!("http://{upstream}"),
            "upstream_resource": format!("http://{upstream}/mcp"),
            "identity_id": Uuid::new_v4(),
            "scopes": ["read"],
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status() == 403 || resp.status() == 404,
        "expected 403/404 for foreign identity_id, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn list_connections_rejects_foreign_identity() {
    let pool = common::test_pool().await;
    let (base, client, owner_session, _identity, _org) = dev_session(pool).await;

    let resp = client
        .get(format!(
            "{base}/v1/identities/{}/mcp_upstream_connections",
            Uuid::new_v4()
        ))
        .header("cookie", format!("oss_session={owner_session}"))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status() == 403 || resp.status() == 404,
        "expected 403/404 listing foreign identity's connections, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn gate_redirects_to_login_when_no_session_cookie() {
    allow_loopback();
    let upstream = start_mock_upstream().await;
    let pool = common::test_pool().await;
    let (base, client, owner_session, _identity, _org) = dev_session(pool).await;

    let body: Value = client
        .post(format!("{base}/v1/mcp_upstream/initiate"))
        .header("cookie", format!("oss_session={owner_session}"))
        .json(&json!({
            "as_issuer": format!("http://{upstream}"),
            "upstream_resource": format!("http://{upstream}/mcp"),
            "scopes": ["read"],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let proxied = body["authorize_urls"]["proxied"].as_str().unwrap();

    // No cookie at all — gate should bounce through login (303/302).
    let r = client.get(proxied).send().await.unwrap();
    assert!(
        r.status().is_redirection(),
        "expected redirect to login when session is missing, got {}",
        r.status()
    );
    let loc = r.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        loc.contains("/auth/login"),
        "expected /auth/login redirect, got {loc}"
    );
    assert!(
        loc.contains("next="),
        "expected ?next= preserve target, got {loc}"
    );
}

#[tokio::test]
async fn idempotent_initiate_returns_existing_flow() {
    allow_loopback();
    let upstream = start_mock_upstream().await;
    let pool = common::test_pool().await;
    let (base, client, owner_session, _identity, _org) = dev_session(pool).await;

    let req = json!({
        "as_issuer": format!("http://{upstream}"),
        "upstream_resource": format!("http://{upstream}/mcp"),
        "scopes": ["read"],
    });
    let first: Value = client
        .post(format!("{base}/v1/mcp_upstream/initiate"))
        .header("cookie", format!("oss_session={owner_session}"))
        .json(&req)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let second: Value = client
        .post(format!("{base}/v1/mcp_upstream/initiate"))
        .header("cookie", format!("oss_session={owner_session}"))
        .json(&req)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(first["flow_id"], second["flow_id"]);
}
