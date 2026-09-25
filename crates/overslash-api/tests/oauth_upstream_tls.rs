//! TLS on the MCP OAuth upstream hops (CASA 4.1.1), end to end.
//!
//! `POST /v1/mcp_upstream/initiate` fetches resource metadata and AS metadata,
//! registers a client, and the callback exchanges the code at the token
//! endpoint — every one of those is server-side traffic to an upstream the
//! caller named or the metadata pointed at. Each hop goes over `https`, by the
//! `services/outbound_tls.rs` rule: plain `http` only to an address inside
//! `OVERSLASH_SSRF_ALLOWED_CIDRS`, which the suite sets to loopback. That is
//! how the mock AS at `http://127.0.0.1` stays reachable — the escape hatch —
//! while the endpoints it advertises on a public address are refused.
//!
//! The refused target is `93.184.216.34`: public, so the SSRF guard lets it
//! through and only TLS stands in the way, and an IP literal, so nothing here
//! depends on DNS or ever reaches the network.

use crate::common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use uuid::Uuid;

use overslash_api::services::jwt;
use overslash_db::repos::mcp_upstream_flow;

/// Public, so the SSRF guard has no objection — only TLS refuses it.
const PLAINTEXT_PUBLIC: &str = "http://93.184.216.34";

#[derive(Clone)]
struct Mock {
    issuer: String,
    /// Merged over the default AS metadata, to point one endpoint elsewhere.
    /// `{issuer}` in a string value is replaced with the mock's own origin.
    overrides: Value,
    registrations: Arc<AtomicUsize>,
}

/// A loopback AS whose metadata can advertise arbitrary endpoints. `/register`
/// counts its hits so a test can prove a refused initiate registered nothing;
/// `/register-redirect` answers with a 307 to a plain-`http` public address.
async fn start_mock_as(overrides: Value) -> (SocketAddr, Arc<AtomicUsize>) {
    async fn metadata(State(m): State<Mock>) -> Json<Value> {
        let mut doc = json!({
            "issuer": m.issuer,
            "authorization_endpoint": format!("{}/authorize", m.issuer),
            "token_endpoint": format!("{}/token", m.issuer),
            "registration_endpoint": format!("{}/register", m.issuer),
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["read"]
        });
        for (k, v) in m.overrides.as_object().unwrap() {
            doc[k] = match v.as_str() {
                Some(s) => json!(s.replace("{issuer}", &m.issuer)),
                None => v.clone(),
            };
        }
        Json(doc)
    }

    async fn resource_metadata(State(m): State<Mock>) -> Json<Value> {
        Json(json!({
            "resource": format!("{}/mcp", m.issuer),
            "authorization_servers": [m.overrides.get("issuer_for_prm").cloned().unwrap_or(json!(m.issuer))],
        }))
    }

    async fn register(State(m): State<Mock>) -> Json<Value> {
        m.registrations.fetch_add(1, Ordering::SeqCst);
        Json(json!({ "client_id": format!("upstream_client_{}", Uuid::new_v4().simple()) }))
    }

    async fn register_redirect() -> impl IntoResponse {
        (
            StatusCode::TEMPORARY_REDIRECT,
            [(header::LOCATION, format!("{PLAINTEXT_PUBLIC}/register"))],
        )
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let registrations = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .route(
            "/.well-known/oauth-protected-resource",
            get(resource_metadata),
        )
        .route("/register", post(register))
        .route("/register-redirect", post(register_redirect))
        .with_state(Mock {
            issuer: format!("http://{addr}"),
            overrides,
            registrations: registrations.clone(),
        });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, registrations)
}

/// `(base, client, session, identity, org, pool)` for a dev-auth session.
async fn dev_session() -> (String, reqwest::Client, String, Uuid, Uuid, sqlx::PgPool) {
    let pool = common::test_pool().await;
    let (base, _) = common::start_api_with_dev_auth(pool.clone()).await;
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
    let key = hex::decode("cd".repeat(32)).unwrap();
    let claims = jwt::verify(&key, &token, jwt::AUD_SESSION).unwrap();
    (base, client, token, claims.sub, claims.org, pool)
}

async fn initiate(
    client: &reqwest::Client,
    base: &str,
    session: &str,
    body: Value,
) -> (u16, String) {
    let resp = client
        .post(format!("{base}/v1/mcp_upstream/initiate"))
        .header("cookie", format!("__Host-oss_session={session}"))
        .json(&body)
        .send()
        .await
        .unwrap();
    (resp.status().as_u16(), resp.text().await.unwrap())
}

/// The refusal names the endpoint it is about and says why.
fn assert_tls_refusal(status: u16, body: &str, field: &str) {
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("refusing plain http://"), "{body}");
    assert!(
        body.contains(&format!("upstream OAuth `{field}`")),
        "{body}"
    );
}

/// The escape hatch: a plain-`http` AS inside the operator-allowed range
/// (loopback, in this suite) completes discovery and registration.
#[tokio::test]
async fn plain_http_inside_the_allowed_range_is_accepted() {
    let (upstream, registrations) = start_mock_as(json!({})).await;
    let (base, client, session, ..) = dev_session().await;
    let (status, body) = initiate(
        &client,
        &base,
        &session,
        json!({
            "as_issuer": format!("http://{upstream}"),
            "upstream_resource": format!("http://{upstream}/mcp"),
        }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(registrations.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_plain_http_public_issuer_is_refused() {
    let (base, client, session, ..) = dev_session().await;
    let (status, body) = initiate(
        &client,
        &base,
        &session,
        json!({
            "as_issuer": PLAINTEXT_PUBLIC,
            "upstream_resource": "https://mcp.example.com/mcp",
        }),
    )
    .await;
    assert_tls_refusal(status, &body, "issuer");
}

#[tokio::test]
async fn a_plain_http_public_resource_metadata_url_is_refused() {
    let (base, client, session, ..) = dev_session().await;
    let (status, body) = initiate(
        &client,
        &base,
        &session,
        json!({
            "resource_metadata_url": format!("{PLAINTEXT_PUBLIC}/.well-known/oauth-protected-resource"),
            "upstream_resource": "https://mcp.example.com/mcp",
        }),
    )
    .await;
    assert_tls_refusal(status, &body, "resource_metadata_url");
}

/// Resource metadata is upstream-controlled too: the AS it names is a hop.
#[tokio::test]
async fn a_plain_http_authorization_server_named_by_resource_metadata_is_refused() {
    let (upstream, registrations) =
        start_mock_as(json!({ "issuer_for_prm": PLAINTEXT_PUBLIC })).await;
    let (base, client, session, ..) = dev_session().await;
    let (status, body) = initiate(
        &client,
        &base,
        &session,
        json!({
            "resource_metadata_url": format!("http://{upstream}/.well-known/oauth-protected-resource"),
            "upstream_resource": format!("http://{upstream}/mcp"),
        }),
    )
    .await;
    assert_tls_refusal(status, &body, "issuer");
    assert_eq!(registrations.load(Ordering::SeqCst), 0);
}

/// Each endpoint the AS metadata advertises is refused if it is plain `http`
/// to a public address — before any client is registered, so nothing is left
/// half-created upstream or in the flow table.
#[tokio::test]
async fn plain_http_endpoints_in_as_metadata_are_refused_before_registering() {
    for field in [
        "registration_endpoint",
        "token_endpoint",
        "authorization_endpoint",
    ] {
        let (upstream, registrations) =
            start_mock_as(json!({ field: format!("{PLAINTEXT_PUBLIC}/{field}") })).await;
        let (base, client, session, identity, _org, pool) = dev_session().await;
        let resource = format!("http://{upstream}/mcp");
        let (status, body) = initiate(
            &client,
            &base,
            &session,
            json!({ "as_issuer": format!("http://{upstream}"), "upstream_resource": resource }),
        )
        .await;
        assert_tls_refusal(status, &body, field);
        assert_eq!(registrations.load(Ordering::SeqCst), 0, "{field}");
        assert!(
            mcp_upstream_flow::find_active_for(&pool, identity, &resource)
                .await
                .unwrap()
                .is_none(),
            "{field}: no flow may be minted"
        );
    }
}

/// The pinned client never follows a redirect, so a registration endpoint that
/// 307s to plain `http` cannot move the request off the hop that was checked.
#[tokio::test]
async fn a_redirect_to_plain_http_is_not_followed() {
    let (upstream, _) =
        start_mock_as(json!({ "registration_endpoint": "{issuer}/register-redirect" })).await;
    let (base, client, session, ..) = dev_session().await;
    let (status, body) = initiate(
        &client,
        &base,
        &session,
        json!({
            "as_issuer": format!("http://{upstream}"),
            "upstream_resource": format!("http://{upstream}/mcp"),
        }),
    )
    .await;
    assert_eq!(status, 502, "{body}");
    assert!(
        body.contains("307"),
        "the redirect must surface, not be followed: {body}"
    );
}

/// A flow minted before https was required can carry a plain-`http` token
/// endpoint. The callback refuses to send the code (and the PKCE verifier)
/// there, and leaves the row unconsumed.
#[tokio::test]
async fn the_callback_refuses_a_stored_plain_http_token_endpoint() {
    let (base, client, session, identity, org, pool) = dev_session().await;
    let flow_id = format!("tlsflow{}", Uuid::new_v4().simple());
    mcp_upstream_flow::create(
        &pool,
        &mcp_upstream_flow::CreateMcpUpstreamFlow {
            id: &flow_id,
            identity_id: identity,
            org_id: org,
            upstream_resource: "https://mcp.example.com/mcp",
            upstream_client_id: "legacy_client",
            upstream_as_issuer: PLAINTEXT_PUBLIC,
            upstream_token_endpoint: &format!("{PLAINTEXT_PUBLIC}/token"),
            upstream_authorize_url: &format!("{PLAINTEXT_PUBLIC}/authorize"),
            pkce_code_verifier: "verifier",
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(10),
            created_ip: None,
            created_user_agent: None,
        },
    )
    .await
    .unwrap();

    let resp = client
        .get(format!(
            "{base}/oauth/upstream/callback?code=anycode&state={flow_id}"
        ))
        .header("cookie", format!("__Host-oss_session={session}"))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap();
    assert_tls_refusal(status, &body, "token_endpoint");

    let row = mcp_upstream_flow::get_by_id(&pool, &flow_id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        row.consumed_at.is_none(),
        "a refused callback must not burn the flow"
    );
}
