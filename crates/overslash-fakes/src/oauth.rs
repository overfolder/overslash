//! OAuth 2.0 + OIDC IdP fake.
//!
//! Endpoints (host-relative — issuer is built dynamically from the `Host`
//! header so callers can reach this server through any reachable address):
//! - `GET  /.well-known/openid-configuration` — OIDC discovery doc
//! - `GET  /oauth/authorize` — authorization code endpoint (auto-approves)
//! - `POST /oauth/token` — token endpoint (`authorization_code` + `refresh_token`)
//! - `GET  /oidc/userinfo` — fixed claims for `sub=oidc-sub-testuser`
//! - `GET  /github/user`, `/github/user/emails`, `/github/user/emails-none-verified`
//!   — stand-ins for the GitHub OAuth identity API used by the social-login flow.
//!
//! Behavior matches the previous in-process `start_mock()` shipped with
//! `tests/common/mod.rs` so the existing backend tests keep passing.

use axum::{
    Form, Json, Router,
    extract::Query,
    http::HeaderMap,
    response::{IntoResponse, Redirect},
    routing::{get, post},
};
use serde_json::{Value, json};
use std::collections::HashMap;

use crate::{Handle, bind, serve};

/// Boot the OAuth/OIDC fake on `127.0.0.1:0` (OS-assigned). Use
/// [`start_on`] when you need a specific port.
pub async fn start() -> Handle {
    start_on("127.0.0.1:0").await
}

pub async fn start_on(bind_addr: &str) -> Handle {
    let (listener, addr, url) = bind(bind_addr).await.expect("bind oauth fake");
    let app = router();
    serve(listener, addr, url, app)
}

pub fn router() -> Router {
    Router::new()
        .route("/oauth/authorize", get(authorize))
        .route("/oauth/token", post(token))
        .route("/oidc/userinfo", get(oidc_userinfo))
        .route("/.well-known/openid-configuration", get(oidc_discovery))
        .route("/github/user", get(github_user))
        .route("/github/user/emails", get(github_user_emails))
        .route(
            "/github/user/emails-none-verified",
            get(github_user_emails_none_verified),
        )
}

/// Fake authorize endpoint: redirects back to `redirect_uri` with a fixed
/// `code` so e2e flows can complete without a consent UI.
async fn authorize(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let redirect_uri = params
        .get("redirect_uri")
        .cloned()
        .unwrap_or_else(|| "http://localhost".into());
    let state = params.get("state").cloned().unwrap_or_default();
    let sep = if redirect_uri.contains('?') { '&' } else { '?' };
    let target = if state.is_empty() {
        format!("{redirect_uri}{sep}code=mock_code")
    } else {
        format!("{redirect_uri}{sep}code=mock_code&state={state}")
    };
    Redirect::temporary(&target)
}

async fn token(Form(params): Form<Vec<(String, String)>>) -> Json<Value> {
    let grant_type = params
        .iter()
        .find(|(k, _)| k == "grant_type")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");

    match grant_type {
        "authorization_code" => {
            let code = params
                .iter()
                .find(|(k, _)| k == "code")
                .map(|(_, v)| v.as_str())
                .unwrap_or("unknown");
            Json(json!({
                "access_token": format!("mock_access_{code}"),
                "refresh_token": format!("mock_refresh_{code}"),
                "expires_in": 3600,
                "token_type": "Bearer",
            }))
        }
        "refresh_token" => Json(json!({
            "access_token": "mock_refreshed_access_token",
            "refresh_token": "mock_refreshed_refresh_token",
            "expires_in": 3600,
            "token_type": "Bearer",
        })),
        _ => Json(json!({"error": "unsupported_grant_type"})),
    }
}

async fn oidc_userinfo(headers: HeaderMap) -> Json<Value> {
    let _token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("unknown");
    Json(json!({
        "sub": "oidc-sub-testuser",
        "email": "testuser@example.com",
        "name": "Test User",
        "picture": "https://example.com/avatar.png",
    }))
}

async fn oidc_discovery(headers: HeaderMap) -> Json<Value> {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let base = format!("http://{host}");
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "userinfo_endpoint": format!("{base}/oidc/userinfo"),
        "jwks_uri": format!("{base}/oidc/jwks"),
        "scopes_supported": ["openid", "email", "profile", "offline_access"],
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
    }))
}

async fn github_user(_headers: HeaderMap) -> Json<Value> {
    Json(json!({
        "id": 12345,
        "login": "testuser",
        "name": "Test GitHub User",
        "avatar_url": "https://github.com/avatar.png",
    }))
}

async fn github_user_emails() -> Json<Value> {
    Json(json!([
        { "email": "testuser@example.com", "primary": true, "verified": true },
        { "email": "other@example.com", "primary": false, "verified": true },
    ]))
}

async fn github_user_emails_none_verified() -> Json<Value> {
    Json(json!([
        { "email": "unverified@example.com", "primary": true, "verified": false },
    ]))
}
