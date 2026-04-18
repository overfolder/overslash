//! OAuth 2.1 Authorization Server metadata endpoints.
//!
//! - `GET /.well-known/oauth-authorization-server` — RFC 8414
//! - `GET /.well-known/oauth-protected-resource` — RFC 9728
//!
//! Both are static documents keyed off `state.config.public_url`. They
//! advertise the MCP Authorization Server layered on top of the existing
//! Overslash IdP flow (see `docs/design/mcp-oauth-transport.md`).

use axum::{Json, Router, extract::State, routing::get};
use serde_json::{Value, json};

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_metadata),
        )
}

async fn authorization_server_metadata(State(state): State<AppState>) -> Json<Value> {
    let issuer = state.config.public_url.trim_end_matches('/').to_string();
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth/authorize"),
        "token_endpoint": format!("{issuer}/oauth/token"),
        "registration_endpoint": format!("{issuer}/oauth/register"),
        "revocation_endpoint": format!("{issuer}/oauth/revoke"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["mcp"],
    }))
}

async fn protected_resource_metadata(State(state): State<AppState>) -> Json<Value> {
    let issuer = state.config.public_url.trim_end_matches('/').to_string();
    Json(json!({
        "resource": format!("{issuer}/mcp"),
        "authorization_servers": [issuer],
        "scopes_supported": ["mcp"],
        "bearer_methods_supported": ["header"],
    }))
}
