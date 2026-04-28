//! OAuth 2.1 Authorization Server metadata endpoints.
//!
//! - `GET /.well-known/oauth-authorization-server` — RFC 8414
//! - `GET /.well-known/oauth-protected-resource` — RFC 9728
//!
//! The issuer URL is per-request: when the caller hit `<slug>.<api-apex>`
//! (or `<slug>.<app-apex>`), the issuer in the metadata reflects that host,
//! so an MCP client discovering AS metadata for `acme.api.overslash.com`
//! receives `acme.api.overslash.com` as the issuer (and the same host on
//! all advertised endpoints). Per-org subdomains otherwise can't satisfy
//! RFC 8414's issuer-URL invariant. Apex requests still return the
//! `state.config.public_url` issuer, so root MCP discovery is unchanged.

use axum::{
    Json, Router,
    extract::{Extension, State},
    http::HeaderMap,
    routing::get,
};
use serde_json::{Value, json};

use crate::{AppState, middleware::subdomain::RequestOrgContext};

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

async fn authorization_server_metadata(
    State(state): State<AppState>,
    ctx: Option<Extension<RequestOrgContext>>,
    headers: HeaderMap,
) -> Json<Value> {
    let ctx = ctx.map(|Extension(c)| c).unwrap_or(RequestOrgContext::Root);
    let issuer = issuer_for(&state, &headers, &ctx);
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

async fn protected_resource_metadata(
    State(state): State<AppState>,
    ctx: Option<Extension<RequestOrgContext>>,
    headers: HeaderMap,
) -> Json<Value> {
    let ctx = ctx.map(|Extension(c)| c).unwrap_or(RequestOrgContext::Root);
    let issuer = issuer_for(&state, &headers, &ctx);
    Json(json!({
        "resource": format!("{issuer}/mcp"),
        "authorization_servers": [issuer],
        "scopes_supported": ["mcp"],
        "bearer_methods_supported": ["header"],
    }))
}

/// Build the issuer URL for the request. `Org { slug }` → `<scheme>://<slug>.<host>`
/// where `<host>` is the request's effective host with the slug label stripped
/// (so the same handler works for `slug.api.x.com` and `slug.app.x.com`).
/// `Root` → `state.config.public_url`. Falls back to `public_url` if for any
/// reason the request host can't be reconstructed.
pub(crate) fn issuer_for(state: &AppState, headers: &HeaderMap, ctx: &RequestOrgContext) -> String {
    match ctx {
        RequestOrgContext::Root => state.config.public_url.trim_end_matches('/').to_string(),
        RequestOrgContext::Org { slug, .. } => {
            let scheme = if state.config.public_url.starts_with("https://") {
                "https"
            } else {
                "http"
            };
            // Use the host the client actually hit (so `acme.api.x.com` and
            // `acme.app.x.com` each produce their own issuer). If the
            // effective host doesn't carry the org's slug — middleware
            // would have rejected an unknown slug, but a misconfigured
            // proxy could still strip headers — fall through to public_url.
            match crate::middleware::subdomain::effective_host(headers) {
                Some(host) if host.starts_with(&format!("{slug}.")) => {
                    format!("{scheme}://{host}")
                }
                _ => state.config.public_url.trim_end_matches('/').to_string(),
            }
        }
    }
}
