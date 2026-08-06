//! OAuth 2.1 Authorization Server endpoints backing the MCP transport.
//!
//! Wired from `docs/design/mcp-oauth-transport.md`.
//!
//! - `POST /oauth/register` — RFC 7591 Dynamic Client Registration.
//!   Open by default; clients are public (PKCE), no `client_secret` issued.
//! - `GET  /oauth/authorize` — OAuth 2.1 §4.1 + PKCE (S256). Bounces through
//!   the existing IdP login if no `oss_session` cookie is present, then
//!   returns a one-shot authorization code bound to the client_id + challenge.
//! - `POST /oauth/token` — `authorization_code` and `refresh_token` grants.
//!   Refresh rotation is single-use per OAuth 2.1 BCP; reuse of a revoked
//!   refresh token revokes the entire chain (replay detection).
//! - `POST /oauth/revoke` — RFC 7009. Revokes a refresh token. Access
//!   tokens are JWT-based (stateless) so revocation there is best-effort.

use std::time::Instant;

use axum::{
    Form, Json, Router,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    AppState,
    error::AppError,
    extractors::ReqExt,
    middleware::subdomain::RequestOrgContext,
    services::{jwt, oauth_as, org_signin, session},
};
use overslash_db::repos::{
    identity, mcp_client_agent_binding, mcp_refresh_token, membership, oauth_mcp_client, org,
};
use overslash_db::scopes::OrgScope;

mod authorize;
mod consent;
mod register;
mod token;

use authorize::authorize;
use consent::{consent_context, consent_finish, consent_switch_org};
use register::register;
use token::{revoke, token};

/// Public OAuth Authorization Server endpoints (RFC 7591 / OAuth 2.1).
///
/// These are reached cross-origin by external OAuth clients — including
/// browser-based debug tools like MCP Inspector — so they sit under the
/// wider `cors_mcp` layer in `lib.rs` (origins = `dashboard_origin` ∪
/// `mcp_extra_origins`). Nothing here returns user data without a
/// preceding consent step, which is gated by `consent_router` below
/// under the tighter `cors_global` layer.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/oauth/register", post(register))
        .route("/oauth/authorize", get(authorize))
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke))
}

/// Dashboard-facing consent UI helpers. The dashboard fetches the
/// consent context and posts the user's decision back here while a
/// `/oauth/authorize` request is paused mid-flow. These leak the
/// pending request's metadata to whoever can read the response, so
/// they MUST stay behind the tight `cors_global` layer that only
/// trusts the dashboard origin — never the MCP Inspector origin.
pub fn consent_router() -> Router<AppState> {
    Router::new()
        .route("/v1/oauth/consent/{request_id}", get(consent_context))
        .route(
            "/v1/oauth/consent/{request_id}/finish",
            post(consent_finish),
        )
        .route(
            "/v1/oauth/consent/{request_id}/switch-org",
            post(consent_switch_org),
        )
}

// ---------------------------------------------------------------------------
// Error shape (RFC 6749 §5.2)
// ---------------------------------------------------------------------------

fn oauth_error(status: StatusCode, code: &'static str, desc: impl Into<String>) -> Response {
    (
        status,
        Json(json!({ "error": code, "error_description": desc.into() })),
    )
        .into_response()
}
