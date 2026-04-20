//! Admin CRUD for MCP OAuth clients registered via DCR.
//!
//! - `GET  /v1/oauth/mcp-clients`                 — list every registered client (admin).
//! - `POST /v1/oauth/mcp-clients/:client_id/revoke` — flip `is_revoked` and
//!   revoke every outstanding refresh token bound to the client.
//!
//! DCR itself is unauthenticated — clients self-register at
//! `POST /oauth/register`. This admin surface is the escape hatch for
//! revoking clients that turn hostile or are no longer wanted.

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde_json::json;

use super::util::fmt_time;
use crate::{
    AppState,
    error::AppError,
    extractors::{AdminAcl, AuthContext},
};
use overslash_db::repos::{mcp_refresh_token, oauth_mcp_client};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/oauth/mcp-clients", get(list))
        .route("/v1/oauth/mcp-clients/{client_id}/revoke", post(revoke))
        .route("/v1/oauth/mcp-clients/mine", get(list_mine))
        .route(
            "/v1/oauth/mcp-clients/{client_id}/revoke/mine",
            post(revoke_mine),
        )
}

async fn list(
    State(state): State<AppState>,
    _acl: AdminAcl,
) -> Result<impl IntoResponse, AppError> {
    let rows = oauth_mcp_client::list_all(&state.db).await?;
    let clients: Vec<_> = rows
        .into_iter()
        .map(|r| {
            json!({
                "client_id": r.client_id,
                "client_name": r.client_name,
                "software_id": r.software_id,
                "software_version": r.software_version,
                "redirect_uris": r.redirect_uris,
                "created_at": fmt_time(r.created_at),
                "last_seen_at": r.last_seen_at.map(fmt_time),
                "is_revoked": r.is_revoked,
            })
        })
        .collect();
    Ok(Json(json!({ "clients": clients })))
}

async fn revoke(
    State(state): State<AppState>,
    _acl: AdminAcl,
    Path(client_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let found = oauth_mcp_client::revoke(&state.db, &client_id).await?;
    if !found {
        return Err(AppError::NotFound("mcp client not found".into()));
    }
    let revoked_tokens = mcp_refresh_token::revoke_all_for_client(&state.db, &client_id).await?;
    Ok((
        StatusCode::OK,
        Json(json!({
            "client_id": client_id,
            "revoked_refresh_tokens": revoked_tokens,
        })),
    ))
}

// User-scoped list: clients the caller has enrolled (has a binding to).
// This is what the dashboard's "MCP Clients" section under /org loads —
// admins use `list` above for the cross-org view.
async fn list_mine(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<impl IntoResponse, AppError> {
    let user_identity_id = auth
        .identity_id
        .ok_or_else(|| AppError::Unauthorized("no identity on session".into()))?;
    let rows = oauth_mcp_client::list_bound_to_user(&state.db, user_identity_id).await?;
    let clients: Vec<_> = rows
        .into_iter()
        .map(|r| {
            json!({
                "client_id": r.client.client_id,
                "client_name": r.client.client_name,
                "software_id": r.client.software_id,
                "software_version": r.client.software_version,
                "redirect_uris": r.client.redirect_uris,
                "created_at": fmt_time(r.client.created_at),
                "last_seen_at": r.client.last_seen_at.map(fmt_time),
                "is_revoked": r.client.is_revoked,
                "agent_identity_id": r.agent_identity_id,
                "bound_at": fmt_time(r.binding_updated_at),
            })
        })
        .collect();
    Ok(Json(json!({ "clients": clients })))
}

// User-scoped revoke: any user can revoke an MCP client they've enrolled,
// without needing admin privileges. Non-owners get a 404 so enumeration of
// other users' client_ids leaks nothing.
async fn revoke_mine(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(client_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let user_identity_id = auth
        .identity_id
        .ok_or_else(|| AppError::Unauthorized("no identity on session".into()))?;
    let owns = oauth_mcp_client::user_has_binding(&state.db, user_identity_id, &client_id).await?;
    if !owns {
        return Err(AppError::NotFound("mcp client not found".into()));
    }
    let found = oauth_mcp_client::revoke(&state.db, &client_id).await?;
    if !found {
        return Err(AppError::NotFound("mcp client not found".into()));
    }
    let revoked_tokens = mcp_refresh_token::revoke_all_for_client(&state.db, &client_id).await?;
    Ok((
        StatusCode::OK,
        Json(json!({
            "client_id": client_id,
            "revoked_refresh_tokens": revoked_tokens,
        })),
    ))
}
