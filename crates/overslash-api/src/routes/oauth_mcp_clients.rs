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
use crate::{AppState, error::AppError, extractors::AdminAcl};
use overslash_db::repos::{mcp_refresh_token, oauth_mcp_client};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/oauth/mcp-clients", get(list))
        .route("/v1/oauth/mcp-clients/{client_id}/revoke", post(revoke))
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
