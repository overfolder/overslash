use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::AuthContext,
    services::oauth,
};
use overslash_core::crypto;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/connections",
            post(initiate_connection).get(list_connections),
        )
        .route("/v1/connections/{id}", delete(delete_connection))
        .route("/v1/oauth/callback", get(oauth_callback))
}

#[derive(Deserialize)]
struct InitiateConnectionRequest {
    provider: String,
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Serialize)]
struct InitiateConnectionResponse {
    auth_url: String,
    state: String,
    provider: String,
}

async fn initiate_connection(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(req): Json<InitiateConnectionRequest>,
) -> Result<Json<InitiateConnectionResponse>> {
    let provider = overslash_db::repos::oauth_provider::get_by_key(&state.db, &req.provider)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("provider '{}' not found", req.provider)))?;

    // For MVP, use system credentials from env. BYOC comes later.
    let client_id = std::env::var(format!("OAUTH_{}_CLIENT_ID", req.provider.to_uppercase()))
        .map_err(|_| {
            AppError::BadRequest(format!(
                "no OAuth client configured for provider '{}'",
                req.provider
            ))
        })?;

    let redirect_uri = format!(
        "{}/v1/oauth/callback",
        std::env::var("PUBLIC_URL").unwrap_or_else(|_| "http://localhost:3000".into())
    );

    // State encodes: org_id:identity_id:provider_key
    let identity_id = auth
        .identity_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| "none".into());
    let oauth_state = format!("{}:{}:{}", auth.org_id, identity_id, req.provider);

    let auth_url = oauth::build_auth_url(
        &provider,
        &client_id,
        &redirect_uri,
        &req.scopes,
        &oauth_state,
    );

    Ok(Json(InitiateConnectionResponse {
        auth_url,
        state: oauth_state,
        provider: req.provider,
    }))
}

#[derive(Deserialize)]
struct OAuthCallbackParams {
    code: String,
    state: String,
}

async fn oauth_callback(
    State(state): State<AppState>,
    Query(params): Query<OAuthCallbackParams>,
) -> Result<Json<serde_json::Value>> {
    // Parse state: org_id:identity_id:provider_key
    let parts: Vec<&str> = params.state.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Err(AppError::BadRequest("invalid state parameter".into()));
    }
    let org_id: Uuid = parts[0]
        .parse()
        .map_err(|_| AppError::BadRequest("invalid org_id in state".into()))?;
    let identity_id: Uuid = parts[1]
        .parse()
        .map_err(|_| AppError::BadRequest("invalid identity_id in state".into()))?;
    let provider_key = parts[2];

    let provider = overslash_db::repos::oauth_provider::get_by_key(&state.db, provider_key)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("provider '{provider_key}' not found")))?;

    let client_id = std::env::var(format!("OAUTH_{}_CLIENT_ID", provider_key.to_uppercase()))
        .map_err(|_| AppError::Internal("missing OAuth client_id".into()))?;

    let client_secret = std::env::var(format!(
        "OAUTH_{}_CLIENT_SECRET",
        provider_key.to_uppercase()
    ))
    .map_err(|_| AppError::Internal("missing OAuth client_secret".into()))?;

    let redirect_uri = format!(
        "{}/v1/oauth/callback",
        std::env::var("PUBLIC_URL").unwrap_or_else(|_| "http://localhost:3000".into())
    );

    // Exchange code for tokens
    let tokens = oauth::exchange_code(
        &state.http_client,
        &provider,
        &client_id,
        &client_secret,
        &params.code,
        &redirect_uri,
    )
    .await
    .map_err(|e| AppError::BadRequest(format!("token exchange failed: {e}")))?;

    // Encrypt tokens
    let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)?;
    let encrypted_access = crypto::encrypt(&enc_key, tokens.access_token.as_bytes())?;
    let encrypted_refresh = tokens
        .refresh_token
        .as_ref()
        .map(|rt| crypto::encrypt(&enc_key, rt.as_bytes()))
        .transpose()?;
    let expires_at = tokens
        .expires_in
        .map(|secs| time::OffsetDateTime::now_utc() + time::Duration::seconds(secs));

    // Store connection
    let conn = overslash_db::repos::connection::create(
        &state.db,
        &overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id,
            provider_key,
            encrypted_access_token: &encrypted_access,
            encrypted_refresh_token: encrypted_refresh.as_deref(),
            token_expires_at: expires_at,
            scopes: &[],
            account_email: None,
        },
    )
    .await?;

    // Audit
    let _ = overslash_db::repos::audit::log(
        &state.db,
        org_id,
        Some(identity_id),
        "connection.created",
        Some("connection"),
        Some(conn.id),
        serde_json::json!({ "provider": provider_key }),
    )
    .await;

    Ok(Json(serde_json::json!({
        "status": "connected",
        "connection_id": conn.id,
        "provider": provider_key,
    })))
}

#[derive(Serialize)]
struct ConnectionSummary {
    id: Uuid,
    provider_key: String,
    account_email: Option<String>,
    is_default: bool,
    created_at: String,
}

async fn list_connections(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<Vec<ConnectionSummary>>> {
    let identity_id = auth
        .identity_id
        .ok_or_else(|| AppError::BadRequest("key must be bound to an identity".into()))?;

    let rows = overslash_db::repos::connection::list_by_identity(&state.db, identity_id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| ConnectionSummary {
                id: r.id,
                provider_key: r.provider_key,
                account_email: r.account_email,
                is_default: r.is_default,
                created_at: r.created_at.to_string(),
            })
            .collect(),
    ))
}

async fn delete_connection(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let deleted = overslash_db::repos::connection::delete(&state.db, id).await?;
    Ok(Json(serde_json::json!({ "deleted": deleted })))
}
