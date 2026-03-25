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
    services::{client_credentials, oauth},
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
    /// Pin a specific BYOC credential for this connection. If omitted, the
    /// cascade resolver picks identity-level → org-level → env fallback.
    byoc_credential_id: Option<Uuid>,
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

    // OAuth connections require an identity-bound API key
    let identity_id = auth
        .identity_id
        .ok_or_else(|| AppError::BadRequest("OAuth requires an identity-bound API key".into()))?;

    let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)?;
    let creds = client_credentials::resolve(
        &state.db,
        &enc_key,
        auth.org_id,
        Some(identity_id),
        &req.provider,
        None,
    )
    .await?;

    let redirect_uri = format!(
        "{}/v1/oauth/callback",
        std::env::var("PUBLIC_URL").unwrap_or_else(|_| "http://localhost:3000".into())
    );

    // Determine which BYOC credential to pin: explicit request > resolved
    let byoc_id = req.byoc_credential_id.or(creds.byoc_credential_id);
    let byoc_segment = byoc_id.map_or_else(|| "_".to_string(), |id| id.to_string());

    // State encodes: org_id:identity_id:provider_key:byoc_credential_id
    let oauth_state = format!(
        "{}:{}:{}:{}",
        auth.org_id, identity_id, req.provider, byoc_segment
    );

    let auth_url = oauth::build_auth_url(
        &provider,
        &creds.client_id,
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
    // Parse state: org_id:identity_id:provider_key:byoc_credential_id
    let parts: Vec<&str> = params.state.splitn(4, ':').collect();
    if parts.len() < 3 {
        return Err(AppError::BadRequest("invalid state parameter".into()));
    }
    let org_id: Uuid = parts[0]
        .parse()
        .map_err(|_| AppError::BadRequest("invalid org_id in state".into()))?;
    let identity_id: Uuid = parts[1]
        .parse()
        .map_err(|_| AppError::BadRequest("invalid identity_id in state".into()))?;
    let provider_key = parts[2];
    let byoc_credential_id: Option<Uuid> = parts
        .get(3)
        .and_then(|s| if *s == "_" { None } else { s.parse().ok() });

    let provider = overslash_db::repos::oauth_provider::get_by_key(&state.db, provider_key)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("provider '{provider_key}' not found")))?;

    let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)?;
    let creds = client_credentials::resolve(
        &state.db,
        &enc_key,
        org_id,
        Some(identity_id),
        provider_key,
        None,
    )
    .await?;

    // Use the BYOC credential from state if pinned, otherwise from resolver
    let effective_byoc_id = byoc_credential_id.or(creds.byoc_credential_id);

    let redirect_uri = format!(
        "{}/v1/oauth/callback",
        std::env::var("PUBLIC_URL").unwrap_or_else(|_| "http://localhost:3000".into())
    );

    // Exchange code for tokens
    let tokens = oauth::exchange_code(
        &state.http_client,
        &provider,
        &creds.client_id,
        &creds.client_secret,
        &params.code,
        &redirect_uri,
    )
    .await
    .map_err(|e| AppError::BadRequest(format!("token exchange failed: {e}")))?;

    // Encrypt tokens
    let encrypted_access = crypto::encrypt(&enc_key, tokens.access_token.as_bytes())?;
    let encrypted_refresh = tokens
        .refresh_token
        .as_ref()
        .map(|rt| crypto::encrypt(&enc_key, rt.as_bytes()))
        .transpose()?;
    let expires_at = tokens
        .expires_in
        .map(|secs| time::OffsetDateTime::now_utc() + time::Duration::seconds(secs));

    // Store connection with pinned BYOC credential
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
            byoc_credential_id: effective_byoc_id,
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
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    // Scope delete: if identity-bound key, must own the connection.
    // Org-level keys can delete any connection in the org.
    let deleted = if let Some(identity_id) = auth.identity_id {
        overslash_db::repos::connection::delete_by_identity(&state.db, id, identity_id).await?
    } else {
        overslash_db::repos::connection::delete_by_org(&state.db, id, auth.org_id).await?
    };
    Ok(Json(serde_json::json!({ "deleted": deleted })))
}
