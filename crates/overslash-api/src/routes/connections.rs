use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::repos::audit::AuditEntry;
use overslash_db::scopes::{OrgScope, UserScope};

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{ClientIp, WriteAcl},
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
    WriteAcl(acl): WriteAcl,
    Json(req): Json<InitiateConnectionRequest>,
) -> Result<Json<InitiateConnectionResponse>> {
    let auth = acl;
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
        req.byoc_credential_id,
    )
    .await?;

    let redirect_uri = format!(
        "{}/v1/oauth/callback",
        std::env::var("PUBLIC_URL").unwrap_or_else(|_| "http://localhost:3000".into())
    );

    let byoc_id = creds.byoc_credential_id;
    let byoc_segment = byoc_id.map_or_else(|| "_".to_string(), |id| id.to_string());

    // Generate PKCE pair if the provider requires it
    let pkce = if provider.supports_pkce {
        Some(oauth::generate_pkce())
    } else {
        None
    };

    let verifier_segment = pkce.as_ref().map(|p| p.verifier.as_str()).unwrap_or("_");

    // State encodes: org_id:identity_id:provider_key:byoc_credential_id:code_verifier
    let oauth_state = format!(
        "{}:{}:{}:{}:{}",
        auth.org_id, identity_id, req.provider, byoc_segment, verifier_segment
    );

    let auth_url = oauth::build_auth_url(
        &provider,
        &creds.client_id,
        &redirect_uri,
        &req.scopes,
        &oauth_state,
        pkce.as_ref().map(|p| p.challenge.as_str()),
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
    ip: ClientIp,
    Query(params): Query<OAuthCallbackParams>,
) -> Result<Json<serde_json::Value>> {
    // Parse state: org_id:identity_id:provider_key:byoc_credential_id[:code_verifier]
    let parts: Vec<&str> = params.state.splitn(5, ':').collect();
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
    let code_verifier: Option<&str> = parts
        .get(4)
        .and_then(|s| if *s == "_" { None } else { Some(*s) });

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
        byoc_credential_id,
    )
    .await?;

    let effective_byoc_id = creds.byoc_credential_id;

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
        code_verifier,
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

    // Store connection with pinned BYOC credential. The org_id from the
    // OAuth state cookie is the source of truth — mint an `OrgScope` from
    // it so the create is bound at the type level. The OAuth callback is
    // unauthenticated by design (the redirect_uri is public), so the org_id
    // comes from the signed state we issued at initiate time.
    let scope = OrgScope::new(org_id, state.db.clone());
    let conn = scope
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id,
            provider_key,
            encrypted_access_token: &encrypted_access,
            encrypted_refresh_token: encrypted_refresh.as_deref(),
            token_expires_at: expires_at,
            scopes: &[],
            account_email: None,
            byoc_credential_id: effective_byoc_id,
        })
        .await?;

    // Audit
    let _ = scope
        .log_audit(AuditEntry {
            org_id,
            identity_id: Some(identity_id),
            action: "connection.created",
            resource_type: Some("connection"),
            resource_id: Some(conn.id),
            detail: serde_json::json!({ "provider": provider_key }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
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

async fn list_connections(scope: UserScope) -> Result<Json<Vec<ConnectionSummary>>> {
    let rows = scope.list_my_connections().await?;
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
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let auth = acl;
    // Scope delete: if identity-bound, must own the connection.
    // Org-level keys can delete any connection in the org.
    let deleted = if let Some(identity_id) = auth.identity_id {
        UserScope::new(auth.org_id, identity_id, state.db.clone())
            .delete_my_connection(id)
            .await?
    } else {
        OrgScope::new(auth.org_id, state.db.clone())
            .delete_connection(id)
            .await?
    };

    if deleted {
        let _ = OrgScope::new(auth.org_id, state.db.clone())
            .log_audit(AuditEntry {
                org_id: auth.org_id,
                identity_id: auth.identity_id,
                action: "connection.deleted",
                resource_type: Some("connection"),
                resource_id: Some(id),
                detail: serde_json::json!({}),
                description: None,
                ip_address: ip.0.as_deref(),
            })
            .await;
    }

    Ok(Json(serde_json::json!({ "deleted": deleted })))
}
