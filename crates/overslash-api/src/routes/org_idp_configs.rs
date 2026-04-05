use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{post, put},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use overslash_db::repos::{
    audit::{self, AuditEntry},
    oauth_provider, org_idp_config,
};

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{ClientIp, UserOrKeyAuth},
    services::oidc_discovery,
};
use overslash_core::crypto;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/org-idp-configs",
            post(create_idp_config).get(list_idp_configs),
        )
        .route(
            "/v1/org-idp-configs/{id}",
            put(update_idp_config).delete(delete_idp_config),
        )
        .route("/v1/org-idp-configs/discover", post(discover_oidc))
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateIdpConfigRequest {
    /// For builtin providers (google, github), provide the provider key directly.
    /// For custom OIDC, omit this and provide `issuer_url` instead.
    provider_key: Option<String>,
    /// OIDC issuer URL — used to auto-discover endpoints and create a custom provider.
    issuer_url: Option<String>,
    /// Human-readable name for custom OIDC providers.
    display_name: Option<String>,
    client_id: String,
    client_secret: String,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    allowed_email_domains: Vec<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
struct UpdateIdpConfigRequest {
    client_id: Option<String>,
    client_secret: Option<String>,
    enabled: Option<bool>,
    allowed_email_domains: Option<Vec<String>>,
}

#[derive(Serialize)]
struct IdpConfigResponse {
    id: Uuid,
    org_id: Uuid,
    provider_key: String,
    display_name: String,
    enabled: bool,
    allowed_email_domains: Vec<String>,
    source: &'static str,
    created_at: String,
    updated_at: String,
}

#[derive(Deserialize)]
struct DiscoverRequest {
    issuer_url: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn create_idp_config(
    State(state): State<AppState>,
    auth: UserOrKeyAuth,
    ip: ClientIp,
    Json(req): Json<CreateIdpConfigRequest>,
) -> Result<Json<IdpConfigResponse>> {
    let provider_key = if let Some(key) = req.provider_key {
        // Validate builtin provider exists
        oauth_provider::get_by_key(&state.db, &key)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("provider '{key}' not found")))?;
        key
    } else if let Some(issuer_url) = &req.issuer_url {
        // Custom OIDC — discover endpoints and create/upsert provider
        let doc = oidc_discovery::discover(&state.http_client, issuer_url)
            .await
            .map_err(|e| AppError::BadRequest(format!("OIDC discovery failed: {e}")))?;

        let display_name = req.display_name.as_deref().unwrap_or(issuer_url);

        // Generate a stable key from the issuer URL
        let key = slugify_issuer(issuer_url);

        let supports_pkce = doc
            .code_challenge_methods_supported
            .as_ref()
            .map(|m| m.iter().any(|s| s == "S256"))
            .unwrap_or(false);

        // OIDC providers generally support refresh tokens via the offline_access scope
        let supports_refresh = doc
            .scopes_supported
            .as_ref()
            .map(|s| s.iter().any(|sc| sc == "offline_access"))
            .unwrap_or(true);

        let token_auth_method = doc
            .token_endpoint_auth_methods_supported
            .as_ref()
            .map(|methods| {
                if methods.contains(&"client_secret_basic".to_string()) {
                    "client_secret_basic"
                } else {
                    "client_secret_post"
                }
            })
            .unwrap_or("client_secret_post");

        oauth_provider::create_custom(
            &state.db,
            &key,
            display_name,
            &doc.authorization_endpoint,
            &doc.token_endpoint,
            doc.revocation_endpoint.as_deref(),
            doc.userinfo_endpoint.as_deref(),
            Some(issuer_url),
            doc.jwks_uri.as_deref(),
            supports_pkce,
            supports_refresh,
            token_auth_method,
        )
        .await?;

        key
    } else {
        return Err(AppError::BadRequest(
            "either provider_key or issuer_url is required".into(),
        ));
    };

    // Check env var precedence — warn if env vars already configure this provider
    if state.config.env_auth_credentials(&provider_key).is_some() {
        return Err(AppError::Conflict(format!(
            "provider '{provider_key}' is configured via environment variables and cannot be overridden"
        )));
    }

    let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)?;
    let encrypted_client_id = crypto::encrypt(&enc_key, req.client_id.as_bytes())?;
    let encrypted_client_secret = crypto::encrypt(&enc_key, req.client_secret.as_bytes())?;

    let row = org_idp_config::create(
        &state.db,
        auth.org_id,
        &provider_key,
        &encrypted_client_id,
        &encrypted_client_secret,
        req.enabled,
        &req.allowed_email_domains,
    )
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(ref db_err) = e {
            if db_err.is_unique_violation() {
                return AppError::Conflict(format!(
                    "IdP config already exists for provider '{provider_key}'"
                ));
            }
        }
        AppError::Database(e)
    })?;

    let display_name = oauth_provider::get_by_key(&state.db, &provider_key)
        .await?
        .map(|p| p.display_name)
        .unwrap_or_else(|| provider_key.clone());

    let desc = format!("Configured {display_name} as login identity provider");
    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "org_idp_config.created",
            resource_type: Some("org_idp_config"),
            resource_id: Some(row.id),
            detail: json!({ "provider_key": provider_key }),
            description: Some(&desc),
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(IdpConfigResponse {
        id: row.id,
        org_id: row.org_id,
        provider_key: row.provider_key,
        display_name,
        enabled: row.enabled,
        allowed_email_domains: row.allowed_email_domains,
        source: "db",
        created_at: row.created_at.to_string(),
        updated_at: row.updated_at.to_string(),
    }))
}

async fn list_idp_configs(
    State(state): State<AppState>,
    auth: UserOrKeyAuth,
) -> Result<Json<Vec<serde_json::Value>>> {
    let mut results: Vec<serde_json::Value> = Vec::new();

    // Env-var-configured providers (read-only, shown with source: "env")
    for (key, display) in [("google", "Google"), ("github", "GitHub")] {
        if state.config.env_auth_credentials(key).is_some() {
            results.push(json!({
                "provider_key": key,
                "display_name": display,
                "source": "env",
                "enabled": true,
            }));
        }
    }

    // DB-configured IdPs for this org
    let db_configs = org_idp_config::list_by_org(&state.db, auth.org_id).await?;
    for config in db_configs {
        // Skip if already shown from env vars
        if results
            .iter()
            .any(|r| r["provider_key"] == config.provider_key)
        {
            continue;
        }
        let display_name = oauth_provider::get_by_key(&state.db, &config.provider_key)
            .await?
            .map(|p| p.display_name)
            .unwrap_or_else(|| config.provider_key.clone());

        results.push(json!({
            "id": config.id,
            "org_id": config.org_id,
            "provider_key": config.provider_key,
            "display_name": display_name,
            "source": "db",
            "enabled": config.enabled,
            "allowed_email_domains": config.allowed_email_domains,
            "created_at": config.created_at.to_string(),
            "updated_at": config.updated_at.to_string(),
        }));
    }

    Ok(Json(results))
}

async fn update_idp_config(
    State(state): State<AppState>,
    auth: UserOrKeyAuth,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateIdpConfigRequest>,
) -> Result<Json<IdpConfigResponse>> {
    // Verify config exists and belongs to this org
    let existing = org_idp_config::get_by_id(&state.db, id, auth.org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("IdP config not found".into()))?;

    // Cannot update env-var-configured providers
    if state
        .config
        .env_auth_credentials(&existing.provider_key)
        .is_some()
    {
        return Err(AppError::Conflict(
            "cannot update env-var-configured provider".into(),
        ));
    }

    let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)?;

    let encrypted_client_id = req
        .client_id
        .as_ref()
        .map(|id| crypto::encrypt(&enc_key, id.as_bytes()))
        .transpose()?;
    let encrypted_client_secret = req
        .client_secret
        .as_ref()
        .map(|s| crypto::encrypt(&enc_key, s.as_bytes()))
        .transpose()?;

    let updated = org_idp_config::update(
        &state.db,
        id,
        auth.org_id,
        encrypted_client_id.as_deref(),
        encrypted_client_secret.as_deref(),
        req.enabled,
        req.allowed_email_domains.as_deref(),
    )
    .await?
    .ok_or_else(|| AppError::NotFound("IdP config not found".into()))?;

    let display_name = oauth_provider::get_by_key(&state.db, &updated.provider_key)
        .await?
        .map(|p| p.display_name)
        .unwrap_or_else(|| updated.provider_key.clone());

    let desc = format!("Updated {display_name} identity provider configuration");
    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "org_idp_config.updated",
            resource_type: Some("org_idp_config"),
            resource_id: Some(id),
            detail: json!({ "provider_key": updated.provider_key }),
            description: Some(&desc),
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(IdpConfigResponse {
        id: updated.id,
        org_id: updated.org_id,
        provider_key: updated.provider_key,
        display_name,
        enabled: updated.enabled,
        allowed_email_domains: updated.allowed_email_domains,
        source: "db",
        created_at: updated.created_at.to_string(),
        updated_at: updated.updated_at.to_string(),
    }))
}

async fn delete_idp_config(
    State(state): State<AppState>,
    auth: UserOrKeyAuth,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let deleted = org_idp_config::delete(&state.db, id, auth.org_id).await?;

    if deleted {
        let _ = audit::log(
            &state.db,
            &AuditEntry {
                org_id: auth.org_id,
                identity_id: auth.identity_id,
                action: "org_idp_config.deleted",
                resource_type: Some("org_idp_config"),
                resource_id: Some(id),
                detail: json!({}),
                description: Some("Removed identity provider configuration"),
                ip_address: ip.0.as_deref(),
            },
        )
        .await;
    }

    Ok(Json(json!({ "deleted": deleted })))
}

/// Preview OIDC discovery for an issuer URL (no persistence).
async fn discover_oidc(
    State(state): State<AppState>,
    _auth: UserOrKeyAuth,
    Json(req): Json<DiscoverRequest>,
) -> Result<Json<serde_json::Value>> {
    let doc = oidc_discovery::discover(&state.http_client, &req.issuer_url)
        .await
        .map_err(|e| AppError::BadRequest(format!("OIDC discovery failed: {e}")))?;

    Ok(Json(json!({
        "issuer": doc.issuer,
        "authorization_endpoint": doc.authorization_endpoint,
        "token_endpoint": doc.token_endpoint,
        "userinfo_endpoint": doc.userinfo_endpoint,
        "jwks_uri": doc.jwks_uri,
        "revocation_endpoint": doc.revocation_endpoint,
        "scopes_supported": doc.scopes_supported,
        "code_challenge_methods_supported": doc.code_challenge_methods_supported,
        "token_endpoint_auth_methods_supported": doc.token_endpoint_auth_methods_supported,
    })))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a stable provider key from an issuer URL.
/// Includes the full host + path to avoid collisions for multi-tenant IdPs.
/// e.g. "https://login.microsoftonline.com/tenant-abc/v2.0" → "oidc-login-microsoftonline-com-tenant-abc-v2-0"
fn slugify_issuer(issuer_url: &str) -> String {
    let without_scheme = issuer_url
        .strip_prefix("https://")
        .or_else(|| issuer_url.strip_prefix("http://"))
        .unwrap_or(issuer_url);
    // Remove trailing slashes, then slugify
    let trimmed = without_scheme.trim_end_matches('/');
    let slug: String = trimmed
        .chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    // Collapse consecutive dashes and trim
    let collapsed: String = slug
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    // Truncate to keep the key reasonable but preserve uniqueness
    let key = if collapsed.len() > 80 {
        &collapsed[..80]
    } else {
        &collapsed
    };
    format!("oidc-{}", key.trim_end_matches('-'))
}
