//! `/v1/org-oauth-credentials` — org-level OAuth App Credentials.
//!
//! Thin wrapper over two well-known org secrets per provider:
//! `OAUTH_{PROVIDER}_CLIENT_ID` / `OAUTH_{PROVIDER}_CLIENT_SECRET`.
//!
//! These feed tier 2 of the SPEC §7 credential cascade and are also the
//! default source for IdP client credentials (§3).

use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, put},
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use overslash_core::crypto;
use overslash_db::OrgScope;
use overslash_db::repos::{audit::AuditEntry, oauth_provider};

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, ClientIp},
    services::client_credentials::oauth_secret_names,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/org-oauth-credentials", get(list_credentials))
        .route(
            "/v1/org-oauth-credentials/{provider_key}",
            put(put_credentials).delete(delete_credentials),
        )
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct PutCredentialsRequest {
    client_id: String,
    client_secret: String,
}

#[derive(Serialize)]
struct CredentialRow {
    provider_key: String,
    display_name: String,
    /// `"db"` for org-secret-backed rows, `"env"` for env-var-configured rows.
    source: &'static str,
    /// Truncated client_id — never the full value, never the secret.
    client_id_preview: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn list_credentials(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
) -> Result<Json<Vec<CredentialRow>>> {
    // Admin-gated: listing which providers are configured (and their
    // truncated client_id fingerprints) is information disclosure about
    // the org's OAuth setup. PUT/DELETE are already admin-only; keeping
    // GET at the same level matches the dashboard's Org Settings gate.
    debug_assert_eq!(acl.org_id, scope.org_id());

    let providers = oauth_provider::list_all(&state.db).await?;
    let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)?;
    let env_fallback_enabled =
        std::env::var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS").is_ok();

    let mut rows: Vec<CredentialRow> = Vec::new();

    for provider in providers {
        let (id_name, secret_name) = oauth_secret_names(&provider.key);

        // Org-secret-backed credentials take precedence in the UI listing —
        // they are the layer admins manage.
        if let (Some(id_version), Some(_)) = (
            scope.get_current_secret_value(&id_name).await?,
            scope.get_current_secret_value(&secret_name).await?,
        ) {
            let client_id =
                String::from_utf8(crypto::decrypt(&enc_key, &id_version.encrypted_value)?)
                    .map_err(|e| {
                        AppError::Internal(format!("org OAuth client_id is not valid UTF-8: {e}"))
                    })?;
            rows.push(CredentialRow {
                provider_key: provider.key.clone(),
                display_name: provider.display_name.clone(),
                source: "db",
                client_id_preview: preview(&client_id),
            });
            continue;
        }

        // Env-var fallback (tier 3) — surface so the UI can display read-only.
        if env_fallback_enabled {
            if let (Ok(client_id), Ok(_)) = (std::env::var(&id_name), std::env::var(&secret_name)) {
                rows.push(CredentialRow {
                    provider_key: provider.key.clone(),
                    display_name: provider.display_name.clone(),
                    source: "env",
                    client_id_preview: preview(&client_id),
                });
            }
        }
    }

    Ok(Json(rows))
}

async fn put_credentials(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(provider_key): Path<String>,
    Json(req): Json<PutCredentialsRequest>,
) -> Result<Json<CredentialRow>> {
    // Validate provider exists
    let provider = oauth_provider::get_by_key(&state.db, &provider_key)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("provider '{provider_key}' not found")))?;

    // Reject when tier 3 (env vars) is already serving this provider — those
    // are operator-managed and must not be overridden via the dashboard.
    if env_provides(&provider_key) {
        return Err(AppError::Conflict(format!(
            "provider '{provider_key}' is configured via environment variables \
             and cannot be overridden from the dashboard"
        )));
    }

    let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)?;
    let (id_name, secret_name) = oauth_secret_names(&provider_key);

    let encrypted_id = crypto::encrypt(&enc_key, req.client_id.as_bytes())?;
    let encrypted_secret = crypto::encrypt(&enc_key, req.client_secret.as_bytes())?;

    // Write the secret value first, then the client_id. Both are needed for
    // the tier-2 resolver to match: missing either returns `Ok(None)` and
    // the cascade falls through. Writing the id last means that on a
    // partial failure before the second call, the resolver still correctly
    // reports "not configured" (rather than "half-configured, id matches
    // but secret is stale/missing"). The admin sees a 500, the org shows
    // as unconfigured, and retrying the PUT completes the pair.
    scope
        .put_secret(&secret_name, &encrypted_secret, acl.identity_id, None)
        .await?;
    scope
        .put_secret(&id_name, &encrypted_id, acl.identity_id, None)
        .await?;

    let _ = scope
        .log_audit(AuditEntry {
            org_id: scope.org_id(),
            identity_id: acl.identity_id,
            action: "oauth_credentials.put",
            resource_type: Some("oauth_credentials"),
            resource_id: None,
            detail: json!({ "provider_key": &provider_key }),
            description: Some(&format!(
                "Configured {} OAuth App Credentials",
                provider.display_name
            )),
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(CredentialRow {
        provider_key: provider.key,
        display_name: provider.display_name,
        source: "db",
        client_id_preview: preview(&req.client_id),
    }))
}

async fn delete_credentials(
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(provider_key): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let (id_name, secret_name) = oauth_secret_names(&provider_key);

    let deleted_id = scope.soft_delete_secret(&id_name).await?;
    let deleted_secret = scope.soft_delete_secret(&secret_name).await?;
    let deleted = deleted_id || deleted_secret;

    if deleted {
        let _ = scope
            .log_audit(AuditEntry {
                org_id: scope.org_id(),
                identity_id: acl.identity_id,
                action: "oauth_credentials.deleted",
                resource_type: Some("oauth_credentials"),
                resource_id: None,
                detail: json!({ "provider_key": &provider_key }),
                description: Some(&format!("Removed {provider_key} OAuth App Credentials")),
                ip_address: ip.0.as_deref(),
            })
            .await;
    }

    Ok(Json(json!({ "deleted": deleted })))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// True when tier-3 env vars currently provide credentials for the given
/// provider. Mirrors the lookup in `client_credentials::resolve`.
fn env_provides(provider_key: &str) -> bool {
    if std::env::var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS").is_err() {
        return false;
    }
    let (id_name, secret_name) = oauth_secret_names(provider_key);
    std::env::var(&id_name).is_ok() && std::env::var(&secret_name).is_ok()
}

/// Client IDs are not secret but they're long; show a stable fingerprint
/// that's recognizable without leaking extra detail. Short inputs fall back
/// to the full value to avoid meaningless previews.
fn preview(client_id: &str) -> String {
    const HEAD: usize = 8;
    const TAIL: usize = 4;
    let len = client_id.chars().count();
    if len <= HEAD + TAIL + 1 {
        return client_id.to_string();
    }
    let head: String = client_id.chars().take(HEAD).collect();
    let tail: String = client_id
        .chars()
        .rev()
        .take(TAIL)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head}…{tail}")
}
