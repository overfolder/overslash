use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, put},
};
use serde::{Deserialize, Serialize};

use overslash_db::repos::audit::AuditEntry;
use overslash_db::scopes::OrgScope;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, ClientIp, SessionAuth, WriteAcl},
};
use overslash_core::crypto;

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/secrets", get(list_secrets)).route(
        "/v1/secrets/{name}",
        put(put_secret).get(get_secret).delete(delete_secret),
    )
}

#[derive(Deserialize)]
struct PutSecretRequest {
    value: String,
    /// If set, attribute the new secret version to this user identity instead
    /// of the calling agent. Caller must be the user itself or an agent whose
    /// owner is this user. Secrets are org-scoped, so this only changes
    /// `created_by` attribution.
    #[serde(default)]
    on_behalf_of: Option<uuid::Uuid>,
}

#[derive(Serialize)]
struct SecretMetadata {
    name: String,
    current_version: i32,
}

#[derive(Serialize)]
struct PutSecretResponse {
    name: String,
    version: i32,
}

async fn put_secret(
    State(state): State<AppState>,
    WriteAcl(acl): WriteAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(name): Path<String>,
    Json(req): Json<PutSecretRequest>,
) -> Result<Json<PutSecretResponse>> {
    let auth = acl;
    let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)?;
    let encrypted = crypto::encrypt(&enc_key, req.value.as_bytes())?;

    let created_by = crate::services::group_ceiling::resolve_owner_identity(
        &scope,
        auth.identity_id,
        req.on_behalf_of,
    )
    .await?;

    // API-driven writes: `created_by` already names the caller, so there is
    // no distinct "provisioning user" to record. That column is reserved for
    // the standalone secret-provide page flow.
    let (secret, _version) = scope
        .put_secret(&name, &encrypted, created_by, None)
        .await?;

    let _ = OrgScope::new(auth.org_id, state.db.clone())
        .log_audit(AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "secret.put",
            resource_type: Some("secret"),
            resource_id: None,
            detail: serde_json::json!({ "name": &secret.name, "version": secret.current_version }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(PutSecretResponse {
        name: secret.name,
        version: secret.current_version,
    }))
}

async fn get_secret(
    // Dashboard-only: secret metadata is never exposed to API keys.
    // `SessionAuth` rejects bearer tokens; `OrgScope` enforces org_id at
    // the SQL boundary.
    session: SessionAuth,
    scope: OrgScope,
    Path(name): Path<String>,
) -> Result<Json<SecretMetadata>> {
    debug_assert_eq!(session.org_id, scope.org_id());
    let secret = scope
        .get_secret_by_name(&name)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("secret '{name}' not found")))?;

    Ok(Json(SecretMetadata {
        name: secret.name,
        current_version: secret.current_version,
    }))
}

async fn list_secrets(
    // Dashboard-only — see `get_secret`.
    session: SessionAuth,
    scope: OrgScope,
) -> Result<Json<Vec<SecretMetadata>>> {
    debug_assert_eq!(session.org_id, scope.org_id());
    let rows = scope.list_secrets().await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| SecretMetadata {
                name: r.name,
                current_version: r.current_version,
            })
            .collect(),
    ))
}

async fn delete_secret(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let auth = acl;
    let deleted = scope.soft_delete_secret(&name).await?;
    if deleted {
        let _ = OrgScope::new(auth.org_id, state.db.clone())
            .log_audit(AuditEntry {
                org_id: auth.org_id,
                identity_id: auth.identity_id,
                action: "secret.deleted",
                resource_type: Some("secret"),
                resource_id: None,
                detail: serde_json::json!({ "name": &name }),
                description: None,
                ip_address: ip.0.as_deref(),
            })
            .await;
        Ok(Json(serde_json::json!({ "deleted": true })))
    } else {
        Err(AppError::NotFound(format!("secret '{name}' not found")))
    }
}
