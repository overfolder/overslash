use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{delete, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::repos::audit::AuditEntry;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, ClientIp},
};
use overslash_core::crypto;
use overslash_db::OrgScope;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/byoc-credentials", post(create_byoc).get(list_byoc))
        .route("/v1/byoc-credentials/{id}", delete(delete_byoc))
}

#[derive(Deserialize)]
struct CreateByocRequest {
    provider: String,
    client_id: String,
    client_secret: String,
    /// Required: BYOC credentials are always identity-bound. The previously
    /// supported "org-level" credential (identity_id = null) was removed in
    /// migration 028.
    identity_id: Uuid,
}

#[derive(Serialize)]
struct ByocCredentialResponse {
    id: Uuid,
    org_id: Uuid,
    identity_id: Uuid,
    provider_key: String,
    created_at: String,
    updated_at: String,
}

async fn create_byoc(
    State(state): State<AppState>,
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Json(req): Json<CreateByocRequest>,
) -> Result<Json<ByocCredentialResponse>> {
    let auth = acl;
    // Validate provider exists
    overslash_db::repos::oauth_provider::get_by_key(&state.db, &req.provider)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("provider '{}' not found", req.provider)))?;

    // Verify the identity belongs to the same org.
    scope
        .get_identity(req.identity_id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;

    let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)?;
    let encrypted_client_id = crypto::encrypt(&enc_key, req.client_id.as_bytes())?;
    let encrypted_client_secret = crypto::encrypt(&enc_key, req.client_secret.as_bytes())?;

    let row = scope
        .create_byoc_credential(
            req.identity_id,
            &req.provider,
            &encrypted_client_id,
            &encrypted_client_secret,
        )
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.code().as_deref() == Some("23505") {
                    return AppError::Conflict(format!(
                        "BYOC credential already exists for provider '{}'",
                        req.provider
                    ));
                }
            }
            AppError::Database(e)
        })?;

    let _ = scope
        .log_audit(AuditEntry {
            org_id: scope.org_id(),
            identity_id: auth.identity_id,
            action: "byoc_credential.created",
            resource_type: Some("byoc_credential"),
            resource_id: Some(row.id),
            detail: serde_json::json!({ "provider": req.provider }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(ByocCredentialResponse {
        id: row.id,
        org_id: row.org_id,
        identity_id: row.identity_id,
        provider_key: row.provider_key,
        created_at: row.created_at.to_string(),
        updated_at: row.updated_at.to_string(),
    }))
}

async fn list_byoc(scope: OrgScope) -> Result<Json<Vec<ByocCredentialResponse>>> {
    let rows = scope.list_byoc_credentials().await?;

    Ok(Json(
        rows.into_iter()
            .map(|r| ByocCredentialResponse {
                id: r.id,
                org_id: r.org_id,
                identity_id: r.identity_id,
                provider_key: r.provider_key,
                created_at: r.created_at.to_string(),
                updated_at: r.updated_at.to_string(),
            })
            .collect(),
    ))
}

async fn delete_byoc(
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let auth = acl;
    let deleted = scope.delete_byoc_credential(id).await?;

    if deleted {
        let _ = scope
            .log_audit(AuditEntry {
                org_id: scope.org_id(),
                identity_id: auth.identity_id,
                action: "byoc_credential.deleted",
                resource_type: Some("byoc_credential"),
                resource_id: Some(id),
                detail: serde_json::json!({}),
                description: None,
                ip_address: ip.0.as_deref(),
            })
            .await;
    }

    Ok(Json(serde_json::json!({ "deleted": deleted })))
}
