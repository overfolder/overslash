use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{delete, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_core::permissions::AccessLevel;
use overslash_db::repos::audit::AuditEntry;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{ClientIp, WriteAcl},
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
    /// BYOC credentials are identity-bound. A caller with Write access can
    /// only create BYOC for their own identity; creating on behalf of
    /// another identity requires Admin.
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
    WriteAcl(acl): WriteAcl,
    scope: OrgScope,
    ip: ClientIp,
    Json(req): Json<CreateByocRequest>,
) -> Result<Json<ByocCredentialResponse>> {
    // Self-or-admin: non-admins can only configure their own OAuth app.
    let caller_identity = acl
        .identity_id
        .ok_or_else(|| AppError::Forbidden("identity-bound credential required for BYOC".into()))?;
    if req.identity_id != caller_identity && acl.access_level < AccessLevel::Admin {
        return Err(AppError::Forbidden(
            "creating BYOC for another identity requires admin access".into(),
        ));
    }

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
            identity_id: Some(caller_identity),
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

async fn list_byoc(
    WriteAcl(acl): WriteAcl,
    scope: OrgScope,
) -> Result<Json<Vec<ByocCredentialResponse>>> {
    let caller_identity = acl
        .identity_id
        .ok_or_else(|| AppError::Forbidden("identity-bound credential required for BYOC".into()))?;
    let rows = scope.list_byoc_credentials().await?;
    let is_admin = acl.access_level >= AccessLevel::Admin;

    Ok(Json(
        rows.into_iter()
            .filter(|r| is_admin || r.identity_id == caller_identity)
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
    WriteAcl(acl): WriteAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let caller_identity = acl
        .identity_id
        .ok_or_else(|| AppError::Forbidden("identity-bound credential required for BYOC".into()))?;

    // Self-or-admin: look up the row first to check ownership. `get_byoc_credential`
    // is org-scoped, so cross-org reads return None here.
    let row = scope
        .get_byoc_credential(id)
        .await?
        .ok_or_else(|| AppError::NotFound("BYOC credential not found".into()))?;
    if row.identity_id != caller_identity && acl.access_level < AccessLevel::Admin {
        return Err(AppError::Forbidden(
            "deleting another identity's BYOC requires admin access".into(),
        ));
    }

    let deleted = scope.delete_byoc_credential(id).await?;

    if deleted {
        let _ = scope
            .log_audit(AuditEntry {
                org_id: scope.org_id(),
                identity_id: Some(caller_identity),
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
