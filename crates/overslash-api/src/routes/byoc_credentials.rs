use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_core::permissions::AccessLevel;
use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::byoc_credential::ByocCredentialRow;

use super::util::fmt_time;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{ClientIp, ReqExt, WriteAcl},
};
use overslash_core::crypto;
use overslash_db::OrgScope;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/byoc-credentials", post(create_byoc).get(list_byoc))
        .route(
            "/v1/byoc-credentials/{id}",
            get(get_byoc).put(update_byoc).delete(delete_byoc),
        )
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
    /// Opaque caller-supplied provenance tag (§6.2), echoed verbatim. Defaults
    /// to `{}` when omitted.
    #[serde(default)]
    metadata: serde_json::Value,
}

/// Body of `PUT /v1/byoc-credentials/{id}` — replaces the encrypted client pair
/// in place so the credential id (and every connection pinned to it) survives.
#[derive(Deserialize)]
struct UpdateByocRequest {
    client_id: String,
    client_secret: String,
    /// Replaces the stored metadata wholesale (never merged). Defaults to `{}`
    /// when omitted, so a stale provenance claim can never outlive the client
    /// material it described (design caveat 6.2a).
    #[serde(default)]
    metadata: serde_json::Value,
}

#[derive(Serialize)]
struct ByocCredentialResponse {
    id: Uuid,
    org_id: Uuid,
    identity_id: Uuid,
    provider_key: String,
    metadata: serde_json::Value,
    created_at: String,
    updated_at: String,
}

/// Normalize caller-supplied metadata: an omitted/`null` value becomes `{}`,
/// an object is kept verbatim, anything else is rejected. Keeping the column an
/// object map upholds the `(key=value)` tag contract and the dashboard's
/// `Record<string,string>` type. The value stays opaque to Overslash otherwise.
fn normalize_metadata(md: serde_json::Value) -> Result<serde_json::Value> {
    match md {
        serde_json::Value::Null => Ok(serde_json::json!({})),
        v @ serde_json::Value::Object(_) => Ok(v),
        _ => Err(AppError::BadRequest(
            "metadata must be a JSON object of key/value tags".into(),
        )),
    }
}

impl From<ByocCredentialRow> for ByocCredentialResponse {
    fn from(row: ByocCredentialRow) -> Self {
        Self {
            id: row.id,
            org_id: row.org_id,
            identity_id: row.identity_id,
            provider_key: row.provider_key,
            metadata: row.metadata,
            created_at: fmt_time(row.created_at),
            updated_at: fmt_time(row.updated_at),
        }
    }
}

async fn create_byoc(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
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
    overslash_db::repos::oauth_provider::get_by_key(state.db(&ext), &req.provider)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("provider '{}' not found", req.provider)))?;

    // Verify the identity belongs to the same org.
    scope
        .get_identity(req.identity_id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;

    let metadata = normalize_metadata(req.metadata)?;
    let enc_key = state.config.keyring()?;
    let encrypted_client_id = crypto::encrypt(&enc_key, req.client_id.as_bytes())?;
    let encrypted_client_secret = crypto::encrypt(&enc_key, req.client_secret.as_bytes())?;

    let row = scope
        .create_byoc_credential(
            req.identity_id,
            &req.provider,
            &encrypted_client_id,
            &encrypted_client_secret,
            &metadata,
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

    Ok(Json(row.into()))
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
            .map(ByocCredentialResponse::from)
            .collect(),
    ))
}

/// `GET /v1/byoc-credentials/{id}` — fetch a single credential (self-or-admin).
/// Echoes `metadata` so a partner can read back the provenance tag it stamped.
async fn get_byoc(
    WriteAcl(acl): WriteAcl,
    scope: OrgScope,
    Path(id): Path<Uuid>,
) -> Result<Json<ByocCredentialResponse>> {
    let caller_identity = acl
        .identity_id
        .ok_or_else(|| AppError::Forbidden("identity-bound credential required for BYOC".into()))?;
    let row = scope
        .get_byoc_credential(id)
        .await?
        .ok_or_else(|| AppError::NotFound("BYOC credential not found".into()))?;
    if row.identity_id != caller_identity && acl.access_level < AccessLevel::Admin {
        return Err(AppError::Forbidden(
            "reading another identity's BYOC requires admin access".into(),
        ));
    }
    Ok(Json(row.into()))
}

/// `PUT /v1/byoc-credentials/{id}` — replace the encrypted client pair (and
/// metadata) in place. The credential id survives, so connections pinned to it
/// keep their binding; but tokens they hold were minted under the *old* OAuth
/// app and can no longer refresh, so every pinned connection is proactively
/// marked `reauth_required`. Self-or-admin, mirroring create/delete.
async fn update_byoc(
    State(state): State<AppState>,
    WriteAcl(acl): WriteAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateByocRequest>,
) -> Result<Json<ByocCredentialResponse>> {
    let caller_identity = acl
        .identity_id
        .ok_or_else(|| AppError::Forbidden("identity-bound credential required for BYOC".into()))?;

    // Self-or-admin: load the row first (org-scoped, so a cross-org id is a
    // NotFound) and check ownership before touching secret material.
    let existing = scope
        .get_byoc_credential(id)
        .await?
        .ok_or_else(|| AppError::NotFound("BYOC credential not found".into()))?;
    if existing.identity_id != caller_identity && acl.access_level < AccessLevel::Admin {
        return Err(AppError::Forbidden(
            "replacing another identity's BYOC requires admin access".into(),
        ));
    }

    let metadata = normalize_metadata(req.metadata)?;
    let enc_key = state.config.keyring()?;
    let encrypted_client_id = crypto::encrypt(&enc_key, req.client_id.as_bytes())?;
    let encrypted_client_secret = crypto::encrypt(&enc_key, req.client_secret.as_bytes())?;

    let row = scope
        .update_byoc_credential(
            id,
            &encrypted_client_id,
            &encrypted_client_secret,
            &metadata,
        )
        .await?
        // The pre-check found the row under this org, so a None here means it
        // was deleted concurrently — surface it as NotFound rather than 500.
        .ok_or_else(|| AppError::NotFound("BYOC credential not found".into()))?;

    // The old client's tokens can't refresh — force reauth on every pinned
    // connection now instead of letting a refresh fail at some later call.
    let reauth_marked = scope.mark_connections_reauth_by_byoc(id).await.unwrap_or(0);

    let _ = scope
        .log_audit(AuditEntry {
            org_id: scope.org_id(),
            identity_id: Some(caller_identity),
            action: "byoc_credential.replaced",
            resource_type: Some("byoc_credential"),
            resource_id: Some(id),
            detail: serde_json::json!({
                "provider": row.provider_key,
                "reauth_marked": reauth_marked,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(row.into()))
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
