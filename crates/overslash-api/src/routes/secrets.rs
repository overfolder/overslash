use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use overslash_db::repos::audit::AuditEntry;
use overslash_db::scopes::OrgScope;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, ClientIp, SessionAuth, WriteAcl},
};
use overslash_core::crypto;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/secrets", get(list_secrets))
        .route(
            "/v1/secrets/{name}",
            put(put_secret).get(get_secret).delete(delete_secret),
        )
        .route(
            "/v1/secrets/{name}/versions/{version}/reveal",
            post(reveal_version),
        )
        .route(
            "/v1/secrets/{name}/versions/{version}/restore",
            post(restore_version),
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

/// Dashboard-shaped metadata. The original `name + current_version` shape
/// is a strict subset of this — extending the response is safe because the
/// secret routes are dashboard-only (SessionAuth rejects bearer tokens).
#[derive(Serialize)]
struct SecretMetadata {
    name: String,
    current_version: i32,
    /// Identity that created version 1 — the slot owner (SPEC §6). `None`
    /// if the version 1 row's `created_by` was nulled out (e.g. the
    /// creating identity was deleted) or the secret has no versions yet.
    owner_identity_id: Option<uuid::Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

#[derive(Serialize)]
struct SecretVersionView {
    version: i32,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    created_by: Option<uuid::Uuid>,
    /// Human who pasted this value on the standalone provide page (if any).
    /// Distinct from `created_by`, which names the target identity. SPEC §11.
    provisioned_by_user_id: Option<uuid::Uuid>,
}

#[derive(Serialize)]
struct ServiceUsingSecretView {
    id: uuid::Uuid,
    name: String,
    status: String,
}

#[derive(Serialize)]
struct SecretDetail {
    #[serde(flatten)]
    meta: SecretMetadata,
    versions: Vec<SecretVersionView>,
    /// Service instances whose `secret_name` references this secret. Lets
    /// the dashboard warn the user before deleting.
    used_by: Vec<ServiceUsingSecretView>,
}

#[derive(Serialize)]
struct PutSecretResponse {
    name: String,
    version: i32,
}

#[derive(Serialize)]
struct RevealResponse {
    version: i32,
    value: String,
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

    overslash_metrics::secrets::record_op("write", "ok");
    Ok(Json(PutSecretResponse {
        name: secret.name,
        version: secret.current_version,
    }))
}

/// Resolve the human-user behind a session, used for visibility filtering.
/// Prefers the JWT's `user_id` claim (set on multi-org sessions). Falls back
/// to walking the session identity to its ceiling user — covers both
/// pre-multi-org sessions and any test/programmatic flow that mints a
/// session JWT for an agent identity.
async fn caller_user_id(scope: &OrgScope, session: &SessionAuth) -> Result<uuid::Uuid> {
    if let Some(uid) = session.user_id {
        return Ok(uid);
    }
    crate::services::group_ceiling::resolve_ceiling_user_id(scope, session.identity_id).await
}

async fn is_admin(scope: &OrgScope, identity_id: uuid::Uuid) -> Result<bool> {
    use overslash_core::permissions::AccessLevel;

    // Fast path matching `OrgAcl::from_request_parts`: the `is_org_admin`
    // flag is the canonical signal for admin status on user identities and
    // is kept in sync with Admins-group membership. Skipping this check
    // would return a non-admin view to a flag-only admin (e.g. the org
    // creator before any group grants are wired up).
    if let Some(ident) = scope.get_identity(identity_id).await?
        && ident.is_org_admin
    {
        return Ok(true);
    }

    let ceiling_user_id =
        crate::services::group_ceiling::resolve_ceiling_user_id(scope, identity_id).await?;
    let ceiling = scope.get_ceiling_for_user(ceiling_user_id).await?;
    let level = ceiling
        .grants
        .iter()
        .filter(|g| g.template_key == "overslash")
        .filter_map(|g| AccessLevel::parse(&g.access_level))
        .max()
        .unwrap_or(AccessLevel::Read);
    Ok(level >= AccessLevel::Admin)
}

async fn build_secret_meta(
    scope: &OrgScope,
    row: overslash_db::repos::secret::SecretRow,
) -> Result<SecretMetadata> {
    let owner = scope.secret_owner_identity(&row.name).await?;
    Ok(SecretMetadata {
        name: row.name,
        current_version: row.current_version,
        owner_identity_id: owner,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

async fn get_secret(
    // Dashboard-only: secret metadata is never exposed to API keys.
    // `SessionAuth` rejects bearer tokens; `OrgScope` enforces org_id at
    // the SQL boundary.
    session: SessionAuth,
    scope: OrgScope,
    Path(name): Path<String>,
) -> Result<Json<SecretDetail>> {
    debug_assert_eq!(session.org_id, scope.org_id());
    let secret = scope
        .get_secret_by_name(&name)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("secret '{name}' not found")))?;

    if !is_admin(&scope, session.identity_id).await? {
        let caller = caller_user_id(&scope, &session).await?;
        if !scope.secret_visible_to_user(&name, caller).await? {
            // Same shape as the not-found above to avoid leaking the
            // existence of an out-of-subtree secret name.
            return Err(AppError::NotFound(format!("secret '{name}' not found")));
        }
    }

    let versions = scope.list_secret_versions(&name).await?;
    let used_by = scope.list_services_using_secret(&name).await?;
    let meta = build_secret_meta(&scope, secret).await?;

    Ok(Json(SecretDetail {
        meta,
        versions: versions
            .into_iter()
            .map(|v| SecretVersionView {
                version: v.version,
                created_at: v.created_at,
                created_by: v.created_by,
                provisioned_by_user_id: v.provisioned_by_user_id,
            })
            .collect(),
        used_by: used_by
            .into_iter()
            .map(|s| ServiceUsingSecretView {
                id: s.id,
                name: s.name,
                status: s.status,
            })
            .collect(),
    }))
}

async fn list_secrets(
    // Dashboard-only — see `get_secret`.
    session: SessionAuth,
    scope: OrgScope,
) -> Result<Json<Vec<SecretMetadata>>> {
    debug_assert_eq!(session.org_id, scope.org_id());

    let rows = if is_admin(&scope, session.identity_id).await? {
        scope.list_secrets().await?
    } else {
        let caller = caller_user_id(&scope, &session).await?;
        scope.list_secrets_visible_to_user(caller).await?
    };

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(build_secret_meta(&scope, row).await?);
    }
    Ok(Json(out))
}

async fn reveal_version(
    State(state): State<AppState>,
    session: SessionAuth,
    scope: OrgScope,
    ip: ClientIp,
    Path((name, version)): Path<(String, i32)>,
) -> Result<Json<RevealResponse>> {
    debug_assert_eq!(session.org_id, scope.org_id());

    if !is_admin(&scope, session.identity_id).await? {
        let caller = caller_user_id(&scope, &session).await?;
        if !scope.secret_visible_to_user(&name, caller).await? {
            return Err(AppError::NotFound(format!("secret '{name}' not found")));
        }
    }

    let row = scope
        .get_secret_value_at_version(&name, version)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!("secret '{name}' version {version} not found"))
        })?;

    let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)?;
    let plaintext = crypto::decrypt(&enc_key, &row.encrypted_value)?;
    let value = String::from_utf8(plaintext)
        .map_err(|_| AppError::Internal("decrypted secret was not valid UTF-8".into()))?;

    let _ = OrgScope::new(session.org_id, state.db.clone())
        .log_audit(AuditEntry {
            org_id: session.org_id,
            identity_id: Some(session.identity_id),
            action: "secret.revealed",
            resource_type: Some("secret"),
            resource_id: None,
            detail: serde_json::json!({ "name": &name, "version": version }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    overslash_metrics::secrets::record_op("reveal", "ok");
    Ok(Json(RevealResponse { version, value }))
}

async fn restore_version(
    State(state): State<AppState>,
    WriteAcl(acl): WriteAcl,
    session: SessionAuth,
    scope: OrgScope,
    ip: ClientIp,
    Path((name, version)): Path<(String, i32)>,
) -> Result<Json<PutSecretResponse>> {
    debug_assert_eq!(session.org_id, scope.org_id());
    let auth = acl;

    if !is_admin(&scope, session.identity_id).await? {
        let caller = caller_user_id(&scope, &session).await?;
        if !scope.secret_visible_to_user(&name, caller).await? {
            return Err(AppError::NotFound(format!("secret '{name}' not found")));
        }
    }

    let row = scope
        .get_secret_value_at_version(&name, version)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!("secret '{name}' version {version} not found"))
        })?;

    // Re-use the existing put path so the new version row inherits all the
    // standard book-keeping (next version number, created_by, audit). We
    // attribute restoration to the caller — the original creator is still
    // visible in the version list.
    let (secret, new_version) = scope
        .put_secret(&name, &row.encrypted_value, auth.identity_id, None)
        .await?;

    let _ = OrgScope::new(auth.org_id, state.db.clone())
        .log_audit(AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "secret.restored",
            resource_type: Some("secret"),
            resource_id: None,
            detail: serde_json::json!({
                "name": &name,
                "from_version": version,
                "new_version": new_version.version,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    overslash_metrics::secrets::record_op("restore", "ok");
    Ok(Json(PutSecretResponse {
        name: secret.name,
        version: secret.current_version,
    }))
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
    overslash_metrics::secrets::record_op("delete", if deleted { "ok" } else { "not_found" });
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
