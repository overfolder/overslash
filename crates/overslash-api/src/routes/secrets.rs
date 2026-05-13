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
    extractors::{AdminAcl, AuthContext, ClientIp, SessionAuth, WriteAcl},
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

/// Dashboard-shaped metadata. Returned to user-kind callers (session auth
/// or, in principle, a user-bound API key). Includes the slot owner so
/// the dashboard can render an "Owner" column.
#[derive(Serialize)]
struct SecretMetadata {
    name: String,
    current_version: i32,
    /// Identity that owns the slot (`secrets.owner_identity_id`). `None` for
    /// legacy/org-wide rows (admin-only). Set on first insert and preserved
    /// across subsequent versions.
    owner_identity_id: Option<uuid::Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

/// Narrow shape for agent/sub-agent callers (bearer auth). Deliberately
/// excludes value, ciphertext, owner identity, and timestamps other than
/// last-rotation — agents shouldn't need to inventory metadata they
/// already know about themselves.
#[derive(Serialize)]
struct SecretNameRow {
    name: String,
    /// Number of versions of the slot. Equal to `secrets.current_version`
    /// (which is incremented on each new write).
    version_count: i32,
    /// `secrets.updated_at`. Bumps on every new version write and on
    /// soft-restore — consistent with `SecretMetadata.updated_at`.
    #[serde(with = "time::serde::rfc3339")]
    last_rotated_at: OffsetDateTime,
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
    let enc_key = state.config.keyring()?;
    let encrypted = crypto::encrypt(&enc_key, req.value.as_bytes())?;

    let owner = crate::services::group_ceiling::resolve_owner_identity(
        &scope,
        auth.identity_id,
        req.on_behalf_of,
    )
    .await?;

    // If the slot already exists, the resolved owner must match it
    // exactly (admins exempt). Otherwise the COALESCE in repo `put`
    // would silently let an agent rotate someone else's secret — the
    // original owner stays put, but the value flips. Strict match
    // forces explicit `on_behalf_of` for shared rotation: an agent
    // wanting to rotate a parent-user-owned slot must declare
    // `on_behalf_of: <user_id>`. Mirror the read-path 404 so an
    // out-of-reach slot's existence isn't leaked.
    let caller_id = auth.identity_id.ok_or_else(|| {
        AppError::Unauthorized("identity-bound auth required to write secrets".into())
    })?;
    if let Some(existing) = scope.get_secret_by_name(&name).await?
        && !is_admin(&scope, caller_id).await?
        && existing.owner_identity_id != owner
    {
        return Err(AppError::NotFound(format!("secret '{name}' not found")));
    }

    // API-driven writes: the resolved identity is both the version's
    // `created_by` (audit attribution) and the slot's `owner_identity_id`
    // (visibility key). The slot's owner is fixed by the first writer;
    // the COALESCE in repo `put` preserves it on subsequent versions.
    // No distinct "provisioning user" — that's only set by the standalone
    // secret-provide page flow.
    let (secret, _version) = scope
        .put_secret(&name, &encrypted, owner, owner, None)
        .await?;

    let _ = OrgScope::new(auth.org_id, state.db.clone())
        .log_audit(AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "secret.put",
            resource_type: Some("secret"),
            resource_id: None,
            detail: serde_json::json!({
                "name": &secret.name,
                "version": secret.current_version,
                "owner_identity_id": secret.owner_identity_id,
            }),
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

fn build_secret_meta(row: overslash_db::repos::secret::SecretRow) -> SecretMetadata {
    SecretMetadata {
        name: row.name,
        current_version: row.current_version,
        owner_identity_id: row.owner_identity_id,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

fn build_secret_name_row(row: overslash_db::repos::secret::SecretRow) -> SecretNameRow {
    SecretNameRow {
        name: row.name,
        version_count: row.current_version,
        last_rotated_at: row.updated_at,
    }
}

async fn get_secret(
    // Dashboard-only: secret detail (version list + provisioning users)
    // is never exposed to bearer-mode callers. `SessionAuth` rejects
    // bearer tokens; agents use the bearer list endpoint.
    session: SessionAuth,
    scope: OrgScope,
    Path(name): Path<String>,
) -> Result<Json<SecretDetail>> {
    debug_assert_eq!(session.org_id, scope.org_id());
    let secret = scope
        .get_secret_by_name(&name)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("secret '{name}' not found")))?;

    if !is_admin(&scope, session.identity_id).await?
        && !scope
            .secret_visible_to_identity(&name, session.identity_id)
            .await?
    {
        // Same shape as the not-found above to avoid leaking the
        // existence of an out-of-subtree secret name.
        return Err(AppError::NotFound(format!("secret '{name}' not found")));
    }

    let versions = scope.list_secret_versions(&name).await?;
    let used_by = scope.list_services_using_secret(&name).await?;
    let meta = build_secret_meta(secret);

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

/// Wire envelope for the list response. User-kind callers (dashboard or
/// user-bound API key) see the full `SecretMetadata` shape; agent and
/// sub-agent callers see the narrow `SecretNameRow` shape — no value, no
/// owner identity, no creation timestamp. The structural split is the
/// belt-and-braces guarantee that values can never leak through this path.
#[derive(Serialize)]
#[serde(untagged)]
enum SecretListResponse {
    Dashboard(Vec<SecretMetadata>),
    BearerNarrow(Vec<SecretNameRow>),
}

async fn list_secrets(
    // Accepts session cookie, MCP bearer (aud=mcp), and `osk_` API keys.
    // Visibility is computed against the caller's identity subtree
    // (descendants via `identities.parent_id`); admins see everything.
    auth: AuthContext,
    scope: OrgScope,
) -> Result<Json<SecretListResponse>> {
    debug_assert_eq!(auth.org_id, scope.org_id());

    let identity_id = auth.identity_id.ok_or_else(|| {
        AppError::Unauthorized("identity-bound auth required for /v1/secrets".into())
    })?;

    let rows = if is_admin(&scope, identity_id).await? {
        scope.list_secrets().await?
    } else {
        scope.list_secrets_visible_to_identity(identity_id).await?
    };

    // Branch on the calling identity's kind: user-kind (or admin via flag)
    // gets the dashboard shape; agent/sub_agent gets the narrow shape.
    let identity = scope
        .get_identity(identity_id)
        .await?
        .ok_or_else(|| AppError::Unauthorized("calling identity no longer exists".into()))?;

    let response = if identity.kind == "user" {
        SecretListResponse::Dashboard(rows.into_iter().map(build_secret_meta).collect())
    } else {
        SecretListResponse::BearerNarrow(rows.into_iter().map(build_secret_name_row).collect())
    };

    Ok(Json(response))
}

async fn reveal_version(
    State(state): State<AppState>,
    session: SessionAuth,
    scope: OrgScope,
    ip: ClientIp,
    Path((name, version)): Path<(String, i32)>,
) -> Result<Json<RevealResponse>> {
    debug_assert_eq!(session.org_id, scope.org_id());

    if !is_admin(&scope, session.identity_id).await?
        && !scope
            .secret_visible_to_identity(&name, session.identity_id)
            .await?
    {
        return Err(AppError::NotFound(format!("secret '{name}' not found")));
    }

    let row = scope
        .get_secret_value_at_version(&name, version)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!("secret '{name}' version {version} not found"))
        })?;

    let enc_key = state.config.keyring()?;
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

    if !is_admin(&scope, session.identity_id).await?
        && !scope
            .secret_visible_to_identity(&name, session.identity_id)
            .await?
    {
        return Err(AppError::NotFound(format!("secret '{name}' not found")));
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
    // visible in the version list. `owner_identity_id` is preserved by the
    // repo's COALESCE on conflict; pass `None` here to make that explicit
    // (the slot already exists, so no first-insert branch can run).
    let (secret, new_version) = scope
        .put_secret(&name, &row.encrypted_value, auth.identity_id, None, None)
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

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn secret_name_row_does_not_serialize_any_value_field() {
        // Belt-and-braces: the type system already prevents values from
        // reaching this struct (no value/encrypted_value field exists).
        // Catch any future field rename that accidentally introduces a
        // value-shaped key into the wire format.
        let row = SecretNameRow {
            name: "stripe_key".into(),
            version_count: 3,
            last_rotated_at: datetime!(2026-05-08 12:00 UTC),
        };
        let json = serde_json::to_value(&row).expect("serialize");
        let obj = json.as_object().expect("object");
        for forbidden in [
            "value",
            "encrypted_value",
            "secret",
            "ciphertext",
            "plaintext",
            "encrypted",
        ] {
            assert!(
                !obj.contains_key(forbidden),
                "SecretNameRow leaked field {forbidden:?}: {json}"
            );
        }
        // Positive assertion — the contract this struct is meant to fulfil.
        let mut keys: Vec<&String> = obj.keys().collect();
        keys.sort();
        assert_eq!(keys, vec!["last_rotated_at", "name", "version_count"]);
    }
}
