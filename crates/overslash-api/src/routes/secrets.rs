use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use overslash_core::types::SecretNamespace;
use overslash_db::repos::audit::AuditEntry;
use overslash_db::scopes::OrgScope;
use uuid::Uuid;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, AuthContext, ClientIp, ReqExt, SessionAuth, WriteAcl},
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
    /// owner is this user. The secret lands in the caller's user vault either
    /// way (an agent's vault *is* its owner's), so this only changes
    /// `created_by` attribution.
    #[serde(default)]
    on_behalf_of: Option<uuid::Uuid>,
}

/// Which vault a `/v1/secrets/{name}` request addresses. Secret names are
/// unique per vault, not per org, so a name alone is not an address.
///
/// * neither set — the caller's own user vault (an agent's is its owner's)
/// * `owner=<user identity id>` — that user's vault; admin-only unless it is
///   the caller's own
/// * `scope=org` — the org-wide vault; admin-only
#[derive(Deserialize, Default)]
struct NamespaceQuery {
    #[serde(default)]
    owner: Option<Uuid>,
    #[serde(default)]
    scope: Option<String>,
}

/// The caller's own vault: its ceiling user's.
async fn own_namespace(scope: &OrgScope, identity_id: Uuid) -> Result<SecretNamespace> {
    Ok(SecretNamespace::User(
        crate::services::group_ceiling::resolve_ceiling_user_id(scope, identity_id).await?,
    ))
}

/// Resolve the `?owner=` / `?scope=` selector against the caller. `Ok(None)`
/// means "out of reach": callers answer 404 so a vault's contents are not
/// probeable by non-admins.
async fn select_namespace(
    scope: &OrgScope,
    identity_id: Uuid,
    q: &NamespaceQuery,
) -> Result<Option<SecretNamespace>> {
    let own = own_namespace(scope, identity_id).await?;
    let wanted = match (q.scope.as_deref(), q.owner) {
        (Some("org"), None) => SecretNamespace::Org,
        (Some("user") | None, None) => return Ok(Some(own)),
        (Some("user") | None, Some(owner)) => SecretNamespace::User(owner),
        (Some(other), _) => {
            return Err(AppError::BadRequest(format!(
                "invalid scope `{other}`: expected `user` or `org`, and `owner` only with `user`"
            )));
        }
    };
    if wanted == own {
        return Ok(Some(own));
    }
    if !is_admin(scope, identity_id).await? {
        return Ok(None);
    }
    if let SecretNamespace::User(owner) = wanted {
        match scope.get_identity(owner).await? {
            Some(i) if i.kind == "user" => {}
            _ => return Ok(None),
        }
    }
    Ok(Some(wanted))
}

fn not_found(name: &str) -> AppError {
    AppError::NotFound(format!("secret '{name}' not found"))
}

/// Dashboard-shaped metadata. Returned to user-kind callers (session auth
/// or, in principle, a user-bound API key). Includes the vault owner so
/// the dashboard can render an "Owner" column.
#[derive(Serialize)]
struct SecretMetadata {
    name: String,
    current_version: i32,
    /// The vault: the owning user identity, `None` for the org vault.
    owner_identity_id: Option<uuid::Uuid>,
    /// `user` or `org`.
    scope: &'static str,
    /// Canonical secret path — what a service binding stores.
    path: String,
    /// The vault owner's name / email, for display. `None` for the org vault.
    owner_name: Option<String>,
    owner_email: Option<String>,
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

#[allow(clippy::too_many_arguments)]
async fn put_secret(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(name): Path<String>,
    Query(q): Query<NamespaceQuery>,
    Json(req): Json<PutSecretRequest>,
) -> Result<Json<PutSecretResponse>> {
    let auth = acl;
    crate::services::secret_paths::validate_new_secret_name(&name)?;
    let caller_id = auth.identity_id.ok_or_else(|| {
        AppError::Unauthorized("identity-bound auth required to write secrets".into())
    })?;

    // `on_behalf_of` is validated (target == caller's owner) and names the
    // version's `created_by`; the vault is the selector's — by default the
    // caller's own, which for an agent is already its owner's.
    let created_by = crate::services::group_ceiling::resolve_owner_identity(
        &scope,
        auth.identity_id,
        req.on_behalf_of,
    )
    .await?;
    let ns = select_namespace(&scope, caller_id, &q)
        .await?
        .ok_or_else(|| AppError::Forbidden("only org admins may write another vault".into()))?;

    let enc_key = state.config.keyring()?;
    let encrypted = crypto::encrypt(&enc_key, req.value.as_bytes())?;
    // No distinct "provisioning user" — that's only set by the standalone
    // secret-provide page flow.
    let (secret, _version) = scope
        .put_secret(&ns.path(&*name), &encrypted, created_by, None)
        .await?;

    let _ = OrgScope::new(auth.org_id, state.db_pool(&ext))
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
                "path": ns.path(&*secret.name).to_canonical(),
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

/// `owners` maps vault-owner identity ids to their (name, email).
fn build_secret_meta(
    row: overslash_db::repos::secret::SecretRow,
    owners: &std::collections::HashMap<Uuid, (String, Option<String>)>,
) -> SecretMetadata {
    let ns = SecretNamespace::from_owner(row.owner_identity_id);
    let owner = row.owner_identity_id.and_then(|id| owners.get(&id));
    SecretMetadata {
        path: ns.path(&*row.name).to_canonical(),
        scope: match ns {
            SecretNamespace::User(_) => "user",
            SecretNamespace::Org => "org",
        },
        owner_name: owner.map(|(n, _)| n.clone()),
        owner_email: owner.and_then(|(_, e)| e.clone()),
        name: row.name,
        current_version: row.current_version,
        owner_identity_id: row.owner_identity_id,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

/// Name/email of every identity owning one of `rows`, in one query.
async fn owner_index(
    scope: &OrgScope,
    rows: &[overslash_db::repos::secret::SecretRow],
) -> Result<std::collections::HashMap<Uuid, (String, Option<String>)>> {
    if rows.iter().all(|r| r.owner_identity_id.is_none()) {
        return Ok(Default::default());
    }
    Ok(scope
        .list_identities()
        .await?
        .into_iter()
        .map(|i| (i.id, (i.name, i.email)))
        .collect())
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
    Query(q): Query<NamespaceQuery>,
) -> Result<Json<SecretDetail>> {
    debug_assert_eq!(session.org_id, scope.org_id());
    // An out-of-reach vault answers exactly like a missing name.
    let path = select_namespace(&scope, session.identity_id, &q)
        .await?
        .ok_or_else(|| not_found(&name))?
        .path(&*name);
    let secret = scope
        .get_secret(&path)
        .await?
        .ok_or_else(|| not_found(&name))?;

    let versions = scope.list_secret_versions(&path).await?;
    let used_by = scope.list_services_using_secret(&path).await?;
    let owners = owner_index(&scope, std::slice::from_ref(&secret)).await?;
    let meta = build_secret_meta(secret, &owners);

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
    // A caller sees its own user vault (an agent's is its owner's); admins
    // see every vault, or one when a selector names it.
    auth: AuthContext,
    scope: OrgScope,
    Query(q): Query<NamespaceQuery>,
) -> Result<Json<SecretListResponse>> {
    debug_assert_eq!(auth.org_id, scope.org_id());

    let identity_id = auth.identity_id.ok_or_else(|| {
        AppError::Unauthorized("identity-bound auth required for /v1/secrets".into())
    })?;

    let selected = q.owner.is_some() || q.scope.is_some();
    let rows = if !selected && is_admin(&scope, identity_id).await? {
        scope.list_secrets().await?
    } else {
        match select_namespace(&scope, identity_id, &q).await? {
            Some(ns) => scope.list_secrets_in(ns).await?,
            None => Vec::new(),
        }
    };

    // Branch on the calling identity's kind: user-kind (or admin via flag)
    // gets the dashboard shape; agent/sub_agent gets the narrow shape.
    let identity = scope
        .get_identity(identity_id)
        .await?
        .ok_or_else(|| AppError::Unauthorized("calling identity no longer exists".into()))?;

    let response = if identity.kind == "user" {
        let owners = owner_index(&scope, &rows).await?;
        SecretListResponse::Dashboard(
            rows.into_iter()
                .map(|r| build_secret_meta(r, &owners))
                .collect(),
        )
    } else {
        SecretListResponse::BearerNarrow(rows.into_iter().map(build_secret_name_row).collect())
    };

    Ok(Json(response))
}

async fn reveal_version(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    session: SessionAuth,
    scope: OrgScope,
    ip: ClientIp,
    Path((name, version)): Path<(String, i32)>,
    Query(q): Query<NamespaceQuery>,
) -> Result<Json<RevealResponse>> {
    debug_assert_eq!(session.org_id, scope.org_id());

    let path = select_namespace(&scope, session.identity_id, &q)
        .await?
        .ok_or_else(|| not_found(&name))?
        .path(&*name);

    let row = scope
        .get_secret_value_at_version(&path, version)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!("secret '{name}' version {version} not found"))
        })?;

    let enc_key = state.config.keyring()?;
    let plaintext = crypto::decrypt(&enc_key, &row.encrypted_value)?;
    let value = String::from_utf8(plaintext)
        .map_err(|_| AppError::Internal("decrypted secret was not valid UTF-8".into()))?;

    let _ = OrgScope::new(session.org_id, state.db_pool(&ext))
        .log_audit(AuditEntry {
            org_id: session.org_id,
            identity_id: Some(session.identity_id),
            action: "secret.revealed",
            resource_type: Some("secret"),
            resource_id: None,
            detail: serde_json::json!({
                "name": &name,
                "path": path.to_canonical(),
                "version": version,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    overslash_metrics::secrets::record_op("reveal", "ok");
    Ok(Json(RevealResponse { version, value }))
}

#[allow(clippy::too_many_arguments)]
async fn restore_version(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    session: SessionAuth,
    scope: OrgScope,
    ip: ClientIp,
    Path((name, version)): Path<(String, i32)>,
    Query(q): Query<NamespaceQuery>,
) -> Result<Json<PutSecretResponse>> {
    debug_assert_eq!(session.org_id, scope.org_id());
    let auth = acl;

    let path = select_namespace(&scope, session.identity_id, &q)
        .await?
        .ok_or_else(|| not_found(&name))?
        .path(&*name);

    let row = scope
        .get_secret_value_at_version(&path, version)
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!("secret '{name}' version {version} not found"))
        })?;

    // Re-use the existing put path so the new version row inherits all the
    // standard book-keeping (next version number, created_by, audit). We
    // attribute restoration to the caller — the original creator is still
    // visible in the version list. The vault is the one the version came from.
    let (secret, new_version) = scope
        .put_secret(&path, &row.encrypted_value, auth.identity_id, None)
        .await?;

    let _ = OrgScope::new(auth.org_id, state.db_pool(&ext))
        .log_audit(AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "secret.restored",
            resource_type: Some("secret"),
            resource_id: None,
            detail: serde_json::json!({
                "name": &name,
                "path": path.to_canonical(),
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
    ReqExt(ext): ReqExt,
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(name): Path<String>,
    Query(q): Query<NamespaceQuery>,
) -> Result<Json<serde_json::Value>> {
    let auth = acl;
    let caller_id = auth.identity_id.ok_or_else(|| {
        AppError::Unauthorized("identity-bound auth required to delete secrets".into())
    })?;
    let Some(ns) = select_namespace(&scope, caller_id, &q).await? else {
        return Err(not_found(&name));
    };
    let path = ns.path(&*name);
    let deleted = scope.soft_delete_secret(&path).await?;
    overslash_metrics::secrets::record_op("delete", if deleted { "ok" } else { "not_found" });
    if deleted {
        let _ = OrgScope::new(auth.org_id, state.db_pool(&ext))
            .log_audit(AuditEntry {
                org_id: auth.org_id,
                identity_id: auth.identity_id,
                action: "secret.deleted",
                resource_type: Some("secret"),
                resource_id: None,
                detail: serde_json::json!({ "name": &name, "path": path.to_canonical() }),
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
