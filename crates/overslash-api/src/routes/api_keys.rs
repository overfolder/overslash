use axum::{Json, Router, routing::get};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use overslash_db::OrgScope;
use overslash_db::repos::audit::AuditEntry;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, ClientIp, OrgAcl},
};

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/api-keys", get(list_api_keys).post(create_api_key))
}

#[derive(Serialize)]
struct ApiKeySummary {
    id: Uuid,
    identity_id: Uuid,
    name: String,
    key_prefix: String,
    scopes: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    last_used_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    revoked_at: Option<OffsetDateTime>,
}

impl From<overslash_db::repos::api_key::ApiKeyRow> for ApiKeySummary {
    fn from(r: overslash_db::repos::api_key::ApiKeyRow) -> Self {
        Self {
            id: r.id,
            identity_id: r.identity_id,
            name: r.name,
            key_prefix: r.key_prefix,
            scopes: r.scopes,
            created_at: r.created_at,
            last_used_at: r.last_used_at,
            revoked_at: r.revoked_at,
        }
    }
}

async fn list_api_keys(_: OrgAcl, scope: OrgScope) -> Result<Json<Vec<ApiKeySummary>>> {
    let rows = scope.list_api_keys().await?;
    Ok(Json(rows.into_iter().map(ApiKeySummary::from).collect()))
}

#[derive(Deserialize)]
struct CreateApiKeyRequest {
    /// The identity the key binds to. Every API key is bound to a User or
    /// Agent — the "org-level" key (identity_id = null) was removed in
    /// migration 028. Omitted means the caller's own identity.
    ///
    /// Must name an identity in the caller's own org: it is resolved through
    /// the caller's `OrgScope`, so an id from another tenant does not exist.
    identity_id: Option<Uuid>,
    name: String,
    /// Optional list of capability scopes for this key. The `"impersonate"`
    /// scope enables `X-Overslash-As` header usage.
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Serialize)]
struct CreateApiKeyResponse {
    id: Uuid,
    identity_id: Uuid,
    key: String,
    key_prefix: String,
    name: String,
    scopes: Vec<String>,
}

/// Create an API key. Requires admin-level ACL access.
///
/// The org is never named by the caller: `OrgScope` is minted from the
/// presented credential — a session JWT's currently *active* org, which
/// `/auth/switch-org` re-mints, or an `osk_` key's own org. That distinction
/// matters because a human can belong to several orgs: deriving from the
/// *user* would let an org-A session write into org B on the grounds that the
/// user is a member there. A multi-org human mints into B by being switched
/// to B, and by nothing else.
///
/// There is no unauthenticated branch. An org's first admin key is minted by
/// `POST /v1/orgs` itself and returned once in that response — see
/// `routes/orgs/create.rs::provision_new_org_contents`.
async fn create_api_key(
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<Json<CreateApiKeyResponse>> {
    let identity_id = req
        .identity_id
        .or(acl.identity_id)
        .ok_or_else(|| AppError::BadRequest("identity_id is required".into()))?;

    // Resolved *through the scope*, so the org bound is a WHERE clause on the
    // lookup rather than a comparison a later edit can quietly drop. An id
    // from another tenant is indistinguishable from one that does not exist.
    if scope.get_identity(identity_id).await?.is_none() {
        return Err(AppError::NotFound("identity not found".into()));
    }

    let (raw_key, key_hash, key_prefix) = generate_api_key()?;

    let row = scope
        .create_api_key(identity_id, &req.name, &key_hash, &key_prefix, &req.scopes)
        .await?;

    let _ = scope
        .log_audit(AuditEntry {
            org_id: acl.org_id,
            identity_id: Some(identity_id),
            action: "api_key.created",
            resource_type: Some("api_key"),
            resource_id: Some(row.id),
            detail: serde_json::json!({
                "name": &row.name,
                "key_prefix": &key_prefix,
                "scopes": &row.scopes,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(CreateApiKeyResponse {
        id: row.id,
        identity_id,
        key: raw_key,
        key_prefix,
        name: row.name,
        scopes: row.scopes,
    }))
}

pub(crate) fn generate_api_key()
-> std::result::Result<(String, String, String), crate::error::AppError> {
    use rand::RngExt;

    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    let encoded = hex::encode(bytes);
    let raw_key = format!("osk_{encoded}");
    let key_prefix = raw_key[..12].to_string();

    // argon2 0.6 generates the salt itself (16 random bytes, the PHC
    // recommended length) — the caller no longer threads one in.
    let hash =
        argon2::PasswordHasher::hash_password(&argon2::Argon2::default(), raw_key.as_bytes())
            .map_err(|e| crate::error::AppError::Internal(format!("hash error: {e}")))?
            .to_string();

    Ok((raw_key, hash, key_prefix))
}
