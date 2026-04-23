use axum::{Json, Router, extract::State, routing::get};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use overslash_db::OrgScope;
use overslash_db::repos::audit::AuditEntry;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{ClientIp, OptionalOrgAcl, OrgAcl},
};
use overslash_core::permissions::AccessLevel;

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/api-keys", get(list_api_keys).post(create_api_key))
}

#[derive(Serialize)]
struct ApiKeySummary {
    id: Uuid,
    identity_id: Uuid,
    name: String,
    key_prefix: String,
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
    org_id: Uuid,
    /// Required: every API key is bound to a User or Agent identity. The
    /// previously-supported "org-level" key (identity_id = null) was removed
    /// in migration 028.
    ///
    /// Exception: in the unauthenticated bootstrap path (no auth header, no
    /// existing keys, no existing users), this field may be omitted — the
    /// server will mint a fresh admin User and bind the key to it.
    identity_id: Option<Uuid>,
    name: String,
}

#[derive(Serialize)]
struct CreateApiKeyResponse {
    id: Uuid,
    key: String,
    key_prefix: String,
    name: String,
}

/// Create an API key. Requires admin-level ACL access.
///
/// Exception: if neither an API key nor an identity exists for the org yet
/// (true bootstrap), allows unauthenticated creation. In that path the server
/// also mints the first admin User and binds the key to it — there is no such
/// thing as a naked "org-level" key.
async fn create_api_key(
    State(state): State<AppState>,
    OptionalOrgAcl(acl): OptionalOrgAcl,
    ip: ClientIp,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<Json<CreateApiKeyResponse>> {
    let create_scope = OrgScope::new(req.org_id, state.db.clone());

    // Resolve which identity the new key will be bound to.
    let identity_id: Uuid = match acl {
        Some(acl) if acl.access_level >= AccessLevel::Admin => {
            // Authenticated admin path. If identity_id is omitted, default to
            // the caller's own identity (the natural "mint a key for myself"
            // case from the dashboard); otherwise honour the request.
            req.identity_id
                .or(acl.identity_id)
                .ok_or_else(|| AppError::BadRequest("identity_id is required".into()))?
        }
        Some(_) => return Err(AppError::Forbidden("admin access required".into())),
        None => {
            // True bootstrap: no auth, no existing keys, no existing identities.
            let key_count = create_scope.count_api_keys().await?;
            let identity_count = create_scope.count_identities().await?;
            if key_count > 0 || identity_count > 0 {
                return Err(AppError::Unauthorized(
                    "missing authorization header".into(),
                ));
            }
            if req.identity_id.is_some() {
                // Bootstrap mints its own admin user; caller must not pre-pick one.
                return Err(AppError::BadRequest(
                    "identity_id must be omitted in the bootstrap path".into(),
                ));
            }
            // Mint the first admin user and add it to Everyone + Admins groups
            // via the existing org bootstrap helper.
            let admin_user = create_scope.create_identity("admin", "user", None).await?;
            overslash_db::repos::identity::set_is_org_admin(
                &state.db,
                req.org_id,
                admin_user.id,
                true,
            )
            .await?;
            overslash_db::repos::org_bootstrap::bootstrap_org(
                &state.db,
                req.org_id,
                Some(admin_user.id),
            )
            .await?;
            admin_user.id
        }
    };

    let (raw_key, key_hash, key_prefix) = generate_api_key()?;

    let row = create_scope
        .create_api_key(identity_id, &req.name, &key_hash, &key_prefix, &[])
        .await?;

    let _ = create_scope
        .log_audit(AuditEntry {
            org_id: req.org_id,
            identity_id: Some(identity_id),
            action: "api_key.created",
            resource_type: Some("api_key"),
            resource_id: Some(row.id),
            detail: serde_json::json!({ "name": &row.name, "key_prefix": &key_prefix }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(CreateApiKeyResponse {
        id: row.id,
        key: raw_key,
        key_prefix,
        name: row.name,
    }))
}

fn generate_api_key() -> std::result::Result<(String, String, String), crate::error::AppError> {
    use rand::RngExt;

    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    let encoded = hex::encode(bytes);
    let raw_key = format!("osk_{encoded}");
    let key_prefix = raw_key[..12].to_string();

    let salt =
        argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let hash = argon2::PasswordHasher::hash_password(
        &argon2::Argon2::default(),
        raw_key.as_bytes(),
        &salt,
    )
    .map_err(|e| crate::error::AppError::Internal(format!("hash error: {e}")))?
    .to_string();

    Ok((raw_key, hash, key_prefix))
}
