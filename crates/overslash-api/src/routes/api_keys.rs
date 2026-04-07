use axum::{Json, Router, extract::State, routing::get};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use overslash_db::repos::audit::{self, AuditEntry};

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
    identity_id: Option<Uuid>,
    name: String,
    key_prefix: String,
    created_at: OffsetDateTime,
    last_used_at: Option<OffsetDateTime>,
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

async fn list_api_keys(
    State(state): State<AppState>,
    OrgAcl { org_id, .. }: OrgAcl,
) -> Result<Json<Vec<ApiKeySummary>>> {
    let rows = overslash_db::repos::api_key::list_by_org(&state.db, org_id).await?;
    Ok(Json(rows.into_iter().map(ApiKeySummary::from).collect()))
}

#[derive(Deserialize)]
struct CreateApiKeyRequest {
    org_id: Uuid,
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
/// Exception: if no API keys exist for the org yet (bootstrap), allows unauthenticated creation.
async fn create_api_key(
    State(state): State<AppState>,
    OptionalOrgAcl(acl): OptionalOrgAcl,
    ip: ClientIp,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<Json<CreateApiKeyResponse>> {
    match acl {
        Some(acl) if acl.access_level >= AccessLevel::Admin => {} // authorized
        Some(_) => return Err(AppError::Forbidden("admin access required".into())),
        None => {
            // No auth provided — allow only as a true bootstrap: no existing keys
            // AND no existing identities for this org. Once any identity is created
            // (e.g., via OAuth signup), the bootstrap window is closed and all
            // future key creation must be authenticated.
            let key_count =
                overslash_db::repos::api_key::count_by_org(&state.db, req.org_id).await?;
            let identity_count =
                overslash_db::repos::identity::count_by_org(&state.db, req.org_id).await?;
            if key_count > 0 || identity_count > 0 {
                return Err(AppError::Unauthorized(
                    "missing authorization header".into(),
                ));
            }
            // Also reject identity-bound bootstrap keys — bootstrap is org-level only.
            if req.identity_id.is_some() {
                return Err(AppError::Unauthorized(
                    "missing authorization header".into(),
                ));
            }
        }
    }

    let (raw_key, key_hash, key_prefix) = generate_api_key()?;

    let row = overslash_db::repos::api_key::create(
        &state.db,
        req.org_id,
        req.identity_id,
        &req.name,
        &key_hash,
        &key_prefix,
        &[],
    )
    .await?;

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: req.org_id,
            identity_id: None,
            action: "api_key.created",
            resource_type: Some("api_key"),
            resource_id: Some(row.id),
            detail: serde_json::json!({ "name": &row.name, "key_prefix": &key_prefix }),
            description: None,
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(CreateApiKeyResponse {
        id: row.id,
        key: raw_key,
        key_prefix,
        name: row.name,
    }))
}

fn generate_api_key() -> std::result::Result<(String, String, String), crate::error::AppError> {
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
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
