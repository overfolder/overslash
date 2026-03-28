use axum::{Json, Router, extract::State, routing::get};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::repos::audit::{self, AuditEntry};

use crate::{
    AppState,
    error::Result,
    extractors::{AuthContext, ClientIp},
};

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/api-keys", get(list_api_keys).post(create_api_key))
}

#[derive(Serialize)]
struct ApiKeyListItem {
    id: Uuid,
    name: String,
    key_prefix: String,
    identity_id: Option<Uuid>,
    last_used_at: Option<String>,
    created_at: String,
}

async fn list_api_keys(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<Vec<ApiKeyListItem>>> {
    let rows = overslash_db::repos::api_key::list_by_org(&state.db, auth.org_id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| ApiKeyListItem {
                id: r.id,
                name: r.name,
                key_prefix: r.key_prefix,
                identity_id: r.identity_id,
                last_used_at: r.last_used_at.map(|t| t.to_string()),
                created_at: r.created_at.to_string(),
            })
            .collect(),
    ))
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

async fn create_api_key(
    State(state): State<AppState>,
    ip: ClientIp,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<Json<CreateApiKeyResponse>> {
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
