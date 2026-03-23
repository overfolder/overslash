use axum::{Json, Router, extract::State, routing::post};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{AppState, error::Result};

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/api-keys", post(create_api_key))
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
