use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::post,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::repos::audit::{self, AuditEntry};

use crate::{
    AppState,
    error::Result,
    extractors::{AuthContext, ClientIp},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/api-keys", post(create_api_key).get(list_api_keys))
        .route("/v1/api-keys/{id}", axum::routing::delete(revoke_api_key))
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

#[derive(Serialize)]
struct ApiKeyResponse {
    id: Uuid,
    name: String,
    key_prefix: String,
    identity_id: Option<Uuid>,
    last_used_at: Option<String>,
    created_at: String,
}

#[derive(Deserialize)]
struct ListApiKeysQuery {
    identity_id: Option<Uuid>,
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

async fn list_api_keys(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(query): Query<ListApiKeysQuery>,
) -> Result<Json<Vec<ApiKeyResponse>>> {
    let rows = overslash_db::repos::api_key::list_by_org(&state.db, auth.org_id).await?;
    let filtered: Vec<ApiKeyResponse> = rows
        .into_iter()
        .filter(|r| match query.identity_id {
            Some(iid) => r.identity_id == Some(iid),
            None => true,
        })
        .map(|r| ApiKeyResponse {
            id: r.id,
            name: r.name,
            key_prefix: r.key_prefix,
            identity_id: r.identity_id,
            last_used_at: r.last_used_at.map(|t| {
                t.format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default()
            }),
            created_at: r
                .created_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        })
        .collect();
    Ok(Json(filtered))
}

async fn revoke_api_key(
    State(state): State<AppState>,
    auth: AuthContext,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    // Verify the key belongs to this org by listing and checking
    let rows = overslash_db::repos::api_key::list_by_org(&state.db, auth.org_id).await?;
    if !rows.iter().any(|r| r.id == id) {
        return Err(crate::error::AppError::NotFound("api key not found".into()));
    }

    overslash_db::repos::api_key::revoke(&state.db, id).await?;

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "api_key.revoked",
            resource_type: Some("api_key"),
            resource_id: Some(id),
            detail: serde_json::json!({}),
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
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
