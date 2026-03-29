use axum::{Json, Router, extract::{Path, State}, routing::post};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use overslash_db::repos::audit::{self, AuditEntry};

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AuthContext, ClientIp},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/identities/{id}/enrollment-token", post(create_enrollment_token))
        .route("/v1/enroll", post(enroll))
}

const DEFAULT_TTL_SECS: i64 = 3600; // 1 hour

#[derive(Deserialize)]
struct CreateEnrollmentTokenRequest {
    ttl_secs: Option<i64>,
}

#[derive(Serialize)]
struct CreateEnrollmentTokenResponse {
    token: String,
    expires_at: String,
}

async fn create_enrollment_token(
    State(state): State<AppState>,
    auth: AuthContext,
    ip: ClientIp,
    Path(identity_id): Path<Uuid>,
    Json(req): Json<CreateEnrollmentTokenRequest>,
) -> Result<Json<CreateEnrollmentTokenResponse>> {
    // Verify the identity exists and belongs to the caller's org
    let identity = overslash_db::repos::identity::get_by_id(&state.db, identity_id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;

    if identity.org_id != auth.org_id {
        return Err(AppError::NotFound("identity not found".into()));
    }

    if identity.kind != "agent" {
        return Err(AppError::BadRequest("enrollment tokens can only be created for agent identities".into()));
    }

    // Generate a secure random token
    let raw_token = generate_token();
    let token_hash = hash_token(&raw_token);
    let ttl = req.ttl_secs.unwrap_or(DEFAULT_TTL_SECS);

    if ttl < 60 || ttl > 86400 {
        return Err(AppError::BadRequest("ttl_secs must be between 60 and 86400".into()));
    }

    let row = overslash_db::repos::enrollment_token::create(
        &state.db,
        identity_id,
        auth.org_id,
        &token_hash,
        ttl,
    )
    .await?;

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "enrollment_token.created",
            resource_type: Some("identity"),
            resource_id: Some(identity_id),
            detail: serde_json::json!({ "ttl_secs": ttl }),
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(CreateEnrollmentTokenResponse {
        token: raw_token,
        expires_at: row.expires_at.format(&time::format_description::well_known::Rfc3339).unwrap(),
    }))
}

#[derive(Deserialize)]
struct EnrollRequest {
    token: String,
}

#[derive(Serialize)]
struct EnrollResponse {
    identity_id: Uuid,
    org_id: Uuid,
    api_key: String,
    key_prefix: String,
}

async fn enroll(
    State(state): State<AppState>,
    ip: ClientIp,
    Json(req): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>> {
    let token_hash = hash_token(&req.token);

    let token_row = overslash_db::repos::enrollment_token::find_by_hash(&state.db, &token_hash)
        .await?
        .ok_or_else(|| AppError::Unauthorized("invalid enrollment token".into()))?;

    // Check if already consumed
    if token_row.consumed_at.is_some() {
        return Err(AppError::Unauthorized("enrollment token already used".into()));
    }

    // Check expiry
    if token_row.expires_at < time::OffsetDateTime::now_utc() {
        return Err(AppError::Unauthorized("enrollment token expired".into()));
    }

    // Atomically consume the token
    let consumed = overslash_db::repos::enrollment_token::consume(&state.db, token_row.id).await?;
    if !consumed {
        return Err(AppError::Unauthorized("enrollment token already used".into()));
    }

    // Generate a permanent API key bound to this identity
    let (raw_key, key_hash, key_prefix) = generate_api_key()?;

    overslash_db::repos::api_key::create(
        &state.db,
        token_row.org_id,
        Some(token_row.identity_id),
        "enrolled-agent-key",
        &key_hash,
        &key_prefix,
        &[],
    )
    .await?;

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: token_row.org_id,
            identity_id: Some(token_row.identity_id),
            action: "identity.enrolled",
            resource_type: Some("identity"),
            resource_id: Some(token_row.identity_id),
            detail: serde_json::json!({ "enrollment_token_id": token_row.id }),
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(EnrollResponse {
        identity_id: token_row.identity_id,
        org_id: token_row.org_id,
        api_key: raw_key,
        key_prefix,
    }))
}

fn generate_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!("ose_{}", hex::encode(bytes))
}

fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex::encode(digest)
}

fn generate_api_key() -> std::result::Result<(String, String, String), AppError> {
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
    .map_err(|e| AppError::Internal(format!("hash error: {e}")))?
    .to_string();

    Ok((raw_key, hash, key_prefix))
}
