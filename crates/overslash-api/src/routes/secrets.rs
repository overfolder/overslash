use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, put},
};
use serde::{Deserialize, Serialize};

use overslash_db::repos::audit::{self, AuditEntry};

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AuthContext, ClientIp},
};
use overslash_core::crypto;

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/secrets", get(list_secrets)).route(
        "/v1/secrets/{name}",
        put(put_secret).get(get_secret).delete(delete_secret),
    )
}

#[derive(Deserialize)]
struct PutSecretRequest {
    value: String,
}

#[derive(Serialize)]
struct SecretMetadata {
    name: String,
    current_version: i32,
}

#[derive(Serialize)]
struct PutSecretResponse {
    name: String,
    version: i32,
}

async fn put_secret(
    State(state): State<AppState>,
    auth: AuthContext,
    ip: ClientIp,
    Path(name): Path<String>,
    Json(req): Json<PutSecretRequest>,
) -> Result<Json<PutSecretResponse>> {
    let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)?;
    let encrypted = crypto::encrypt(&enc_key, req.value.as_bytes())?;

    let (secret, _version) = overslash_db::repos::secret::put(
        &state.db,
        auth.org_id,
        &name,
        &encrypted,
        auth.identity_id,
    )
    .await?;

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "secret.put",
            resource_type: Some("secret"),
            resource_id: None,
            detail: serde_json::json!({ "name": &secret.name, "version": secret.current_version }),
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    Ok(Json(PutSecretResponse {
        name: secret.name,
        version: secret.current_version,
    }))
}

async fn get_secret(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(name): Path<String>,
) -> Result<Json<SecretMetadata>> {
    let secret = overslash_db::repos::secret::get_by_name(&state.db, auth.org_id, &name)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("secret '{name}' not found")))?;

    Ok(Json(SecretMetadata {
        name: secret.name,
        current_version: secret.current_version,
    }))
}

async fn list_secrets(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<Vec<SecretMetadata>>> {
    let rows = overslash_db::repos::secret::list_by_org(&state.db, auth.org_id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| SecretMetadata {
                name: r.name,
                current_version: r.current_version,
            })
            .collect(),
    ))
}

async fn delete_secret(
    State(state): State<AppState>,
    auth: AuthContext,
    ip: ClientIp,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let deleted = overslash_db::repos::secret::soft_delete(&state.db, auth.org_id, &name).await?;
    if deleted {
        let _ = overslash_db::repos::audit::log(
            &state.db,
            &overslash_db::repos::audit::AuditEntry {
                org_id: auth.org_id,
                identity_id: auth.identity_id,
                action: "secret.deleted",
                resource_type: Some("secret"),
                resource_id: None,
                detail: serde_json::json!({ "name": &name }),
                ip_address: ip.0.as_deref(),
            },
        )
        .await;
        Ok(Json(serde_json::json!({ "deleted": true })))
    } else {
        Err(AppError::NotFound(format!("secret '{name}' not found")))
    }
}
