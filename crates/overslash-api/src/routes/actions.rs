use std::collections::HashMap;

use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::post};
use serde::Serialize;
use uuid::Uuid;

use crate::{AppState, error::AppError, extractors::AuthContext, services::http_executor};
use overslash_core::{
    crypto,
    permissions::{PermissionKey, PermissionResult, check_permissions},
    secret_injection::inject_secrets,
    types::{ActionRequest, ActionResult, PermissionEffect, PermissionRule},
};

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/actions/execute", post(execute_action))
}

#[derive(Serialize)]
#[serde(tag = "status")]
enum ExecuteResponse {
    #[serde(rename = "executed")]
    Executed {
        result: ActionResult,
        audit_id: Option<Uuid>,
    },
    #[serde(rename = "pending_approval")]
    PendingApproval {
        approval_id: Uuid,
        approval_url: String,
        action_description: String,
        expires_at: String,
    },
    #[serde(rename = "denied")]
    Denied { reason: String },
}

async fn execute_action(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(request): Json<ActionRequest>,
) -> Result<impl IntoResponse, AppError> {
    let identity_id = auth
        .identity_id
        .ok_or_else(|| AppError::BadRequest("api key must be bound to an identity".into()))?;

    // Derive permission keys
    let perm_keys = PermissionKey::from_http(&request.method, &request.url);

    // If secrets are referenced, we need permission
    let needs_gate = !request.secrets.is_empty();

    if needs_gate {
        // Load permission rules for this identity
        let rule_rows =
            overslash_db::repos::permission_rule::list_by_identity(&state.db, identity_id).await?;

        let rules: Vec<PermissionRule> = rule_rows
            .into_iter()
            .map(|r| PermissionRule {
                id: r.id,
                org_id: r.org_id,
                identity_id: r.identity_id,
                action_pattern: r.action_pattern,
                effect: if r.effect == "deny" {
                    PermissionEffect::Deny
                } else {
                    PermissionEffect::Allow
                },
                created_at: r.created_at,
            })
            .collect();

        match check_permissions(&rules, &perm_keys) {
            PermissionResult::Allowed => {
                // Fall through to execution
            }
            PermissionResult::NeedsApproval(uncovered) => {
                // Create approval
                let token = generate_token();
                let expires_at = time::OffsetDateTime::now_utc()
                    + time::Duration::seconds(state.config.approval_expiry_secs as i64);
                let summary = format!("{} {}", request.method, request.url);
                let keys: Vec<String> = uncovered.iter().map(|k| k.0.clone()).collect();

                let approval = overslash_db::repos::approval::create(
                    &state.db,
                    &overslash_db::repos::approval::CreateApproval {
                        org_id: auth.org_id,
                        identity_id,
                        action_summary: &summary,
                        action_detail: Some(serde_json::to_value(&request).unwrap_or_default()),
                        permission_keys: &keys,
                        token: &token,
                        expires_at,
                    },
                )
                .await?;

                let _ = overslash_db::repos::audit::log(
                    &state.db,
                    auth.org_id,
                    Some(identity_id),
                    "approval.created",
                    Some("approval"),
                    Some(approval.id),
                    serde_json::json!({ "summary": summary }),
                )
                .await;

                return Ok((
                    StatusCode::ACCEPTED,
                    Json(ExecuteResponse::PendingApproval {
                        approval_id: approval.id,
                        approval_url: format!("/approve/{}", approval.token),
                        action_description: summary,
                        expires_at: expires_at.to_string(),
                    }),
                ));
            }
            PermissionResult::Denied(reason) => {
                return Ok((
                    StatusCode::FORBIDDEN,
                    Json(ExecuteResponse::Denied { reason }),
                ));
            }
        }
    }

    // Resolve secrets and inject
    let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)?;
    let mut secret_values = HashMap::new();
    for secret_ref in &request.secrets {
        let version = overslash_db::repos::secret::get_current_value(
            &state.db,
            auth.org_id,
            &secret_ref.name,
        )
        .await?
        .ok_or_else(|| AppError::BadRequest(format!("secret '{}' not found", secret_ref.name)))?;
        let decrypted = crypto::decrypt(&enc_key, &version.encrypted_value)?;
        let value = String::from_utf8(decrypted)
            .map_err(|_| AppError::Internal("secret is not valid utf-8".into()))?;
        secret_values.insert(secret_ref.name.clone(), value);
    }

    let (resolved_url, resolved_headers) = inject_secrets(&request, &secret_values)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    // Execute the HTTP request
    let result = http_executor::execute(
        &state.http_client,
        &request.method,
        &resolved_url,
        &resolved_headers,
        request.body.as_deref(),
    )
    .await?;

    // Audit log
    let _ = overslash_db::repos::audit::log(
        &state.db,
        auth.org_id,
        Some(identity_id),
        "action.executed",
        None,
        None,
        serde_json::json!({
            "method": request.method,
            "url": request.url,
            "status_code": result.status_code,
            "duration_ms": result.duration_ms,
        }),
    )
    .await;

    Ok((
        StatusCode::OK,
        Json(ExecuteResponse::Executed {
            result,
            audit_id: None,
        }),
    ))
}

fn generate_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
