use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::repos::audit::{self, AuditEntry};

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AuthContext, ClientIp},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/approvals", get(list_approvals))
        .route("/v1/approvals/{id}", get(get_approval))
        .route("/v1/approvals/{id}/resolve", post(resolve_approval))
}

#[derive(Serialize)]
struct ApprovalResponse {
    id: Uuid,
    identity_id: Uuid,
    action_summary: String,
    permission_keys: Vec<String>,
    status: String,
    token: String,
    expires_at: String,
    created_at: String,
}

impl From<overslash_db::repos::approval::ApprovalRow> for ApprovalResponse {
    fn from(r: overslash_db::repos::approval::ApprovalRow) -> Self {
        Self {
            id: r.id,
            identity_id: r.identity_id,
            action_summary: r.action_summary,
            permission_keys: r.permission_keys,
            status: r.status,
            token: r.token,
            expires_at: r.expires_at.to_string(),
            created_at: r.created_at.to_string(),
        }
    }
}

async fn list_approvals(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<Vec<ApprovalResponse>>> {
    let rows = overslash_db::repos::approval::list_pending_by_org(&state.db, auth.org_id).await?;
    Ok(Json(rows.into_iter().map(ApprovalResponse::from).collect()))
}

async fn get_approval(
    State(state): State<AppState>,
    _auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<ApprovalResponse>> {
    let row = overslash_db::repos::approval::get_by_id(&state.db, id)
        .await?
        .ok_or_else(|| AppError::NotFound("approval not found".into()))?;
    Ok(Json(ApprovalResponse::from(row)))
}

#[derive(Deserialize)]
struct ResolveRequest {
    resolution: String, // "allow", "deny", "allow_remember"
    remember_keys: Option<Vec<String>>,
    ttl: Option<String>,
}

async fn resolve_approval(
    State(state): State<AppState>,
    auth: AuthContext,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<ResolveRequest>,
) -> Result<Json<ApprovalResponse>> {
    let (status, remember) = match req.resolution.as_str() {
        "allow" => ("allowed", false),
        "deny" => ("denied", false),
        "allow_remember" => ("allowed", true),
        other => return Err(AppError::BadRequest(format!("invalid resolution: {other}"))),
    };

    let row = overslash_db::repos::approval::resolve(&state.db, id, status, "user", remember)
        .await?
        .ok_or_else(|| AppError::Conflict("approval is not pending".into()))?;

    // If allow_remember, create permission rules from the resolved keys
    if remember {
        let identity_id = row.identity_id;
        let keys = req.remember_keys.as_deref().unwrap_or(&row.permission_keys);

        // Validate remember_keys are a subset of the approval's permission_keys
        if req.remember_keys.is_some() {
            for key in keys {
                if !row.permission_keys.iter().any(|pk| pk == key) {
                    return Err(AppError::BadRequest(format!(
                        "remember_key '{key}' is not in the approval's permission_keys"
                    )));
                }
            }
        }

        // Parse and validate TTL
        let expires_at = match req.ttl.as_deref() {
            Some(t) => {
                let dur = overslash_core::types::duration::parse_ttl(t)
                    .ok_or_else(|| AppError::BadRequest(format!("invalid ttl: {t}")))?;
                let secs: i64 = dur
                    .as_secs()
                    .try_into()
                    .map_err(|_| AppError::BadRequest("ttl value too large".into()))?;
                Some(time::OffsetDateTime::now_utc() + time::Duration::new(secs, 0))
            }
            None => None,
        };

        for key in keys {
            let _ = overslash_db::repos::permission_rule::create(
                &state.db,
                auth.org_id,
                identity_id,
                key,
                "allow",
                expires_at,
            )
            .await;
        }
    }

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: auth.org_id,
            identity_id: auth.identity_id,
            action: "approval.resolved",
            resource_type: Some("approval"),
            resource_id: Some(id),
            detail: serde_json::json!({
                "resolution": &req.resolution,
                "status": &row.status,
                "action_summary": &row.action_summary,
            }),
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    // Dispatch webhook (fire-and-forget)
    {
        let db = state.db.clone();
        let client = state.http_client.clone();
        let org_id = auth.org_id;
        let approval_id = row.id;
        let summary = row.action_summary.clone();
        let final_status = row.status.clone();
        tokio::spawn(async move {
            crate::services::webhook_dispatcher::dispatch(
                &db,
                &client,
                org_id,
                "approval.resolved",
                serde_json::json!({
                    "approval_id": approval_id,
                    "status": final_status,
                    "action_summary": summary,
                }),
            )
            .await;
        });
    }

    Ok(Json(ApprovalResponse::from(row)))
}
