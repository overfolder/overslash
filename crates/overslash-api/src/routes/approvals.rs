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
        // Token-based endpoints (no auth required — for standalone approval pages)
        .route("/v1/approvals/by-token/{token}", get(get_approval_by_token))
        .route(
            "/v1/approvals/by-token/{token}/resolve",
            post(resolve_approval_by_token),
        )
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
    decision: String, // "allow", "deny", "allow_remember"
}

async fn resolve_approval(
    State(state): State<AppState>,
    auth: AuthContext,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<ResolveRequest>,
) -> Result<Json<ApprovalResponse>> {
    let (status, remember) = match req.decision.as_str() {
        "allow" => ("allowed", false),
        "deny" => ("denied", false),
        "allow_remember" => ("allowed", true),
        other => return Err(AppError::BadRequest(format!("invalid decision: {other}"))),
    };

    let row = overslash_db::repos::approval::resolve(&state.db, id, status, "user", remember)
        .await?
        .ok_or_else(|| AppError::Conflict("approval is not pending".into()))?;

    // If allow_remember, create permission rules from the approval's permission keys
    if remember {
        let identity_id = row.identity_id;
        for key in &row.permission_keys {
            let _ = overslash_db::repos::permission_rule::create(
                &state.db,
                auth.org_id,
                identity_id,
                key,
                "allow",
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
                "decision": &req.decision,
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

// --- Token-based endpoints (unauthenticated, for standalone approval pages) ---

async fn get_approval_by_token(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Json<ApprovalResponse>> {
    let row = overslash_db::repos::approval::get_by_token(&state.db, &token)
        .await?
        .ok_or_else(|| AppError::NotFound("approval not found".into()))?;

    // Don't expose expired approvals via public endpoint
    if row.status == "pending" && row.expires_at < time::OffsetDateTime::now_utc() {
        return Err(AppError::Gone("approval has expired".into()));
    }

    Ok(Json(ApprovalResponse::from(row)))
}

async fn resolve_approval_by_token(
    State(state): State<AppState>,
    ip: ClientIp,
    Path(token): Path<String>,
    Json(req): Json<ResolveRequest>,
) -> Result<Json<ApprovalResponse>> {
    let existing = overslash_db::repos::approval::get_by_token(&state.db, &token)
        .await?
        .ok_or_else(|| AppError::NotFound("approval not found".into()))?;

    if existing.status != "pending" {
        return Err(AppError::Conflict("approval is not pending".into()));
    }

    if existing.expires_at < time::OffsetDateTime::now_utc() {
        return Err(AppError::Gone("approval has expired".into()));
    }

    let (status, remember) = match req.decision.as_str() {
        "allow" => ("allowed", false),
        "deny" => ("denied", false),
        "allow_remember" => ("allowed", true),
        other => return Err(AppError::BadRequest(format!("invalid decision: {other}"))),
    };

    let row =
        overslash_db::repos::approval::resolve(&state.db, existing.id, status, "token", remember)
            .await?
            .ok_or_else(|| AppError::Conflict("approval is not pending".into()))?;

    // If allow_remember, create permission rules from the approval's permission keys
    if remember {
        for key in &row.permission_keys {
            let _ = overslash_db::repos::permission_rule::create(
                &state.db,
                row.org_id,
                row.identity_id,
                key,
                "allow",
            )
            .await;
        }
    }

    let _ = audit::log(
        &state.db,
        &AuditEntry {
            org_id: row.org_id,
            identity_id: None,
            action: "approval.resolved",
            resource_type: Some("approval"),
            resource_id: Some(row.id),
            detail: serde_json::json!({
                "decision": &req.decision,
                "status": &row.status,
                "action_summary": &row.action_summary,
                "resolved_via": "token",
            }),
            ip_address: ip.0.as_deref(),
        },
    )
    .await;

    // Dispatch webhook (fire-and-forget)
    {
        let db = state.db.clone();
        let client = state.http_client.clone();
        let org_id = row.org_id;
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
