use axum::{
    Json, Router,
    extract::{Path, Query, State},
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
    gap_identity_id: Option<Uuid>,
    can_be_handled_by: Vec<Uuid>,
    grant_to: Option<Uuid>,
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
            gap_identity_id: r.gap_identity_id,
            can_be_handled_by: r.can_be_handled_by,
            grant_to: r.grant_to,
        }
    }
}

#[derive(Deserialize)]
struct ListApprovalsQuery {
    scope: Option<String>,
}

async fn list_approvals(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(query): Query<ListApprovalsQuery>,
) -> Result<Json<Vec<ApprovalResponse>>> {
    let scope = query.scope.as_deref().unwrap_or("all");

    let rows = if let Some(identity_id) = auth.identity_id {
        overslash_db::repos::approval::list_pending_scoped(
            &state.db,
            auth.org_id,
            identity_id,
            scope,
        )
        .await?
    } else {
        // Org-level key — show all pending for the org
        overslash_db::repos::approval::list_pending_by_org(&state.db, auth.org_id).await?
    };

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
    grant_to: Option<Uuid>,
    expires_in: Option<String>,
}

/// Parse a duration string like "30d", "7d", "24h", "1h" into seconds.
fn parse_duration_secs(s: &str) -> std::result::Result<i64, String> {
    let s = s.trim();
    if let Some(days) = s.strip_suffix('d') {
        let n: i64 = days.parse().map_err(|_| format!("invalid duration: {s}"))?;
        Ok(n * 86400)
    } else if let Some(hours) = s.strip_suffix('h') {
        let n: i64 = hours
            .parse()
            .map_err(|_| format!("invalid duration: {s}"))?;
        Ok(n * 3600)
    } else if let Some(mins) = s.strip_suffix('m') {
        let n: i64 = mins.parse().map_err(|_| format!("invalid duration: {s}"))?;
        Ok(n * 60)
    } else {
        Err(format!(
            "invalid duration format: {s} (use e.g. '30d', '24h', '15m')"
        ))
    }
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

    // Load the approval to check authorization
    let existing = overslash_db::repos::approval::get_by_id(&state.db, id)
        .await?
        .ok_or_else(|| AppError::NotFound("approval not found".into()))?;

    // Authorization check for hierarchical approvals
    if existing.gap_identity_id.is_some() && !existing.can_be_handled_by.is_empty() {
        let resolver_id = auth.identity_id.ok_or_else(|| {
            AppError::Forbidden("must be authenticated as an identity to resolve".into())
        })?;

        // Self-approval forbidden
        if Some(resolver_id) == existing.gap_identity_id {
            return Err(AppError::Forbidden(
                "cannot self-approve: the gap identity cannot resolve its own approval".into(),
            ));
        }

        // Must be in can_be_handled_by
        if !existing.can_be_handled_by.contains(&resolver_id) {
            return Err(AppError::Forbidden(
                "not authorized to resolve this approval".into(),
            ));
        }
    }

    let resolved_by = auth
        .identity_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| "org-key".to_string());

    let row = overslash_db::repos::approval::resolve(
        &state.db,
        id,
        status,
        &resolved_by,
        remember,
        req.grant_to,
    )
    .await?
    .ok_or_else(|| AppError::Conflict("approval is not pending".into()))?;

    // If allow_remember, create permission rules
    if remember {
        let target_identity = req
            .grant_to
            .or(row.gap_identity_id)
            .unwrap_or(row.identity_id);

        let expires_at = if let Some(ref dur_str) = req.expires_in {
            let secs = parse_duration_secs(dur_str).map_err(|e| AppError::BadRequest(e))?;
            Some(time::OffsetDateTime::now_utc() + time::Duration::seconds(secs))
        } else {
            None
        };

        for key in &row.permission_keys {
            let _ = overslash_db::repos::permission_rule::create_with_expiry(
                &state.db,
                auth.org_id,
                target_identity,
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
                "decision": &req.decision,
                "status": &row.status,
                "action_summary": &row.action_summary,
                "grant_to": req.grant_to,
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
        let gap_id = row.gap_identity_id;
        let grant_to = row.grant_to;
        let resolved_by_clone = resolved_by.clone();
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
                    "gap_identity_id": gap_id,
                    "resolved_by": resolved_by_clone,
                    "grant_to": grant_to,
                }),
            )
            .await;
        });
    }

    Ok(Json(ApprovalResponse::from(row)))
}
