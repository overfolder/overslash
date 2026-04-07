use axum::{
    Json, Router,
    extract::{Path, State},
    routing::delete,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::OrgScope;
use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::rate_limit;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AuthContext, ClientIp},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/rate-limits",
            axum::routing::put(upsert_rate_limit).get(list_rate_limits),
        )
        .route("/v1/rate-limits/{id}", delete(delete_rate_limit))
}

// ── Request / Response types ────────────────────────────────────────

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RateLimitScope {
    Org,
    Group,
    User,
    IdentityCap,
}

impl RateLimitScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::Org => "org",
            Self::Group => "group",
            Self::User => "user",
            Self::IdentityCap => "identity_cap",
        }
    }
}

#[derive(Deserialize)]
struct UpsertRateLimitRequest {
    scope: RateLimitScope,
    identity_id: Option<Uuid>,
    group_id: Option<Uuid>,
    max_requests: i32,
    window_seconds: i32,
}

#[derive(Serialize)]
struct RateLimitResponse {
    id: Uuid,
    org_id: Uuid,
    scope: String,
    identity_id: Option<Uuid>,
    group_id: Option<Uuid>,
    max_requests: i32,
    window_seconds: i32,
    created_at: String,
    updated_at: String,
}

impl From<rate_limit::RateLimitRow> for RateLimitResponse {
    fn from(r: rate_limit::RateLimitRow) -> Self {
        Self {
            id: r.id,
            org_id: r.org_id,
            scope: r.scope,
            identity_id: r.identity_id,
            group_id: r.group_id,
            max_requests: r.max_requests,
            window_seconds: r.window_seconds,
            created_at: r
                .created_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            updated_at: r
                .updated_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        }
    }
}

/// Invalidate cached config entries so updates take effect immediately.
fn invalidate_cache_for(
    state: &AppState,
    scope: &RateLimitScope,
    org_id: Uuid,
    identity_id: Option<Uuid>,
) {
    match scope {
        // Org defaults and group defaults can affect any user → flush the whole org
        RateLimitScope::Org | RateLimitScope::Group => {
            state.rate_limit_cache.invalidate_org(org_id);
        }
        RateLimitScope::User => {
            if let Some(id) = identity_id {
                state.rate_limit_cache.invalidate_user_budget(org_id, id);
            }
        }
        RateLimitScope::IdentityCap => {
            if let Some(id) = identity_id {
                state.rate_limit_cache.invalidate_identity_cap(org_id, id);
            }
        }
    }
}

// ── Handlers ────────────────────────────────────────────────────────

async fn upsert_rate_limit(
    State(state): State<AppState>,
    auth: AuthContext,
    scope: OrgScope,
    ip: ClientIp,
    Json(req): Json<UpsertRateLimitRequest>,
) -> Result<Json<RateLimitResponse>> {
    // Validate required fields per scope
    match req.scope {
        RateLimitScope::Org => {
            if req.identity_id.is_some() || req.group_id.is_some() {
                return Err(AppError::BadRequest(
                    "org scope must not have identity_id or group_id".into(),
                ));
            }
        }
        RateLimitScope::Group => {
            if req.group_id.is_none() {
                return Err(AppError::BadRequest("group scope requires group_id".into()));
            }
            if req.identity_id.is_some() {
                return Err(AppError::BadRequest(
                    "group scope must not have identity_id".into(),
                ));
            }
        }
        RateLimitScope::User | RateLimitScope::IdentityCap => {
            if req.identity_id.is_none() {
                return Err(AppError::BadRequest(format!(
                    "{} scope requires identity_id",
                    req.scope.as_str()
                )));
            }
            if req.group_id.is_some() {
                return Err(AppError::BadRequest(format!(
                    "{} scope must not have group_id",
                    req.scope.as_str()
                )));
            }
        }
    }

    if req.max_requests <= 0 {
        return Err(AppError::BadRequest("max_requests must be positive".into()));
    }
    if req.window_seconds <= 0 {
        return Err(AppError::BadRequest(
            "window_seconds must be positive".into(),
        ));
    }

    let scope_str = req.scope.as_str();

    let row = scope
        .upsert_rate_limit(
            scope_str,
            req.identity_id,
            req.group_id,
            req.max_requests,
            req.window_seconds,
        )
        .await?;

    // Invalidate cached configs so the new value takes effect immediately
    // (rather than waiting up to 30s for the cache TTL).
    invalidate_cache_for(&state, &req.scope, auth.org_id, req.identity_id);

    // Audit
    scope
        .log_audit(AuditEntry {
            org_id: scope.org_id(),
            identity_id: auth.identity_id,
            action: "rate_limit.upsert",
            resource_type: Some("rate_limit"),
            resource_id: Some(row.id),
            detail: serde_json::json!({
                "scope": scope_str,
                "identity_id": req.identity_id,
                "group_id": req.group_id,
                "max_requests": req.max_requests,
                "window_seconds": req.window_seconds,
            }),
            ip_address: ip.0.as_deref(),
            description: Some(&format!(
                "Set {} rate limit: {} requests per {}s",
                scope_str, req.max_requests, req.window_seconds
            )),
        })
        .await?;

    Ok(Json(row.into()))
}

async fn list_rate_limits(scope: OrgScope) -> Result<Json<Vec<RateLimitResponse>>> {
    let rows = scope.list_rate_limits().await?;
    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn delete_rate_limit(
    State(state): State<AppState>,
    auth: AuthContext,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let deleted = scope.delete_rate_limit(id).await?;
    if !deleted {
        return Err(AppError::NotFound("rate limit config not found".into()));
    }

    // Invalidate everything for the org. We don't know the scope of the deleted row
    // (we'd need to fetch it first), so the safest course is to flush the org's cache.
    state.rate_limit_cache.invalidate_org(scope.org_id());

    scope
        .log_audit(AuditEntry {
            org_id: scope.org_id(),
            identity_id: auth.identity_id,
            action: "rate_limit.delete",
            resource_type: Some("rate_limit"),
            resource_id: Some(id),
            detail: serde_json::json!({}),
            ip_address: ip.0.as_deref(),
            description: Some("Deleted rate limit config"),
        })
        .await?;

    Ok(Json(serde_json::json!({ "deleted": true })))
}
