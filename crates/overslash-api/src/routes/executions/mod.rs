//! `/v1/executions` — executions addressed in their own right.
//!
//! Before async execution an execution was only reachable through the approval
//! that produced it. An async call may have no approval at all, so it needs a
//! resource of its own.
//!
//! Every handler takes [`OrgAcl`], not `AuthContext`. That is the whole point:
//! taking `AuthContext` is exactly what made
//! `GET /v1/approvals/{id}/execution` readable by any identity-bound
//! credential in the org. The rule lives in
//! [`crate::services::execution_access`] and is shared with the approval read
//! paths, so it cannot be stated twice.

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::repos::execution::ExecutionRow;
use overslash_db::scopes::OrgScope;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::OrgAcl,
    routes::approvals::ExecutionSummary,
    services::execution_access,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/executions", get(list_executions))
        .route("/v1/executions/{id}", get(get_execution))
        .route("/v1/executions/{id}/cancel", post(cancel_execution))
}

/// One execution, addressed on its own.
///
/// Flattens [`ExecutionSummary`] rather than redefining its fields, so the
/// nested-in-an-approval view and this one can never describe the same column
/// differently — and the TS mirror can literally `extends` it.
#[derive(Serialize)]
struct ExecutionDetail {
    #[serde(flatten)]
    summary: ExecutionSummary,
    /// Derived from whether an approval is attached; not a stored column.
    origin: &'static str,
    identity_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_id: Option<Uuid>,
    tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    /// Attempts that ended by losing a worker lease. Non-zero means the job was
    /// interrupted at least once, usually by a scale-in.
    #[serde(skip_serializing_if = "is_zero")]
    attempts: i32,
    /// A cancel is recorded but the worker has not yet observed it.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    cancel_requested: bool,
}

fn is_zero(n: &i32) -> bool {
    *n == 0
}

impl ExecutionDetail {
    fn from_row(row: ExecutionRow) -> Self {
        let origin = if row.approval_id.is_some() {
            "approval"
        } else {
            "async_call"
        };
        let identity_id = row.identity_id;
        let approval_id = row.approval_id;
        let tags = row.tags.clone();
        let service = row.service_key.clone();
        let attempts = row.attempts;
        let cancel_requested = row.cancel_requested;
        Self {
            summary: ExecutionSummary::from_row(row),
            origin,
            identity_id,
            approval_id,
            tags,
            service,
            attempts,
            cancel_requested,
        }
    }
}

#[derive(Deserialize)]
struct ListQuery {
    /// `mine` (default) or `subtree`.
    scope: Option<String>,
    status: Option<String>,
    origin: Option<String>,
    limit: Option<i64>,
}

/// `GET /v1/executions`
///
/// List rows never carry `result`. Fetching the body is also what marks it
/// read, so a list that inlined it would let a caller scrape every result
/// without ever acknowledging one — the same reasoning `services::inbox` gives
/// for keeping payloads out of the event feed.
async fn list_executions(
    State(_state): State<AppState>,
    acl: OrgAcl,
    scope: OrgScope,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<ExecutionDetail>>> {
    let subtree = match q.scope.as_deref() {
        None | Some("mine") => false,
        Some("subtree") => true,
        Some(other) => {
            return Err(AppError::BadRequest(format!(
                "invalid scope '{other}': expected 'mine' or 'subtree'"
            )));
        }
    };
    let caller = acl
        .identity_id
        .ok_or_else(|| AppError::Forbidden("identity-bound credential required".into()))?;
    let limit = q.limit.unwrap_or(50).clamp(1, 200);

    // Rejected rather than treated as "matches nothing": a typo would otherwise
    // return an empty list that looks like an answer.
    if let Some(other) = q.origin.as_deref()
        && other != "approval"
        && other != "async_call"
    {
        return Err(AppError::BadRequest(format!(
            "invalid origin '{other}': expected 'approval' or 'async_call'"
        )));
    }

    // `origin` is filtered in SQL, not here. Applied after `LIMIT` it would
    // silently short a page — asking for 50 async calls could return 20 because
    // the first 50 rows by date happened to include 30 approval-backed ones.
    let rows = scope
        .list_executions_for_identity(
            caller,
            subtree,
            q.status.as_deref(),
            q.origin.as_deref(),
            limit,
        )
        .await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let mut detail = ExecutionDetail::from_row(row);
        // Always: see the reasoning on this handler.
        detail.summary.redact_result();
        out.push(detail);
    }
    Ok(Json(out))
}

/// `GET /v1/executions/{id}`
///
/// Reading here is also what stamps `result_viewed_at` — but only for the
/// requester, so a supervisor glancing at a result does not mark it read on the
/// agent's behalf.
async fn get_execution(
    State(_state): State<AppState>,
    acl: OrgAcl,
    scope: OrgScope,
    Path(id): Path<Uuid>,
) -> Result<Json<ExecutionDetail>> {
    let row = scope
        .get_execution(id)
        .await?
        .ok_or_else(|| AppError::NotFound("execution not found".into()))?;

    let resolver_id = resolver_for(&scope, &row).await;
    if !execution_access::may_read_execution(&scope, &acl, row.identity_id, resolver_id).await? {
        return Err(execution_access::forbidden());
    }

    // Re-read when the stamp actually lands, so `output_read` describes the row
    // as it now is rather than as it was a statement ago. Without this the
    // first read reports `false` while the server considers it read — and, more
    // to the point, disagrees with `/v1/approvals/{id}/execution`, which
    // re-fetches. Two endpoints serving the same DTO must not answer
    // differently, or the field is not usable by a client at all.
    //
    // `mark_execution_viewed` returns true only on the transition, so the extra
    // point read costs nothing on every subsequent call.
    let row = if acl.identity_id == Some(row.identity_id) {
        match scope.mark_execution_viewed(row.id).await {
            Ok(true) => scope.get_execution(id).await?.unwrap_or(row),
            _ => row,
        }
    } else {
        row
    };
    Ok(Json(ExecutionDetail::from_row(row)))
}

/// `POST /v1/executions/{id}/cancel`
///
/// Cooperative. A `pending` row is cancelled outright; an `executing` one has
/// its intent recorded and the worker stops on its next heartbeat. Either way
/// this stops Overslash waiting — it does not recall a request the upstream
/// has already received.
async fn cancel_execution(
    State(_state): State<AppState>,
    acl: OrgAcl,
    scope: OrgScope,
    Path(id): Path<Uuid>,
) -> Result<Json<ExecutionDetail>> {
    let row = scope
        .get_execution(id)
        .await?
        .ok_or_else(|| AppError::NotFound("execution not found".into()))?;

    let resolver_id = resolver_for(&scope, &row).await;
    if !execution_access::may_cancel_execution(&scope, &acl, row.identity_id, resolver_id).await? {
        return Err(execution_access::forbidden());
    }

    // A synchronous execution is cancelled through its approval, not here.
    // `request_execution_cancel` filters on `request IS NOT NULL`, so without
    // this check a sync row would fall through to the conflict below and be
    // told it was no longer cancellable — which is not why it failed, and
    // points the caller at the wrong problem.
    if !row.has_request {
        return Err(AppError::BadRequest(format!(
            "execution {id} is not an async call; cancel it through its approval \
             with POST /v1/approvals/{{approval_id}}/cancel"
        )));
    }

    let cancelled = scope.request_execution_cancel(id).await?.ok_or_else(|| {
        // Deliberately does not quote a status. `row` was read before the
        // update, so a job that finished in between would be reported with the
        // state it *was* in rather than the one that refused the cancel.
        AppError::Conflict(
            "execution is no longer in a cancellable state — it may have completed, \
             failed, or expired since it was read"
                .into(),
        )
    })?;
    Ok(Json(ExecutionDetail::from_row(cancelled)))
}

/// The approval's current resolver, when this execution came from one.
///
/// A failed lookup degrades to `None`, which only ever *narrows* who may read —
/// the safe direction for a transient database error.
async fn resolver_for(scope: &OrgScope, row: &ExecutionRow) -> Option<Uuid> {
    let approval_id = row.approval_id?;
    scope
        .get_approval(approval_id)
        .await
        .ok()
        .flatten()
        .map(|a| a.current_resolver_identity_id)
}
