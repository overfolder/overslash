//! Read endpoints: list approvals, get one approval, get its execution.

use super::*;

#[derive(Deserialize)]
pub(super) struct ListQuery {
    /// Optional visibility filter (SPEC §5 — Visibility Scoping):
    ///   * `mine` — approvals the caller has requested
    ///     (`identity_id = caller`).
    ///   * `assigned` — approvals where the caller is the current resolver
    ///     right now (`current_resolver_identity_id = caller`). Strict
    ///     "inbox" view; does NOT include approvals sitting on descendants.
    ///   * `actionable` — approvals the caller could act on: caller is the
    ///     current resolver, or any descendant of theirs is. Excludes
    ///     approvals the caller requested themselves.
    ///
    /// Unset preserves the legacy org-wide listing.
    scope: Option<String>,
    /// Optional: list pending approvals for a specific identity (used by the
    /// identity hierarchy view). Caller must own the identity's org.
    identity_id: Option<Uuid>,
    /// Optional: filter results to a specific approval status
    /// (pending | allowed | denied | expired).
    status: Option<String>,
}

pub(super) async fn list_approvals(
    State(state): State<AppState>,
    acl: OrgAcl,
    scope: OrgScope,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<ApprovalResponse>>> {
    // ?identity_id= is the identity-hierarchy detail panel filter: list
    // pending approvals **requested by** that identity. Cross-tenant ids
    // return NotFound at the scope boundary.
    if let Some(identity_id) = q.identity_id {
        scope
            .get_identity(identity_id)
            .await?
            .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
        let rows = scope.list_mine_approvals(identity_id).await?;
        return Ok(Json(
            batch_responses(&scope, &state.registry, rows, &acl).await?,
        ));
    }
    let rows = match q.scope.as_deref() {
        Some("mine") => {
            let identity_id = acl.identity_id.ok_or_else(|| {
                AppError::BadRequest("scope=mine requires an identity-bound api key".into())
            })?;
            if let Some(ref status) = q.status {
                let rows = scope
                    .list_mine_approvals_by_status(identity_id, status)
                    .await?;
                return Ok(Json(
                    batch_responses(&scope, &state.registry, rows, &acl).await?,
                ));
            }
            scope.list_mine_approvals(identity_id).await?
        }
        Some("assigned") => {
            let identity_id = acl.identity_id.ok_or_else(|| {
                AppError::BadRequest("scope=assigned requires an identity-bound api key".into())
            })?;
            scope.list_assigned_approvals(identity_id).await?
        }
        Some("actionable") => {
            let identity_id = acl.identity_id.ok_or_else(|| {
                AppError::BadRequest("scope=actionable requires an identity-bound api key".into())
            })?;
            scope.list_actionable_approvals(identity_id).await?
        }
        Some(other) => {
            return Err(AppError::BadRequest(format!(
                "invalid scope '{other}': expected 'mine', 'assigned', or 'actionable'"
            )));
        }
        None => scope.list_pending_approvals().await?,
    };
    let mut rows = rows;
    if let Some(ref s) = q.status {
        rows.retain(|r| r.status == *s);
    }
    Ok(Json(
        batch_responses(&scope, &state.registry, rows, &acl).await?,
    ))
}

/// Assemble `ApprovalResponse`s for a list of approvals, batching the
/// execution lookup with a single `WHERE approval_id = ANY(...)` to avoid
/// the N+1 a per-row `build_response` would produce on that path. When
/// `viewer` is `Some`, each response is also decorated with the
/// caller↔requester relationship — that decoration walks the requester's
/// ancestor chain per row (still one query each, the existing recursive
/// CTE), so the function is no longer fully batch-shaped on identity-bound
/// callers. Worth revisiting if approval lists grow long enough to feel it
/// in latency; for now it's a single recursive CTE per row, not the wider
/// N+1 the execution batching avoids.
async fn batch_responses(
    scope: &OrgScope,
    registry: &ServiceRegistry,
    rows: Vec<overslash_db::repos::approval::ApprovalRow>,
    acl: &OrgAcl,
) -> Result<Vec<ApprovalResponse>> {
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let approval_ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let executions = scope.list_executions_by_approvals(&approval_ids).await?;
    // `approval_id` is nullable since async executions can exist without one,
    // but every row here came from a lookup *by* approval id, so the filter
    // drops nothing in practice — it just avoids an unwrap that would be a
    // panic waiting for the first async row to reach this code path.
    let mut exec_map: std::collections::HashMap<Uuid, ExecutionRow> = executions
        .into_iter()
        .filter_map(|e| e.approval_id.map(|aid| (aid, e)))
        .collect();
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let (identity_path, identity_path_ids) =
            crate::services::identity_path::build_for_identity(scope, row.identity_id)
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!("failed to build identity_path for approval {}: {e}", row.id);
                    None
                })
                .map(|(p, ids)| (Some(p), ids))
                .unwrap_or((None, Vec::new()));
        let execution = exec_map.remove(&row.id);
        let requester_id = row.identity_id;
        let resolver_id = row.current_resolver_identity_id;
        let mut resp =
            ApprovalResponse::from_row(row, identity_path, identity_path_ids, execution, registry);
        resp.decorate_relationship(scope, acl.identity_id).await?;
        // The embedded execution carries the same body `/execution` serves, so
        // it needs the same gate — fixing only that endpoint would leave the
        // hole wide open one route over.
        redact_execution_if_needed(scope, acl, requester_id, resolver_id, &mut resp).await?;
        out.push(resp);
    }
    Ok(out)
}

pub(super) async fn get_approval(
    State(state): State<AppState>,
    acl: OrgAcl,
    scope: OrgScope,
    Path(id): Path<Uuid>,
) -> Result<Json<ApprovalResponse>> {
    let row = scope
        .get_approval(id)
        .await?
        .ok_or_else(|| AppError::NotFound("approval not found".into()))?;
    Ok(Json(
        build_response(&scope, &state.registry, row, &acl).await?,
    ))
}

/// `GET /v1/approvals/{id}/execution`
///
/// Takes [`OrgAcl`], not `AuthContext`. It used to take the latter and check
/// only org scope, which made every identity-bound credential in an org a
/// reader of every upstream response body in it. The rule now lives in
/// [`crate::services::execution_access`], shared with `/v1/executions`.
pub(super) async fn get_execution(
    State(_state): State<AppState>,
    acl: OrgAcl,
    scope: OrgScope,
    Path(id): Path<Uuid>,
) -> Result<Json<ExecutionSummary>> {
    // Require the approval exists in this org (4xx-not-leaky).
    let approval = scope
        .get_approval(id)
        .await?
        .ok_or_else(|| AppError::NotFound("approval not found".into()))?;

    // 403 rather than 404: `GET /v1/approvals/{id}` answers 200 for this
    // caller, so pretending the execution does not exist would be a lie that
    // helps nobody debug.
    if !crate::services::execution_access::may_read_execution(
        &scope,
        &acl,
        approval.identity_id,
        Some(approval.current_resolver_identity_id),
    )
    .await?
    {
        return Err(crate::services::execution_access::forbidden());
    }

    let exec = scope
        .get_execution_by_approval(id)
        .await?
        .ok_or_else(|| AppError::NotFound("no execution for this approval".into()))?;

    // Mark-as-read: only the *requesting* agent's first read flips
    // `result_viewed_at`. Dashboard reads (admin/resolver) leave the row
    // unread so the operator's view doesn't accidentally clear the
    // "agent hasn't pulled this yet" surface from the pending-calls list.
    let exec = if acl.identity_id == Some(approval.identity_id) {
        match scope.mark_execution_viewed(exec.id).await {
            Ok(true) => scope.get_execution_by_approval(id).await?.unwrap_or(exec),
            _ => exec,
        }
    } else {
        exec
    };

    Ok(Json(ExecutionSummary::from_row(exec)))
}

/// Hide an embedded execution's body from a viewer who may see that the call
/// happened but not what it returned.
///
/// Kept as a helper rather than inlined because `list_approvals`,
/// `get_approval`, and `resolve_approval` all embed the same summary, and a
/// rule applied at two of three sites is not a rule.
///
/// Cheap in the common cases: [`crate::services::execution_access::may_read_execution`]
/// answers admin and self without touching the database, and an approval with
/// no execution never gets here at all. Only a non-admin looking at someone
/// else's row pays for an ancestry walk.
pub(super) async fn redact_execution_if_needed(
    scope: &OrgScope,
    acl: &OrgAcl,
    requester_id: Uuid,
    resolver_id: Uuid,
    resp: &mut ApprovalResponse,
) -> Result<()> {
    if resp.execution.is_none() {
        return Ok(());
    }
    let allowed = crate::services::execution_access::may_read_execution(
        scope,
        acl,
        requester_id,
        Some(resolver_id),
    )
    .await?;
    if !allowed && let Some(exec) = resp.execution.as_mut() {
        exec.redact_result();
    }
    Ok(())
}
