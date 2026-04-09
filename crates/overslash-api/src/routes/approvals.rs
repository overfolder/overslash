use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::repos::audit::AuditEntry;
use overslash_db::scopes::OrgScope;

use overslash_core::permissions::{GroupCeilingResult, PermissionKey, parse_derived_key};
use overslash_core::types::service::Risk;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AuthContext, ClientIp, WriteAcl},
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
    /// The identity that originally requested the action.
    identity_id: Uuid,
    /// Alias of `identity_id`, named explicitly for clarity in the bubbling model.
    requesting_identity_id: Uuid,
    /// The identity currently expected to act on this approval. Bubbles upward
    /// on explicit BubbleUp or via the auto-bubble timer.
    current_resolver_identity_id: Uuid,
    /// SPIFFE-style hierarchical path of the requesting identity
    /// (`spiffe://<org>/user/alice/agent/henry/...`). See
    /// `crate::services::identity_path`.
    identity_path: Option<String>,
    action_summary: String,
    permission_keys: Vec<String>,
    derived_keys: Vec<overslash_core::permissions::DerivedKey>,
    suggested_tiers: Vec<overslash_core::permissions::SuggestedTier>,
    status: String,
    token: String,
    expires_at: String,
    created_at: String,
}

impl ApprovalResponse {
    fn from_row(
        r: overslash_db::repos::approval::ApprovalRow,
        identity_path: Option<String>,
    ) -> Self {
        let derived_keys = overslash_core::permissions::derive_keys(&r.permission_keys);
        let suggested_tiers = overslash_core::permissions::suggest_tiers(&r.permission_keys);
        Self {
            id: r.id,
            identity_id: r.identity_id,
            requesting_identity_id: r.identity_id,
            current_resolver_identity_id: r.current_resolver_identity_id,
            identity_path,
            action_summary: r.action_summary,
            permission_keys: r.permission_keys,
            derived_keys,
            suggested_tiers,
            status: r.status,
            token: r.token,
            expires_at: r.expires_at.to_string(),
            created_at: r.created_at.to_string(),
        }
    }
}

async fn build_response(
    scope: &OrgScope,
    row: overslash_db::repos::approval::ApprovalRow,
) -> Result<ApprovalResponse> {
    let identity_path = crate::services::identity_path::build_for_identity(scope, row.identity_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("failed to build identity_path for approval {}: {e}", row.id);
            None
        });
    Ok(ApprovalResponse::from_row(row, identity_path))
}

#[derive(Deserialize)]
struct ListQuery {
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
}

async fn list_approvals(
    State(_state): State<AppState>,
    auth: AuthContext,
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
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(build_response(&scope, row).await?);
        }
        return Ok(Json(out));
    }
    let rows = match q.scope.as_deref() {
        Some("mine") => {
            let identity_id = auth.identity_id.ok_or_else(|| {
                AppError::BadRequest("scope=mine requires an identity-bound api key".into())
            })?;
            scope.list_mine_approvals(identity_id).await?
        }
        Some("assigned") => {
            let identity_id = auth.identity_id.ok_or_else(|| {
                AppError::BadRequest("scope=assigned requires an identity-bound api key".into())
            })?;
            scope.list_assigned_approvals(identity_id).await?
        }
        Some("actionable") => {
            let identity_id = auth.identity_id.ok_or_else(|| {
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
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(build_response(&scope, row).await?);
    }
    Ok(Json(out))
}

async fn get_approval(
    State(_state): State<AppState>,
    scope: OrgScope,
    Path(id): Path<Uuid>,
) -> Result<Json<ApprovalResponse>> {
    let row = scope
        .get_approval(id)
        .await?
        .ok_or_else(|| AppError::NotFound("approval not found".into()))?;
    Ok(Json(build_response(&scope, row).await?))
}

#[derive(Deserialize)]
struct ResolveRequest {
    resolution: String, // "allow", "deny", "allow_remember", "bubble_up"
    remember_keys: Option<Vec<String>>,
    ttl: Option<String>,
}

async fn resolve_approval(
    State(state): State<AppState>,
    WriteAcl(acl): WriteAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<ResolveRequest>,
) -> Result<Json<ApprovalResponse>> {
    let auth = acl;

    // Load the approval through the org-scoped lookup. A foreign id returns
    // None at the SQL boundary — 404 (not 403) avoids leaking existence.
    let approval_pre = scope
        .get_approval(id)
        .await?
        .ok_or_else(|| AppError::NotFound("approval not found".into()))?;

    // ── Authorize the caller as the current resolver (or an ancestor of them).
    // Org admins (Users with `is_org_admin = true` or Agents with admin grant
    // on the overslash meta service — both surfaced as `Admin` access level by
    // the OrgAcl extractor) bypass the chain walk: they can resolve any
    // approval in their org. Non-admin callers must be the current resolver or
    // one of its ancestors.
    //
    // SPEC §5: "The requesting agent itself — never. An agent cannot resolve
    // its own approval requests." This catches edge cases (e.g. an orphaned
    // non-user identity ending up as its own resolver after the chain walk
    // falls back) where is_self_or_ancestor would otherwise pass the same id
    // against itself.
    use overslash_core::permissions::AccessLevel;
    if let Some(caller_identity) = auth.identity_id {
        if caller_identity == approval_pre.identity_id {
            return Err(AppError::Forbidden(
                "agents cannot resolve their own approval requests".into(),
            ));
        }
        if auth.access_level < AccessLevel::Admin {
            let allowed = crate::services::permission_chain::is_self_or_ancestor(
                &scope,
                caller_identity,
                approval_pre.current_resolver_identity_id,
            )
            .await?;
            if !allowed {
                return Err(AppError::Forbidden(
                    "caller is not authorized to resolve this approval".into(),
                ));
            }
        }
    }

    // ── BubbleUp: advance the resolver instead of resolving.
    if req.resolution == "bubble_up" {
        let perm_keys: Vec<PermissionKey> = approval_pre
            .permission_keys
            .iter()
            .map(|k| PermissionKey(k.clone()))
            .collect();
        let next = crate::services::permission_chain::find_next_resolver(
            &scope,
            approval_pre.identity_id,
            approval_pre.current_resolver_identity_id,
            &perm_keys,
        )
        .await?;
        // Already at the top of the chain (typically the user) — there is
        // nowhere to bubble to. Reject so we don't reset the auto-bubble
        // timer or log a misleading "bubbled from X to X" audit entry.
        if next == approval_pre.current_resolver_identity_id {
            return Err(AppError::Conflict(
                "approval is already at the final resolver".into(),
            ));
        }
        let updated = scope
            .update_approval_resolver(id, next, approval_pre.current_resolver_identity_id)
            .await?
            .ok_or_else(|| {
                AppError::Conflict(
                    "approval was concurrently resolved or bubbled by another caller".into(),
                )
            })?;

        let _ = OrgScope::new(auth.org_id, state.db.clone())
            .log_audit(AuditEntry {
                org_id: auth.org_id,
                identity_id: auth.identity_id,
                action: "approval.bubbled",
                resource_type: Some("approval"),
                resource_id: Some(id),
                detail: serde_json::json!({
                    "from": approval_pre.current_resolver_identity_id,
                    "to": next,
                }),
                description: None,
                ip_address: ip.0.as_deref(),
            })
            .await;

        return Ok(Json(build_response(&scope, updated).await?));
    }

    let (status, remember) = match req.resolution.as_str() {
        "allow" => ("allowed", false),
        "deny" => ("denied", false),
        "allow_remember" => ("allowed", true),
        other => return Err(AppError::BadRequest(format!("invalid resolution: {other}"))),
    };

    let mut parsed_expires_at: Option<time::OffsetDateTime> = None;
    if remember {
        if let Some(t) = req.ttl.as_deref() {
            let dur = overslash_core::types::duration::parse_ttl(t)
                .ok_or_else(|| AppError::BadRequest(format!("invalid ttl: {t}")))?;
            if dur.as_secs() > 365 * 86400 {
                return Err(AppError::BadRequest("ttl must not exceed 365 days".into()));
            }
            let secs: i64 = dur
                .as_secs()
                .try_into()
                .map_err(|_| AppError::BadRequest("ttl value too large".into()))?;
            parsed_expires_at =
                time::OffsetDateTime::now_utc().checked_add(time::Duration::new(secs, 0));
        }
        let approval = &approval_pre;

        // Determine which keys will be stored: explicit remember_keys or fallback to permission_keys
        let effective_keys: &[String] = if let Some(ref keys) = req.remember_keys {
            if keys.is_empty() {
                return Err(AppError::BadRequest(
                    "remember_keys must not be empty".into(),
                ));
            }

            // Validate against suggested tiers (prevents submitting `*:*:*`)
            let tiers = overslash_core::permissions::suggest_tiers(&approval.permission_keys);
            let allowed_keys: std::collections::HashSet<&str> = tiers
                .iter()
                .flat_map(|t| t.keys.iter().map(|k| k.as_str()))
                .collect();

            for key in keys {
                if !allowed_keys.contains(key.as_str()) {
                    return Err(AppError::BadRequest(format!(
                        "remember_key '{key}' is not in any suggested tier"
                    )));
                }
            }

            keys
        } else {
            &approval.permission_keys
        };

        // Validate keys don't exceed group ceiling (applies to both explicit and fallback keys)
        let ceiling_user_id =
            crate::services::group_ceiling::resolve_ceiling_user_id(&scope, approval.identity_id)
                .await?;

        let ceiling = crate::services::group_ceiling::load_ceiling(&scope, ceiling_user_id).await?;

        if ceiling.has_groups {
            for key in effective_keys {
                let dk = parse_derived_key(key);
                // Check that the service is in the group at any access level.
                // The execution-time ceiling check will enforce the actual access level.
                let result = crate::services::group_ceiling::check_ceiling(
                    &ceiling,
                    &dk.service,
                    Risk::Read,
                );
                if let GroupCeilingResult::ExceedsCeiling(reason) = result {
                    return Err(AppError::BadRequest(format!(
                        "key '{key}' exceeds group ceiling: {reason}"
                    )));
                }
            }
        }
    }

    let row = scope
        .resolve_approval(
            id,
            status,
            "user",
            remember,
            approval_pre.current_resolver_identity_id,
        )
        .await?
        .ok_or_else(|| {
            AppError::Conflict(
                "approval was concurrently resolved or bubbled by another caller".into(),
            )
        })?;

    if remember {
        // Place the rule on the requester's closest non-inherit_permissions
        // ancestor (inclusive). For a Researcher(inherit) under Marketing,
        // approving "remember" puts the rule on Marketing — not Researcher.
        let placement_id =
            crate::services::permission_chain::rule_placement_for(&scope, row.identity_id).await?;
        let keys = req.remember_keys.as_deref().unwrap_or(&row.permission_keys);
        for key in keys {
            let _ = scope
                .create_permission_rule(placement_id, key, "allow", parsed_expires_at)
                .await;
        }
    }

    let _ = OrgScope::new(auth.org_id, state.db.clone())
        .log_audit(AuditEntry {
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
            description: None,
            ip_address: ip.0.as_deref(),
        })
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

    Ok(Json(build_response(&scope, row).await?))
}
