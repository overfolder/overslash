//! Instance-admin billing controls: managed trials
//! (`POST`/`PATCH /v1/orgs/{id}/trial`) and direct plan changes
//! (`PATCH /v1/orgs/{id}/plan`).

use super::*;

// ---------------------------------------------------------------------------
// Instance-admin trial controls
//
// These put an existing org on (or off) an instance-admin-managed trial —
// `plan='trial'` + `trial_ends_at`. Enforcement is banner-only (DECISIONS
// D25): expiry drives dashboard messaging, not API access. `free_unlimited`
// (e.g. Reveni) is exempt — it is never `plan='trial'`, and `PATCH .../plan`
// is how a trial org opts out. Self-serve card-backed trials go through Stripe
// (`/v1/billing/checkout` with `trial: true`), not these endpoints.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct StartTrialRequest {
    /// Trial length in days. Defaults to `TRIAL_DEFAULT_DURATION_DAYS`.
    #[serde(default)]
    duration_days: Option<u32>,
}

#[derive(Deserialize)]
pub(super) struct ExtendTrialRequest {
    /// Days to add to the current window end (or to now, if already past).
    /// Defaults to `TRIAL_DEFAULT_DURATION_DAYS`.
    #[serde(default)]
    extend_days: Option<u32>,
}

#[derive(Serialize)]
pub(super) struct TrialResponse {
    org_id: Uuid,
    plan: String,
    /// Trial window end, unix seconds.
    trial_ends_at: i64,
}

/// Resolve a requested duration to a bounded day count, defaulting to config.
fn resolve_trial_days(requested: Option<u32>, default_days: u32) -> Result<u32> {
    let days = requested.unwrap_or(default_days);
    if days == 0 {
        return Err(AppError::BadRequest(
            "duration must be at least 1 day".into(),
        ));
    }
    // Guard against absurd windows (and i64 overflow on the timestamp math).
    if days > 3650 {
        return Err(AppError::BadRequest(
            "duration must be at most 3650 days".into(),
        ));
    }
    Ok(days)
}

/// POST /v1/orgs/{id}/trial — start (or restart) a managed trial on an org.
pub(super) async fn start_trial(
    admin: InstanceAdminAuth,
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<StartTrialRequest>,
) -> Result<Json<TrialResponse>> {
    let days = resolve_trial_days(req.duration_days, state.config.trial_default_duration_days)?;
    let ends_at = OffsetDateTime::now_utc() + time::Duration::days(days as i64);

    if !overslash_db::repos::org::set_trial(state.db(&ext), id, ends_at).await? {
        return Err(AppError::NotFound("org not found".into()));
    }
    // Propagate immediately rather than waiting out the cache TTL.
    state.free_unlimited_cache(&ext).invalidate(id);

    let _ = overslash_db::OrgScope::new(id, state.db_pool(&ext))
        .log_audit(AuditEntry {
            org_id: id,
            identity_id: None,
            action: "org.trial_started",
            resource_type: Some("org"),
            resource_id: Some(id),
            detail: serde_json::json!({
                "trial_ends_at": ends_at.unix_timestamp(),
                "duration_days": days,
                "set_by_instance_admin": admin.user_id.to_string(),
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(TrialResponse {
        org_id: id,
        plan: "trial".into(),
        trial_ends_at: ends_at.unix_timestamp(),
    }))
}

/// PATCH /v1/orgs/{id}/trial — bump an existing trial's end date.
pub(super) async fn extend_trial(
    admin: InstanceAdminAuth,
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<ExtendTrialRequest>,
) -> Result<Json<TrialResponse>> {
    let days = resolve_trial_days(req.extend_days, state.config.trial_default_duration_days)?;

    let org = overslash_db::repos::org::get_by_id(state.db(&ext), id)
        .await?
        .ok_or_else(|| AppError::NotFound("org not found".into()))?;
    if org.plan != "trial" {
        return Err(AppError::BadRequest("org is not on a trial".into()));
    }

    // Extend from the later of (current end, now) so bumping an already-expired
    // trial still grants a fresh window rather than landing in the past.
    let now = OffsetDateTime::now_utc();
    let base = org.trial_ends_at.unwrap_or(now).max(now);
    let ends_at = base + time::Duration::days(days as i64);

    if !overslash_db::repos::org::extend_trial(state.db(&ext), id, ends_at).await? {
        // Lost the trial between read and write (raced with an opt-out).
        return Err(AppError::BadRequest("org is not on a trial".into()));
    }
    state.free_unlimited_cache(&ext).invalidate(id);

    let _ = overslash_db::OrgScope::new(id, state.db_pool(&ext))
        .log_audit(AuditEntry {
            org_id: id,
            identity_id: None,
            action: "org.trial_extended",
            resource_type: Some("org"),
            resource_id: Some(id),
            detail: serde_json::json!({
                "trial_ends_at": ends_at.unix_timestamp(),
                "extend_days": days,
                "set_by_instance_admin": admin.user_id.to_string(),
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(TrialResponse {
        org_id: id,
        plan: "trial".into(),
        trial_ends_at: ends_at.unix_timestamp(),
    }))
}

#[derive(Deserialize)]
pub(super) struct SetPlanRequest {
    plan: String,
}

#[derive(Serialize)]
pub(super) struct PlanResponse {
    org_id: Uuid,
    plan: String,
}

/// PATCH /v1/orgs/{id}/plan — set an org's billing tier directly. Used to opt a
/// trial org out (to `free_unlimited`, e.g. Reveni) or back to `standard`.
/// Starting a trial goes through `POST /v1/orgs/{id}/trial`, so `'trial'` is
/// intentionally rejected here.
pub(super) async fn set_org_plan(
    admin: InstanceAdminAuth,
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<SetPlanRequest>,
) -> Result<Json<PlanResponse>> {
    if !matches!(req.plan.as_str(), "standard" | "free_unlimited") {
        return Err(AppError::BadRequest(
            "plan must be 'standard' or 'free_unlimited'".into(),
        ));
    }

    if !overslash_db::repos::org::set_plan(state.db(&ext), id, &req.plan).await? {
        return Err(AppError::NotFound("org not found".into()));
    }
    state.free_unlimited_cache(&ext).invalidate(id);

    let _ = overslash_db::OrgScope::new(id, state.db_pool(&ext))
        .log_audit(AuditEntry {
            org_id: id,
            identity_id: None,
            action: "org.plan.updated",
            resource_type: Some("org"),
            resource_id: Some(id),
            detail: serde_json::json!({
                "plan": &req.plan,
                "set_by_instance_admin": admin.user_id.to_string(),
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(PlanResponse {
        org_id: id,
        plan: req.plan,
    }))
}
