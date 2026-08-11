//! Per-org read/update endpoints: the org itself, sub-agent cleanup
//! config, template/catalog policy, secret-request policy, execution
//! defaults, audit capture, managed sign-in and headless mode.

use super::*;

pub(super) async fn get_org(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<OrgResponse>> {
    if id != auth.org_id {
        return Err(AppError::Forbidden("cannot read another org".into()));
    }
    let org = overslash_db::repos::org::get_by_id(state.db(&ext), id)
        .await?
        .ok_or_else(|| AppError::NotFound("org not found".into()))?;
    Ok(Json(org.into()))
}

#[derive(Deserialize)]
pub(super) struct PatchOrgRequest {
    // Reserved for future use; currently no top-level org fields are mutable here.
    // Sub-agent cleanup config is mutated via its own endpoint for clarity.
}

pub(super) async fn patch_org(
    State(_state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(_req): Json<PatchOrgRequest>,
) -> Result<Json<OrgResponse>> {
    if id != auth.org_id {
        return Err(AppError::Forbidden("cannot mutate another org".into()));
    }
    Err(AppError::BadRequest("no patchable fields supplied".into()))
}

#[derive(Deserialize)]
pub(super) struct PatchCleanupConfigRequest {
    subagent_idle_timeout_secs: i32,
    subagent_archive_retention_days: i32,
}

pub(super) async fn patch_subagent_cleanup_config(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    AdminAcl(acl): AdminAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<PatchCleanupConfigRequest>,
) -> Result<Json<OrgResponse>> {
    // Org-level config is admin-only — read-only and write-only callers must
    // not be able to widen idle timeouts or retention windows.
    if id != acl.org_id {
        return Err(AppError::Forbidden(
            "cannot mutate another org's config".into(),
        ));
    }

    if !(MIN_IDLE_TIMEOUT_SECS..=MAX_IDLE_TIMEOUT_SECS).contains(&req.subagent_idle_timeout_secs) {
        return Err(AppError::BadRequest(format!(
            "subagent_idle_timeout_secs must be between {MIN_IDLE_TIMEOUT_SECS} and {MAX_IDLE_TIMEOUT_SECS} (4h–60d)"
        )));
    }
    if !(MIN_RETENTION_DAYS..=MAX_RETENTION_DAYS).contains(&req.subagent_archive_retention_days) {
        return Err(AppError::BadRequest(format!(
            "subagent_archive_retention_days must be between {MIN_RETENTION_DAYS} and {MAX_RETENTION_DAYS}"
        )));
    }

    let org = overslash_db::repos::org::update_subagent_cleanup_config(
        state.db(&ext),
        id,
        req.subagent_idle_timeout_secs,
        req.subagent_archive_retention_days,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("org not found".into()))?;

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db_pool(&ext))
        .log_audit(AuditEntry {
            org_id: org.id,
            identity_id: acl.identity_id,
            action: "org.subagent_cleanup_config.updated",
            resource_type: Some("org"),
            resource_id: Some(org.id),
            detail: serde_json::json!({
                "subagent_idle_timeout_secs": org.subagent_idle_timeout_secs,
                "subagent_archive_retention_days": org.subagent_archive_retention_days,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(org.into()))
}

#[derive(Deserialize)]
pub(super) struct PatchTemplateSettingsRequest {
    /// `none` | `restrictive` | `full` — whether members may create
    /// user-namespace layers.
    user_template_policy: Option<String>,
    global_templates_enabled: Option<bool>,
    /// When false (default), non-admins cannot instantiate global templates
    /// that fall outside the org's curated catalog.
    allow_services_outside_catalog: Option<bool>,
}

#[derive(Serialize)]
pub(super) struct TemplateSettingsResponse {
    user_template_policy: String,
    global_templates_enabled: bool,
    allow_services_outside_catalog: bool,
}

/// Accepted values for `user_template_policy`.
const USER_TEMPLATE_POLICIES: [&str; 3] = ["none", "restrictive", "full"];

/// Read the org's template/catalog settings. Admin-only: these govern which
/// global templates members can see and instantiate.
pub(super) async fn get_template_settings(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    AdminAcl(acl): AdminAcl,
    Path(id): Path<Uuid>,
) -> Result<Json<TemplateSettingsResponse>> {
    if id != acl.org_id {
        return Err(AppError::Forbidden(
            "cannot read another org's config".into(),
        ));
    }

    let settings = overslash_db::repos::org::get_template_settings(state.db(&ext), id)
        .await?
        .ok_or_else(|| AppError::NotFound("org not found".into()))?;

    Ok(Json(TemplateSettingsResponse {
        user_template_policy: settings.user_template_policy,
        global_templates_enabled: settings.global_templates_enabled,
        allow_services_outside_catalog: settings.allow_services_outside_catalog,
    }))
}

pub(super) async fn patch_template_settings(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    AdminAcl(acl): AdminAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<PatchTemplateSettingsRequest>,
) -> Result<Json<TemplateSettingsResponse>> {
    if id != acl.org_id {
        return Err(AppError::Forbidden(
            "cannot mutate another org's config".into(),
        ));
    }

    if req.user_template_policy.is_none()
        && req.global_templates_enabled.is_none()
        && req.allow_services_outside_catalog.is_none()
    {
        return Err(AppError::BadRequest("no fields supplied".into()));
    }

    if let Some(policy) = &req.user_template_policy
        && !USER_TEMPLATE_POLICIES.contains(&policy.as_str())
    {
        return Err(AppError::BadRequest(format!(
            "user_template_policy must be one of {USER_TEMPLATE_POLICIES:?}"
        )));
    }

    let settings = overslash_db::repos::org::update_template_settings(
        state.db(&ext),
        id,
        req.user_template_policy.as_deref(),
        req.global_templates_enabled,
        req.allow_services_outside_catalog,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("org not found".into()))?;

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db_pool(&ext))
        .log_audit(AuditEntry {
            org_id: id,
            identity_id: acl.identity_id,
            action: "org.template_settings.updated",
            resource_type: Some("org"),
            resource_id: Some(id),
            detail: serde_json::json!({
                "user_template_policy": settings.user_template_policy,
                "global_templates_enabled": settings.global_templates_enabled,
                "allow_services_outside_catalog": settings.allow_services_outside_catalog,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(TemplateSettingsResponse {
        user_template_policy: settings.user_template_policy,
        global_templates_enabled: settings.global_templates_enabled,
        allow_services_outside_catalog: settings.allow_services_outside_catalog,
    }))
}

// ─── Secret-request settings (User Signed Mode) ───────────────────────

#[derive(Serialize)]
pub(super) struct SecretRequestSettingsResponse {
    /// When false, every newly-minted secret-request URL will carry
    /// `require_user_session = true`, blocking anonymous submission on the
    /// public provide page. Outstanding URLs minted while this was true
    /// remain anonymous-capable — the toggle is forward-only.
    allow_unsigned_secret_provide: bool,
}

#[derive(Deserialize)]
pub(super) struct PatchSecretRequestSettingsRequest {
    allow_unsigned_secret_provide: bool,
}

pub(super) async fn get_secret_request_settings(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<SecretRequestSettingsResponse>> {
    if id != auth.org_id {
        return Err(AppError::Forbidden("cannot read another org".into()));
    }
    let allow = overslash_db::repos::org::get_allow_unsigned_secret_provide(state.db(&ext), id)
        .await?
        .ok_or_else(|| AppError::NotFound("org not found".into()))?;
    Ok(Json(SecretRequestSettingsResponse {
        allow_unsigned_secret_provide: allow,
    }))
}

pub(super) async fn patch_secret_request_settings(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    AdminAcl(acl): AdminAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<PatchSecretRequestSettingsRequest>,
) -> Result<Json<SecretRequestSettingsResponse>> {
    if id != acl.org_id {
        return Err(AppError::Forbidden(
            "cannot mutate another org's config".into(),
        ));
    }

    let updated = overslash_db::repos::org::set_allow_unsigned_secret_provide(
        state.db(&ext),
        id,
        req.allow_unsigned_secret_provide,
    )
    .await?;
    if !updated {
        return Err(AppError::NotFound("org not found".into()));
    }

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db_pool(&ext))
        .log_audit(AuditEntry {
            org_id: id,
            identity_id: acl.identity_id,
            action: "org.secret_request_settings.updated",
            resource_type: Some("org"),
            resource_id: Some(id),
            detail: serde_json::json!({
                "allow_unsigned_secret_provide": req.allow_unsigned_secret_provide,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(SecretRequestSettingsResponse {
        allow_unsigned_secret_provide: req.allow_unsigned_secret_provide,
    }))
}

// ─── Execution settings (auto-call-on-approve org default) ──────────────

#[derive(Serialize)]
pub(super) struct ExecutionSettingsResponse {
    /// When `true`, newly-created agents in this org are seeded with
    /// `auto_call_on_approve = false` — they require an explicit
    /// `POST /v1/approvals/{id}/call` after a resolver allows the
    /// approval. Existing agents are not touched when this flag flips;
    /// per-agent overrides win for them. Default: `false` (auto-call on).
    default_deferred_execution: bool,
    /// Default upstream timeout for action calls in this org, in ms.
    /// `null` inherits the deployment default (`CALL_TIMEOUT_MS`).
    /// A template action or an individual call still overrides it.
    call_timeout_ms: Option<i32>,
    /// Ceiling on any resolved call timeout in this org, in ms. `null`
    /// inherits `CALL_TIMEOUT_MAX_MS`. A caller asking for more is
    /// rejected; a template or org *default* above it is clamped.
    max_call_timeout_ms: Option<i32>,
}

/// Partial patch: an absent key leaves the setting alone.
///
/// The two timeouts are `Option<Option<i32>>` because they are genuinely
/// three-valued — absent, explicit `null` (clear it, back to the deployment
/// default), or a number. A plain `Option` would make "clear it" unexpressible,
/// leaving an org permanently pinned to whatever it once set.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PatchExecutionSettingsRequest {
    #[serde(default)]
    default_deferred_execution: Option<bool>,
    #[serde(default, deserialize_with = "double_option")]
    call_timeout_ms: Option<Option<i32>>,
    #[serde(default, deserialize_with = "double_option")]
    max_call_timeout_ms: Option<Option<i32>>,
}

/// Distinguish an absent key from an explicit `null`.
///
/// `#[serde(default)]` alone collapses both to `None`; this makes a present
/// `null` deserialize to `Some(None)`.
fn double_option<'de, D, T>(de: D) -> std::result::Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Deserialize::deserialize(de).map(Some)
}

pub(super) async fn get_execution_settings(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<ExecutionSettingsResponse>> {
    if id != auth.org_id {
        return Err(AppError::Forbidden("cannot read another org".into()));
    }
    let value = overslash_db::repos::org::get_default_deferred_execution(state.db(&ext), id)
        .await?
        .ok_or_else(|| AppError::NotFound("org not found".into()))?;
    let timeouts = overslash_db::repos::org::get_call_settings(state.db(&ext), id)
        .await?
        .ok_or_else(|| AppError::NotFound("org not found".into()))?;
    Ok(Json(ExecutionSettingsResponse {
        default_deferred_execution: value,
        call_timeout_ms: timeouts.call_timeout_ms,
        max_call_timeout_ms: timeouts.max_call_timeout_ms,
    }))
}

pub(super) async fn patch_execution_settings(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    AdminAcl(acl): AdminAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<PatchExecutionSettingsRequest>,
) -> Result<Json<ExecutionSettingsResponse>> {
    if id != acl.org_id {
        return Err(AppError::Forbidden(
            "cannot mutate another org's config".into(),
        ));
    }

    // Validate at the boundary, so the DB CHECK is never the thing that
    // rejects bad input.
    for (label, value) in [
        ("call_timeout_ms", req.call_timeout_ms),
        ("max_call_timeout_ms", req.max_call_timeout_ms),
    ] {
        if let Some(Some(ms)) = value
            && !(MIN_CALL_TIMEOUT_MS..=MAX_CALL_TIMEOUT_MS).contains(&ms)
        {
            return Err(AppError::BadRequest(format!(
                "{label} must be between {MIN_CALL_TIMEOUT_MS} and {MAX_CALL_TIMEOUT_MS} ms"
            )));
        }
    }

    // The cross-field rule spans a value this patch may not mention, so the
    // read, the check and the write happen together under a row lock inside
    // the repo — validating here against a separate read would let two
    // concurrent patches each pass on stale state and leave the second to
    // trip the DB CHECK as a 500.
    let outcome = overslash_db::repos::org::update_execution_settings(
        state.db(&ext),
        id,
        req.default_deferred_execution,
        req.call_timeout_ms.is_some(),
        req.call_timeout_ms.flatten(),
        req.max_call_timeout_ms.is_some(),
        req.max_call_timeout_ms.flatten(),
    )
    .await?;

    use overslash_db::repos::org::ExecutionSettingsUpdate;
    let (next_deferred, next_call, next_max) = match outcome {
        ExecutionSettingsUpdate::NotFound => {
            return Err(AppError::NotFound("org not found".into()));
        }
        ExecutionSettingsUpdate::WouldViolateBounds {
            call_timeout_ms,
            max_call_timeout_ms,
        } => {
            return Err(AppError::BadRequest(format!(
                "call_timeout_ms ({}) cannot exceed max_call_timeout_ms ({})",
                call_timeout_ms.unwrap_or_default(),
                max_call_timeout_ms.unwrap_or_default()
            )));
        }
        ExecutionSettingsUpdate::Applied {
            default_deferred_execution,
            call_timeout_ms,
            max_call_timeout_ms,
        } => (
            default_deferred_execution,
            call_timeout_ms,
            max_call_timeout_ms,
        ),
    };

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db_pool(&ext))
        .log_audit(AuditEntry {
            org_id: id,
            identity_id: acl.identity_id,
            action: "org.execution_settings.updated",
            resource_type: Some("org"),
            resource_id: Some(id),
            detail: serde_json::json!({
                "default_deferred_execution": next_deferred,
                "call_timeout_ms": next_call,
                "max_call_timeout_ms": next_max,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(ExecutionSettingsResponse {
        default_deferred_execution: next_deferred,
        call_timeout_ms: next_call,
        max_call_timeout_ms: next_max,
    }))
}

// ─── Audit settings (response body capture mode) ────────────────────────

#[derive(Serialize)]
pub(super) struct AuditSettingsResponse {
    /// Whether `action.executed` audit rows persist the upstream response
    /// body: `"off"` (default) stores nothing, `"errors_only"` stores
    /// bodies when the normalized `detail.is_error` flag is true, `"all"`
    /// stores every captured body. Bodies are truncated at
    /// `AUDIT_RESPONSE_BODY_MAX_BYTES` (default 64 KB).
    response_body_mode: String,
}

#[derive(Deserialize)]
pub(super) struct PatchAuditSettingsRequest {
    response_body_mode: String,
}

pub(super) async fn get_audit_settings(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<AuditSettingsResponse>> {
    if id != auth.org_id {
        return Err(AppError::Forbidden("cannot read another org".into()));
    }
    let value = overslash_db::repos::org::get_audit_response_body_mode(state.db(&ext), id)
        .await?
        .ok_or_else(|| AppError::NotFound("org not found".into()))?;
    Ok(Json(AuditSettingsResponse {
        response_body_mode: value,
    }))
}

pub(super) async fn patch_audit_settings(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    AdminAcl(acl): AdminAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<PatchAuditSettingsRequest>,
) -> Result<Json<AuditSettingsResponse>> {
    if id != acl.org_id {
        return Err(AppError::Forbidden(
            "cannot mutate another org's config".into(),
        ));
    }

    // Parse at the boundary so the DB CHECK constraint is never the thing
    // that rejects bad input.
    let mode = AuditResponseBodyMode::parse(&req.response_body_mode).ok_or_else(|| {
        AppError::BadRequest("response_body_mode must be one of: off, errors_only, all".into())
    })?;

    let updated =
        overslash_db::repos::org::set_audit_response_body_mode(state.db(&ext), id, mode.as_str())
            .await?;
    if !updated {
        return Err(AppError::NotFound("org not found".into()));
    }

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db_pool(&ext))
        .log_audit(AuditEntry {
            org_id: id,
            identity_id: acl.identity_id,
            action: "org.audit_settings.updated",
            resource_type: Some("org"),
            resource_id: Some(id),
            detail: serde_json::json!({
                "response_body_mode": mode.as_str(),
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(AuditSettingsResponse {
        response_body_mode: mode.as_str().to_string(),
    }))
}

// ─── Managed sign-in (Overslash-managed env-var IdPs, invite-gated) ───

#[derive(Serialize)]
pub(super) struct ManagedSigninResponse {
    /// When `true`, members can authenticate via Overslash's managed env-var
    /// OAuth apps (`GOOGLE_AUTH_*`, etc.). Admission is then gated by either
    /// invites or the domain allowlist below — see migration 066/092 and
    /// `crates/overslash-api/src/routes/auth.rs::provision_org_subdomain`.
    allow_overslash_managed_signin: bool,
    /// When `true` (default), a managed-signin org admits invite-only. When
    /// `false`, admission falls back to `managed_signin_allowed_domains`.
    require_invite_admission: bool,
    /// Org-wide email-domain allowlist for the managed path when
    /// `require_invite_admission = false`. Empty ⇒ domain admission is
    /// unconfigured (managed sign-ins are rejected as misconfigured).
    managed_signin_allowed_domains: Vec<String>,
}

impl From<&overslash_db::repos::org::OrgRow> for ManagedSigninResponse {
    fn from(o: &overslash_db::repos::org::OrgRow) -> Self {
        Self {
            allow_overslash_managed_signin: o.allow_overslash_managed_signin,
            require_invite_admission: o.require_invite_admission,
            managed_signin_allowed_domains: o.managed_signin_allowed_domains.clone(),
        }
    }
}

#[derive(Deserialize)]
pub(super) struct PatchManagedSigninRequest {
    /// All three fields are optional so the dashboard can flip one toggle at
    /// a time; a `None` leaves the stored value untouched.
    allow_overslash_managed_signin: Option<bool>,
    require_invite_admission: Option<bool>,
    managed_signin_allowed_domains: Option<Vec<String>>,
}

/// Normalize an admin-supplied domain list: lowercase, trim surrounding
/// whitespace, strip a leading `@` (so `@acme.com` and `acme.com` both work),
/// drop empties, and dedupe while preserving order. Admission compares
/// case-insensitively, but storing a canonical form keeps the API/UI honest.
fn normalize_domains(raw: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for d in raw {
        let cleaned = d.trim().trim_start_matches('@').to_lowercase();
        if cleaned.is_empty() {
            continue;
        }
        if seen.insert(cleaned.clone()) {
            out.push(cleaned);
        }
    }
    out
}

pub(super) async fn get_managed_signin(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<ManagedSigninResponse>> {
    if id != auth.org_id {
        return Err(AppError::Forbidden("cannot read another org".into()));
    }
    let org = overslash_db::repos::org::get_by_id(state.db(&ext), id)
        .await?
        .ok_or_else(|| AppError::NotFound("org not found".into()))?;
    Ok(Json((&org).into()))
}

pub(super) async fn patch_managed_signin(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    AdminAcl(acl): AdminAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<PatchManagedSigninRequest>,
) -> Result<Json<ManagedSigninResponse>> {
    if id != acl.org_id {
        return Err(AppError::Forbidden(
            "cannot mutate another org's config".into(),
        ));
    }

    let normalized_domains = req
        .managed_signin_allowed_domains
        .as_deref()
        .map(normalize_domains);

    let org = overslash_db::repos::org::update_managed_admission(
        state.db(&ext),
        id,
        req.allow_overslash_managed_signin,
        req.require_invite_admission,
        normalized_domains.as_deref(),
    )
    .await?
    .ok_or_else(|| AppError::NotFound("org not found".into()))?;

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db_pool(&ext))
        .log_audit(AuditEntry {
            org_id: id,
            identity_id: acl.identity_id,
            action: "org.managed_signin.updated",
            resource_type: Some("org"),
            resource_id: Some(id),
            detail: serde_json::json!({
                "allow_overslash_managed_signin": org.allow_overslash_managed_signin,
                "require_invite_admission": org.require_invite_admission,
                "managed_signin_allowed_domains": org.managed_signin_allowed_domains,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json((&org).into()))
}

// ─── Headless (white-label, URL-less auth-recovery) ───

#[derive(Serialize)]
pub(super) struct HeadlessResponse {
    /// When `true`, this is a white-label org whose end users have no Overslash
    /// dashboard session. Auth-recovery on an action call (`reauth_required`,
    /// `needs_authentication`, `missing_scopes`) returns a typed, URL-less
    /// envelope (no gated `/connect-authorize` link, no `oauth_connection_flows`
    /// row); the integration re-runs its own OAuth dance and re-imports via
    /// `POST /v1/connections/import`. Admin/provisioning-only — a partner
    /// onboarding capability with no end-user surface (no dashboard toggle).
    headless: bool,
}

#[derive(Deserialize)]
pub(super) struct PatchHeadlessRequest {
    headless: bool,
}

pub(super) async fn get_headless(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<HeadlessResponse>> {
    if id != auth.org_id {
        return Err(AppError::Forbidden("cannot read another org".into()));
    }
    let value = overslash_db::repos::org::get_headless(state.db(&ext), id)
        .await?
        .ok_or_else(|| AppError::NotFound("org not found".into()))?;
    Ok(Json(HeadlessResponse { headless: value }))
}

pub(super) async fn patch_headless(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    AdminAcl(acl): AdminAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<PatchHeadlessRequest>,
) -> Result<Json<HeadlessResponse>> {
    if id != acl.org_id {
        return Err(AppError::Forbidden(
            "cannot mutate another org's config".into(),
        ));
    }

    let updated = overslash_db::repos::org::set_headless(state.db(&ext), id, req.headless).await?;
    if !updated {
        return Err(AppError::NotFound("org not found".into()));
    }

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db_pool(&ext))
        .log_audit(AuditEntry {
            org_id: id,
            identity_id: acl.identity_id,
            action: "org.headless.updated",
            resource_type: Some("org"),
            resource_id: Some(id),
            detail: serde_json::json!({ "headless": req.headless }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(HeadlessResponse {
        headless: req.headless,
    }))
}
