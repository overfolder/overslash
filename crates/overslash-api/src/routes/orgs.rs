use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, patch, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::{identity, membership, user as user_repo};

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, AuthContext, ClientIp, SessionAuth},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/orgs", post(create_org))
        .route("/v1/orgs/{id}", get(get_org).patch(patch_org))
        .route(
            "/v1/orgs/{id}/subagent-cleanup-config",
            patch(patch_subagent_cleanup_config),
        )
        .route(
            "/v1/orgs/{id}/template-settings",
            patch(patch_template_settings),
        )
        .route(
            "/v1/orgs/{id}/secret-request-settings",
            get(get_secret_request_settings).patch(patch_secret_request_settings),
        )
}

// Bounds for sub-agent idle cleanup config (per replan).
// Floor: 4h. Ceiling: 60d.
const MIN_IDLE_TIMEOUT_SECS: i32 = 4 * 60 * 60; // 14_400
const MAX_IDLE_TIMEOUT_SECS: i32 = 60 * 24 * 60 * 60; // 5_184_000
const MIN_RETENTION_DAYS: i32 = 1;
const MAX_RETENTION_DAYS: i32 = 60;

#[derive(Deserialize)]
struct CreateOrgRequest {
    name: String,
    slug: String,
}

#[derive(Serialize)]
struct OrgResponse {
    id: Uuid,
    name: String,
    slug: String,
    subagent_idle_timeout_secs: i32,
    subagent_archive_retention_days: i32,
    is_personal: bool,
    /// Absolute URL the dashboard should hard-reload to after creation —
    /// points at the new org's subdomain so the creator lands inside their
    /// bootstrap-admin session rather than bouncing through the switcher.
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect_to: Option<String>,
}

impl From<overslash_db::repos::org::OrgRow> for OrgResponse {
    fn from(o: overslash_db::repos::org::OrgRow) -> Self {
        Self {
            id: o.id,
            name: o.name,
            slug: o.slug,
            subagent_idle_timeout_secs: o.subagent_idle_timeout_secs,
            subagent_archive_retention_days: o.subagent_archive_retention_days,
            is_personal: o.is_personal,
            redirect_to: None,
        }
    }
}

/// POST /v1/orgs — create a corp org. The caller becomes an Overslash-backed
/// bootstrap admin (`is_bootstrap=true`), which persists as breakglass even
/// after the org configures its own IdP. This is the ONLY path by which an
/// Overslash-level IdP grants membership into a non-personal org. See
/// `docs/design/multi_org_auth.md` §Corp Org Creation Bootstrap.
async fn create_org(
    State(state): State<AppState>,
    ip: ClientIp,
    session: SessionAuth,
    Json(req): Json<CreateOrgRequest>,
) -> Result<Json<OrgResponse>> {
    // Self-hosted lockdown: operators can disable creation after initial
    // setup. Env flag parsed once at startup; default true.
    if !state.config.allow_org_creation {
        return Err(AppError::Forbidden("org_creation_disabled".into()));
    }

    let user_id = session.user_id.ok_or_else(|| {
        AppError::Unauthorized("session has no user_id; sign in again after the rewire".into())
    })?;
    let user = user_repo::get_by_id(&state.db, user_id)
        .await?
        .ok_or_else(|| AppError::Unauthorized("session user no longer exists".into()))?;

    let org = overslash_db::repos::org::create(&state.db, &req.name, &req.slug).await?;

    // Create an identity in the new org for the creator so permission checks
    // downstream have something to bind to. is_org_admin=true so bootstrap
    // grants flow through the existing admin fast-path in OrgAcl.
    let display_name = user
        .display_name
        .clone()
        .unwrap_or_else(|| user.email.clone().unwrap_or_else(|| "admin".into()));
    let metadata = serde_json::json!({ "bootstrap": true });
    let creator_identity = identity::create_with_email(
        &state.db,
        org.id,
        &display_name,
        "user",
        None,
        user.email.as_deref(),
        metadata,
    )
    .await?;
    // Link the identity back to the human and flag admin.
    identity::set_is_org_admin(&state.db, org.id, creator_identity.id, true).await?;
    identity::set_user_id(&state.db, org.id, creator_identity.id, Some(user_id)).await?;

    // Bootstrap system assets (overslash service, groups, grants) and place
    // the creator in Everyone + Admins.
    overslash_db::repos::org_bootstrap::bootstrap_org(&state.db, org.id, Some(creator_identity.id))
        .await?;

    // Breakglass membership — `is_bootstrap=true` so the dashboard can label
    // it in the admins list and the caller can drop it once their IdP-backed
    // account exists.
    membership::create(
        &state.db,
        user_id,
        org.id,
        membership::ROLE_ADMIN,
        /* is_bootstrap = */ true,
    )
    .await?;

    let bootstrap_scope = overslash_db::OrgScope::new(org.id, state.db.clone());
    let _ = bootstrap_scope
        .log_audit(AuditEntry {
            org_id: org.id,
            identity_id: Some(creator_identity.id),
            action: "org.created",
            resource_type: Some("org"),
            resource_id: Some(org.id),
            detail: serde_json::json!({
                "name": &org.name,
                "slug": &org.slug,
                "bootstrap_user_id": user_id,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    let redirect_to = redirect_for_org(&state, &org);
    let mut resp: OrgResponse = org.into();
    resp.redirect_to = Some(redirect_to);
    Ok(Json(resp))
}

fn redirect_for_org(state: &AppState, org: &overslash_db::repos::org::OrgRow) -> String {
    let scheme = if state.config.public_url.starts_with("https://") {
        "https"
    } else {
        "http"
    };
    if let Some(apex) = state.config.app_host_suffix.as_deref() {
        format!("{scheme}://{}.{apex}/", org.slug)
    } else {
        state.config.dashboard_url_for("/")
    }
}

async fn get_org(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<OrgResponse>> {
    if id != auth.org_id {
        return Err(AppError::Forbidden("cannot read another org".into()));
    }
    let org = overslash_db::repos::org::get_by_id(&state.db, id)
        .await?
        .ok_or_else(|| AppError::NotFound("org not found".into()))?;
    Ok(Json(org.into()))
}

#[derive(Deserialize)]
struct PatchOrgRequest {
    // Reserved for future use; currently no top-level org fields are mutable here.
    // Sub-agent cleanup config is mutated via its own endpoint for clarity.
}

async fn patch_org(
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
struct PatchCleanupConfigRequest {
    subagent_idle_timeout_secs: i32,
    subagent_archive_retention_days: i32,
}

async fn patch_subagent_cleanup_config(
    State(state): State<AppState>,
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
        &state.db,
        id,
        req.subagent_idle_timeout_secs,
        req.subagent_archive_retention_days,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("org not found".into()))?;

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db.clone())
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
struct PatchTemplateSettingsRequest {
    allow_user_templates: Option<bool>,
    global_templates_enabled: Option<bool>,
}

#[derive(Serialize)]
struct TemplateSettingsResponse {
    allow_user_templates: bool,
    global_templates_enabled: bool,
}

async fn patch_template_settings(
    State(state): State<AppState>,
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

    if req.allow_user_templates.is_none() && req.global_templates_enabled.is_none() {
        return Err(AppError::BadRequest("no fields supplied".into()));
    }

    let (allow, globals) = overslash_db::repos::org::update_template_settings(
        &state.db,
        id,
        req.allow_user_templates,
        req.global_templates_enabled,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("org not found".into()))?;

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db.clone())
        .log_audit(AuditEntry {
            org_id: id,
            identity_id: acl.identity_id,
            action: "org.template_settings.updated",
            resource_type: Some("org"),
            resource_id: Some(id),
            detail: serde_json::json!({
                "allow_user_templates": allow,
                "global_templates_enabled": globals,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(TemplateSettingsResponse {
        allow_user_templates: allow,
        global_templates_enabled: globals,
    }))
}

// ─── Secret-request settings (User Signed Mode) ───────────────────────

#[derive(Serialize)]
struct SecretRequestSettingsResponse {
    /// When false, every newly-minted secret-request URL will carry
    /// `require_user_session = true`, blocking anonymous submission on the
    /// public provide page. Outstanding URLs minted while this was true
    /// remain anonymous-capable — the toggle is forward-only.
    allow_unsigned_secret_provide: bool,
}

#[derive(Deserialize)]
struct PatchSecretRequestSettingsRequest {
    allow_unsigned_secret_provide: bool,
}

async fn get_secret_request_settings(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<SecretRequestSettingsResponse>> {
    if id != auth.org_id {
        return Err(AppError::Forbidden("cannot read another org".into()));
    }
    let allow = overslash_db::repos::org::get_allow_unsigned_secret_provide(&state.db, id)
        .await?
        .ok_or_else(|| AppError::NotFound("org not found".into()))?;
    Ok(Json(SecretRequestSettingsResponse {
        allow_unsigned_secret_provide: allow,
    }))
}

async fn patch_secret_request_settings(
    State(state): State<AppState>,
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
        &state.db,
        id,
        req.allow_unsigned_secret_provide,
    )
    .await?;
    if !updated {
        return Err(AppError::NotFound("org not found".into()));
    }

    let _ = overslash_db::OrgScope::new(acl.org_id, state.db.clone())
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
