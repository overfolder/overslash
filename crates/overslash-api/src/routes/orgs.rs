use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, header},
    response::IntoResponse,
    routing::{get, patch, post},
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::{identity, membership, user as user_repo};

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, AuthContext, ClientIp},
    routes::auth::{session_cookie, signing_key_bytes},
    services::jwt,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/orgs", post(create_org))
        .route("/v1/orgs/check-slug", get(check_slug))
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

/// Slug rejection reason, kept as a stable string so the dashboard can render
/// human-readable copy without string-matching error messages.
#[derive(Debug, Clone, Copy)]
enum SlugReject {
    TooShort,
    TooLong,
    InvalidChars,
    LeadingOrTrailingHyphen,
    Reserved,
}

impl SlugReject {
    fn code(self) -> &'static str {
        match self {
            SlugReject::TooShort => "slug_too_short",
            SlugReject::TooLong => "slug_too_long",
            SlugReject::InvalidChars => "slug_invalid_chars",
            SlugReject::LeadingOrTrailingHyphen => "slug_leading_or_trailing_hyphen",
            SlugReject::Reserved => "slug_reserved",
        }
    }
}

const SLUG_MIN: usize = 2;
// DNS label max is 63 octets. We use the slug as a subdomain label, so
// anything above that cannot be represented as `<slug>.<apex>`.
const SLUG_MAX: usize = 63;

/// Subdomains we can't route to an org because the middleware already
/// reserves them for the root apex or operator-controlled hosts. Keep in
/// sync with `middleware::subdomain`.
const RESERVED_SLUGS: &[&str] = &[
    "www",
    "app",
    "api",
    "auth",
    "admin",
    "dashboard",
    "root",
    "static",
    "mcp",
];

/// Validate slug format without touching the DB. Mirrors DNS-label rules and
/// the dashboard's client-side check.
/// Public wrapper used by the billing route to validate a slug before Stripe
/// round-trips. Returns the rejection code as a static str on error.
pub(crate) fn validate_slug_format_pub(slug: &str) -> std::result::Result<(), &'static str> {
    validate_slug_format(slug).map_err(|r| r.code())
}

fn validate_slug_format(slug: &str) -> std::result::Result<(), SlugReject> {
    if slug.len() < SLUG_MIN {
        return Err(SlugReject::TooShort);
    }
    if slug.len() > SLUG_MAX {
        return Err(SlugReject::TooLong);
    }
    if !slug
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(SlugReject::InvalidChars);
    }
    if slug.starts_with('-') || slug.ends_with('-') {
        return Err(SlugReject::LeadingOrTrailingHyphen);
    }
    if RESERVED_SLUGS.contains(&slug) {
        return Err(SlugReject::Reserved);
    }
    Ok(())
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

/// POST /v1/orgs — create an org. Behavior depends on who's calling:
///
/// * **Multi-org session present** (Overslash-backed user, `user_id` claim
///   set) → attach the caller as a regular `admin` member + an admin
///   identity in the new org. This is the canonical cloud path — see
///   `docs/design/multi_org_auth.md` §Org Creation. The creator's
///   Overslash-backed login continues to work against the new org
///   indefinitely; the org may choose to configure its own IdP later, at
///   which point other humans join through that IdP while the creator
///   retains their root-login access via this membership.
/// * **No session** → create the org without any human attached. Legacy
///   bootstrap entrypoint used by provisioning scripts and the test harness
///   (the first org on a fresh deployment). Subsequent members join
///   through the org's IdP configured afterwards.
///
/// Gated in both cases by `ALLOW_ORG_CREATION` so self-hosted operators can
/// lock the surface after initial setup.
async fn create_org(
    State(state): State<AppState>,
    ip: ClientIp,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateOrgRequest>,
) -> Result<axum::response::Response> {
    if !state.config.allow_org_creation {
        return Err(AppError::Forbidden("org_creation_disabled".into()));
    }

    // In cloud billing mode, all org creation through this HTTP route is
    // blocked: Team orgs go through Stripe Checkout, personal orgs are
    // auto-provisioned during the auth signup flow (which calls the DB
    // layer directly, not this route). There is intentionally no escape
    // hatch here — letting the request flag personal would let attackers
    // bypass billing.
    if state.config.cloud_billing {
        return Err(AppError::Forbidden("team_org_requires_subscription".into()));
    }

    let name = req.name.trim();
    if name.is_empty() {
        return Err(AppError::BadRequest("name is required".into()));
    }
    if let Err(reject) = validate_slug_format(&req.slug) {
        return Err(AppError::BadRequest(reject.code().into()));
    }

    let org = match overslash_db::repos::org::create(&state.db, name, &req.slug).await {
        Ok(row) => row,
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(AppError::Conflict("slug_taken".into()));
        }
        Err(e) => return Err(e.into()),
    };

    // Optional session: if the caller presents a valid `oss_session` with a
    // multi-org `user_id` claim, attach the bootstrap admin. Otherwise the
    // org is created anonymously (legacy + test-harness path).
    let session_user_id = extract_optional_session_user(&state, &headers);

    // The follow-up writes (identity create, admin flag, bootstrap_org
    // system-asset seeding, membership row) each run in their own sqlx
    // transactions — sqlx doesn't nest, so a single outer tx isn't
    // available without refactoring `bootstrap_org`. Instead we roll our
    // own compensating-rollback: if any step after `org::create` fails,
    // delete the org (which cascades to identities / memberships /
    // groups / service_instances / group_grants) and surface the error.
    let bootstrap_result: Result<Option<Uuid>> =
        provision_new_org_contents(&state, org.id, session_user_id).await;
    let bootstrap_identity_id = match bootstrap_result {
        Ok(id) => id,
        Err(e) => {
            // Best-effort cleanup. If this also fails we leave a dangling
            // org row, but that's strictly better than the half-bootstrapped
            // state; admins can sweep manually. The audit log entry below
            // is skipped in this branch.
            if let Err(cleanup_err) = sqlx::query!("DELETE FROM orgs WHERE id = $1", org.id)
                .execute(&state.db)
                .await
            {
                tracing::error!(
                    org_id = %org.id,
                    bootstrap_error = %e,
                    cleanup_error = %cleanup_err,
                    "create_org rollback failed; manual cleanup required"
                );
            }
            return Err(e);
        }
    };

    let bootstrap_scope = overslash_db::OrgScope::new(org.id, state.db.clone());
    let _ = bootstrap_scope
        .log_audit(AuditEntry {
            org_id: org.id,
            identity_id: bootstrap_identity_id,
            action: "org.created",
            resource_type: Some("org"),
            resource_id: Some(org.id),
            detail: serde_json::json!({
                "name": &org.name,
                "slug": &org.slug,
                "bootstrap_user_id": session_user_id.map(|u| u.to_string()),
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    let redirect_to = redirect_for_org(&state, &org);
    let mut resp: OrgResponse = org.into();
    resp.redirect_to = Some(redirect_to);

    // Re-mint the session cookie scoped to the new org when the caller came
    // in with a multi-org session. Without this, the client redirects to
    // the new subdomain and the old JWT's `org` claim trips the
    // subdomain↔JWT guard (`org_mismatch` 401), forcing an extra switch-org
    // round-trip. Anonymous creators keep no session.
    let mut response_headers = HeaderMap::new();
    if let (Some(user_id), Some(identity_id)) = (session_user_id, bootstrap_identity_id) {
        let jwt_secret = signing_key_bytes(&state.config.signing_key);
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let claims = jwt::Claims {
            sub: identity_id,
            org: resp.id,
            email: user_repo::get_by_id(&state.db, user_id)
                .await?
                .and_then(|u| u.email)
                .unwrap_or_default(),
            aud: jwt::AUD_SESSION.into(),
            iat: now,
            exp: now + 7 * 24 * 3600,
            user_id: Some(user_id),
            mcp_client_id: None,
        };
        let token = jwt::mint(&jwt_secret, &claims)
            .map_err(|e| AppError::Internal(format!("jwt mint failed: {e}")))?;
        response_headers.insert(header::SET_COOKIE, session_cookie(&state, &token)?);
    }

    Ok((response_headers, Json(resp)).into_response())
}

#[derive(Deserialize)]
struct CheckSlugQuery {
    slug: String,
}

#[derive(Serialize)]
struct CheckSlugResponse {
    available: bool,
    reason: Option<&'static str>,
}

/// GET /v1/orgs/check-slug?slug=xxx — live-validate a slug for the create-org
/// form. Unauthenticated: slugs are effectively public (subdomain probing
/// reveals the same info) and the dashboard needs this before a session
/// exists for first-time cloud signups.
async fn check_slug(
    State(state): State<AppState>,
    Query(q): Query<CheckSlugQuery>,
) -> Json<CheckSlugResponse> {
    if let Err(reject) = validate_slug_format(&q.slug) {
        return Json(CheckSlugResponse {
            available: false,
            reason: Some(reject.code()),
        });
    }
    match overslash_db::repos::org::get_by_slug(&state.db, &q.slug).await {
        Ok(Some(_)) => Json(CheckSlugResponse {
            available: false,
            reason: Some("slug_taken"),
        }),
        Ok(None) => Json(CheckSlugResponse {
            available: true,
            reason: None,
        }),
        Err(_) => Json(CheckSlugResponse {
            available: false,
            reason: Some("lookup_failed"),
        }),
    }
}

/// Best-effort session lookup. Returns Some(user_id) only when the cookie
/// verifies AND carries a `user_id` claim — legacy tokens and unauthed
/// callers fall through to None and the handler creates the org without a
/// bootstrap admin.
fn extract_optional_session_user(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Option<Uuid> {
    let cookie = headers.get("cookie").and_then(|v| v.to_str().ok())?;
    let token = cookie
        .split(';')
        .map(str::trim)
        .find_map(|kv| kv.strip_prefix("oss_session="))?;
    let signing_key = hex::decode(&state.config.signing_key)
        .unwrap_or_else(|_| state.config.signing_key.as_bytes().to_vec());
    let claims =
        crate::services::jwt::verify(&signing_key, token, crate::services::jwt::AUD_SESSION)
            .ok()?;
    claims.user_id
}

pub(crate) async fn provision_new_org_contents(
    state: &AppState,
    org_id: Uuid,
    session_user_id: Option<Uuid>,
) -> Result<Option<Uuid>> {
    match session_user_id {
        Some(user_id) => {
            let user = user_repo::get_by_id(&state.db, user_id)
                .await?
                .ok_or_else(|| AppError::Unauthorized("session user no longer exists".into()))?;
            let display_name = user
                .display_name
                .clone()
                .unwrap_or_else(|| user.email.clone().unwrap_or_else(|| "admin".into()));
            let creator_identity = identity::create_with_email(
                &state.db,
                org_id,
                &display_name,
                "user",
                None,
                user.email.as_deref(),
                serde_json::json!({ "bootstrap": true }),
            )
            .await?;
            identity::set_is_org_admin(&state.db, org_id, creator_identity.id, true).await?;
            identity::set_user_id(&state.db, org_id, creator_identity.id, Some(user_id)).await?;

            overslash_db::repos::org_bootstrap::bootstrap_org(
                &state.db,
                org_id,
                Some(creator_identity.id),
            )
            .await?;
            membership::create(&state.db, user_id, org_id, membership::ROLE_ADMIN).await?;
            Ok(Some(creator_identity.id))
        }
        None => {
            overslash_db::repos::org_bootstrap::bootstrap_org(&state.db, org_id, None).await?;
            Ok(None)
        }
    }
}

pub(crate) fn redirect_for_org(state: &AppState, org: &overslash_db::repos::org::OrgRow) -> String {
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
