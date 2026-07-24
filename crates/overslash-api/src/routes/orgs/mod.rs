//! Org endpoints: creation and slug validation, instance-admin trial and
//! plan controls, and the per-org settings surfaces.

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
    extractors::{AdminAcl, AuthContext, ClientIp, InstanceAdminAuth, ReqExt},
    routes::auth::{session_cookie, signing_key_bytes},
    services::{audit_capture::AuditResponseBodyMode, jwt},
};

mod billing_admin;
mod create;
mod settings;
mod slug;

use billing_admin::{extend_trial, set_org_plan, start_trial};
use create::{check_slug, create_free_unlimited_org, create_org};
use settings::{
    get_audit_settings, get_execution_settings, get_headless, get_managed_signin, get_org,
    get_secret_request_settings, get_template_settings, patch_audit_settings,
    patch_execution_settings, patch_headless, patch_managed_signin, patch_org,
    patch_secret_request_settings, patch_subagent_cleanup_config, patch_template_settings,
};

// Re-exported at the historical `crate::routes::orgs::*` paths — the
// billing route imports these.
pub(crate) use create::{provision_new_org_contents, redirect_for_org};
pub(crate) use slug::validate_slug_format_pub;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/orgs", post(create_org))
        .route("/v1/orgs/free-unlimited", post(create_free_unlimited_org))
        .route("/v1/orgs/check-slug", get(check_slug))
        .route("/v1/orgs/{id}", get(get_org).patch(patch_org))
        .route(
            "/v1/orgs/{id}/subagent-cleanup-config",
            patch(patch_subagent_cleanup_config),
        )
        .route(
            "/v1/orgs/{id}/template-settings",
            get(get_template_settings).patch(patch_template_settings),
        )
        .route(
            "/v1/orgs/{id}/secret-request-settings",
            get(get_secret_request_settings).patch(patch_secret_request_settings),
        )
        .route(
            "/v1/orgs/{id}/execution-settings",
            get(get_execution_settings).patch(patch_execution_settings),
        )
        .route(
            "/v1/orgs/{id}/audit-settings",
            get(get_audit_settings).patch(patch_audit_settings),
        )
        .route(
            "/v1/orgs/{id}/managed-signin",
            get(get_managed_signin).patch(patch_managed_signin),
        )
        .route(
            "/v1/orgs/{id}/headless",
            get(get_headless).patch(patch_headless),
        )
        // Instance-admin-only trial controls. Not org-scoped by AdminAcl —
        // an instance admin acts on any org by id.
        .route("/v1/orgs/{id}/trial", post(start_trial).patch(extend_trial))
        .route("/v1/orgs/{id}/plan", patch(set_org_plan))
}

// Bounds for sub-agent idle cleanup config (per replan).
// Floor: 4h. Ceiling: 60d.
const MIN_IDLE_TIMEOUT_SECS: i32 = 4 * 60 * 60; // 14_400
const MAX_IDLE_TIMEOUT_SECS: i32 = 60 * 24 * 60 * 60; // 5_184_000
const MIN_RETENTION_DAYS: i32 = 1;
const MAX_RETENTION_DAYS: i32 = 60;

#[derive(Serialize)]
pub(super) struct OrgResponse {
    id: Uuid,
    name: String,
    slug: String,
    subagent_idle_timeout_secs: i32,
    subagent_archive_retention_days: i32,
    is_personal: bool,
    /// When `true`, this org accepts Overslash-managed sign-in (migration
    /// 066). Surfaced here so the dashboard can render the toggle's
    /// current state without a follow-up call.
    allow_overslash_managed_signin: bool,
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
            allow_overslash_managed_signin: o.allow_overslash_managed_signin,
            redirect_to: None,
        }
    }
}
