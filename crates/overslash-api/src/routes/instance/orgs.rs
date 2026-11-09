//! `GET /v1/instance/orgs` and `POST /v1/instance/orgs`.
//!
//! Plan and trial changes on an existing org stay on their original routes
//! (`PATCH /v1/orgs/{id}/plan`, `POST`/`PATCH /v1/orgs/{id}/trial`); this
//! module only lists orgs and creates them.

use axum::{
    Json,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use overslash_db::repos::instance_admin;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{ClientIp, InstanceAdminAuth, ReqExt},
};

#[derive(Deserialize)]
pub(super) struct ListQuery {
    #[serde(default)]
    include_personal: bool,
}

#[derive(Serialize)]
pub(super) struct InstanceOrg {
    id: Uuid,
    name: String,
    slug: String,
    plan: String,
    /// Unix seconds. Set only while `plan = 'trial'`.
    trial_ends_at: Option<i64>,
    is_personal: bool,
    member_count: i64,
    /// Unix seconds.
    last_activity_at: Option<i64>,
    /// Unix seconds.
    created_at: i64,
}

#[derive(Serialize)]
pub(super) struct ListResponse {
    orgs: Vec<InstanceOrg>,
    /// `TRIAL_DEFAULT_DURATION_DAYS`, so the Manage Plan dialog can prefill it.
    trial_default_duration_days: u32,
    allow_org_creation: bool,
}

pub(super) async fn list(
    _admin: InstanceAdminAuth,
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    Query(q): Query<ListQuery>,
) -> Result<Json<ListResponse>> {
    let rows = instance_admin::list_orgs(state.db(&ext), q.include_personal).await?;
    Ok(Json(ListResponse {
        orgs: rows
            .into_iter()
            .map(|r| InstanceOrg {
                id: r.id,
                name: r.name,
                slug: r.slug,
                plan: r.plan,
                trial_ends_at: r.trial_ends_at.map(OffsetDateTime::unix_timestamp),
                is_personal: r.is_personal,
                member_count: r.member_count,
                last_activity_at: r.last_activity_at.map(OffsetDateTime::unix_timestamp),
                created_at: r.created_at.unix_timestamp(),
            })
            .collect(),
        trial_default_duration_days: state.config.trial_default_duration_days,
        allow_org_creation: state.config.allow_org_creation,
    }))
}

#[derive(Deserialize)]
pub(super) struct CreateRequest {
    name: String,
    slug: String,
    /// `standard`, `trial` or `free_unlimited`.
    plan: String,
    /// Trial length when `plan = 'trial'`. Defaults to
    /// `TRIAL_DEFAULT_DURATION_DAYS`.
    #[serde(default)]
    trial_days: Option<u32>,
}

/// Create an org with any plan. The instance admin becomes its bootstrap admin
/// so it is never orphaned, but their session stays where it is.
pub(super) async fn create(
    admin: InstanceAdminAuth,
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    ip: ClientIp,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateRequest>,
) -> Result<axum::response::Response> {
    let trial_ends_at = match req.plan.as_str() {
        "standard" | "free_unlimited" => None,
        "trial" => {
            let days = req
                .trial_days
                .unwrap_or(state.config.trial_default_duration_days);
            if !(1..=3650).contains(&days) {
                return Err(AppError::BadRequest(
                    "trial_days must be between 1 and 3650".into(),
                ));
            }
            Some(OffsetDateTime::now_utc() + time::Duration::days(days as i64))
        }
        _ => {
            return Err(AppError::BadRequest(
                "plan must be 'standard', 'trial' or 'free_unlimited'".into(),
            ));
        }
    };
    crate::routes::orgs::create_for_instance_admin(
        &state,
        &ext,
        &headers,
        ip,
        admin.user_id,
        crate::routes::orgs::NewOrgSpec {
            name: &req.name,
            slug: &req.slug,
            plan: &req.plan,
            trial_ends_at,
        },
    )
    .await
}
