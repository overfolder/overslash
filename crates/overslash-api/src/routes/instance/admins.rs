//! Instance admins: list, grant, revoke, and the user search behind the Grant
//! dialog.
//!
//! Only users with a root-domain (Overslash IdP) login can hold the role —
//! the `users_instance_admin_requires_overslash_idp` CHECK. Users known only
//! through one org's own IdP are listed by the search but marked ineligible.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use overslash_db::repos::instance_admin::{self, GrantOutcome, RevokeOutcome};

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{ClientIp, InstanceAdminAuth, ReqExt},
};

#[derive(Serialize)]
pub(super) struct InstanceAdmin {
    user_id: Uuid,
    email: Option<String>,
    name: Option<String>,
    /// Root IdP the user signs in with (`google`, `github`, `email`, …).
    provider: Option<String>,
    /// Unix seconds. `None` = bootstrapped out-of-band (psql).
    granted_at: Option<i64>,
    granted_by_email: Option<String>,
    /// Unix seconds.
    last_seen_at: Option<i64>,
    is_you: bool,
}

pub(super) async fn list(
    admin: InstanceAdminAuth,
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
) -> Result<Json<Vec<InstanceAdmin>>> {
    let rows = instance_admin::list_admins(state.db(&ext)).await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| InstanceAdmin {
                is_you: r.user_id == admin.user_id,
                user_id: r.user_id,
                email: r.email,
                name: r.display_name,
                provider: r.overslash_idp_provider,
                granted_at: r.granted_at.map(OffsetDateTime::unix_timestamp),
                granted_by_email: r.granted_by_email,
                last_seen_at: r.last_seen_at.map(OffsetDateTime::unix_timestamp),
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub(super) struct SearchQuery {
    #[serde(default)]
    q: String,
}

#[derive(Serialize)]
pub(super) struct UserResult {
    id: Uuid,
    email: Option<String>,
    name: Option<String>,
    provider: Option<String>,
    is_instance_admin: bool,
    eligible: bool,
    /// Why the user can't be granted, when `eligible` is false.
    reason: Option<String>,
}

pub(super) async fn search_users(
    _admin: InstanceAdminAuth,
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    Query(q): Query<SearchQuery>,
) -> Result<Json<Vec<UserResult>>> {
    let q = q.q.trim();
    // Two characters before searching: a one-letter ILIKE over every user on
    // the instance is a dump, not a search.
    if q.chars().count() < 2 {
        return Ok(Json(Vec::new()));
    }
    let rows = instance_admin::search_users(state.db(&ext), q, 20).await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| {
                let eligible = r.overslash_idp_provider.is_some();
                let reason = (!eligible).then(|| match &r.any_org_name {
                    Some(org) => format!("Signs in only through {org}'s identity provider"),
                    None => "Has no Overslash sign-in".to_string(),
                });
                UserResult {
                    id: r.id,
                    email: r.email,
                    name: r.display_name,
                    provider: r.overslash_idp_provider,
                    is_instance_admin: r.is_instance_admin,
                    eligible,
                    reason,
                }
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub(super) struct GrantRequest {
    user_id: Uuid,
}

pub(super) async fn grant(
    admin: InstanceAdminAuth,
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    ip: ClientIp,
    Json(req): Json<GrantRequest>,
) -> Result<StatusCode> {
    let email = target_email(&state, &ext, req.user_id).await;
    let mut tx = state.db(&ext).begin().await?;
    let outcome = instance_admin::grant(&mut tx, req.user_id, admin.user_id).await?;
    match outcome {
        GrantOutcome::Granted => {}
        GrantOutcome::AlreadyAdmin => return Ok(StatusCode::NO_CONTENT),
        GrantOutcome::NotFound => return Err(AppError::NotFound("user not found".into())),
        GrantOutcome::NotEligible => return Err(AppError::BadRequest("not_eligible".into())),
    }
    instance_admin::log(
        &mut *tx,
        &instance_admin::InstanceAuditEntry {
            actor_user_id: admin.user_id,
            action: "instance_admin.granted",
            org_id: None,
            detail: serde_json::json!({ "user_id": req.user_id, "email": email }),
            ip_address: ip.0.as_deref(),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn revoke(
    admin: InstanceAdminAuth,
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    ip: ClientIp,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode> {
    let email = target_email(&state, &ext, user_id).await;
    let mut tx = state.db(&ext).begin().await?;
    match instance_admin::revoke(&mut tx, user_id).await? {
        RevokeOutcome::Revoked => {}
        RevokeOutcome::NotAdmin => {
            return Err(AppError::NotFound("not an instance admin".into()));
        }
        RevokeOutcome::LastAdmin => {
            return Err(AppError::Conflict("last_instance_admin".into()));
        }
    }
    instance_admin::log(
        &mut *tx,
        &instance_admin::InstanceAuditEntry {
            actor_user_id: admin.user_id,
            action: "instance_admin.revoked",
            org_id: None,
            detail: serde_json::json!({ "user_id": user_id, "email": email }),
            ip_address: ip.0.as_deref(),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The target's email for the audit detail, so the row still names them after
/// the user is gone.
async fn target_email(
    state: &AppState,
    ext: &axum::http::Extensions,
    user_id: Uuid,
) -> Option<String> {
    overslash_db::repos::user::get_by_id(state.db(ext), user_id)
        .await
        .ok()
        .flatten()
        .and_then(|u| u.email)
}
