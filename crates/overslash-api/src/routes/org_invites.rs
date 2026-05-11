//! `org_invites` admin CRUD. Pending invites are the membership gate for
//! orgs that opt into Overslash-managed sign-in (migration 066): without
//! a matching invite the OAuth callback rejects with `not_invited`. See
//! `crates/overslash-api/src/routes/auth.rs::provision_org_subdomain` and
//! `docs/design/multi_org_auth.md`.

use axum::{
    Json, Router,
    extract::Path,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use overslash_db::OrgScope;
use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::membership;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, ClientIp},
};

use super::util::fmt_time;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/org-invites", post(create_invite).get(list_invites))
        .route(
            "/v1/org-invites/{id}",
            get(get_invite).delete(delete_invite),
        )
}

#[derive(Deserialize)]
struct CreateInviteRequest {
    email: String,
    /// Must be `"admin"` or `"member"`. Enforced both server-side and by
    /// the DB CHECK on `org_invites.role`.
    role: String,
}

#[derive(Serialize)]
struct InviteResponse {
    id: Uuid,
    org_id: Uuid,
    email: String,
    role: String,
    invited_by: Option<Uuid>,
    created_at: String,
    accepted_at: Option<String>,
    accepted_by_user_id: Option<Uuid>,
    status: &'static str,
}

impl From<overslash_db::repos::org_invite::OrgInviteRow> for InviteResponse {
    fn from(row: overslash_db::repos::org_invite::OrgInviteRow) -> Self {
        let status = if row.accepted_at.is_some() {
            "accepted"
        } else {
            "pending"
        };
        Self {
            id: row.id,
            org_id: row.org_id,
            email: row.email,
            role: row.role,
            invited_by: row.invited_by,
            created_at: fmt_time(row.created_at),
            accepted_at: row.accepted_at.map(fmt_time),
            accepted_by_user_id: row.accepted_by_user_id,
            status,
        }
    }
}

fn validate_email(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::BadRequest("email is required".into()));
    }
    // Cheap structural check — matches the dashboard's client-side gate.
    // Real verification comes from the IdP at callback time.
    if !trimmed.contains('@') || trimmed.contains(' ') {
        return Err(AppError::BadRequest("invalid email".into()));
    }
    Ok(trimmed.to_lowercase())
}

async fn create_invite(
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Json(req): Json<CreateInviteRequest>,
) -> Result<Json<InviteResponse>> {
    let email = validate_email(&req.email)?;

    // Server-side mirror of the DB CHECK so callers get a clear 400 instead
    // of a generic constraint-violation error.
    if req.role != membership::ROLE_ADMIN && req.role != membership::ROLE_MEMBER {
        return Err(AppError::BadRequest(
            "role must be 'admin' or 'member'".into(),
        ));
    }

    let row = scope
        .create_org_invite(&email, &req.role, acl.identity_id)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.is_unique_violation() {
                    return AppError::Conflict(format!(
                        "a pending invite for '{email}' already exists"
                    ));
                }
            }
            AppError::Database(e)
        })?;

    let _ = scope
        .log_audit(AuditEntry {
            org_id: scope.org_id(),
            identity_id: acl.identity_id,
            action: "org_invite.created",
            resource_type: Some("org_invite"),
            resource_id: Some(row.id),
            detail: json!({ "email": &row.email, "role": &row.role }),
            description: Some(&format!("Invited {} as {}", row.email, row.role)),
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(row.into()))
}

// Invite rows expose PII (invitee emails), the inviter's identity, and the
// org's pending role grants — admin-only on read for the same reason
// create/delete are.
async fn list_invites(
    AdminAcl(_acl): AdminAcl,
    scope: OrgScope,
) -> Result<Json<Vec<InviteResponse>>> {
    let rows = scope.list_org_invites().await?;
    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn get_invite(
    AdminAcl(_acl): AdminAcl,
    scope: OrgScope,
    Path(id): Path<Uuid>,
) -> Result<Json<InviteResponse>> {
    let row = scope
        .get_org_invite(id)
        .await?
        .ok_or_else(|| AppError::NotFound("invite not found".into()))?;
    Ok(Json(row.into()))
}

async fn delete_invite(
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    // Read first so the audit row carries the email/role even if another
    // request races us to the DELETE. The actual delete is gated on
    // `accepted_at IS NULL` by the repo helper, so accepted invites
    // return `deleted: false` (history preserved).
    let existing = scope.get_org_invite(id).await?;

    let deleted = scope.delete_org_invite(id).await?;

    if deleted {
        if let Some(row) = existing {
            let _ = scope
                .log_audit(AuditEntry {
                    org_id: scope.org_id(),
                    identity_id: acl.identity_id,
                    action: "org_invite.revoked",
                    resource_type: Some("org_invite"),
                    resource_id: Some(row.id),
                    detail: json!({ "email": row.email, "role": row.role }),
                    description: Some(&format!("Revoked invite for {}", row.email)),
                    ip_address: ip.0.as_deref(),
                })
                .await;
        }
    }

    Ok(Json(json!({ "deleted": deleted })))
}
