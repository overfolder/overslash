//! Org membership role management — promote/demote an existing member to/from
//! org admin. Admin-gated. The mutation is atomic and keeps all three admin
//! signals (`user_org_memberships.role`, the per-identity `is_org_admin` flag,
//! and `Admins`-group membership) in lock-step via
//! [`identity::set_org_member_admin`] — the same primitive the invite-accept
//! path uses when an invited "admin" is provisioned. Without the flag + group
//! a role='admin' membership does NOT pass `AdminAcl` (see `extractors.rs`).

use axum::{
    Json, Router,
    extract::{Path, State},
    routing::patch,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use overslash_db::OrgScope;
use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::identity::{self, SetOrgMemberAdminOutcome};
use overslash_db::repos::membership;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, ClientIp, ReqExt},
};

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/org-members/{identity_id}", patch(update_member_role))
}

#[derive(Deserialize)]
struct UpdateMemberRoleRequest {
    /// Target role: `"admin"` or `"member"`.
    role: String,
}

#[derive(Serialize)]
struct MemberRoleResponse {
    identity_id: Uuid,
    user_id: Uuid,
    role: String,
    is_org_admin: bool,
}

/// PATCH /v1/org-members/{identity_id} — promote or demote a user member.
///
/// `{identity_id}` is a user-kind identity (the shape the Members page holds).
/// We resolve it to the human `user_id` and flip both the membership role and
/// the per-identity admin flag/group across every identity that human holds in
/// the org. Refuses to demote the org's last admin (including self-demotion).
async fn update_member_role(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(identity_id): Path<Uuid>,
    Json(req): Json<UpdateMemberRoleRequest>,
) -> Result<Json<MemberRoleResponse>> {
    let make_admin = match req.role.as_str() {
        membership::ROLE_ADMIN => true,
        membership::ROLE_MEMBER => false,
        _ => {
            return Err(AppError::BadRequest(
                "role must be 'admin' or 'member'".into(),
            ));
        }
    };

    // Resolve the target identity → its human `user_id`. Only user-kind members
    // carry a membership role; agents/sub-agents have none.
    let ident = scope
        .get_identity(identity_id)
        .await?
        .ok_or_else(|| AppError::NotFound("member not found".into()))?;
    if ident.kind != "user" {
        return Err(AppError::BadRequest(
            "only user members can be promoted or demoted".into(),
        ));
    }
    let user_id = ident
        .user_id
        .ok_or_else(|| AppError::BadRequest("member has no linked user account".into()))?;

    match identity::set_org_member_admin(state.db(&ext), scope.org_id(), user_id, make_admin)
        .await?
    {
        SetOrgMemberAdminOutcome::NotFound => {
            Err(AppError::NotFound("member is not part of this org".into()))
        }
        SetOrgMemberAdminOutcome::LastAdmin => Err(AppError::BadRequest(
            "cannot demote the last admin of the org".into(),
        )),
        SetOrgMemberAdminOutcome::Updated { changed } => {
            if changed {
                let _ = scope
                    .log_audit(AuditEntry {
                        org_id: scope.org_id(),
                        identity_id: acl.identity_id,
                        action: if make_admin {
                            "org_member.promoted"
                        } else {
                            "org_member.demoted"
                        },
                        resource_type: Some("identity"),
                        resource_id: Some(identity_id),
                        detail: json!({ "user_id": user_id, "role": req.role }),
                        description: Some(&format!(
                            "{} {}",
                            if make_admin { "Promoted" } else { "Demoted" },
                            ident.name
                        )),
                        ip_address: ip.0.as_deref(),
                    })
                    .await;
            }
            Ok(Json(MemberRoleResponse {
                identity_id,
                user_id,
                role: if make_admin {
                    membership::ROLE_ADMIN
                } else {
                    membership::ROLE_MEMBER
                }
                .to_string(),
                is_org_admin: make_admin,
            }))
        }
    }
}
