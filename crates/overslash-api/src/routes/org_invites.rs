//! `org_invites` admin CRUD — now a thin projection over `identities`.
//!
//! A "pending invite" is a `kind='user'` identity that has never completed a
//! sign-in (`external_id IS NULL`). Creating one is the membership gate for
//! orgs that opt into Overslash-managed sign-in: the OAuth callback admits an
//! email only if such an identity already exists, then adopts it by setting
//! its `external_id`. See `auth.rs::provision_org_subdomain` and
//! `docs/design/multi_org_auth.md`. The `org_invites` table was dropped by
//! migration 103; these routes keep their wire shape for existing callers.

use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use overslash_db::OrgScope;
use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::identity::IdentityRow;
use overslash_db::repos::{identity, membership, org, user};

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, ClientIp, ReqExt},
};

use super::util::{fmt_time, validate_email};

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
    /// Must be `"admin"` or `"member"`.
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

/// Project a pre-created member identity onto the invite wire shape.
/// `pending` while the person has never signed in (`external_id IS NULL`);
/// `accepted` once an SSO callback adopted the identity.
impl From<IdentityRow> for InviteResponse {
    fn from(row: IdentityRow) -> Self {
        let accepted = row.external_id.is_some();
        let role = if row.is_org_admin {
            membership::ROLE_ADMIN
        } else {
            membership::ROLE_MEMBER
        };
        let invited_by = row
            .metadata
            .get("invited_by")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok());
        Self {
            id: row.id,
            org_id: row.org_id,
            email: row.email.unwrap_or_default(),
            role: role.to_string(),
            invited_by,
            created_at: fmt_time(row.created_at),
            // The identity has no distinct "accepted at" column; its first
            // sign-in stamps `updated_at`, which is the closest signal.
            accepted_at: accepted.then(|| fmt_time(row.updated_at)),
            accepted_by_user_id: row.user_id,
            status: if accepted { "accepted" } else { "pending" },
        }
    }
}

async fn create_invite(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    AdminAcl(acl): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Json(req): Json<CreateInviteRequest>,
) -> Result<Json<InviteResponse>> {
    let email = validate_email(&req.email)?;

    // Server-side mirror of the old DB CHECK so callers get a clear 400.
    if req.role != membership::ROLE_ADMIN && req.role != membership::ROLE_MEMBER {
        return Err(AppError::BadRequest(
            "role must be 'admin' or 'member'".into(),
        ));
    }

    // One user identity per email in an org. A live match — pending or an
    // already-signed-in member — is a 409, matching the old "a pending invite
    // already exists" behaviour and covering "they're already a member".
    if scope
        .find_user_identity_by_email_in_org(&email)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict(format!(
            "a member or pending invite for '{email}' already exists"
        )));
    }

    // Provenance: who minted the invite. Stored on the identity metadata so
    // the projection can surface `invited_by` without a side table.
    let metadata = match acl.identity_id {
        Some(id) => json!({ "invited_by": id.to_string() }),
        None => json!({}),
    };
    let name = email.split('@').next().unwrap_or(&email).to_string();
    let row = scope
        .create_identity_with_email(&name, "user", None, Some(&email), metadata)
        .await?;

    // Everyone + Myself, exactly like any other user-identity creation path.
    overslash_db::repos::org_bootstrap::bootstrap_user_in_org(
        state.db(&ext),
        scope.org_id(),
        row.id,
    )
    .await?;

    // Admin invites become real org admins on creation: Admins-group
    // membership + the `is_org_admin` flag, via the same primitive the
    // promote-member endpoint uses.
    if req.role == membership::ROLE_ADMIN {
        identity::set_is_org_admin(state.db(&ext), scope.org_id(), row.id, true).await?;
    }

    let _ = scope
        .log_audit(AuditEntry {
            org_id: scope.org_id(),
            identity_id: acl.identity_id,
            action: "org_invite.created",
            resource_type: Some("identity"),
            resource_id: Some(row.id),
            detail: json!({ "email": &email, "role": &req.role }),
            description: Some(&format!("Invited {email} as {}", req.role)),
            ip_address: ip.0.as_deref(),
        })
        .await;

    // Best-effort notification email; all failures are logged and swallowed
    // so a mailer hiccup never fails invite creation.
    match org::get_by_id(state.db(&ext), scope.org_id()).await {
        Ok(Some(org_row)) => {
            let inviter_name = match acl.identity_id {
                Some(id) => resolve_inviter_display_name(&state, &ext, scope.org_id(), id).await,
                None => None,
            };
            crate::services::invite_email::send(
                &state,
                &email,
                &req.role,
                row.id,
                &org_row,
                inviter_name.as_deref(),
            )
            .await;
        }
        Ok(None) => {
            tracing::warn!(
                org_id = %scope.org_id(),
                "org-invite email skipped: org row not found",
            );
        }
        Err(e) => {
            tracing::warn!(
                org_id = %scope.org_id(),
                error = %e,
                "org-invite email skipped: org lookup failed",
            );
        }
    }

    // Re-read so the response reflects the admin flag / groups we just set.
    let fresh = scope.get_identity(row.id).await?.unwrap_or(row);
    Ok(Json(fresh.into()))
}

/// Best-effort lookup of the inviter's display name for the email body.
/// Resolves identity → user → display_name. Returns `None` (caller falls
/// back to a generic label) for API-key identities with no linked user.
async fn resolve_inviter_display_name(
    state: &AppState,
    ext: &axum::http::Extensions,
    org_id: Uuid,
    identity_id: Uuid,
) -> Option<String> {
    let identity_row = identity::get_by_id(state.db(ext), org_id, identity_id)
        .await
        .ok()
        .flatten()?;
    let user_id = identity_row.user_id?;
    let user_row = user::get_by_id(state.db(ext), user_id)
        .await
        .ok()
        .flatten()?;
    user_row
        .display_name
        .filter(|s| !s.trim().is_empty())
        .or_else(|| user_row.email.filter(|s| !s.trim().is_empty()))
}

/// Pending + accepted pre-created members expose PII (emails) and the org's
/// role grants — admin-only, same as create/delete.
async fn list_invites(
    AdminAcl(_acl): AdminAcl,
    scope: OrgScope,
) -> Result<Json<Vec<InviteResponse>>> {
    // Pending members only — a `user` identity that carries an email but has
    // never signed in (`external_id IS NULL`). An *accepted* invite is now
    // indistinguishable from any other member (both have an email AND an IdP
    // subject), so returning them here would list the entire org — including
    // every SSO-provisioned member, which all carry an email. Accepted
    // members belong on the Members page; this endpoint stays "who is invited
    // but hasn't joined yet".
    let rows = scope.list_identities().await?;
    let out: Vec<InviteResponse> = rows
        .into_iter()
        .filter(|r| {
            r.kind == "user"
                && r.archived_at.is_none()
                && r.email.is_some()
                && r.external_id.is_none()
        })
        .map(InviteResponse::from)
        .collect();
    Ok(Json(out))
}

async fn get_invite(
    AdminAcl(_acl): AdminAcl,
    scope: OrgScope,
    Path(id): Path<Uuid>,
) -> Result<Json<InviteResponse>> {
    let row = scope
        .get_identity(id)
        .await?
        .filter(|r| r.kind == "user")
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
    // request races us. Only a *pending* identity (never signed in) is
    // revocable here — once adopted, removing the member is a Members-page
    // action, so an accepted identity returns `deleted: false`.
    let existing = scope.get_identity(id).await?.filter(|r| r.kind == "user");

    // Use the leaf-safe delete, not a raw `DELETE`: a pending member who was
    // pre-created by name-based impersonation can already own an agent
    // subtree (`alice@acme.com/henry/...`), and `identities.parent_id` is
    // `ON DELETE CASCADE` — a bare delete would silently wipe those agents.
    // Refuse with 409 instead so the admin deals with the subtree first.
    let deleted = match &existing {
        Some(row) if row.external_id.is_none() => match scope.delete_identity_leaf(id).await? {
            overslash_db::repos::identity::DeleteLeafOutcome::Deleted => true,
            overslash_db::repos::identity::DeleteLeafOutcome::NotFound => false,
            overslash_db::repos::identity::DeleteLeafOutcome::HasChildren => {
                return Err(AppError::Conflict(
                        "this pending member has agents provisioned under them; delete or move those first".into(),
                    ));
            }
        },
        _ => false,
    };

    if deleted {
        if let Some(row) = existing {
            let email = row.email.unwrap_or_default();
            let role = if row.is_org_admin {
                membership::ROLE_ADMIN
            } else {
                membership::ROLE_MEMBER
            };
            let _ = scope
                .log_audit(AuditEntry {
                    org_id: scope.org_id(),
                    identity_id: acl.identity_id,
                    action: "org_invite.revoked",
                    resource_type: Some("identity"),
                    resource_id: Some(id),
                    detail: json!({ "email": email, "role": role }),
                    description: Some(&format!("Revoked invite for {email}")),
                    ip_address: ip.0.as_deref(),
                })
                .await;
        }
    }

    Ok(Json(json!({ "deleted": deleted })))
}
