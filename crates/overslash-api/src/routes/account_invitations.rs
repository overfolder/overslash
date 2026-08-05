//! The invitee's view of org invitations — "which orgs invited *me*".
//!
//! The mirror image of `routes/org_invites.rs`, which is admin-only and
//! org-scoped and answers "who did *this org* invite". These routes are keyed
//! on the caller's verified email instead of on an org, so they deliberately
//! reach across org boundaries: an invitation is, by definition, from an org
//! the caller is not yet a member of.
//!
//! Trust model. The email match is the whole authorization story, so it must
//! use an email the *IdP* asserted, not one an org admin can write:
//! `identities.email` is admin-writable (that is how an invite is created),
//! while `users.email` is refreshed from IdP userinfo on every sign-in. We
//! therefore resolve the caller's email from their `users` row via the
//! session's `user_id` claim, never from `claims.email` — which on an org
//! subdomain is the org-side identity email.
//!
//! Accepting here links the pending identity to the caller's `users` row
//! without any IdP round-trip against the target org, so it is gated on the
//! org having opted into Overslash-managed sign-in. An org that runs its own
//! IdP still admits through that IdP on its own subdomain; we surface the
//! invitation, but the accept has to happen there.

use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;

use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::identity::IdentityRow;
use overslash_db::repos::{membership, org, user as user_repo};
use overslash_db::{OrgScope, SystemScope};

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{ClientIp, ReqExt, SessionAuth},
};

use super::org_invites::is_pending_invite;
use super::util::fmt_time;

/// `archived_reason` stamped on an invitation the invitee turned down.
/// Declining archives the pre-created identity rather than deleting it: the
/// row can own an agent subtree, archive is the reversible primitive, and the
/// reason keeps a declined invite distinguishable from a removed member in the
/// audit trail.
const REASON_DECLINED: &str = "invite_declined";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/account/invitations", get(list_invitations))
        .route(
            "/v1/account/invitations/{id}/accept",
            post(accept_invitation),
        )
        .route(
            "/v1/account/invitations/{id}/decline",
            post(decline_invitation),
        )
}

#[derive(Serialize)]
pub(crate) struct InvitationResponse {
    /// The pending identity's id. Opaque to the client: ownership is proven
    /// by the email match, so this is a handle, not an org-scope escape.
    pub id: Uuid,
    pub org_id: Uuid,
    pub org_name: String,
    pub org_slug: String,
    /// `"admin"` or `"member"` — the role the invitee will hold on accept.
    pub role: &'static str,
    pub created_at: String,
    /// `false` when the org runs its own IdP: the dashboard then links to
    /// `sign_in_url` instead of offering an in-place Accept, and `accept`
    /// rejects with `org_requires_idp_signin`.
    pub can_accept_in_place: bool,
    /// Where to sign in when accepting in place isn't allowed.
    pub sign_in_url: String,
}

/// Resolve the caller's IdP-verified email. `None` for legacy sessions with
/// no `user_id` claim and for users whose `users` row carries no email —
/// both yield an empty invitation list rather than a fallback to the
/// admin-writable identity email.
async fn verified_email(
    state: &AppState,
    ext: &axum::http::Extensions,
    session: &SessionAuth,
) -> Result<Option<(Uuid, String)>> {
    let Some(user_id) = session.user_id else {
        return Ok(None);
    };
    let Some(user) = user_repo::get_by_id(state.db(ext), user_id).await? else {
        return Ok(None);
    };
    Ok(user
        .email
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty())
        .map(|e| (user_id, e)))
}

/// Can this org admit a member without an IdP round-trip on its own
/// subdomain? Mirrors the admission gate in
/// `auth::provisioning::provision_org_subdomain`: managed sign-in means
/// Overslash-level IdPs are the trust boundary, and in single-org mode the
/// self-hosted operator's env-var IdP is.
fn can_accept_in_place(state: &AppState, org_row: &org::OrgRow) -> bool {
    let single_org = state
        .config
        .single_org_mode
        .as_deref()
        .map(|pinned| pinned == org_row.slug)
        .unwrap_or(false);
    org_row.allow_overslash_managed_signin || single_org
}

/// Every pending invitation addressed to the caller, shaped for the wire.
/// Shared with `/auth/me/identity`, which embeds the same list so the shell
/// needs no extra round trip.
pub(crate) async fn list_pending_invitations(
    state: &AppState,
    ext: &axum::http::Extensions,
    session: &SessionAuth,
) -> Result<Vec<InvitationResponse>> {
    let Some((user_id, email)) = verified_email(state, ext, session).await? else {
        return Ok(Vec::new());
    };

    let rows = SystemScope::new_internal(state.db_pool(ext))
        .list_pending_invitations_for_email(&email)
        .await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(org_row) = org::get_by_id(state.db(ext), row.org_id).await? else {
            continue; // Org deleted out from under the invite.
        };
        // A personal org is nobody's to join, and an existing membership means
        // this is a stale duplicate row rather than a live invitation.
        if org_row.is_personal {
            continue;
        }
        if membership::find(state.db(ext), user_id, org_row.id)
            .await?
            .is_some()
        {
            continue;
        }
        out.push(InvitationResponse {
            id: row.id,
            org_id: org_row.id,
            org_name: org_row.name.clone(),
            org_slug: org_row.slug.clone(),
            role: if row.is_org_admin {
                membership::ROLE_ADMIN
            } else {
                membership::ROLE_MEMBER
            },
            created_at: fmt_time(row.created_at),
            can_accept_in_place: can_accept_in_place(state, &org_row),
            sign_in_url: crate::routes::auth::build_org_redirect(state, &org_row),
        });
    }
    Ok(out)
}

async fn list_invitations(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    session: SessionAuth,
) -> Result<Json<Vec<InvitationResponse>>> {
    Ok(Json(
        list_pending_invitations(&state, &ext, &session).await?,
    ))
}

/// Re-resolve an invitation by id under the caller's verified email.
///
/// Returns 404 — never 403 — when the id doesn't belong to the caller: a
/// wrong-owner probe must not confirm that the invitation exists. Also
/// re-asserts `is_pending_invite` so a row that was accepted, declined, or
/// revoked between the list and the click can't be acted on twice.
async fn resolve_owned_invitation(
    state: &AppState,
    ext: &axum::http::Extensions,
    session: &SessionAuth,
    id: Uuid,
) -> Result<(Uuid, String, IdentityRow, org::OrgRow)> {
    let not_found = || AppError::NotFound("invitation not found".into());

    let (user_id, email) = verified_email(state, ext, session)
        .await?
        .ok_or_else(not_found)?;
    let row = SystemScope::new_internal(state.db_pool(ext))
        .list_pending_invitations_for_email(&email)
        .await?
        .into_iter()
        .find(|r| r.id == id)
        .filter(is_pending_invite)
        .ok_or_else(not_found)?;
    let org_row = org::get_by_id(state.db(ext), row.org_id)
        .await?
        .ok_or_else(not_found)?;
    if org_row.is_personal {
        return Err(not_found());
    }
    Ok((user_id, email, row, org_row))
}

/// POST /v1/account/invitations/{id}/accept — join the org from the current
/// session. The caller ends up a full member; the dashboard then calls
/// `/auth/switch-org` to get a session scoped to the new org.
async fn accept_invitation(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    session: SessionAuth,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let (user_id, email, row, org_row) =
        resolve_owned_invitation(&state, &ext, &session, id).await?;

    if !can_accept_in_place(&state, &org_row) {
        // The org gates admission on its own IdP. Accepting here would admit
        // the caller on the strength of an Overslash-level login the org
        // never opted into. Send them to the org's own sign-in instead.
        return Err(AppError::Forbidden("org_requires_idp_signin".into()));
    }

    crate::services::invite_adoption::adopt_pending_identity(
        &state,
        &ext,
        &org_row,
        &row,
        user_id,
        &email,
        crate::services::invite_adoption::AdoptionVia::InAppAccept,
    )
    .await?;

    Ok(Json(json!({
        "org_id": org_row.id,
        "slug": org_row.slug,
    })))
}

/// POST /v1/account/invitations/{id}/decline — turn the invitation down.
/// Archives the pre-created identity, which drops it from both the invitee's
/// list and the admin's Invites card and frees the email for a fresh invite.
async fn decline_invitation(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    session: SessionAuth,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let (_user_id, email, row, org_row) =
        resolve_owned_invitation(&state, &ext, &session, id).await?;

    // Scope the write to the *target* org — the caller's session org is a
    // different tenant entirely, and every identity write goes through an
    // org-bounded scope.
    let target_scope = OrgScope::new(org_row.id, state.db_pool(&ext));
    let archived = target_scope
        .archive_identity(row.id, Some(REASON_DECLINED))
        .await?
        .is_some();

    if archived {
        let role = if row.is_org_admin {
            membership::ROLE_ADMIN
        } else {
            membership::ROLE_MEMBER
        };
        let _ = target_scope
            .log_audit(AuditEntry {
                org_id: org_row.id,
                identity_id: Some(row.id),
                action: "org_invite.declined",
                resource_type: Some("identity"),
                resource_id: Some(row.id),
                detail: json!({ "email": &email, "role": role }),
                description: Some(&format!("{email} declined their invitation")),
                ip_address: ip.0.as_deref(),
            })
            .await;
    }

    Ok(Json(json!({ "declined": archived })))
}
