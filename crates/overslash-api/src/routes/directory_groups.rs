//! REST surface for directory groups: what the org's IdP has reported, and the
//! admin-owned mapping that turns it into Layer 1 group membership.
//!
//! Separate from `routes::groups` because the two answer different questions.
//! `groups.rs` manages ceilings; this manages a membership feed. Keeping the
//! feed out of `GET /v1/groups` is what stops an org with two hundred Okta
//! groups from burying the handful that actually carry grants.

use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::repos::audit::AuditEntry;
use overslash_db::scopes::OrgScope;

use super::util::fmt_time;
use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, ClientIp, ReqExt},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/directory-groups", get(list_directory_groups))
        .route(
            "/v1/groups/{id}/directory-sources",
            post(add_directory_source).get(list_directory_sources),
        )
        .route(
            "/v1/groups/{id}/directory-sources/{directory_group_id}",
            delete(remove_directory_source),
        )
        .route("/v1/groups/{id}/member-origins", get(list_member_origins))
}

// ── Request / response types ─────────────────────────────────────────

#[derive(Deserialize)]
struct AddDirectorySourceRequest {
    directory_group_id: Uuid,
}

#[derive(Serialize)]
struct DirectoryGroupResponse {
    id: Uuid,
    org_id: Uuid,
    /// The IdP config that reported this group, when it came from a login.
    #[serde(skip_serializing_if = "Option::is_none")]
    idp_config_id: Option<Uuid>,
    source: String,
    external_id: String,
    display_name: String,
    first_seen_at: String,
    last_seen_at: String,
}

#[derive(Serialize)]
struct DirectoryGroupSummaryResponse {
    id: Uuid,
    org_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    idp_config_id: Option<Uuid>,
    source: String,
    external_id: String,
    display_name: String,
    /// Humans the directory currently places in this group.
    member_count: i64,
    /// Overslash groups this directory group currently feeds. Empty means the
    /// group has been discovered but confers nothing.
    mapped_group_ids: Vec<Uuid>,
    first_seen_at: String,
    last_seen_at: String,
}

/// One member of a group and how they got there. A member can be both.
#[derive(Serialize)]
struct MemberOriginResponse {
    identity_id: Uuid,
    /// An `identity_groups` row exists — an admin put them here, and an admin
    /// can take them out.
    direct: bool,
    /// The directory groups routing this human in. Non-empty with
    /// `direct: false` means the dashboard must not offer a remove button.
    via_directory_group_ids: Vec<Uuid>,
}

// ── Handlers ─────────────────────────────────────────────────────────

/// Every directory group discovered in this org.
///
/// Readable by any member rather than admin-only, matching `GET /v1/groups`:
/// this is the org's own directory structure, which its members already know,
/// and seeing it is what lets a non-admin ask for the right mapping.
async fn list_directory_groups(
    scope: OrgScope,
) -> Result<Json<Vec<DirectoryGroupSummaryResponse>>> {
    let rows = scope.list_directory_groups().await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| DirectoryGroupSummaryResponse {
                id: r.id,
                org_id: r.org_id,
                idp_config_id: r.idp_config_id,
                source: r.source,
                external_id: r.external_id,
                display_name: r.display_name,
                member_count: r.member_count,
                mapped_group_ids: r.mapped_group_ids,
                first_seen_at: fmt_time(r.first_seen_at),
                last_seen_at: fmt_time(r.last_seen_at),
            })
            .collect(),
    ))
}

/// Map a directory group into an Overslash group.
///
/// This is the act that grants something: from here on, everyone the directory
/// places in `directory_group_id` holds `group_id`'s ceiling. Admin-only, and
/// refused for system groups.
async fn add_directory_source(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    AdminAcl(auth): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(group_id): Path<Uuid>,
    Json(req): Json<AddDirectorySourceRequest>,
) -> Result<Json<serde_json::Value>> {
    let grp = scope
        .get_group(group_id)
        .await?
        .ok_or_else(|| AppError::NotFound("group not found".into()))?;

    // System groups are not valid targets, and the reason differs per kind.
    //
    // *Admins* is the sharp one: membership there is held in lockstep with
    // `identities.is_org_admin` by `sync_admins_group_tx`. A mapping would let
    // an IdP group claim confer org-admin without ever setting the flag,
    // leaving the two views of "who is an admin" disagreeing — and making
    // admin a thing an IdP can hand out.
    //
    // *Myself* has exactly one member by construction, and *Everyone* already
    // contains every member of the org, so a mapping onto either is either
    // incoherent or a no-op.
    if grp.is_system {
        return Err(AppError::BadRequest(
            "system groups cannot take a directory source; map onto a group you created".into(),
        ));
    }

    let directory_group = scope
        .get_directory_group(req.directory_group_id)
        .await?
        .ok_or_else(|| AppError::NotFound("directory group not found".into()))?;

    let created = scope
        .add_group_directory_source(group_id, req.directory_group_id)
        .await?;

    if created {
        let _ = OrgScope::new(auth.org_id, state.db_pool(&ext))
            .log_audit(AuditEntry {
                org_id: auth.org_id,
                identity_id: auth.identity_id,
                action: "group_directory_source.created",
                resource_type: Some("group"),
                resource_id: Some(group_id),
                detail: serde_json::json!({
                    "group_id": group_id,
                    "group_name": &grp.name,
                    "directory_group_id": req.directory_group_id,
                    "directory_group_external_id": &directory_group.external_id,
                    "source": &directory_group.source,
                }),
                description: None,
                ip_address: ip.0.as_deref(),
            })
            .await;
    }

    Ok(Json(serde_json::json!({ "created": created })))
}

/// The directory groups feeding one Overslash group.
async fn list_directory_sources(
    scope: OrgScope,
    Path(group_id): Path<Uuid>,
) -> Result<Json<Vec<DirectoryGroupResponse>>> {
    scope
        .get_group(group_id)
        .await?
        .ok_or_else(|| AppError::NotFound("group not found".into()))?;

    let rows = scope.list_group_directory_sources(group_id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| DirectoryGroupResponse {
                id: r.id,
                org_id: r.org_id,
                idp_config_id: r.idp_config_id,
                source: r.source,
                external_id: r.external_id,
                display_name: r.display_name,
                first_seen_at: fmt_time(r.first_seen_at),
                last_seen_at: fmt_time(r.last_seen_at),
            })
            .collect(),
    ))
}

/// Unmap a directory group. Revocation is immediate — the next ceiling read
/// stops traversing this edge, with no sync or session refresh in between.
async fn remove_directory_source(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    AdminAcl(auth): AdminAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path((group_id, directory_group_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>> {
    let grp = scope
        .get_group(group_id)
        .await?
        .ok_or_else(|| AppError::NotFound("group not found".into()))?;

    let deleted = scope
        .remove_group_directory_source(group_id, directory_group_id)
        .await?;

    if deleted {
        let _ = OrgScope::new(auth.org_id, state.db_pool(&ext))
            .log_audit(AuditEntry {
                org_id: auth.org_id,
                identity_id: auth.identity_id,
                action: "group_directory_source.deleted",
                resource_type: Some("group"),
                resource_id: Some(group_id),
                detail: serde_json::json!({
                    "group_id": group_id,
                    "group_name": &grp.name,
                    "directory_group_id": directory_group_id,
                }),
                description: None,
                ip_address: ip.0.as_deref(),
            })
            .await;
    }

    Ok(Json(serde_json::json!({ "deleted": deleted })))
}

/// Members of a group, each tagged direct / via-directory / both.
///
/// A companion to `GET /v1/groups/{id}/members` rather than a change to it:
/// that endpoint returns a bare id list and is already consumed, so the origin
/// detail rides alongside instead of reshaping a live response.
async fn list_member_origins(
    scope: OrgScope,
    Path(group_id): Path<Uuid>,
) -> Result<Json<Vec<MemberOriginResponse>>> {
    scope
        .get_group(group_id)
        .await?
        .ok_or_else(|| AppError::NotFound("group not found".into()))?;

    let rows = scope.list_group_members_with_origin(group_id).await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| MemberOriginResponse {
                identity_id: r.identity_id,
                direct: r.direct,
                via_directory_group_ids: r.via_directory_group_ids,
            })
            .collect(),
    ))
}
