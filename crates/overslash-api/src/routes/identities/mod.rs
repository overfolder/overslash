//! Identity CRUD, lifecycle (archive/restore) and MCP-connection endpoints
//! under `/v1/identities`, plus the Bearer-friendly `/v1/whoami` probe.

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, patch, post},
};
use overslash_core::types::IdentityKind;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::OrgScope;
use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::identity::{ARCHIVED_REASON_MANUAL, RestoreOutcome};

use super::util::fmt_time;
use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, AuthContext, ClientIp, ReqExt, WriteAcl},
};

mod crud;
mod lifecycle;
mod mcp_connection;

use crud::{
    create_identity, delete_identity, get_chain, list_children, list_identities, update_identity,
    whoami,
};
use lifecycle::{archive_identity, restore_identity};
use mcp_connection::{
    disconnect_mcp_connection, get_mcp_connection, patch_auto_call_on_approve, patch_mcp_connection,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/identities", post(create_identity).get(list_identities))
        .route(
            "/v1/identities/{id}",
            patch(update_identity).delete(delete_identity),
        )
        .route("/v1/identities/{id}/children", get(list_children))
        .route("/v1/identities/{id}/chain", get(get_chain))
        .route("/v1/identities/{id}/restore", post(restore_identity))
        .route("/v1/identities/{id}/archive", post(archive_identity))
        .route(
            "/v1/identities/{id}/mcp-connection",
            get(get_mcp_connection).patch(patch_mcp_connection),
        )
        .route(
            "/v1/identities/{id}/mcp-connection/disconnect",
            post(disconnect_mcp_connection),
        )
        .route(
            "/v1/identities/{id}/auto-call-on-approve",
            patch(patch_auto_call_on_approve),
        )
        .route("/v1/whoami", get(whoami))
}

#[derive(Serialize)]
pub(super) struct IdentityResponse {
    id: Uuid,
    org_id: Uuid,
    name: String,
    kind: String,
    external_id: Option<String>,
    email: Option<String>,
    provider: Option<String>,
    picture: Option<String>,
    parent_id: Option<Uuid>,
    depth: i32,
    owner_id: Option<Uuid>,
    inherit_permissions: bool,
    /// Org-admin fast-path flag. `true` for user identities that hold org
    /// admin authorization (kept in lock-step with `Admins`-group membership
    /// by `identity::set_is_org_admin` / `set_org_member_admin`). Always
    /// `false` for agents/sub-agents. Drives the Members page admin badge and
    /// promote/demote control.
    is_org_admin: bool,
    /// When `true` (default), resolving an approval for this identity as
    /// `allow`/`allow_remember` automatically replays the underlying call.
    /// Flipping to `false` puts the agent in "deferred execution" mode —
    /// the resolver/agent must call `POST /v1/approvals/{id}/call`
    /// explicitly. Meaningless for `user`-kind rows.
    auto_call_on_approve: bool,
    /// `true` for a `user` identity that was pre-created (invited or
    /// impersonation-provisioned) but has never completed a sign-in
    /// (`external_id IS NULL`). Drives the Members-page "pending" badge.
    pending: bool,
    /// How this identity came to exist, when it was auto-provisioned — e.g.
    /// `"impersonation"`. Projected from `metadata.provisioned_by`; `None`
    /// for identities created through the normal API/UI/SSO paths.
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioned_by: Option<String>,
    created_at: String,
    last_active_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    archived_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    archived_reason: Option<String>,
}

impl From<overslash_db::repos::identity::IdentityRow> for IdentityResponse {
    fn from(r: overslash_db::repos::identity::IdentityRow) -> Self {
        let provider = r
            .metadata
            .get("provider")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let picture = r
            .metadata
            .get("picture")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let provisioned_by = r
            .metadata
            .get("provisioned_by")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let pending = r.kind == "user" && r.external_id.is_none();
        Self {
            id: r.id,
            org_id: r.org_id,
            name: r.name,
            kind: r.kind,
            external_id: r.external_id,
            email: r.email,
            provider,
            picture,
            parent_id: r.parent_id,
            depth: r.depth,
            owner_id: r.owner_id,
            inherit_permissions: r.inherit_permissions,
            is_org_admin: r.is_org_admin,
            auto_call_on_approve: r.auto_call_on_approve,
            pending,
            provisioned_by,
            created_at: fmt_time(r.created_at),
            last_active_at: fmt_time(r.last_active_at),
            archived_at: r.archived_at.map(fmt_time),
            archived_reason: r.archived_reason,
        }
    }
}
