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
use overslash_db::repos::mcp_client_agent_binding::AgentClientRow;

use super::util::fmt_time;
use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, AuthContext, ClientIp, ReqExt, WriteAcl},
    services::agent_icon,
};
use std::collections::HashMap;

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
    /// impersonation-provisioned) and never claimed by a human — neither by
    /// an SSO sign-in (`external_id`) nor by accepting the invitation from
    /// the dashboard (`user_id`). Drives the Members-page "pending" badge.
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
    /// The mark for this agent: the logo of the MCP client it is bound to, or
    /// the generic bot when we do not recognise the client (or there is no
    /// binding). Absent for `user` identities, which render `picture` instead,
    /// and on the rare build where even the bot glyph is missing. See D70.
    #[serde(skip_serializing_if = "Option::is_none")]
    icon_url: Option<String>,
    /// Three `#rrggbb` colours derived from this agent's id, rendered as a bar
    /// under the icon. Two agents on the same client share a logo and are told
    /// apart by this. Absent for `user` identities.
    #[serde(skip_serializing_if = "Option::is_none")]
    icon_stripe: Option<[String; agent_icon::STRIPE_SEGMENTS]>,
    /// What the bound MCP client calls itself, for a tooltip — e.g.
    /// `Claude Code`. Absent when the agent has no MCP binding.
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp_client_label: Option<String>,
}

/// True for the identity kinds that get a client mark. Users render their IdP
/// `picture` instead, and have no MCP client to speak of.
fn wears_an_agent_icon(kind: &str) -> bool {
    kind == "agent" || kind == "sub_agent"
}

/// Everything [`IdentityResponse`] needs to resolve an agent's icon, gathered
/// once for a whole response rather than once per row.
///
/// This is a parameter rather than something `IdentityResponse` looks up for
/// itself so that the cost is visible and batched: the agents tree renders
/// every identity in an org, and a per-row lookup would be a query per row.
///
/// It replaced a plain `From<IdentityRow>` impl deliberately. With `From`, an
/// endpoint that forgot to enrich still compiled and still returned valid
/// JSON — it just quietly rendered every agent as the generic bot. Threading
/// the context through the constructor makes that omission a compile error.
pub(super) struct IdentityIconCtx {
    public_url: String,
    clients: HashMap<Uuid, AgentClientRow>,
}

impl IdentityIconCtx {
    /// Resolve the MCP client of every agent among `rows`, in one round trip.
    pub(super) async fn build(
        state: &AppState,
        scope: &OrgScope,
        rows: &[overslash_db::repos::identity::IdentityRow],
    ) -> Result<Self> {
        let agent_ids: Vec<Uuid> = rows
            .iter()
            .filter(|r| wears_an_agent_icon(&r.kind))
            .map(|r| r.id)
            .collect();
        // Skip the query outright for an all-users response (the Members page).
        let clients = if agent_ids.is_empty() {
            HashMap::new()
        } else {
            overslash_db::repos::mcp_client_agent_binding::clients_for_agents(
                scope.db(),
                scope.org_id(),
                &agent_ids,
            )
            .await?
            .into_iter()
            .map(|c| (c.agent_identity_id, c))
            .collect()
        };
        Ok(Self {
            public_url: state.config.public_url.clone(),
            clients,
        })
    }

    /// The context for a response carrying exactly one identity.
    pub(super) async fn for_one(
        state: &AppState,
        scope: &OrgScope,
        row: &overslash_db::repos::identity::IdentityRow,
    ) -> Result<Self> {
        Self::build(state, scope, std::slice::from_ref(row)).await
    }
}

impl IdentityResponse {
    pub(super) fn from_row(
        r: overslash_db::repos::identity::IdentityRow,
        ctx: &IdentityIconCtx,
    ) -> Self {
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
        let pending = r.kind == "user" && r.external_id.is_none() && r.user_id.is_none();
        // A user identity has an IdP `picture` and no MCP client, so it gets
        // neither half of the agent mark.
        let (icon_url, icon_stripe, mcp_client_label) = if wears_an_agent_icon(&r.kind) {
            let client = ctx.clients.get(&r.id);
            // `clientInfo.name` from the `initialize` handshake — see
            // routes/mcp/initialize.rs, which persists the whole object.
            let info_name = client
                .and_then(|c| c.client_info.as_ref())
                .and_then(|v| v.get("name"))
                .and_then(|v| v.as_str());
            let client_name = client.and_then(|c| c.client_name.as_deref());
            let software_id = client.and_then(|c| c.software_id.as_deref());
            (
                agent_icon::icon_url_for_client(
                    info_name,
                    client_name,
                    software_id,
                    &ctx.public_url,
                ),
                Some(agent_icon::stripe_for(r.id)),
                info_name.or(client_name).map(str::to_owned),
            )
        } else {
            (None, None, None)
        };
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
            icon_url,
            icon_stripe,
            mcp_client_label,
        }
    }
}
