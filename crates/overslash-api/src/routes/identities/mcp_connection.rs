//! MCP-connection binding endpoints for an agent identity, plus the
//! per-agent `auto_call_on_approve` toggle.

use super::*;

// ---------------------------------------------------------------------------
// /v1/identities/{id}/mcp-connection
// ---------------------------------------------------------------------------
// Reads and writes the MCP binding (oauth_mcp_clients + mcp_client_agent_bindings)
// for a given agent identity. Used by the Agents detail page to render the
// "MCP Connection" section, toggle elicitation approvals, and disconnect.
//
// Authorization: GET is open to any authenticated org member (OrgAcl) — the
// Agents detail page is read-only for most users and the empty card otherwise
// renders for anyone without `overslash:write`. PATCH and disconnect remain
// gated on WriteAcl since they mutate binding state.

#[derive(Debug, Serialize)]
pub(super) struct McpConnectionResponse {
    connection: Option<McpConnectionDto>,
}

#[derive(Debug, Serialize)]
struct McpConnectionDto {
    client_id: String,
    client_name: Option<String>,
    software_id: Option<String>,
    software_version: Option<String>,
    capabilities: Option<serde_json::Value>,
    client_info: Option<serde_json::Value>,
    protocol_version: Option<String>,
    session_id: Option<Uuid>,
    connected_at: String,
    last_seen_at: Option<String>,
    elicitation_enabled: bool,
    elicitation_supported: bool,
    self_approve_enabled: bool,
}

async fn load_mcp_connection(
    state: &AppState,
    ext: &axum::http::Extensions,
    agent_id: Uuid,
) -> Result<Option<McpConnectionDto>> {
    let binding = overslash_db::repos::mcp_client_agent_binding::get_by_agent_identity(
        state.db(ext),
        agent_id,
    )
    .await?;
    let Some(binding) = binding else {
        return Ok(None);
    };
    let client =
        overslash_db::repos::oauth_mcp_client::get_by_client_id(state.db(ext), &binding.client_id)
            .await?;
    let Some(client) = client else {
        return Ok(None);
    };
    let elicitation_supported = client.elicitation_supported();
    Ok(Some(McpConnectionDto {
        client_id: client.client_id,
        client_name: client.client_name,
        software_id: client.software_id,
        software_version: client.software_version,
        capabilities: client.capabilities,
        client_info: client.client_info,
        protocol_version: client.protocol_version,
        session_id: client.last_session_id,
        connected_at: fmt_time(binding.created_at),
        last_seen_at: client.last_seen_at.map(fmt_time),
        elicitation_enabled: binding.elicitation_enabled,
        elicitation_supported,
        self_approve_enabled: binding.self_approve_enabled,
    }))
}

async fn ensure_agent(scope: &OrgScope, id: Uuid) -> Result<()> {
    let ident = scope
        .get_identity(id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    if ident.kind != "agent" && ident.kind != "sub_agent" {
        return Err(AppError::BadRequest(
            "MCP connections only apply to agent identities".into(),
        ));
    }
    Ok(())
}

pub(super) async fn get_mcp_connection(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    _: crate::extractors::OrgAcl,
    scope: OrgScope,
    Path(id): Path<Uuid>,
) -> Result<Json<McpConnectionResponse>> {
    ensure_agent(&scope, id).await?;
    let connection = load_mcp_connection(&state, &ext, id).await?;
    Ok(Json(McpConnectionResponse { connection }))
}

#[derive(Debug, Deserialize)]
pub(super) struct PatchMcpConnectionRequest {
    elicitation_enabled: Option<bool>,
    self_approve_enabled: Option<bool>,
}

pub(super) async fn patch_mcp_connection(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<PatchMcpConnectionRequest>,
) -> Result<Json<McpConnectionResponse>> {
    ensure_agent(&scope, id).await?;

    if let Some(enabled) = req.elicitation_enabled {
        // Fan the toggle out to every binding under this agent. The
        // dashboard surfaces a single per-agent toggle, so applying the
        // change to only the most-recently-updated binding would leave
        // older client bindings reading a stale flag (the eligibility
        // check is keyed on the calling client's binding).
        let updated =
            overslash_db::repos::mcp_client_agent_binding::set_elicitation_enabled_for_agent(
                state.db(&ext),
                id,
                enabled,
            )
            .await?;
        if updated == 0 {
            return Err(AppError::NotFound(
                "no MCP connection bound to this agent".into(),
            ));
        }
        let _ = scope
            .log_audit(AuditEntry {
                org_id: acl.org_id,
                identity_id: acl.identity_id,
                action: "mcp_connection.elicitation_toggled",
                resource_type: Some("identity"),
                resource_id: Some(id),
                detail: serde_json::json!({
                    "elicitation_enabled": enabled,
                    "bindings_updated": updated,
                }),
                description: None,
                ip_address: ip.0.as_deref(),
            })
            .await;
    }

    if let Some(enabled) = req.self_approve_enabled {
        // Same fan-out rationale as `elicitation_enabled`: the dashboard
        // surfaces a single per-agent toggle, and the MCP visibility check
        // (in `routes/mcp.rs::tools_list_response`) plus the resolve-time
        // gate (in `routes/approvals.rs::resolve_approval`) both read the
        // calling client's binding row, so all bindings under the agent
        // need to stay in lockstep.
        let updated =
            overslash_db::repos::mcp_client_agent_binding::set_self_approve_enabled_for_agent(
                state.db(&ext),
                id,
                enabled,
            )
            .await?;
        if updated == 0 {
            return Err(AppError::NotFound(
                "no MCP connection bound to this agent".into(),
            ));
        }
        let _ = scope
            .log_audit(AuditEntry {
                org_id: acl.org_id,
                identity_id: acl.identity_id,
                action: "mcp_connection.self_approve_toggled",
                resource_type: Some("identity"),
                resource_id: Some(id),
                detail: serde_json::json!({
                    "self_approve_enabled": enabled,
                    "bindings_updated": updated,
                }),
                description: None,
                ip_address: ip.0.as_deref(),
            })
            .await;
    }

    let connection = load_mcp_connection(&state, &ext, id).await?;
    Ok(Json(McpConnectionResponse { connection }))
}

// ─── Auto-call-on-approve toggle (agent-level) ──────────────────────────
// Per-agent override of the default auto-call behavior. Default `true`;
// flipping to `false` puts the agent in "deferred execution" mode where
// the resolver or agent must call `POST /v1/approvals/{id}/call`
// explicitly after a resolver allows the approval. Replaces the prior
// per-MCP-binding column so REST and white-label agents can opt in too.

#[derive(Debug, Deserialize)]
pub(super) struct PatchAutoCallOnApproveRequest {
    enabled: bool,
}

pub(super) async fn patch_auto_call_on_approve(
    WriteAcl(acl): WriteAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<PatchAutoCallOnApproveRequest>,
) -> Result<Json<IdentityResponse>> {
    // Only meaningful for agent/sub_agent identities. Reject up front so a
    // mistaken call against a user-kind row gets a clean error instead of
    // silently writing a no-op flag.
    let target = scope
        .get_identity(id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    if target.kind != "agent" && target.kind != "sub_agent" {
        return Err(AppError::BadRequest(
            "auto_call_on_approve only applies to agent identities".into(),
        ));
    }

    let updated = scope
        .set_identity_auto_call_on_approve(id, req.enabled)
        .await?;
    if !updated {
        return Err(AppError::NotFound("identity not found".into()));
    }

    let _ = scope
        .log_audit(AuditEntry {
            org_id: acl.org_id,
            identity_id: acl.identity_id,
            action: "identity.auto_call_on_approve_toggled",
            resource_type: Some("identity"),
            resource_id: Some(id),
            detail: serde_json::json!({
                "auto_call_on_approve": req.enabled,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    let row = scope
        .get_identity(id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    Ok(Json(row.into()))
}

pub(super) async fn disconnect_mcp_connection(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    scope: OrgScope,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    ensure_agent(&scope, id).await?;
    let removed =
        overslash_db::repos::mcp_client_agent_binding::delete_by_agent_identity(state.db(&ext), id)
            .await?;
    if removed.is_empty() {
        return Err(AppError::NotFound(
            "no MCP connection bound to this agent".into(),
        ));
    }

    // Cancel any in-flight elicitations for this agent so an orphaned SSE
    // stream doesn't sit polling. Keyed on `agent_identity_id` (not
    // `last_session_id`) so a re-initialize between elicitation-start and
    // disconnect doesn't leave stale rows pinned to an older session id —
    // and so multi-binding-per-agent (reauth flow) is fully covered.
    let _ = overslash_db::repos::mcp_elicitation::cancel_for_agent(state.db(&ext), id).await;

    // Audit one row per removed binding so the trail names every client_id
    // we just disconnected, not just whichever one Postgres returned first.
    for binding in &removed {
        let _ = scope
            .log_audit(AuditEntry {
                org_id: acl.org_id,
                identity_id: acl.identity_id,
                action: "mcp_connection.disconnected",
                resource_type: Some("identity"),
                resource_id: Some(id),
                detail: serde_json::json!({
                    "client_id": binding.client_id,
                    "binding_id": binding.id,
                }),
                description: None,
                ip_address: ip.0.as_deref(),
            })
            .await;
    }
    Ok(StatusCode::NO_CONTENT)
}
