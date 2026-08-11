//! `initialize` handshake and the `tools/list` catalog response.

use super::*;

pub(super) async fn initialize_response(
    state: &AppState,
    ext: &axum::http::Extensions,
    auth: &AuthContext,
    req: &JsonRpcRequest,
) -> Response {
    // Persist capabilities + clientInfo + protocolVersion declared by the
    // client so we can later decide whether elicitation is reachable for
    // that connection. Best-effort: a DB hiccup must not block the
    // handshake (initialize is synchronous from the client's POV).
    let session_id = Uuid::new_v4();
    if let Some(client_id) = auth.mcp_client_id.as_deref() {
        let capabilities = req
            .params
            .get("capabilities")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let client_info = req
            .params
            .get("clientInfo")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let protocol_version = req
            .params
            .get("protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or("");
        if let Err(e) = overslash_db::repos::oauth_mcp_client::update_initialize_state(
            state.db(ext),
            client_id,
            &capabilities,
            &client_info,
            protocol_version,
            session_id,
        )
        .await
        {
            tracing::warn!(client_id, "failed to persist mcp initialize state: {e}");
        }
    }

    let body = json!({
        "jsonrpc": "2.0",
        "id": req.id,
        "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": { "tools": {} },
            "serverInfo": {
                "name": "overslash",
                "version": build_info().version,
            },
            "instructions": "Overslash MCP server. Use overslash_search to discover \
        services, overslash_read to invoke read-class actions (the server \
        rejects writes/deletes routed through it), overslash_call to invoke \
        any action or resume a pending approval, and overslash_auth for \
        identity introspection (whoami, service_status). Prefer overslash_read \
        when the action only reads data — clients can skip the confirmation \
        prompt.",
        }
    });
    (
        StatusCode::OK,
        [("Mcp-Session-Id", session_id.to_string())],
        Json(body),
    )
        .into_response()
}

pub(super) async fn tools_list_response(
    state: &AppState,
    ext: &axum::http::Extensions,
    auth: &AuthContext,
    id: Value,
) -> Response {
    // The two `overslash_approve_*` tools both forward to the same resolve
    // endpoint; the split exists so Claude Code permission rules can
    // separately allowlist `overslash_approve` (the always-on downstream-only
    // tool, delegation) and
    // ask for `overslash_approve_self` (the agent rubber-stamping its own
    // request). The self variant is hidden from `tools/list` by default —
    // only surfaces when the operator flips `self_approve_enabled` on the
    // MCP binding for this client. See docs/design/agent-self-management.md
    // §2 + §4.
    let mut self_approve_visible = false;
    if let (Some(identity_id), Some(client_id)) = (auth.identity_id, auth.mcp_client_id.as_deref())
        && let Ok(Some(binding)) =
            overslash_db::repos::mcp_client_agent_binding::get_for_agent_and_client(
                state.db(ext),
                identity_id,
                client_id,
            )
            .await
    {
        self_approve_visible = binding.self_approve_enabled;
    }

    let approve_input_schema = json!({
        "type": "object",
        "properties": {
            "approval_id": { "type": "string" },
            "resolution": {
                "type": "string",
                "enum": ["allow", "deny", "allow_remember"],
                "description": "Allow / deny outcome. Use `allow_remember` together with `remember_keys` + `ttl` to mint a permission rule for future calls."
            },
            "remember_keys": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Permission keys to remember when `resolution` is `allow_remember`. Must be a subset of the approval's suggested tiers."
            },
            "ttl": {
                "type": "string",
                "description": "Duration the remembered rule stays live (e.g. `24h`, `30d`). Only meaningful with `allow_remember`."
            }
        },
        "required": ["approval_id", "resolution"],
        "additionalProperties": false
    });

    let mut tools = vec![
        json!({
            "name": "overslash_search",
            "title": "Search Overslash services",
            "description": "Discover Overslash service instances and actions available to the caller. Each result's `service` field is the instance name to pass directly as `overslash_call.service` (e.g. `gmail_work`, `whatsapp_angel`) — never the `template` key. Templates with multiple connected instances fan out into one row per instance. Pass `include_catalog: true` to also surface un-connected templates; those rows are marked `setup_required: true` and have no `service` field — set them up with `overslash_auth.create_service_from_template` before calling. Pass `exclude` to drop specific services from the response (e.g. when retrying after one already failed). An empty `query` lists every callable instance without actions (browse mode).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Free-text query. Pass an empty string to list every callable instance (no actions)."
                    },
                    "include_catalog": {
                        "type": "boolean",
                        "default": false,
                        "description": "When true, also surface un-connected templates as `setup_required: true` rows. Default returns only configured instances the caller can call right now."
                    },
                    "exclude": {
                        "type": "string",
                        "description": "Comma-separated list of services to omit. Each entry matches against both the instance name (e.g. `gmail_work`) and the template key (e.g. `gmail`), so one entry can drop one instance or every instance of a template. Applied before scoring and `limit` truncation."
                    }
                },
                "additionalProperties": false
            },
            "annotations": {
                "readOnlyHint": true,
                "idempotentHint": true,
                "openWorldHint": false
            }
        }),
        json!({
            "name": "overslash_read",
            "title": "Read via Overslash",
            "description": "Call a read-class Overslash action on a configured service instance. The `service` argument must be an *instance name* (e.g. `gmail_work`), discoverable via overslash_search — not a template key like `gmail`. The server rejects this call if the resolved action's risk is not `read`. Use overslash_call for write/delete actions or to resume a pending approval.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "service": {
                        "type": "string",
                        "description": "Instance name (e.g. `gmail_work`). Pass the `service` field from an overslash_search result, not the `template` key."
                    },
                    "action":  { "type": "string" },
                    "params":  {},
                    "verbose": {
                        "type": "boolean",
                        "default": false,
                        "description": "Return the full ActionResult including response headers and the untruncated raw body. Default false — the compact shape (status_code, duration_ms, parsed body capped at ~8 KB) is enough for almost every read. Pass true only when you need a specific header or the response was cropped."
                    },
                    "deliver": {
                        "type": "string",
                        "enum": ["inline", "url"],
                        "default": "inline",
                        "description": "Where the response body goes. `inline` (default) returns it in the result. `url` returns a short-lived download URL instead and does NOT put the bytes in your context — use it for files (images, video, PDFs, any binary or large payload), then pipe the URL to disk with something like `curl -o <path> \"<download_url>\"`. The URL needs no credentials and expires, so fetch it promptly."
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "description": "How long to wait on the upstream, in milliseconds. Omit it and the action's own template default applies, which is usually right. Raise it for known-slow work like a large analytics query. Asking for more than this org's maximum is rejected rather than silently reduced, and the error names the ceiling."
                    }
                },
                "required": ["service", "action"],
                "additionalProperties": false
            },
            "annotations": {
                "readOnlyHint": true,
                "idempotentHint": true,
                "openWorldHint": true
            }
        }),
        json!({
            "name": "overslash_call",
            "title": "Call an Overslash action",
            "description": "Call any Overslash action (read, write, or delete) on a configured service instance, or resume a pending approval. The `service` argument must be an *instance name* (e.g. `gmail_work`), discoverable via overslash_search — not a template key like `gmail`. May return pending_approval if the user must approve — once approved, call this tool again with `approval_id` (and no service/action/params) to trigger the stored request and receive the result. A pending approval expires 15 minutes after the user allows it. The `pending_approval` envelope's `auto_call_on_approve` field tells you whether the gateway will auto-replay the call once approved (`true` — the result lands on the execution record via webhook/audit, no follow-up call needed) or whether the agent is in deferred-execution mode and you must replay explicitly (`false`). Prefer overslash_read for read-only actions so clients can skip the confirmation prompt.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "service": {
                        "type": "string",
                        "description": "Instance name (e.g. `gmail_work`). Pass the `service` field from an overslash_search result, not the `template` key."
                    },
                    "action":      { "type": "string" },
                    "params":      {},
                    "approval_id": {
                        "type": "string",
                        "description": "Trigger the replay of a previously-approved action. Mutually exclusive with service/action/params."
                    },
                    "verbose": {
                        "type": "boolean",
                        "default": false,
                        "description": "Return the full ActionResult including response headers and the untruncated raw body. Default false — the compact shape (status_code, duration_ms, parsed body capped at ~8 KB) is enough for almost every call. Pass true only when you need a specific header or the response was cropped. Only takes effect on fresh calls (service + action); ignored when `approval_id` is set, since approval replays return an ApprovalResponse with its own shape."
                    },
                    "deliver": {
                        "type": "string",
                        "enum": ["inline", "url"],
                        "default": "inline",
                        "description": "Where the response body goes. `inline` (default) returns it in the result. `url` returns a short-lived download URL instead and does NOT put the bytes in your context — use it for files (images, video, PDFs, any binary or large payload), then pipe the URL to disk with something like `curl -o <path> \"<download_url>\"`. The URL needs no credentials and expires, so fetch it promptly. Only takes effect on fresh calls (service + action)."
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "description": "How long to wait on the upstream, in milliseconds. Omit it and the action's own template default applies, which is usually right. Raise it for known-slow work like a large analytics query. Asking for more than this org's maximum is rejected rather than silently reduced, and the error names the ceiling. Only takes effect on fresh calls (service + action); an approval replay reuses the timeout resolved when the call was first made."
                    }
                },
                "additionalProperties": false
            },
            "annotations": {
                "readOnlyHint": false,
                "destructiveHint": true,
                "idempotentHint": false,
                "openWorldHint": true
            }
        }),
        json!({
            "name": "overslash_auth",
            "title": "Identity & service status",
            "description": "Identity introspection sub-actions: whoami, service_status.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": { "type": "string" },
                    "params": {}
                },
                "required": ["action"],
                "additionalProperties": false
            },
            "annotations": {
                "readOnlyHint": true,
                "idempotentHint": true,
                "openWorldHint": false
            }
        }),
        json!({
            "name": "overslash_approve",
            "title": "Approve a downstream agent's pending action",
            "description": "Resolve a pending approval that was requested by a *descendant* of the caller (delegation). Forwards to POST /v1/approvals/{approval_id}/resolve. The server classifies caller↔requester relationship and rejects if the caller is not an ancestor of the requester — the tool name is for permission scoping in clients like Claude Code, not the security boundary. Use the `approval_id` from the `pending_approval` envelope returned by an earlier `overslash_call`; the envelope's `relationship` field tells you whether to use this tool (`\"downstream\"`) or `overslash_approve_self` (`\"self\"`).",
            "inputSchema": approve_input_schema,
            "annotations": {
                "readOnlyHint": false,
                "destructiveHint": false,
                "idempotentHint": true,
                "openWorldHint": false
            }
        }),
    ];

    if self_approve_visible {
        tools.push(json!({
            "name": "overslash_approve_self",
            "title": "Approve the caller's own pending action",
            "description": "Resolve a pending approval that the *caller itself* requested. Only available when the human at the keyboard has enabled self-approval for this MCP connection — without that flag this tool is hidden from tools/list. Forwards to POST /v1/approvals/{approval_id}/resolve; the server re-checks the binding flag on every call so a revoked toggle takes effect immediately. Use the `approval_id` from a `pending_approval` envelope whose `relationship` is `\"self\"`.",
            "inputSchema": approve_input_schema,
            "annotations": {
                "readOnlyHint": false,
                "destructiveHint": true,
                "idempotentHint": true,
                "openWorldHint": false
            }
        }));
    }

    rpc_ok_response(id, json!({ "tools": tools }))
}
