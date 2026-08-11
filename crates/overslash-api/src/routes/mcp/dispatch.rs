//! Per-tool dispatchers — each maps one MCP tool call onto a loopback REST
//! request via `forward`.

use super::*;

// Workaround for claude.ai / Claude Desktop connectors that stringify
// object-typed tool arguments (anthropics/claude-code#5504, #24599, #26094):
// if `params` arrives as a JSON-encoded string, decode it in place. Scoped to
// the top-level field — recursing would double-decode payloads that
// legitimately arrive as JSON strings (e.g. Mode A request bodies).
pub(super) fn normalize_stringified_params(args: &mut Value) {
    let Some(obj) = args.as_object_mut() else {
        return;
    };
    let Some(p) = obj.get_mut("params") else {
        return;
    };
    let Some(s) = p.as_str() else {
        return;
    };

    if s.is_empty() {
        *p = Value::Null;
        tracing::warn!(
            client_quirk = "stringified_params",
            "rewrote empty-string params to null"
        );
        return;
    }

    match serde_json::from_str::<Value>(s) {
        Ok(parsed) if parsed.is_object() || parsed.is_null() => {
            *p = parsed;
            tracing::warn!(
                client_quirk = "stringified_params",
                "rewrote stringified JSON params to object"
            );
        }
        _ => {}
    }
}

pub(super) async fn dispatch_search(
    state: &AppState,
    bearer: &str,
    args: &Value,
) -> Result<ForwardOutcome, String> {
    // Empty query is supported: it triggers browse mode in the REST handler,
    // returning every visible *connected* service (without actions) so an
    // agent can catalog what it can run right now before issuing a scoped
    // query. `include_catalog=true` surfaces the un-connected catalog too.
    let q = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
    let include_catalog = args
        .get("include_catalog")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let exclude = args.get("exclude").and_then(|v| v.as_str()).unwrap_or("");
    let mut path = format!(
        "/v1/search?q={}&include_catalog={}",
        urlencoding::encode(q),
        include_catalog,
    );
    if !exclude.is_empty() {
        path.push_str("&exclude=");
        path.push_str(&urlencoding::encode(exclude));
    }
    forward(state, bearer, Method::GET, &path, None).await
}

/// Read-only fast path: forwards to `/v1/actions/call` with `require_risk=read`
/// so the action handler rejects the call when the resolved action's risk is
/// not `Risk::Read`. The split lets MCP clients skip confirmation prompts on
/// the readonly tool while still routing through the same execution pipeline.
///
/// `approval_id` is rejected here: approval resume always replays a previously
/// permission-gated (i.e. write/delete) action, so it has no place on a tool
/// annotated `readOnlyHint: true`.
pub(super) async fn dispatch_read(
    state: &AppState,
    bearer: &str,
    args: &Value,
) -> Result<ForwardOutcome, String> {
    if args.get("approval_id").is_some() {
        return Err(
            "approval_id is not allowed on overslash_read; use overslash_call to resume a pending approval".into(),
        );
    }
    let service = args
        .get("service")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "service required".to_string())?;
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "action required".to_string())?;

    // The `overslash` meta-service exposes both read and write sub-actions
    // through the same `dispatch_overslash_platform` code path. Route the
    // read sub-actions through the appropriate path and reject the write
    // ones explicitly so the user gets a clear error rather than a 404 from
    // the actions handler:
    //   - `list_pending` / `get_result` / `get_events` are thin wrappers over
    //     GET /v1/approvals... and have no kernel behind them, so they go
    //     through the platform dispatcher directly.
    //   - `list_templates` / `get_template` are bridged read-class platform
    //     actions; fall through to the regular `/v1/actions/call` forwarding
    //     so `require_risk=read` is enforced at the action gateway.
    if service == "overslash" {
        return match action {
            // `require_risk: "read"` is forwarded so the actions handler
            // enforces the risk gate for the *bridged* actions in this list —
            // defense in depth if a write-class action ever sneaks in by
            // mistake. It is inert for `list_pending` / `get_result` /
            // `get_events`, which forward straight to `/v1/approvals...` and
            // never reach the gate; those three are read-only by construction
            // (GET, no kernel).
            "list_pending" | "get_result" | "get_events" | "list_services" | "get_service"
            | "list_templates" | "get_template" => {
                dispatch_overslash_platform(state, bearer, action, args, Some("read")).await
            }
            other => Err(format!(
                "overslash platform action '{other}' is not read-class; use overslash_call"
            )),
        };
    }

    let mut body = serde_json::Map::new();
    body.insert("service".into(), Value::String(service.into()));
    body.insert("action".into(), Value::String(action.into()));
    body.insert("require_risk".into(), Value::String("read".into()));
    // Forward `params` only when the caller actually supplied a map. The
    // receiving CallRequest's `params: HashMap<...>` deserializer rejects an
    // explicit `null` (it expects a map), even though `#[serde(default)]`
    // would happily fill in an empty map for an absent key.
    if let Some(p) = args.get("params").filter(|v| !v.is_null()) {
        body.insert("params".into(), p.clone());
    }
    // MCP defaults to the compact response shape (the HTTP API defaults to
    // verbose for backward compatibility). Forward the caller's explicit
    // `verbose` flag when supplied; otherwise stamp `false` so the inner
    // handler picks compact.
    body.insert("verbose".into(), Value::Bool(verbose_flag(args)));
    insert_deliver(&mut body, args);
    insert_timeout_ms(&mut body, args);
    forward(
        state,
        bearer,
        Method::POST,
        "/v1/actions/call",
        Some(Value::Object(body)),
    )
    .await
}

/// Forward the caller's `deliver` tool argument when they set one.
///
/// Omitted rather than defaulted: the action handler already treats an absent
/// `deliver` as inline, and stamping an explicit value here would mean any
/// future default lived in two places. Unknown strings are passed through so
/// the handler's own deserializer produces the error, rather than this layer
/// silently swallowing a typo into inline delivery — which would put a video
/// in the model's context, the exact outcome the flag exists to prevent.
fn insert_deliver(body: &mut serde_json::Map<String, Value>, args: &Value) {
    if let Some(d) = args.get("deliver").filter(|v| !v.is_null()) {
        body.insert("deliver".into(), d.clone());
    }
}

/// Forward a caller-supplied `timeout_ms` when there is one.
///
/// Same discipline as [`insert_deliver`]: pass it through untouched and let
/// the inner `CallRequest` deserializer and the D56 resolver produce the
/// error. Validating here would mean duplicating the org-ceiling logic in a
/// place that has no org row.
fn insert_timeout_ms(body: &mut serde_json::Map<String, Value>, args: &Value) {
    if let Some(t) = args.get("timeout_ms").filter(|v| !v.is_null()) {
        body.insert("timeout_ms".into(), t.clone());
    }
}

/// Read the caller-supplied `verbose: bool` tool argument, defaulting to
/// `false`. Non-boolean values are ignored (the JSON schema's `boolean`
/// type already filters this for well-behaved clients).
fn verbose_flag(args: &Value) -> bool {
    args.get("verbose")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub(super) async fn dispatch_call(
    state: &AppState,
    bearer: &str,
    args: &Value,
) -> Result<ForwardOutcome, String> {
    // Resume-mode: caller is triggering the replay of a previously-approved
    // action. Forwards to POST /v1/approvals/{id}/call.
    if let Some(approval_id) = args.get("approval_id").and_then(|v| v.as_str()) {
        if args.get("service").is_some() || args.get("action").is_some() {
            return Err("approval_id is mutually exclusive with service/action/params".into());
        }
        let path = format!("/v1/approvals/{}/call", urlencoding::encode(approval_id));
        return forward(state, bearer, Method::POST, &path, None).await;
    }

    // Fresh-call mode: service + action required.
    let service = args
        .get("service")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            "service required (or pass approval_id to resume a pending approval)".to_string()
        })?;
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "action required".to_string())?;

    // Overslash metaservice platform actions are handled in-process; they have
    // no upstream HTTP host to forward to. No `require_risk` here — the call
    // tool admits read/write/delete equally.
    if service == "overslash" {
        return dispatch_overslash_platform(state, bearer, action, args, None).await;
    }

    let mut body = serde_json::Map::new();
    body.insert("service".into(), Value::String(service.into()));
    body.insert("action".into(), Value::String(action.into()));
    // See `dispatch_read` — explicit `null` would 422 the action handler;
    // omit when the caller didn't supply a map.
    if let Some(p) = args.get("params").filter(|v| !v.is_null()) {
        body.insert("params".into(), p.clone());
    }
    // Same rationale as `dispatch_read`: MCP forwards `verbose: false` by
    // default so the LLM consumer gets the compact shape.
    body.insert("verbose".into(), Value::Bool(verbose_flag(args)));
    insert_deliver(&mut body, args);
    insert_timeout_ms(&mut body, args);
    forward(
        state,
        bearer,
        Method::POST,
        "/v1/actions/call",
        Some(Value::Object(body)),
    )
    .await
}

async fn dispatch_overslash_platform(
    state: &AppState,
    bearer: &str,
    action: &str,
    args: &Value,
    require_risk: Option<&str>,
) -> Result<ForwardOutcome, String> {
    let params = args.get("params");
    let verbose = verbose_flag(args);
    match action {
        "list_pending" => {
            let outcome = forward(
                state,
                bearer,
                Method::GET,
                "/v1/approvals?scope=mine&status=allowed",
                None,
            )
            .await?;
            // An approval's status stays 'allowed' even after its execution
            // has been dispatched, failed, or expired, so the raw listing is
            // too broad. Keep two classes:
            //   * `pending` — still dispatchable via call_pending.
            //   * terminal but unread — the execution already ran (the
            //     `auto_call_on_approve` default) and the agent has never
            //     fetched the output. Dropping these was the bug: an
            //     auto-called action vanished from every MCP surface the
            //     moment it succeeded. See `dispatch_get_events`.
            // `map_ok` skips this filter for typed-error envelopes (which
            // aren't arrays).
            Ok(outcome.map_ok(|mut value| {
                if let Some(arr) = value.as_array_mut() {
                    arr.retain(inbox::needs_attention);
                }
                value
            }))
        }
        "get_result" => {
            let id = params
                .and_then(|p| p.get("approval_id"))
                .and_then(Value::as_str)
                .ok_or_else(|| "get_result requires params.approval_id".to_string())?;
            let path = format!("/v1/approvals/{}/execution", urlencoding::encode(id));
            forward(state, bearer, Method::GET, &path, None).await
        }
        "get_events" => dispatch_get_events(state, bearer).await,
        "call_pending" => {
            let id = params
                .and_then(|p| p.get("approval_id"))
                .and_then(Value::as_str)
                .ok_or_else(|| "call_pending requires params.approval_id".to_string())?;
            let path = format!("/v1/approvals/{}/call", urlencoding::encode(id));
            forward(state, bearer, Method::POST, &path, None).await
        }
        "cancel_pending" => {
            let id = params
                .and_then(|p| p.get("approval_id"))
                .and_then(Value::as_str)
                .ok_or_else(|| "cancel_pending requires params.approval_id".to_string())?;
            let path = format!("/v1/approvals/{}/cancel", urlencoding::encode(id));
            forward(state, bearer, Method::POST, &path, None).await
        }
        // Bridged platform kernels — forward through `/v1/actions/call` so the
        // platform_target dispatcher in `routes/actions.rs` runs the kernel via
        // `state.platform_registry`. Permission gating is handled by the
        // action's `permission:` anchor in `services/overslash.yaml` (the
        // `manage_services_own` / `manage_services_share`,
        // `manage_templates_own` / `manage_templates_publish`,
        // `manage_connections_own`, and `request_secrets_own` /
        // `request_secrets_share` splits). When the caller is the read tool,
        // `require_risk` is forwarded so the action handler enforces the
        // risk gate.
        "list_services" | "get_service" | "create_service" | "update_service"
        | "list_templates" | "get_template" | "create_template" | "import_template"
        | "delete_template" | "create_connection" | "request_secret" => {
            forward_overslash_action(state, bearer, action, params, require_risk, verbose).await
        }
        other => Err(format!(
            "overslash platform action '{other}' is not callable via MCP"
        )),
    }
}

/// MCP wrapper over the agent inbox. Fetches the two listings that
/// [`inbox::build_events`] classifies — see that module for what the event
/// types mean and why `result_unread` is the reason any of this exists.
async fn dispatch_get_events(state: &AppState, bearer: &str) -> Result<ForwardOutcome, String> {
    // Two listings, merged. A typed error from either short-circuits — a
    // partial inbox would read as "nothing else needs you", which is exactly
    // the wrong thing to tell an agent that is about to stop polling.
    let actionable = match forward(
        state,
        bearer,
        Method::GET,
        "/v1/approvals?scope=actionable",
        None,
    )
    .await?
    {
        ForwardOutcome::Ok(v) => v,
        typed @ ForwardOutcome::TypedError(_) => return Ok(typed),
    };
    let mine = match forward(
        state,
        bearer,
        Method::GET,
        "/v1/approvals?scope=mine&status=allowed",
        None,
    )
    .await?
    {
        ForwardOutcome::Ok(v) => v,
        typed @ ForwardOutcome::TypedError(_) => return Ok(typed),
    };

    Ok(ForwardOutcome::Ok(Value::Array(inbox::build_events(
        &actionable,
        &mine,
    ))))
}

/// Forward an `overslash`-platform action through `/v1/actions/call` so the
/// existing platform_target dispatch in `routes/actions.rs` runs the kernel
/// via `state.platform_registry`. Returns whatever the actions endpoint
/// returned (which may be `pending_approval` if the agent lacks the
/// permission anchor declared on the action).
async fn forward_overslash_action(
    state: &AppState,
    bearer: &str,
    action: &str,
    params: Option<&Value>,
    require_risk: Option<&str>,
    verbose: bool,
) -> Result<ForwardOutcome, String> {
    let mut body = serde_json::Map::new();
    body.insert("service".into(), Value::String("overslash".into()));
    body.insert("action".into(), Value::String(action.into()));
    if let Some(risk) = require_risk {
        body.insert("require_risk".into(), Value::String(risk.into()));
    }
    if let Some(p) = params.filter(|v| !v.is_null()) {
        body.insert("params".into(), p.clone());
    }
    // Same rationale as `dispatch_call` / `dispatch_read`: MCP picks the
    // compact shape by default and the caller can flip `verbose: true` to
    // opt back in. Without this stamp the inner handler would default to
    // verbose for every `overslash` platform action.
    body.insert("verbose".into(), Value::Bool(verbose));
    forward(
        state,
        bearer,
        Method::POST,
        "/v1/actions/call",
        Some(Value::Object(body)),
    )
    .await
}

pub(super) async fn dispatch_auth(
    state: &AppState,
    bearer: &str,
    args: &Value,
) -> Result<ForwardOutcome, String> {
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "action required".to_string())?;
    let params = args.get("params").cloned().unwrap_or(Value::Null);

    // Self-management sub-actions (list_secrets, request_secret,
    // create_subagent, create_service_from_template) have been removed from
    // the MCP surface intentionally. Agents should use already-configured
    // services via overslash_call; creation and credential plumbing live
    // in the dashboard until the work in
    // docs/design/agent-self-management.md lands.
    let (method, path, body) = match action {
        "whoami" => (Method::GET, "/v1/whoami".to_string(), None),
        "service_status" => {
            let name = params
                .get("service")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "service_status requires `service`".to_string())?;
            (
                Method::GET,
                format!("/v1/services/{}", urlencoding::encode(name)),
                None,
            )
        }
        other => {
            return Err(format!(
                "unknown action `{other}` — supported: whoami, service_status"
            ));
        }
    };
    forward(state, bearer, method, &path, body).await
}

/// Shared dispatcher for `overslash_approve` and
/// `overslash_approve_self`. Both forward to the same resolve endpoint —
/// the tool name is for client-side permission scoping (Claude Code rules),
/// not authorization. The server-side classifier in `resolve_approval`
/// decides whether the caller↔requester relationship matches the tool.
pub(super) async fn dispatch_approve(
    state: &AppState,
    bearer: &str,
    args: &Value,
) -> Result<ForwardOutcome, String> {
    let approval_id = args
        .get("approval_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "approval_id required".to_string())?;
    if Uuid::parse_str(approval_id).is_err() {
        return Err(format!("invalid approval_id `{approval_id}`"));
    }
    let resolution = args
        .get("resolution")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "resolution required".to_string())?;
    if !matches!(resolution, "allow" | "deny" | "allow_remember") {
        return Err(format!(
            "invalid resolution `{resolution}` — expected one of allow / deny / allow_remember"
        ));
    }

    // Build the ResolveRequest body — pass through `remember_keys` and `ttl`
    // when the caller supplied them so an `allow_remember` round-trips
    // straight through to the existing rule-minting path.
    let mut body = serde_json::Map::new();
    body.insert("resolution".into(), Value::String(resolution.to_string()));
    if let Some(keys) = args.get("remember_keys").cloned() {
        body.insert("remember_keys".into(), keys);
    }
    if let Some(ttl) = args.get("ttl").cloned() {
        body.insert("ttl".into(), ttl);
    }

    let path = format!("/v1/approvals/{}/resolve", urlencoding::encode(approval_id));
    forward(
        state,
        bearer,
        Method::POST,
        &path,
        Some(Value::Object(body)),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stringified_empty_object_becomes_object() {
        let mut args = json!({"service": "x", "action": "y", "params": "{}"});
        normalize_stringified_params(&mut args);
        assert_eq!(args["params"], json!({}));
    }

    #[test]
    fn stringified_object_with_content_is_decoded() {
        let mut args = json!({
            "service": "x",
            "action": "y",
            "params": "{\"approval_id\":\"abc\",\"n\":3}"
        });
        normalize_stringified_params(&mut args);
        assert_eq!(args["params"], json!({"approval_id": "abc", "n": 3}));
    }

    #[test]
    fn empty_string_params_becomes_null() {
        let mut args = json!({"service": "x", "action": "y", "params": ""});
        normalize_stringified_params(&mut args);
        assert!(args["params"].is_null());
    }

    #[test]
    fn real_object_params_unchanged() {
        let original = json!({"service": "x", "action": "y", "params": {"k": "v"}});
        let mut args = original.clone();
        normalize_stringified_params(&mut args);
        assert_eq!(args, original);
    }

    #[test]
    fn missing_params_is_noop() {
        let original = json!({"service": "x", "action": "y"});
        let mut args = original.clone();
        normalize_stringified_params(&mut args);
        assert_eq!(args, original);
    }

    #[test]
    fn null_params_unchanged() {
        let original = json!({"service": "x", "action": "y", "params": null});
        let mut args = original.clone();
        normalize_stringified_params(&mut args);
        assert_eq!(args, original);
    }

    #[test]
    fn non_json_string_passes_through() {
        // We don't try to "rescue" arbitrary strings: leave them in place
        // so the downstream typed deserializer surfaces a clear error.
        let original = json!({"service": "x", "action": "y", "params": "not json"});
        let mut args = original.clone();
        normalize_stringified_params(&mut args);
        assert_eq!(args, original);
    }

    #[test]
    fn stringified_non_object_passes_through() {
        // A stringified array or number is not the bug we're fixing — leave it.
        let original = json!({"service": "x", "action": "y", "params": "[1,2,3]"});
        let mut args = original.clone();
        normalize_stringified_params(&mut args);
        assert_eq!(args, original);
    }

    #[test]
    fn non_object_args_is_noop() {
        let mut args = Value::Null;
        normalize_stringified_params(&mut args);
        assert_eq!(args, Value::Null);
    }

    #[test]
    fn timeout_ms_is_forwarded_when_supplied() {
        let mut body = serde_json::Map::new();
        insert_timeout_ms(&mut body, &serde_json::json!({"timeout_ms": 90_000}));
        assert_eq!(body.get("timeout_ms"), Some(&serde_json::json!(90_000)));
    }

    #[test]
    fn an_absent_or_null_timeout_ms_is_not_stamped() {
        // The inner `CallRequest` uses `#[serde(deny_unknown_fields)]` and a
        // plain `Option`, so stamping a key the caller never sent would turn
        // "no opinion" into an explicit null and skip the cascade.
        for args in [
            serde_json::json!({}),
            serde_json::json!({"timeout_ms": null}),
        ] {
            let mut body = serde_json::Map::new();
            insert_timeout_ms(&mut body, &args);
            assert!(body.is_empty(), "nothing should be stamped for {args}");
        }
    }

    /// A bad value is forwarded verbatim rather than validated here — the
    /// resolver owns the org ceiling, and this layer has no org row to check
    /// it against. Guards against someone "helpfully" adding a local check
    /// that would drift from the real one.
    #[test]
    fn an_invalid_timeout_ms_is_passed_through_for_the_resolver_to_reject() {
        let mut body = serde_json::Map::new();
        insert_timeout_ms(&mut body, &serde_json::json!({"timeout_ms": "30s"}));
        assert_eq!(body.get("timeout_ms"), Some(&serde_json::json!("30s")));
    }
}
