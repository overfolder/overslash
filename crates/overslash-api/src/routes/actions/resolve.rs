//! Request resolution: cheap metadata pre-resolve and full `ActionRequest` resolution.

use std::collections::HashMap;

use uuid::Uuid;

use overslash_db::scopes::OrgScope;

use crate::{AppState, error::AppError, extractors::AuthContext, services::platform_connections};
use overslash_core::types::{
    ActionRequest, McpAuth, ParamLocation, ResolvedActionRequest, Runtime,
};

use super::*;
use super::{auth::*, errors::*, service_resolve::*};

pub(super) async fn resolve_action_metadata(
    state: &AppState,
    ext: &axum::http::Extensions,
    auth: &AuthContext,
    scope: &OrgScope,
    ceiling_user_id: Uuid,
    req: &CallRequest,
) -> Result<(ActionMetadata, Option<ResolvedModeC>), AppError> {
    // `service` is required. Mode A's legacy no-`service` raw-HTTP shape
    // is rejected with a clear migration hint — callers send
    // `service: "http"` instead, which routes through the verb shape
    // below against the synthetic `http` pseudo-service.
    if req.service.is_none() {
        return Err(AppError::BadRequest(
            "'service' is required (use service: 'http' for raw HTTP)".into(),
        ));
    }

    // Service + HTTP verb (SPEC §8). Caller names a service instance and
    // an HTTP method + path/url; auth is auto-injected from the instance's
    // binding; the template's `hosts[]` bounds where the bearer can land.
    // For `service: "http"`, `hosts` is empty and the caller's `url`
    // carries the full target (see `resolve_verb_host_and_path`).
    if let (Some(service_key), None) = (&req.service, &req.action) {
        let raw_method = req.method.clone().ok_or_else(|| {
            AppError::BadRequest(
                "'method' required for service + HTTP verb (set 'action' for the action shape)"
                    .into(),
            )
        })?;
        let (instance, svc) = resolve_service_for_verb_shape(
            state,
            ext,
            auth,
            scope,
            ceiling_user_id,
            req.service_id,
            service_key,
        )
        .await?;
        // Verb shape is HTTP-only — MCP / Platform runtimes have no
        // notion of "method + path" and would crash downstream when we
        // hand them an `ActionRequest` with a method. Reject up-front
        // with a clear 400 instead of bubbling out as a 500.
        if svc.runtime != Runtime::Http {
            return Err(AppError::BadRequest(format!(
                "service '{service_key}' has runtime={:?}; service + HTTP verb is HTTP-only. \
                 Use 'action' to call the runtime's tool / kernel.",
                svc.runtime
            )));
        }
        let (path, raw_url) = resolve_verb_host_and_path(&svc, service_key, &req.url, &req.path)?;
        let auth_injected_estimate = !svc.auth.is_empty()
            || instance
                .as_ref()
                .map(|i| i.connection_id.is_some() || i.secret_name.is_some())
                .unwrap_or(false);
        let metadata = ActionMetadata {
            validation_params: HashMap::new(),
            service_scope: Some(ServiceScope {
                service_key: service_key.clone(),
                action_key: String::new(),
                scope_param: None,
                http_verb: Some(HttpVerb {
                    method: raw_method.clone(),
                    path,
                }),
            }),
            risk: None,
            raw_method,
            raw_url,
            needs_gate: !req.secrets.is_empty() || auth_injected_estimate,
        };
        return Ok((metadata, Some(ResolvedModeC { svc, instance })));
    }

    // Service + defined action: load template, look up action, expose
    // schema + scope for validation and permission derivation.
    if let (Some(service_key), Some(action_key)) = (&req.service, &req.action) {
        let instance = resolve_instance_for_call(
            scope,
            auth.identity_id,
            ceiling_user_id,
            req.service_id,
            service_key,
        )
        .await?;

        let svc = if let Some(ref inst) = instance {
            crate::routes::templates::resolve_template_definition(
                state,
                ext,
                auth.org_id,
                auth.identity_id,
                &inst.template_key,
            )
            .await?
        } else {
            let from_template = crate::routes::templates::resolve_template_definition(
                state,
                ext,
                auth.org_id,
                auth.identity_id,
                service_key,
            )
            .await
            .ok();
            match from_template.or_else(|| state.registry.get(service_key).cloned()) {
                Some(s) => s,
                None => {
                    let available = caller_visible_instance_names(
                        scope,
                        auth.identity_id,
                        Some(ceiling_user_id),
                    )
                    .await?;
                    return Err(unknown_service_error(service_key, available));
                }
            }
        };

        let action = svc.actions.get(action_key).ok_or_else(|| {
            AppError::NotFound(format!(
                "action '{action_key}' not found in service '{service_key}'"
            ))
        })?;

        // MCP-runtime templates hide disabled tools from agents — mirror
        // the check `resolve_request` makes inside the MCP fork so
        // `/validate` doesn't green-light an action that `/call` would
        // refuse with 404.
        if svc.runtime == Runtime::Mcp && action.disabled {
            return Err(AppError::NotFound(format!(
                "action '{action_key}' is disabled on service '{service_key}'"
            )));
        }

        // Platform actions use the `permission` field as the action_key
        // for permission scoping (mirrors `resolve_request`).
        let perm_action_key = if svc.runtime == Runtime::Platform {
            action
                .permission
                .as_deref()
                .unwrap_or(action_key)
                .to_string()
        } else {
            action_key.clone()
        };

        // `needs_gate` is a *conservative estimate* of `/call`'s
        // post-resolve `meta.auth_injected`. MCP and Platform always
        // inject auth (gate=true). HTTP estimates from cheap signals:
        // a template auth method or an instance binding (connection or
        // secret). The estimate can over-gate vs. `/call` in one
        // direction only — when an HTTP service has auth declared but
        // OAuth token resolution at `/call` time fails, `/call` sets
        // `auth_injected=false` and skips Layer 2, while `/validate`
        // (which never resolves tokens, by design) keeps the gate on
        // and reports `would_require_approval`. That's a worse-case
        // surface for the dry-run, not a silent allow, so it's worth
        // the runtime savings of skipping the OAuth round-trip.
        let auth_injected_estimate = match svc.runtime {
            Runtime::Mcp | Runtime::Platform => true,
            Runtime::Http => {
                !svc.auth.is_empty()
                    || instance
                        .as_ref()
                        .map(|i| i.connection_id.is_some() || i.secret_name.is_some())
                        .unwrap_or(false)
            }
        };

        let metadata = ActionMetadata {
            validation_params: action.params.clone(),
            service_scope: Some(ServiceScope {
                service_key: service_key.clone(),
                action_key: perm_action_key,
                scope_param: action.scope_param.clone(),
                http_verb: None,
            }),
            risk: Some(action.risk),
            raw_method: String::new(),
            raw_url: String::new(),
            needs_gate: !req.secrets.is_empty() || auth_injected_estimate,
        };
        return Ok((metadata, Some(ResolvedModeC { svc, instance })));
    }

    // Unreachable: the no-service rejection at the top + the two
    // shape branches above (verb when `action` is None, action when both
    // are Some) cover every well-formed request.
    Err(AppError::BadRequest(
        "request must include 'service' plus either 'action' or ('method' + 'url'/'path')".into(),
    ))
}

/// Resolve a CallRequest into a concrete ActionRequest + metadata.
/// Handles both SPEC §8 shapes (Service + action, Service + HTTP verb).
/// Mode A raw HTTP rides on the verb shape against the synthetic `http`
/// pseudo-service.
///
/// `pre_resolved_mode_c` lets the caller hand in the template+instance
/// already looked up by `resolve_action_metadata`, so service shapes
/// don't pay for a duplicate DB lookup. `None` is fine for the validate
/// path or for callers that don't share that work.
#[allow(clippy::too_many_arguments)]
pub(super) async fn resolve_request(
    state: &AppState,
    ext: &axum::http::Extensions,
    auth: &AuthContext,
    scope: &OrgScope,
    // Connections + auth recovery resolve at `ceiling_user_id` (the owner, D22);
    // permission/service resolution below uses `auth.identity_id` (the caller).
    // There is no remaining need for a separately-threaded caller identity.
    ceiling_user_id: Uuid,
    req: &CallRequest,
    pre_resolved_mode_c: Option<ResolvedModeC>,
) -> Result<(ResolvedActionRequest, ResolvedMeta), AppError> {
    // Parse the optional `return_url` hint once, at the request boundary.
    // Doing it here (rather than relying on the kernel's re-validation deep
    // in the mint path) means a malformed hint fails fast with 400 instead
    // of surfacing as a 500 from `needs_authentication_for_service` (which
    // maps mint errors to `Internal`) or being silently dropped by
    // `check_required_scopes`. The validated value threads into every
    // reactive mint site so the OAuth callback can 303 the user back to the
    // partner. Host allow-listing still happens at callback time.
    let return_url_hint = platform_connections::parse_return_url(req.return_url.as_deref())?;
    let return_url_hint = return_url_hint.as_deref();

    // Service + HTTP verb (SPEC §8): caller-supplied method + path/url
    // against a service instance. Auth is auto-injected from the binding;
    // `svc.hosts` bounds where the bearer can land.
    if let (Some(service_key), None) = (&req.service, &req.action) {
        let raw_method = req.method.clone().ok_or_else(|| {
            AppError::BadRequest(
                "'method' required for service + HTTP verb (set 'action' for the action shape)"
                    .into(),
            )
        })?;
        let (instance, svc) = if let Some(pre) = pre_resolved_mode_c {
            (pre.instance, pre.svc)
        } else {
            resolve_service_for_verb_shape(
                state,
                ext,
                auth,
                scope,
                ceiling_user_id,
                req.service_id,
                service_key,
            )
            .await?
        };
        // Defense in depth: `resolve_action_metadata` already rejects
        // non-HTTP runtimes for the verb shape, so reaching here is a
        // bug. Re-check rather than crashing in the executor.
        if svc.runtime != Runtime::Http {
            return Err(AppError::BadRequest(format!(
                "service '{service_key}' has runtime={:?}; service + HTTP verb is HTTP-only.",
                svc.runtime
            )));
        }

        let (path, url) = resolve_verb_host_and_path(&svc, service_key, &req.url, &req.path)?;

        let resolved_auth = if let Some(ref inst) = instance {
            resolve_instance_auth(
                state,
                ext,
                scope,
                ceiling_user_id,
                inst,
                &svc,
                &req.secrets,
                return_url_hint,
            )
            .await?
        } else {
            resolve_service_auth(
                state,
                ext,
                scope,
                ceiling_user_id,
                &svc,
                &req.secrets,
                return_url_hint,
            )
            .await?
        };

        let description = format!("{} {} ({})", raw_method, path, svc.display_name);

        return Ok((
            ResolvedActionRequest {
                request: ActionRequest {
                    method: raw_method.clone(),
                    url,
                    headers: req.headers.clone(),
                    body: req.body.clone(),
                    secrets: resolved_auth.secrets,
                },
                auth_header: resolved_auth.auth_header,
            },
            ResolvedMeta {
                description: Some(description),
                service_scope: Some(ServiceScope {
                    service_key: service_key.clone(),
                    action_key: String::new(),
                    scope_param: None,
                    http_verb: Some(HttpVerb {
                        method: raw_method,
                        path,
                    }),
                }),
                risk: None,
                disclose: Vec::new(),
                redact: Vec::new(),
                params: HashMap::new(),
                mcp_target: None,
                platform_target: None,
                instance_id: instance.as_ref().map(|i| i.id),
            },
        ));
    }

    // Service + defined action
    if let (Some(service_key), Some(action_key)) = (&req.service, &req.action) {
        // Reuse the template/instance lookup performed by
        // `resolve_action_metadata` if the caller threaded it through.
        // Otherwise fall back to the same DB walk it would have run.
        let (instance, svc) = if let Some(pre) = pre_resolved_mode_c {
            (pre.instance, pre.svc)
        } else {
            let instance = resolve_instance_for_call(
                scope,
                auth.identity_id,
                ceiling_user_id,
                req.service_id,
                service_key,
            )
            .await?;

            let svc = if let Some(ref inst) = instance {
                // Instance exists — resolve its template; propagate errors (don't fall back
                // to global registry, which could match on the wrong key)
                crate::routes::templates::resolve_template_definition(
                    state,
                    ext,
                    auth.org_id,
                    auth.identity_id,
                    &inst.template_key,
                )
                .await?
            } else {
                // No instance — try unified resolution, then fall back to global registry.
                // When neither matches, surface a structured ServiceResolution
                // error that names a few instances the agent could call
                // instead, so the agent doesn't dead-end on "service not found".
                let from_template = crate::routes::templates::resolve_template_definition(
                    state,
                    ext,
                    auth.org_id,
                    auth.identity_id,
                    service_key,
                )
                .await
                .ok();
                match from_template.or_else(|| state.registry.get(service_key).cloned()) {
                    Some(s) => s,
                    None => {
                        let available = caller_visible_instance_names(
                            scope,
                            auth.identity_id,
                            Some(ceiling_user_id),
                        )
                        .await?;
                        return Err(unknown_service_error(service_key, available));
                    }
                }
            };
            (instance, svc)
        };

        let action = svc.actions.get(action_key).ok_or_else(|| {
            AppError::NotFound(format!(
                "action '{action_key}' not found in service '{service_key}'"
            ))
        })?;

        // Note: argument validation against `action.params` happens
        // upstream in `call_action_impl` via `resolve_action_metadata`,
        // before any permission/approval work. Keeping it out of here
        // means the validation gate is structurally guaranteed to run
        // before the approval-creation branch — a future refactor of
        // this function can't accidentally reorder past it.

        // ── MCP runtime fork ─────────────────────────────────────────
        // Disabled tools are invisible to agents even when they exist in
        // the compiled action map. Every MCP call force-gates (auth_injected)
        // so empty-auth MCP templates cannot bypass Layer 2 approvals.
        if svc.runtime == Runtime::Mcp {
            if action.disabled {
                return Err(AppError::NotFound(format!(
                    "action '{action_key}' is disabled on service '{service_key}'"
                )));
            }
            let mcp_spec = svc.mcp.clone().ok_or_else(|| {
                AppError::Internal(format!(
                    "service '{service_key}' has runtime=mcp but no mcp block"
                ))
            })?;

            // Resolve URL: instance wins, template is fallback.
            let resolved_url = match instance
                .as_ref()
                .and_then(|i| i.url.as_deref().map(str::to_string))
                .or(mcp_spec.url.clone())
            {
                Some(u) => u,
                None => {
                    return Err(mcp_missing_config_error(
                        scope,
                        auth.identity_id,
                        Some(ceiling_user_id),
                        service_key,
                        instance.as_ref(),
                        "url",
                    )
                    .await);
                }
            };

            // Resolve bearer secret_name: instance wins, template is fallback.
            let resolved_auth = match &mcp_spec.auth {
                McpAuth::None => McpAuth::None,
                McpAuth::Bearer {
                    secret_name: tpl_sn,
                } => {
                    let sn = match instance
                        .as_ref()
                        .and_then(|i| i.secret_name.as_deref())
                        .or(tpl_sn.as_deref())
                    {
                        Some(s) => s.to_string(),
                        None => {
                            return Err(mcp_missing_config_error(
                                scope,
                                auth.identity_id,
                                Some(ceiling_user_id),
                                service_key,
                                instance.as_ref(),
                                "secret_name",
                            )
                            .await);
                        }
                    };
                    McpAuth::Bearer {
                        secret_name: Some(sn),
                    }
                }
            };

            let tool = action
                .mcp_tool
                .clone()
                .unwrap_or_else(|| action_key.clone());
            let arguments = serde_json::to_value(&req.params).unwrap_or(serde_json::Value::Null);
            // Interpolate `{param}` placeholders in the action description
            // using the caller's supplied params. Mirrors the HTTP path so
            // approvals and audit rows name the actual target — e.g.
            // "Search issues in team ENG" instead of "Search issues in team
            // {team}". Resolvers don't apply (MCP has no HTTP parameter
            // schema), so we pass an empty resolved map.
            let interpolated = overslash_core::description::interpolate_description_with_resolved(
                &action.description,
                &req.params,
                &std::collections::HashMap::new(),
            );
            let description = format!("{interpolated} ({})", svc.display_name);
            return Ok((
                ResolvedActionRequest {
                    request: ActionRequest {
                        method: String::new(),
                        url: resolved_url.clone(),
                        headers: HashMap::new(),
                        body: None,
                        secrets: Vec::new(),
                    },
                    auth_header: None,
                },
                ResolvedMeta {
                    description: Some(description),
                    service_scope: Some(ServiceScope {
                        service_key: service_key.clone(),
                        action_key: action_key.clone(),
                        scope_param: action.scope_param.clone(),
                        http_verb: None,
                    }),
                    risk: Some(action.risk),
                    disclose: action.disclose.clone(),
                    redact: action.redact.clone(),
                    params: req.params.clone(),
                    mcp_target: Some(McpTarget {
                        url: resolved_url,
                        auth: resolved_auth,
                        tool,
                        arguments,
                    }),
                    platform_target: None,
                    instance_id: None,
                },
            ));
        }

        // ── Platform runtime fork ─────────────────────────────────────
        // Platform-runtime services route to the in-process handler registry.
        // They have no HTTP method/path, no secret injection. `auth_injected`
        // is set to true so the permission chain is always evaluated.
        if svc.runtime == Runtime::Platform {
            // Use the permission field as the action_key for PermissionKey derivation
            // so `list_templates`/`get_template`/`create_template` all resolve to
            // the `overslash:manage_templates_own:*` permission anchor.
            let perm_action_key = action
                .permission
                .as_deref()
                .unwrap_or(action_key)
                .to_string();
            let description = format!("{} ({})", action.description, svc.display_name);
            let params_map: serde_json::Map<String, serde_json::Value> =
                req.params.clone().into_iter().collect();
            return Ok((
                ResolvedActionRequest {
                    request: ActionRequest {
                        method: String::new(),
                        url: String::new(),
                        headers: HashMap::new(),
                        body: None,
                        secrets: Vec::new(),
                    },
                    auth_header: None,
                },
                ResolvedMeta {
                    description: Some(description),
                    service_scope: Some(ServiceScope {
                        service_key: service_key.clone(),
                        action_key: perm_action_key,
                        scope_param: action.scope_param.clone(),
                        http_verb: None,
                    }),
                    risk: Some(action.risk),
                    disclose: Vec::new(),
                    redact: Vec::new(),
                    params: HashMap::new(),
                    mcp_target: None,
                    platform_target: Some(PlatformTarget {
                        action_key: action_key.clone(),
                        params: params_map,
                    }),
                    instance_id: None,
                },
            ));
        }

        let host = svc
            .hosts
            .first()
            .ok_or_else(|| AppError::Internal(format!("service '{service_key}' has no hosts")))?;

        let mut path = action.path.clone();
        for (k, v) in &req.params {
            let placeholder = format!("{{{k}}}");
            if path.contains(&placeholder) {
                let val = v.as_str().unwrap_or(&v.to_string()).to_string();
                path = path.replace(&placeholder, &val);
            }
        }

        // Support hosts with explicit scheme (e.g. "http://localhost:1234" for tests)
        let base_url = if host.contains("://") {
            format!("{host}{path}")
        } else {
            format!("https://{host}{path}")
        };

        // Header-located params (e.g. a template-pinned `Notion-Version`) are
        // routed into the request headers below — they must not leak into the
        // query string or JSON body like path/query/body params do.
        let is_header_param = |k: &str| {
            action
                .params
                .get(k)
                .map(|p| p.location == ParamLocation::Header)
                .unwrap_or(false)
        };

        let non_path_params: HashMap<String, serde_json::Value> = req
            .params
            .iter()
            .filter(|(k, _)| !action.path.contains(&format!("{{{k}}}")))
            .filter(|(k, _)| !is_header_param(k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let (url, body) = if action.method == "GET" || action.method == "HEAD" {
            // Append non-path params as query string
            let pairs = non_path_params
                .iter()
                .flat_map(|(k, v)| encode_query_param(k, v))
                .collect::<Vec<_>>();
            let url = if pairs.is_empty() {
                base_url
            } else {
                format!("{base_url}?{}", pairs.join("&"))
            };
            (url, None)
        } else {
            // Split non-path params: query-located ones (per the template's
            // `in: query`) go to the query string, the rest become the JSON body.
            let (query_params, body_params): (Vec<_>, Vec<_>) =
                non_path_params.iter().partition(|(k, _)| {
                    action
                        .params
                        .get(k.as_str())
                        .map(|p| p.location == ParamLocation::Query)
                        .unwrap_or(false)
                });
            let pairs = query_params
                .iter()
                .flat_map(|(k, v)| encode_query_param(k, v))
                .collect::<Vec<_>>();
            let url = if pairs.is_empty() {
                base_url
            } else {
                format!("{base_url}?{}", pairs.join("&"))
            };
            let body = if body_params.is_empty() {
                None
            } else {
                let map: serde_json::Map<String, serde_json::Value> = body_params
                    .into_iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                Some(serde_json::to_string(&map).unwrap_or_default())
            };
            (url, body)
        };

        let mut headers = HashMap::new();
        if body.is_some() {
            headers.insert("Content-Type".to_string(), "application/json".to_string());
        }
        // Template-declared header params (`in: header`) are sent verbatim as
        // request headers. `apply_defaults` has already filled any that carry a
        // `default` and were omitted by the caller (e.g. `Notion-Version`), so
        // this stamps the constant version header on every call.
        for (k, v) in &req.params {
            if is_header_param(k) {
                let val = v
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| v.to_string());
                headers.insert(k.clone(), val);
            }
        }

        // Scope gate: if the action declares `required_scopes`, and the
        // connection we'd use to auth doesn't carry all of them, return
        // `missing_scopes` with the upgrade URL *before* the outgoing call
        // happens. This is the fail-fast path promised by SPEC §9 — we don't
        // want the provider's 403 to surface as a generic upstream error.
        check_required_scopes(
            state,
            scope,
            ceiling_user_id,
            instance.as_ref(),
            &svc,
            action,
            return_url_hint,
        )
        .await?;

        // Auth resolution: if instance has a bound connection/secret, use that;
        // otherwise fall back to auto-resolve from the template's auth config.
        // RefreshFailed / NoRefreshToken from the resolver bubble up as
        // `ReauthRequired` (with a freshly-minted gated URL) instead of being
        // swallowed and surfaced as opaque upstream errors downstream.
        let resolved_auth = if let Some(ref inst) = instance {
            resolve_instance_auth(
                state,
                ext,
                scope,
                ceiling_user_id,
                inst,
                &svc,
                &req.secrets,
                return_url_hint,
            )
            .await?
        } else {
            resolve_service_auth(
                state,
                ext,
                scope,
                ceiling_user_id,
                &svc,
                &req.secrets,
                return_url_hint,
            )
            .await?
        };

        // After resolution, if the template declares OAuth and *nothing*
        // was injected — no header, no secret, no connection — the
        // upstream call is going to fail with whatever the provider
        // returns when faced with an empty Authorization header. Catch
        // it here and hand the agent a freshly-minted gated URL it can
        // forward to the user. Same envelope shape as the RefreshFailed
        // path so MCP clients only need one branch.
        //
        // ApiKey-only templates aren't covered: there's no OAuth provider
        // to mint a URL for, and the existing secret-not-found errors
        // already give the operator a "set this secret" path. MCP-bearer
        // templates take a different fork (the runtime check above) and
        // never reach this branch.
        if !resolved_auth.oauth_injected && resolved_auth.secrets.is_empty() {
            if let Some(err) = needs_authentication_for_service(
                state,
                ext,
                scope.org_id(),
                ceiling_user_id,
                &svc,
                action,
                instance.as_ref(),
                service_key,
                return_url_hint,
            )
            .await?
            {
                return Err(err);
            }
        }

        let resolver_base = if host.contains("://") {
            host.to_string()
        } else {
            format!("https://{host}")
        };
        // Display-param resolution makes authenticated GETs against the
        // provider — merge the live auth header into a throwaway map for
        // those calls only; it never lands on the ActionRequest itself.
        let resolver_headers = {
            let mut h = headers.clone();
            if let Some(ah) = &resolved_auth.auth_header {
                h.insert(ah.name.clone(), ah.value.clone());
            }
            h
        };
        let resolved = crate::services::param_resolver::resolve_display_params(
            &state.http_client,
            &resolver_base,
            &resolver_headers,
            action,
            &req.params,
        )
        .await;

        let interpolated = overslash_core::description::interpolate_description_with_resolved(
            &action.description,
            &req.params,
            &resolved,
        );
        let description = format!("{interpolated} ({})", svc.display_name);

        let action_risk = action.risk;

        return Ok((
            ResolvedActionRequest {
                request: ActionRequest {
                    method: action.method.clone(),
                    url,
                    headers,
                    body,
                    secrets: resolved_auth.secrets,
                },
                auth_header: resolved_auth.auth_header,
            },
            ResolvedMeta {
                description: Some(description),
                service_scope: Some(ServiceScope {
                    service_key: service_key.clone(),
                    action_key: action_key.clone(),
                    scope_param: action.scope_param.clone(),
                    http_verb: None,
                }),
                risk: Some(action_risk),
                disclose: action.disclose.clone(),
                redact: action.redact.clone(),
                params: req.params.clone(),
                mcp_target: None,
                platform_target: None,
                instance_id: instance.as_ref().map(|i| i.id),
            },
        ));
    }

    // Unreachable: `resolve_action_metadata` rejects no-`service` requests
    // up front, and the two arms above cover both well-formed shapes.
    Err(AppError::BadRequest(
        "request must include 'service' plus either 'action' or ('method' + 'url'/'path')".into(),
    ))
}

/// Serialize one query param into zero or more URL-encoded `key=value`
/// pairs. Arrays expand to one pair per element (OpenAPI form/explode
/// style, e.g. Gmail's repeatable `labelIds`); an empty array emits
/// nothing. Nested arrays/objects inside an array fall through to their
/// JSON string encoding — templates only declare arrays of scalars, so
/// that case is a template bug, not a runtime one.
fn encode_query_param(key: &str, value: &serde_json::Value) -> Vec<String> {
    let encode = |v: &serde_json::Value| {
        let val = v.as_str().unwrap_or(&v.to_string()).to_string();
        format!("{key}={}", urlencoding::encode(&val))
    };
    match value {
        serde_json::Value::Array(items) => items.iter().map(encode).collect(),
        other => vec![encode(other)],
    }
}

#[cfg(test)]
mod tests {
    use super::encode_query_param;
    use serde_json::json;

    #[test]
    fn array_expands_to_repeated_pairs() {
        assert_eq!(
            encode_query_param("labelIds", &json!(["INBOX", "UNREAD"])),
            vec!["labelIds=INBOX", "labelIds=UNREAD"]
        );
    }

    #[test]
    fn scalars_produce_single_pair() {
        assert_eq!(encode_query_param("q", &json!("hello")), vec!["q=hello"]);
        assert_eq!(
            encode_query_param("maxResults", &json!(50)),
            vec!["maxResults=50"]
        );
        assert_eq!(
            encode_query_param("includeSpamTrash", &json!(true)),
            vec!["includeSpamTrash=true"]
        );
    }

    #[test]
    fn empty_array_emits_nothing() {
        assert_eq!(
            encode_query_param("labelIds", &json!([])),
            Vec::<String>::new()
        );
    }

    #[test]
    fn elements_are_url_encoded() {
        assert_eq!(
            encode_query_param("q", &json!(["a b&c", "d=e"])),
            vec!["q=a%20b%26c", "q=d%3De"]
        );
    }
}
