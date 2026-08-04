//! Request resolution: full `ActionRequest` resolution.
//!
//! The cheap metadata pre-resolve lives in `resolve_metadata` (re-exported
//! below so `use super::resolve::*` keeps reaching it); the body/query
//! encoding helpers live in `resolve_encode`.

use std::collections::HashMap;

use uuid::Uuid;

use overslash_db::scopes::OrgScope;

use crate::{AppState, error::AppError, extractors::AuthContext, services::platform_connections};
use overslash_core::types::{ActionRequest, ParamLocation, ResolvedActionRequest, Runtime};

use super::*;
use super::{
    auth_envelopes::*, auth_resolve::*, auth_scopes::*, errors::*, resolve_encode::*,
    service_resolve::*,
};

pub(super) use super::resolve_metadata::resolve_action_metadata;

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
                    scope_param: Default::default(),
                    http_verb: Some(HttpVerb {
                        method: raw_method,
                        path,
                    }),
                }),
                risk: None,
                disclose: Vec::new(),
                redact: Vec::new(),
                download: None,
                params: HashMap::new(),
                resolved: HashMap::new(),
                mcp_target: None,
                platform_target: None,
                instance_id: instance.as_ref().map(|i| i.id),
                binding: BindingFacts::new(instance.as_ref(), &svc, resolved_auth.principal),
            },
        ));
    }

    // Service + defined action
    if let (Some(service_key), Some(action_key)) = (&req.service, &req.action) {
        // Reuse the template/instance lookup performed by
        // `resolve_action_metadata` if the caller threaded it through.
        // Otherwise fall back to the same DB walk it would have run.
        let (instance, mut svc) = if let Some(pre) = pre_resolved_mode_c {
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
        overlay_instance_discovered_tools(instance.as_ref(), &mut svc);

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

            // Effective URL + auth: instance wins, template is fallback.
            // Shared with the instance-scoped resync route (mcp_resolve).
            let ResolvedMcp {
                url: resolved_url,
                auth: resolved_auth,
                oauth_header: mcp_oauth_header,
            } = resolve_effective_mcp(
                state,
                ext,
                scope,
                auth.identity_id,
                ceiling_user_id,
                service_key,
                instance.as_ref(),
                &mcp_spec,
                svc.instance_defaults
                    .as_ref()
                    .and_then(|d| d.url.as_deref()),
                return_url_hint,
            )
            .await?;

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
                action.label_template(),
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
                    download: action.download.clone(),
                    params: req.params.clone(),
                    // Resolvers don't run for MCP (no HTTP parameter schema),
                    // so the disclosure projection's `resolved` stays empty.
                    resolved: HashMap::new(),
                    mcp_target: Some(McpTarget {
                        url: resolved_url,
                        auth: resolved_auth,
                        auth_header: mcp_oauth_header,
                        tool,
                        arguments,
                    }),
                    platform_target: None,
                    instance_id: None,
                    binding: BindingFacts::new(instance.as_ref(), &svc, None),
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
                    download: None,
                    params: HashMap::new(),
                    resolved: HashMap::new(),
                    mcp_target: None,
                    platform_target: Some(PlatformTarget {
                        action_key: action_key.clone(),
                        params: params_map,
                    }),
                    instance_id: None,
                    binding: BindingFacts::new(instance.as_ref(), &svc, None),
                },
            ));
        }

        let mut path = action.path.clone();
        for (k, v) in &req.params {
            let placeholder = format!("{{{k}}}");
            if path.contains(&placeholder) {
                let val = v.as_str().unwrap_or(&v.to_string()).to_string();
                path = path.replace(&placeholder, &val);
            }
        }

        // Not `Internal`: an instance created before the template lost its host
        // (or restored from a backup that predates the endpoint check in
        // `kernel_create_service`) is a configuration gap the operator can
        // close, not a bug in the gateway — so say what to do rather than
        // returning an opaque 500.
        let base = effective_base(instance.as_ref(), &svc).ok_or_else(|| {
            AppError::BadRequest(format!(
                "service '{service_key}' has no endpoint: the template declares no host and \
                 this instance sets no `url`. Set one on the instance, or org-wide on a \
                 layer's `instance_defaults.url`."
            ))
        })?;
        let base_url = format!("{base}{path}");

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
            // Whether a body is sent follows the template's declared
            // `requestBody`, not whether the caller happened to supply fields.
            // An operation whose fields are all optional (`POST /email/search`)
            // still sends `{}` — a strict upstream extractor checks
            // `Content-Type` before it ever looks at the body, so omitting the
            // body omits the header and the call is rejected outright.
            let body = action
                .request_body
                .as_ref()
                .filter(|rb| rb.is_json())
                .map(|_| {
                    let mut map = serde_json::Map::new();
                    for (k, v) in body_params {
                        // A string param whose `x-overslash-sql-field` names a
                        // path other than its own name is *moved* there
                        // (`query` → `{"native": {"query": …}}`), keeping the
                        // caller surface flat while matching the upstream's
                        // nested payload (D43). Object-mode sql params (the
                        // path points inside the caller-supplied object) place
                        // flat like everything else.
                        let nested_path = action.params.get(k.as_str()).and_then(|p| {
                            p.sql_field
                                .as_deref()
                                .filter(|path| p.param_type != "object" && *path != k.as_str())
                        });
                        match nested_path {
                            Some(path) => insert_at_body_path(&mut map, path, v.clone()),
                            None => {
                                map.insert(k.clone(), v.clone());
                            }
                        }
                    }
                    serde_json::to_string(&map).unwrap_or_default()
                });
            (url, body)
        };

        let mut headers = HashMap::new();
        // `Content-Type` describes the payload, so it is emitted with the body
        // and only with the body — never on a bodyless GET, and never without
        // one. Template-chosen headers travel their own channel (`in: header`
        // params and `securitySchemes`), so the two never contend.
        if body.is_some() {
            if let Some(rb) = &action.request_body {
                headers.insert("Content-Type".to_string(), rb.content_type.clone());
            }
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

        // Reuse the same base the action URL resolved to (instance override or
        // template host) so display-param GETs hit the same deployment.
        let resolver_base = base.clone();
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
            &state.config,
            &resolver_base,
            &resolver_headers,
            action,
            &req.params,
        )
        .await;

        // The approval title and audit row use the short `summary` (falling
        // back to `description` when an action authors only the long form) —
        // the agent-facing `description` is free to run to a paragraph, which
        // no approval prompt should render.
        let interpolated = overslash_core::description::interpolate_description_with_resolved(
            action.label_template(),
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
                download: None,
                params: req.params.clone(),
                resolved,
                mcp_target: None,
                platform_target: None,
                instance_id: instance.as_ref().map(|i| i.id),
                binding: BindingFacts::new(instance.as_ref(), &svc, resolved_auth.principal),
            },
        ));
    }

    // Unreachable: `resolve_action_metadata` rejects no-`service` requests
    // up front, and the two arms above cover both well-formed shapes.
    Err(AppError::BadRequest(
        "request must include 'service' plus either 'action' or ('method' + 'url'/'path')".into(),
    ))
}
