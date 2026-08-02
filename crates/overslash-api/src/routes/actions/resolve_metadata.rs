//! Cheap, side-effect-free pre-resolution of a `CallRequest` into
//! [`ActionMetadata`] (schema for `validate_args`, permission scope,
//! declared risk) plus the template/instance the call path reuses.
//!
//! Split out of `resolve.rs`, which owns the full `ActionRequest`
//! resolution.

use std::collections::HashMap;

use uuid::Uuid;

use overslash_db::scopes::OrgScope;

use crate::{AppState, error::AppError, extractors::AuthContext};
use overslash_core::types::Runtime;

use super::*;
use super::{errors::*, service_resolve::*};

pub(crate) async fn resolve_action_metadata(
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
                scope_param: Default::default(),
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

        let mut svc = if let Some(ref inst) = instance {
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
        overlay_instance_discovered_tools(instance.as_ref(), &mut svc);

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
