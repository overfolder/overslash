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

use super::service_resolve::*;
use super::*;

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
        let (instance, svc) = resolve_service_for_call(
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
        crate::services::outbound_tls::check_url(&raw_url)?;
        let auth_injected_estimate = !svc.auth.is_empty()
            || instance.connection_id.is_some()
            || instance.secret_name.is_some();
        let metadata = ActionMetadata {
            validation_params: HashMap::new(),
            // Moot: `validate_args` short-circuits on an empty schema, so
            // there is nothing here for the flag to relax. Named explicitly
            // rather than left to a `Default` so the verb shape's answer is
            // visible next to the empty schema that makes it irrelevant.
            additional_properties: false,
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
            subactions: None,
            subaction_of: None,
        };
        return Ok((metadata, Some(ResolvedModeC { svc, instance })));
    }

    // Service + defined action: load template, look up action, expose
    // schema + scope for validation and permission derivation.
    if let (Some(service_key), Some(action_key)) = (&req.service, &req.action) {
        let (instance, mut svc) = resolve_service_for_call(
            state,
            ext,
            auth,
            scope,
            ceiling_user_id,
            req.service_id,
            service_key,
        )
        .await?;
        overlay_instance_discovered_tools(Some(&instance), &mut svc);

        let metadata = action_metadata(&svc, &instance, service_key, action_key, req)?;
        return Ok((metadata, Some(ResolvedModeC { svc, instance })));
    }

    // Unreachable: the no-service rejection at the top + the two
    // shape branches above (verb when `action` is None, action when both
    // are Some) cover every well-formed request.
    Err(AppError::BadRequest(
        "request must include 'service' plus either 'action' or ('method' + 'url'/'path')".into(),
    ))
}

/// [`ActionMetadata`] for one action of an already-resolved service.
///
/// Split out of [`resolve_action_metadata`] so a callable subaction, once
/// rewritten into its parent's params, can be re-described as the parent
/// without a second template/instance lookup.
pub(super) fn action_metadata(
    svc: &overslash_core::types::ServiceDefinition,
    instance: &overslash_db::repos::service_instance::ServiceInstanceRow,
    service_key: &str,
    action_key: &str,
    req: &CallRequest,
) -> Result<ActionMetadata, AppError> {
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
        action_key.to_string()
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
                || instance.connection_id.is_some()
                || instance.secret_name.is_some()
        }
    };

    let metadata = ActionMetadata {
        validation_params: action.params.clone(),
        additional_properties: action.additional_properties,
        service_scope: Some(ServiceScope {
            service_key: service_key.to_string(),
            action_key: perm_action_key,
            scope_param: action.scope_param.clone(),
            http_verb: None,
        }),
        risk: Some(action.risk),
        raw_method: String::new(),
        raw_url: String::new(),
        needs_gate: !req.secrets.is_empty() || auth_injected_estimate,
        subactions: action.subactions.clone().map(|spec| SubactionContext {
            spec,
            label_template: action.label_template().to_string(),
            service_display_name: svc.display_name.clone(),
        }),
        subaction_of: action.subaction_of.clone(),
    };
    Ok(metadata)
}

/// Canonicalize and validate a call's arguments against `meta`'s schema:
/// aliases, pinned instance config, defaults, coercion, then `validate_args`.
///
/// One function so `/call` and `/validate` run the same sequence in the same
/// order — their `invalid_action_args` 400 bodies are byte-identical by
/// contract — and so a callable subaction can run it twice: once against its
/// own schema, and again as the parent it was rewritten into.
pub(super) fn prepare_args(
    meta: &ActionMetadata,
    mode_c: Option<&ResolvedModeC>,
    params: &mut HashMap<String, serde_json::Value>,
) -> Result<(), AppError> {
    use overslash_core::openapi::validate_input;
    // Aliases first, so defaults, coercion, validation, the approval replay
    // payload, and resolution all see canonical keys only.
    validate_input::apply_aliases(&meta.validation_params, params);
    // Pins after aliases (they land on canonical keys) and before defaults (a
    // pin beats the template default while an explicit caller arg still beats
    // the pin). Precedence, high to low: caller arg > instance config >
    // org-layer default > template default.
    super::apply_instance_config(&meta.validation_params, mode_c, params);
    // Defaults before validation, so a `required` param with a default isn't
    // rejected as missing, and before resolution, so the default flows into the
    // outgoing request like a caller-supplied value.
    validate_input::apply_defaults(&meta.validation_params, params);
    // Repair fixable shape problems (int→string, enum case) in place before
    // validating — the coerced value is what gets approved and executed.
    validate_input::coerce_args(&meta.validation_params, params);
    validate_input::validate_args(&meta.validation_params, params, meta.additional_properties)
        .map_err(|errors| {
            super::validate::invalid_action_args_error(&meta.validation_params, errors)
        })
}
