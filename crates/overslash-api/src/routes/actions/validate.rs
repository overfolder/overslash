//! `POST /v1/actions/validate` dry-run handler + arg-validation error builder.

use std::collections::HashMap;

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use overslash_db::scopes::OrgScope;

use crate::{
    AppState,
    error::AppError,
    extractors::{AuthContext, ReqExt},
    services::{
        group_ceiling,
        response_filter::{self},
    },
};
use overslash_core::{
    permissions::{GroupCeilingResult, PermissionKey},
    types::service::Risk,
};

use super::*;
use super::{resolve::*, service_resolve::*};

/// Outcome label tracked alongside the response so the metrics wrapper
/// can distinguish e.g. `validated` vs `would_require_approval` without
/// re-parsing the response body.
pub(super) async fn validate_action_impl(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
    scope: OrgScope,
    Json(mut req): Json<CallRequest>,
) -> Result<(Response, &'static str), AppError> {
    // Filter syntax — same gate as `/call`. A malformed expression is a
    // 400, not a wasted upstream burn.
    if let Some(filter) = req.filter.as_ref() {
        response_filter::validate_syntax(filter).map_err(AppError::FilterSyntax)?;
    }

    let identity_id = auth
        .identity_id
        .ok_or_else(|| AppError::BadRequest("api key must be bound to an identity".into()))?;
    let identity = scope
        .get_identity(identity_id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    let ceiling_user_id = group_ceiling::ceiling_user_id_from_identity(&identity)?;

    // Cheap resolution — loads the action template (service shapes)
    // without running OAuth, param resolvers, or scope checks. The
    // resolved template/instance ride along but the validate path
    // doesn't forward them anywhere; they're dropped at the end of
    // this scope.
    let (meta, resolved_mode_c) =
        resolve_action_metadata(&state, &ext, &auth, &scope, ceiling_user_id, &req).await?;

    // Mirror `/call`'s admin-as-owner rebind so validation answers reflect
    // the identity that would actually run the action — see the matching
    // block in `call_action_impl` for the full rationale.
    let (identity, identity_id, ceiling_user_id, scope) = apply_owner_impersonation(
        &scope,
        identity,
        identity_id,
        ceiling_user_id,
        resolved_mode_c.as_ref().and_then(|m| m.instance.as_ref()),
        req.service_id.is_some(),
    )
    .await?;

    // Rewrite parameter aliases to canonical names in lockstep with `/call`
    // so the dry-run validates the exact keys the real call would execute.
    overslash_core::openapi::validate_input::apply_aliases(
        &meta.validation_params,
        &mut req.params,
    );
    // Overlay the pinned config (instance's own, then the org layer's defaults)
    // in lockstep with `/call`, so a param satisfied by a pin doesn't validate
    // here as missing.
    super::apply_instance_config(
        &meta.validation_params,
        resolved_mode_c.as_ref(),
        &mut req.params,
    );
    // Fill template-declared defaults before validating — mirrors `/call`
    // so a defaulted-required param (e.g. `calendarId: primary`) omitted by
    // the caller validates here exactly as it would execute there.
    overslash_core::openapi::validate_input::apply_defaults(
        &meta.validation_params,
        &mut req.params,
    );
    // Coerce in lockstep with `/call` so the dry-run validates the same value
    // the real call would execute, keeping the 400 bodies byte-identical.
    overslash_core::openapi::validate_input::coerce_args(&meta.validation_params, &mut req.params);

    // Argument validation runs before the risk gate so a request with
    // both bad params and a wrong-risk assertion produces the same
    // `invalid_action_args` 400 it would on `/call` — the byte-identical
    // 400 contract is meaningful only when the gates fire in the same
    // order in both endpoints.
    if let Err(errors) =
        overslash_core::openapi::validate_input::validate_args(&meta.validation_params, &req.params)
    {
        return Err(invalid_action_args_error(&meta.validation_params, errors));
    }

    // Caller-asserted risk gate — mirrors `/call` (which runs it inside
    // `resolve_request` after `validate_args` has already gated bad args).
    if let Some(required) = req.require_risk {
        let effective = meta
            .risk
            .unwrap_or_else(|| Risk::from_http_method(&meta.raw_method));
        if required == Risk::Read && effective.is_mutating() {
            let action_label = req
                .action
                .as_deref()
                .or(req.service.as_deref())
                .unwrap_or(&meta.raw_url);
            return Err(AppError::BadRequest(format!(
                "action '{action_label}' is risk={effective}; this entry point only permits risk=read actions. Use overslash_call instead."
            )));
        }
    }

    // Permission key derivation — same logic as `/call` runs after
    // `resolve_request` returns, using the resolved scope and method.
    // After the no-`service` rejection in `resolve_action_metadata`,
    // `meta.service_scope` is always `Some` (both action and verb shapes
    // populate it; `http` flows through the verb shape).
    let svc = meta.service_scope.as_ref().expect(
        "resolve_action_metadata always sets service_scope after the no-service-rejection gate",
    );
    let perm_keys = if let Some(ref verb) = svc.http_verb {
        PermissionKey::from_service_http(&svc.service_key, &verb.method, &verb.path)
    } else {
        PermissionKey::from_service_action(
            &svc.service_key,
            &svc.action_key,
            &svc.scope_param,
            &req.params,
        )
    };

    // Layer 1: group ceiling. Surfaced as a permission status, not a
    // 403 — validate always returns 200 on a well-formed call so the
    // caller has a single decode path.
    let ceiling_service = svc.service_key.clone();
    let ceiling_risk = meta
        .risk
        .unwrap_or_else(|| Risk::from_http_method(&meta.raw_method));
    let ceiling = group_ceiling::load_ceiling(&scope, ceiling_user_id).await?;
    let mut skip_layer2 = false;
    if ceiling.has_groups {
        match group_ceiling::check_ceiling(&ceiling, &ceiling_service, ceiling_risk) {
            GroupCeilingResult::ExceedsCeiling(reason) => {
                let body = serde_json::json!({
                    "ok": true,
                    "permission": {
                        "status": "exceeds_ceiling",
                        "reason": reason,
                    },
                });
                return Ok((
                    (StatusCode::OK, Json(body)).into_response(),
                    "exceeds_ceiling",
                ));
            }
            GroupCeilingResult::WithinCeiling { read_bypass } => {
                if read_bypass && identity.kind != "user" {
                    skip_layer2 = true;
                }
            }
            GroupCeilingResult::NoGroups => {}
        }
    }

    // Layer 2: permission chain. Users are gated by groups only, so
    // they get an immediate `allowed`. Agents walk the chain — first
    // gap reports `would_require_approval` without writing an approval
    // row or firing a webhook.
    if identity.kind == "user" || !meta.needs_gate || skip_layer2 {
        let body = serde_json::json!({
            "ok": true,
            "permission": { "status": "allowed" },
        });
        return Ok(((StatusCode::OK, Json(body)).into_response(), "validated"));
    }

    let bubble_secs =
        overslash_db::repos::org::get_approval_auto_bubble_secs(state.db(&ext), auth.org_id)
            .await?
            .unwrap_or(300);
    let force_user_resolver = bubble_secs == 0;

    let outcome = crate::services::permission_chain::walk(
        &scope,
        identity_id,
        &perm_keys,
        force_user_resolver,
    )
    .await?;

    let (body, label) = match outcome {
        crate::services::permission_chain::ChainWalkResult::Allowed => (
            serde_json::json!({
                "ok": true,
                "permission": { "status": "allowed" },
            }),
            "validated",
        ),
        crate::services::permission_chain::ChainWalkResult::Gap {
            uncovered_keys,
            gap_identity_id,
            initial_resolver_id,
            rule_placement_id: _,
        } => {
            let keys: Vec<String> = uncovered_keys.iter().map(|k| k.0.clone()).collect();
            (
                serde_json::json!({
                    "ok": true,
                    "permission": {
                        "status": "would_require_approval",
                        "uncovered_keys": keys,
                        "gap_identity_id": gap_identity_id,
                        "initial_resolver_id": initial_resolver_id,
                    },
                }),
                "would_require_approval",
            )
        }
        crate::services::permission_chain::ChainWalkResult::Denied(reason) => (
            serde_json::json!({
                "ok": true,
                "permission": { "status": "denied", "reason": reason },
            }),
            "denied",
        ),
    };
    Ok(((StatusCode::OK, Json(body)).into_response(), label))
}

/// Build the structured 400 returned when caller args don't match an
/// action's declared input contract. Surfaces the full `required` /
/// `allowed` schema so an agent runner can hand a clean shape to the LLM
/// instead of grepping a sentence.
pub(super) fn invalid_action_args_error(
    params: &HashMap<String, overslash_core::types::ActionParam>,
    errors: Vec<overslash_core::openapi::validate_input::ArgError>,
) -> AppError {
    let mut required: Vec<String> = params
        .iter()
        .filter(|(_, p)| p.required)
        .map(|(k, _)| k.clone())
        .collect();
    required.sort();
    let mut allowed: Vec<String> = params.keys().cloned().collect();
    allowed.sort();
    let detail = overslash_core::openapi::validate_input::format_errors(&errors);
    let errors = errors.into_iter().map(Into::into).collect();
    AppError::InvalidActionArgs {
        required,
        allowed,
        errors,
        detail,
    }
}
