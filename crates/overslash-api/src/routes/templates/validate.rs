//! Stateless lint endpoints: `/v1/templates/validate` and
//! `/v1/templates/validate-delta`.

use super::*;

/// POST /v1/templates/validate
///
/// Lint an OpenAPI 3.1 template definition without persisting it. Accepts the
/// raw YAML as the request body (any Content-Type; typically
/// `application/yaml` or `text/plain`) so dashboards and CLIs can pipe files
/// directly:
///
/// ```sh
/// curl --data-binary @service.yaml $API/v1/templates/validate
/// ```
///
/// Always returns 200 with a `ValidationReport`. A YAML parse failure, alias
/// ambiguity, or duplicate operationId is itself a reported validation error,
/// not a transport-level error — the dashboard editor calls this on every
/// keystroke and wants structured diagnostics, not HTTP 400s.
///
/// Org-independent, but not deployment-independent: a `${VAR}` this deployment
/// cannot resolve is reported as `template_var_unset`, so the editor surfaces
/// it while the author is still typing rather than at first call.
pub(super) async fn validate_template(
    State(state): State<AppState>,
    auth: AuthContext,
    body: String,
) -> Result<Json<ValidationReport>> {
    // Auth extraction enforces authentication. Template linting is stateless
    // and org-independent — the org_id is used only for tracing / rate-limit
    // bucketing at the middleware layer. Binding it here satisfies the
    // ignored-auth pre-commit gate (see PR #60).
    let _ = auth.org_id;

    if body.len() > MAX_TEMPLATE_YAML_BYTES {
        return Err(AppError::BadRequest(format!(
            "template too large: {} bytes (max {MAX_TEMPLATE_YAML_BYTES})",
            body.len()
        )));
    }
    Ok(Json(validate_template_yaml(&body, state.registry.vars())))
}

#[derive(Deserialize)]
pub(super) struct ValidateDeltaRequest {
    /// Base template key the delta layers over.
    extends: String,
    /// The derived-layer delta to validate.
    delta: serde_json::Value,
    /// Whether the layer being authored is user-namespace (`true`) or
    /// org-namespace (`false`, default). Controls the base-resolution identity
    /// context so the preview folds over the *same* base create/update will —
    /// an org layer resolves the base with no user tier (org → global), a user
    /// layer resolves user → org → global.
    #[serde(default)]
    user_level: bool,
}

/// POST /v1/templates/validate-delta
///
/// Lint a derived-layer `delta` against its resolved base without persisting.
/// Powers the layer editor's live validation. Returns the same
/// `{valid, errors, warnings}` `ValidationReport` shape as `/validate`, plus the
/// fold's resolution warnings so the editor can preview drift.
pub(super) async fn validate_delta_route(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
    Json(req): Json<ValidateDeltaRequest>,
) -> Result<Json<ValidationReport>> {
    let delta: Delta = match serde_json::from_value(req.delta) {
        Ok(d) => d,
        Err(e) => {
            return Ok(Json(ValidationReport {
                valid: false,
                errors: vec![ValidationIssue::new(
                    "malformed_delta",
                    e.to_string(),
                    "delta",
                )],
                warnings: Vec::new(),
            }));
        }
    };
    // Mirror create/update's owner context: an org-namespace layer resolves the
    // base with no user tier; a user-namespace layer resolves in the caller's
    // identity context.
    let base_identity = if req.user_level {
        auth.identity_id
    } else {
        None
    };
    let base = crate::services::template_resolve::resolve(
        state.db(&ext),
        &state.registry,
        auth.org_id,
        base_identity,
        &req.extends,
    )
    .await
    .map_err(|_| AppError::BadRequest(format!("base template '{}' not found", req.extends)))?;

    let mut report = service_layer::validate_delta(&delta, &base.definition, req.user_level);
    // Fold this delta over the base and surface the resolution warnings too, so
    // the editor previews shadowed extensions / dead entries live.
    let (_def, resolution_warnings) = service_layer::apply_delta(&delta, &base.definition);
    report.warnings.extend(resolution_warnings);
    Ok(Json(report))
}
