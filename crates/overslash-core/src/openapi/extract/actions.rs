//! `paths.*.*` and `x-overslash-platform_actions.*` → `ServiceAction`.

use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::template_validation::ValidationIssue;
use crate::types::{ActionParam, DeclaredRisk, ParamLocation, Risk, ServiceAction};

use super::super::ext::{self, Ext, Pos};
use super::params::{collect_body_parameters, collect_parameters, parse_request_body};
use super::{
    parse_aliases, parse_disclose, parse_instance_config, parse_pagination, parse_redact,
    parse_scope_params, parse_sql_policy, parse_timeout_ms, parse_wait_mode,
};

// ── paths.*.* → ServiceAction ────────────────────────────────────────

/// Pick the required OAuth scopes out of a `security` array Value.
///
/// For each security requirement object we pick the first non-empty scope
/// list — matches the OpenAPI 3.1 "requirements are OR-ed" model for the
/// common case of a single `oauth2` scheme. A non-array Value, an empty array,
/// or requirements with only empty scope lists yield no scopes.
fn scopes_from_security(security: &Value) -> Vec<String> {
    security
        .as_array()
        .and_then(|reqs| {
            reqs.iter().find_map(|req| {
                req.as_object()?.values().find_map(|scopes| {
                    let arr = scopes.as_array()?;
                    if arr.is_empty() {
                        None
                    } else {
                        Some(
                            arr.iter()
                                .filter_map(Value::as_str)
                                .map(str::to_string)
                                .collect::<Vec<_>>(),
                        )
                    }
                })
            })
        })
        .unwrap_or_default()
}

pub(crate) fn extract_http_action(
    path_key: &str,
    method: &str,
    op: &Map<String, Value>,
    path_level_params: Option<&Value>,
    root_security: Option<&Value>,
    sink: &mut HashMap<String, ServiceAction>,
) -> Result<(), Vec<ValidationIssue>> {
    let base = format!("paths.{path_key}.{method}");

    let action_key = op
        .get("operationId")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            vec![ValidationIssue::new(
                "missing_field",
                "operationId is required (used as the action key)",
                format!("{base}.operationId"),
            )]
        })?
        .to_string();

    // `description` is what the agent reads and what search scores against;
    // `summary` is the one-line label a human sees on an approval, with its
    // `{param}` placeholders interpolated. An operation authoring only one of
    // the two gets it used for both, which is how every template behaved
    // before the split. Matches `extract_platform_action` below.
    let summary = op
        .get("summary")
        .and_then(Value::as_str)
        .map(str::to_string);
    let description = op
        .get("description")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| summary.clone())
        .unwrap_or_default();

    let risk = match ext::get(op, Pos::Operation, Ext::Risk).and_then(Value::as_str) {
        Some("read") => DeclaredRisk::Read,
        Some("write") => DeclaredRisk::Write,
        Some("delete") => DeclaredRisk::Delete,
        // Classified per call from the SQL the caller supplies (D42);
        // validation rejects it on actions with no `x-overslash-sql-field` param.
        Some("dynamic") => DeclaredRisk::Dynamic,
        Some(other) => {
            return Err(vec![ValidationIssue::new(
                "invalid_risk",
                format!(
                    "{} must be one of read/write/delete/dynamic (got {other:?})",
                    Ext::Risk.key()
                ),
                format!("{base}.{}", Ext::Risk.key()),
            )]);
        }
        None => Risk::from_http_method(method).into(),
    };

    let scope_param = parse_scope_params(ext::get(op, Pos::Operation, Ext::ScopeParam), &base)
        .map_err(|e| vec![e])?;

    let response_type = detect_response_type(op);

    // Merge path-level parameters with operation-level parameters. Operation-
    // level entries win on name collision (OpenAPI rule).
    //
    // `param_errors` is the same sink `disclose_errors` becomes below; it is
    // declared up here because parameter lowering is the first thing that can
    // report an issue (a malformed `cache_ttl` on a resolver).
    let mut param_errors: Vec<ValidationIssue> = Vec::new();
    let mut params: HashMap<String, ActionParam> = HashMap::new();
    if let Some(arr) = path_level_params.and_then(Value::as_array) {
        collect_parameters(arr, &mut params, &base, &mut param_errors);
    }
    if let Some(arr) = op.get("parameters").and_then(Value::as_array) {
        collect_parameters(arr, &mut params, &base, &mut param_errors);
    }
    collect_body_parameters(op.get("requestBody"), &mut params, &base, &mut param_errors);
    let request_body = parse_request_body(op.get("requestBody"));

    // Per-action OAuth scopes. The operation's own `security` key, when present
    // (even as an empty array `[]`, which OpenAPI 3.1 treats as an explicit
    // opt-out / "no security"), takes precedence. When the operation omits
    // `security` entirely it inherits the document root-level default.
    let required_scopes = op
        .get("security")
        .or(root_security)
        .map(scopes_from_security)
        .unwrap_or_default();

    let mut disclose_errors = param_errors;
    let disclose = parse_disclose(
        ext::get(op, Pos::Operation, Ext::Disclose),
        &base,
        &mut disclose_errors,
    );
    let redact = parse_redact(
        ext::get(op, Pos::Operation, Ext::Redact),
        &base,
        &mut disclose_errors,
    );
    let timeout_ms = parse_timeout_ms(
        ext::get(op, Pos::Operation, Ext::TimeoutMs),
        Ext::TimeoutMs.key(),
        &base,
        &mut disclose_errors,
    );
    let wait_mode = parse_wait_mode(
        ext::get(op, Pos::Operation, Ext::WaitMode),
        Ext::WaitMode.key(),
        &base,
        &mut disclose_errors,
    );
    let handoff_after_ms = parse_timeout_ms(
        ext::get(op, Pos::Operation, Ext::HandoffAfterMs),
        Ext::HandoffAfterMs.key(),
        &base,
        &mut disclose_errors,
    );
    let pagination = parse_pagination(
        ext::get(op, Pos::Operation, Ext::Pagination),
        &base,
        &mut disclose_errors,
    );
    if !disclose_errors.is_empty() {
        return Err(disclose_errors);
    }

    sink.insert(
        action_key,
        ServiceAction {
            method: method.to_uppercase(),
            path: path_key.to_string(),
            description,
            summary,
            risk,
            response_type,
            timeout_ms,
            wait_mode,
            handoff_after_ms,
            pagination,
            params,
            scope_param,
            required_scopes,
            disclose,
            redact,
            request_body,
            // Everything else defaults. Notably `download`: an HTTP action that
            // returns bytes already *is* its own download, since `deliver:
            // "url"` mints a token from the resolved request. Only MCP, whose
            // result merely points at the object, needs the declaration.
            ..Default::default()
        },
    );

    Ok(())
}

pub(crate) fn extract_platform_action(
    action_key: &str,
    op: &Map<String, Value>,
) -> Result<ServiceAction, Vec<ValidationIssue>> {
    let base = format!("{}.{action_key}", Ext::PlatformActions.key());

    let description = op
        .get("description")
        .and_then(Value::as_str)
        .or_else(|| op.get("summary").and_then(Value::as_str))
        .unwrap_or("")
        .to_string();

    let risk = match ext::get(op, Pos::PlatformAction, Ext::Risk).and_then(Value::as_str) {
        Some("read") | None => DeclaredRisk::Read,
        Some("write") => DeclaredRisk::Write,
        Some("delete") => DeclaredRisk::Delete,
        // Platform actions carry no SQL param, so `dynamic` is rejected —
        // there is nothing for a classifier to read.
        Some(other) => {
            return Err(vec![ValidationIssue::new(
                "invalid_risk",
                format!(
                    "{} must be one of read/write/delete (got {other:?})",
                    Ext::Risk.key()
                ),
                format!("{base}.{}", Ext::Risk.key()),
            )]);
        }
    };

    let params = op
        .get("params")
        .and_then(Value::as_object)
        .map(|m| parse_platform_params(m, &base))
        .unwrap_or_default();

    let permission = op
        .get("permission")
        .and_then(Value::as_str)
        .map(str::to_string);

    let scope_param = parse_scope_params(ext::get(op, Pos::PlatformAction, Ext::ScopeParam), &base)
        .map_err(|e| vec![e])?;

    Ok(ServiceAction {
        description,
        risk,
        params,
        scope_param,
        permission,
        // Everything else defaults. Platform actions are dispatched in-process
        // and never over HTTP, so there is no outbound payload to disclose or
        // redact, no request body, no download — and no upstream to time out,
        // which is why `timeout_ms` stays `None` here rather than being
        // readable from the template.
        ..Default::default()
    })
}

/// Parse a flat `{name: {type, required, description}}` map (the platform_actions
/// params format) into the same `HashMap<String, ActionParam>` used by HTTP actions.
fn parse_platform_params(raw: &Map<String, Value>, _base: &str) -> HashMap<String, ActionParam> {
    raw.iter()
        .filter_map(|(name, spec)| {
            let obj = spec.as_object()?;
            // Empty = type unspecified (see `schema_fields`) — runtime type
            // checks skip it rather than guess "string".
            let param_type = obj
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let required = obj
                .get("required")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let description = obj
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let aliases = parse_aliases(Some(obj), name, Pos::PlatformActionParam);
            let instance_config = parse_instance_config(Some(obj), Pos::PlatformActionParam);
            let (sql_field, sql_database) = parse_sql_policy(Some(obj), Pos::PlatformActionParam);
            Some((
                name.clone(),
                ActionParam {
                    param_type,
                    required,
                    description,
                    enum_values: None,
                    default: None,
                    resolve: None,
                    aliases,
                    location: ParamLocation::Body,
                    instance_config,
                    sql_field,
                    sql_database,
                },
            ))
        })
        .collect()
}

fn detect_response_type(op: &Map<String, Value>) -> Option<String> {
    let responses = op.get("responses")?.as_object()?;
    // Prefer 200; fall back to any 2xx code. Binary wins if any content entry
    // is octet-stream or application/pdf etc.
    let ordered: Vec<&String> = responses.keys().collect();
    for code in ordered {
        if !code.starts_with('2') && code.as_str() != "default" {
            continue;
        }
        let Some(content) = responses[code]
            .as_object()
            .and_then(|r| r.get("content"))
            .and_then(Value::as_object)
        else {
            continue;
        };
        for media in content.keys() {
            let m = media.to_lowercase();
            if m.starts_with("application/json") || m.starts_with("application/problem+json") {
                return Some("json".into());
            }
            if m.starts_with("application/octet-stream")
                || m.starts_with("application/pdf")
                || m.starts_with("image/")
                || m.starts_with("video/")
                || m.starts_with("audio/")
            {
                return Some("binary".into());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openapi::compile_service;
    use serde_json::json;

    // ── extract_http_action: risk / description fallbacks ────────────

    #[test]
    fn risk_defaults_from_method() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {
                "/a": {"get": {"operationId": "a"}},
                "/b": {"post": {"operationId": "b"}},
                "/c": {"delete": {"operationId": "c"}}
            }
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.actions["a"].risk, Risk::Read);
        assert_eq!(svc.actions["b"].risk, Risk::Write);
        assert_eq!(svc.actions["c"].risk, Risk::Delete);
    }

    #[test]
    fn rejects_invalid_risk_on_operation() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {
                "/a": {"get": {"operationId": "a", "x-overslash-risk": "catastrophic"}}
            }
        });
        let err = compile_service(&doc).unwrap_err();
        assert_eq!(err[0].code, "invalid_risk");
    }

    #[test]
    fn description_falls_back_to_description_field() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"get": {
                "operationId": "x",
                "description": "Long-form description"
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.actions["x"].description, "Long-form description");
    }

    #[test]
    fn missing_operation_id_errors() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"get": {}}}
        });
        let err = compile_service(&doc).unwrap_err();
        assert_eq!(err[0].code, "missing_field");
        assert!(err[0].path.ends_with(".operationId"));
    }

    // ── extract_platform_action ──────────────────────────────────────

    #[test]
    fn platform_action_not_object_errors() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "x-overslash-platform_actions": {
                "bad": "not-an-object"
            }
        });
        let err = compile_service(&doc).unwrap_err();
        assert_eq!(err[0].code, "openapi_invalid");
        assert!(err[0].path.ends_with(".bad"));
    }

    #[test]
    fn platform_action_rejects_invalid_risk() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "x-overslash-platform_actions": {
                "act": {"description": "x", "x-overslash-risk": "yolo"}
            }
        });
        let err = compile_service(&doc).unwrap_err();
        assert_eq!(err[0].code, "invalid_risk");
    }

    #[test]
    fn platform_action_falls_back_to_summary_when_description_missing() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "x-overslash-platform_actions": {
                "act": {"summary": "Summary fallback", "x-overslash-risk": "write"}
            }
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.actions["act"].description, "Summary fallback");
    }

    /// The agent reads `description`; the approval screen reads `summary`. An
    /// operation authoring both must keep them separate — cramming the long
    /// form into `summary` used to be the only way to reach the model, and it
    /// made the approval title a paragraph.
    #[test]
    fn http_action_description_wins_and_summary_is_kept_for_the_label() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "servers": [{"url": "https://x.test"}],
            "paths": {"/search": {"post": {
                "operationId": "search",
                "summary": "Search folder '{folder}' for {criteria}",
                "description": "Raw IMAP SEARCH criteria — not free text.",
                "x-overslash-risk": "read"
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        let a = &svc.actions["search"];
        assert_eq!(a.description, "Raw IMAP SEARCH criteria — not free text.");
        assert_eq!(
            a.summary.as_deref(),
            Some("Search folder '{folder}' for {criteria}")
        );
        assert_eq!(
            a.label_template(),
            "Search folder '{folder}' for {criteria}"
        );
    }

    /// The overwhelmingly common shape: `summary` only. It must still be both
    /// the agent text and the label, exactly as before the split.
    #[test]
    fn http_action_summary_only_serves_as_both_description_and_label() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "servers": [{"url": "https://x.test"}],
            "paths": {"/send": {"post": {
                "operationId": "send",
                "summary": "Send email '{subject}' to {to}",
                "x-overslash-risk": "write"
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        let a = &svc.actions["send"];
        assert_eq!(a.description, "Send email '{subject}' to {to}");
        assert_eq!(a.label_template(), "Send email '{subject}' to {to}");
    }

    /// `description` only: no summary to fall back on, so the label reuses it.
    #[test]
    fn http_action_description_only_labels_with_the_description() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "servers": [{"url": "https://x.test"}],
            "paths": {"/list": {"get": {
                "operationId": "list",
                "description": "List everything."
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        let a = &svc.actions["list"];
        assert_eq!(a.description, "List everything.");
        assert_eq!(a.summary, None);
        assert_eq!(a.label_template(), "List everything.");
    }

    #[test]
    fn platform_action_default_risk_is_read() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "x-overslash-platform_actions": {
                "act": {"description": "x"}
            }
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.actions["act"].risk, Risk::Read);
    }

    // ── detect_response_type ─────────────────────────────────────────

    #[test]
    fn response_type_none_when_no_responses() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"get": {"operationId": "x"}}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert!(svc.actions["x"].response_type.is_none());
    }

    #[test]
    fn response_type_ignores_non_success_codes() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"get": {
                "operationId": "x",
                "responses": {
                    "400": {"content": {"application/octet-stream": {}}},
                    "500": {"content": {"application/octet-stream": {}}}
                }
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert!(svc.actions["x"].response_type.is_none());
    }

    #[test]
    fn response_type_picks_up_default_code() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"get": {
                "operationId": "x",
                "responses": {
                    "default": {"content": {"application/json": {}}}
                }
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.actions["x"].response_type.as_deref(), Some("json"));
    }

    #[test]
    fn response_type_detects_binary_for_pdf_image_video_audio() {
        for media in ["application/pdf", "image/png", "video/mp4", "audio/mpeg"] {
            let doc = json!({
                "info": {"title": "T", "x-overslash-key": "t"},
                "paths": {"/x": {"get": {
                    "operationId": "x",
                    "responses": {"200": {"content": {media: {}}}}
                }}}
            });
            let (svc, _) = compile_service(&doc).unwrap();
            assert_eq!(
                svc.actions["x"].response_type.as_deref(),
                Some("binary"),
                "expected binary for media type {media}"
            );
        }
    }

    #[test]
    fn response_type_detects_octet_stream() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/file": {"get": {
                "operationId": "download",
                "responses": {"200": {"content": {"application/octet-stream": {}}}}
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(
            svc.actions["download"].response_type.as_deref(),
            Some("binary")
        );
    }

    // ── per-op security → required_scopes ─────────────────────────────

    #[test]
    fn per_op_security_populates_required_scopes() {
        let doc = json!({
            "info": {"title": "Gmail", "x-overslash-key": "gmail"},
            "paths": {
                "/gmail/v1/users/{userId}/drafts": {"post": {
                    "operationId": "create_draft",
                    "security": [{"oauth": ["https://www.googleapis.com/auth/gmail.compose"]}]
                }},
                "/gmail/v1/users/{userId}/messages/send": {"post": {
                    "operationId": "send_message",
                    "security": [{"oauth": ["https://www.googleapis.com/auth/gmail.send"]}]
                }}
            }
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(
            svc.actions["create_draft"].required_scopes,
            vec!["https://www.googleapis.com/auth/gmail.compose"]
        );
        assert_eq!(
            svc.actions["send_message"].required_scopes,
            vec!["https://www.googleapis.com/auth/gmail.send"]
        );
    }

    #[test]
    fn missing_op_security_yields_empty_required_scopes() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"get": {"operationId": "x"}}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert!(svc.actions["x"].required_scopes.is_empty());
    }

    // ── root-level security → default required_scopes ─────────────────

    #[test]
    fn root_security_inherited_when_op_omits_security() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "security": [{"oauth": ["https://example.com/auth/default"]}],
            "paths": {"/x": {"get": {"operationId": "x"}}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(
            svc.actions["x"].required_scopes,
            vec!["https://example.com/auth/default"]
        );
    }

    #[test]
    fn op_security_overrides_root_security() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "security": [{"oauth": ["https://example.com/auth/default"]}],
            "paths": {"/x": {"get": {
                "operationId": "x",
                "security": [{"oauth": ["https://example.com/auth/override"]}]
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(
            svc.actions["x"].required_scopes,
            vec!["https://example.com/auth/override"]
        );
    }

    #[test]
    fn op_empty_security_array_opts_out_of_root_default() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "security": [{"oauth": ["https://example.com/auth/default"]}],
            "paths": {"/x": {"get": {
                "operationId": "x",
                "security": []
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert!(svc.actions["x"].required_scopes.is_empty());
    }
}
