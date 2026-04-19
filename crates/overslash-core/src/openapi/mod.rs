//! OpenAPI 3.1 + `x-overslash-*` front door for service templates.
//!
//! Service templates are authored as OpenAPI 3.1 documents. Fields the gateway
//! needs that OpenAPI cannot express natively (risk class, permission-scope
//! binding, parameter resolution, symbolic OAuth provider, default secret
//! name) live under the `x-overslash-*` vendor-extension namespace.
//!
//! To keep authoring ergonomic, the same keys may also be written without the
//! prefix (`risk:` instead of `x-overslash-risk:`). The normalizer in this
//! module rewrites every known alias to its canonical form before the rest of
//! the pipeline sees the document, and rejects ambiguous documents (both
//! forms present on the same object) with a `ambiguous_alias` issue.
//!
//! This module is split into three parts:
//!
//! - [`alias`] — context-aware alias-to-canonical rewriter and its tests.
//! - [`extract`] — compile-step helpers (hosts, auth, actions, parameters,
//!   response types, resolvers) and their tests.
//! - this module — public API ([`parse_yaml`], [`to_yaml_string`],
//!   [`normalize_aliases`], [`compile_service`]) plus end-to-end tests.

use std::collections::HashMap;

use serde_json::Value;

use crate::template_validation::ValidationIssue;
use crate::types::{ServiceAction, ServiceDefinition};

mod alias;
mod extract;
pub mod import;

use alias::APIKEY_HTTP_SEC_ALIASES;
use alias::{
    HTTP_METHODS, INFO_ALIASES, OAUTH2_SEC_ALIASES, OPERATION_ALIASES, ROOT_ALIASES,
    normalize_parameters_in, rewrite_aliases,
};
use extract::{extract_auth, extract_hosts, extract_http_action, extract_platform_action};

// ── Public API ───────────────────────────────────────────────────────

/// Serialize a normalized OpenAPI JSON document back to a YAML string for
/// display in the dashboard editor. The stored form is `serde_json::Value`
/// (JSONB in the DB); round-tripping through `serde_yaml::Value` preserves
/// structure.
#[cfg(feature = "yaml")]
pub fn to_yaml_string(v: &Value) -> Result<String, ValidationIssue> {
    serde_yaml::to_string(v).map_err(|e| {
        ValidationIssue::new(
            "openapi_parse_error",
            format!("failed to serialize openapi to YAML: {e}"),
            "",
        )
    })
}

/// Parse an OpenAPI YAML document into a `serde_json::Value`.
#[cfg(feature = "yaml")]
pub fn parse_yaml(src: &str) -> Result<Value, ValidationIssue> {
    let y: serde_yaml::Value = serde_yaml::from_str(src).map_err(|e| {
        ValidationIssue::new(
            "openapi_parse_error",
            format!("failed to parse YAML: {e}"),
            "",
        )
    })?;
    serde_json::to_value(y).map_err(|e| {
        ValidationIssue::new(
            "openapi_parse_error",
            format!("failed to convert YAML to JSON: {e}"),
            "",
        )
    })
}

/// Walk the document and rewrite every alias key under its supported context
/// to its canonical `x-overslash-*` form. Returns issues for any ambiguous
/// objects that carry both forms at once.
pub fn normalize_aliases(v: &mut Value) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    let Value::Object(root) = v else {
        return issues;
    };

    rewrite_aliases(root, ROOT_ALIASES, "", &mut issues);

    if let Some(info) = root.get_mut("info").and_then(Value::as_object_mut) {
        rewrite_aliases(info, INFO_ALIASES, "info", &mut issues);
    }

    if let Some(paths) = root.get_mut("paths").and_then(Value::as_object_mut) {
        for (path_key, path_item) in paths.iter_mut() {
            let Value::Object(path_obj) = path_item else {
                continue;
            };
            // Path-level parameters (shared across all methods on this path)
            // also carry parameter aliases and must be normalized.
            let path_base = format!("paths.{path_key}");
            normalize_parameters_in(path_obj, &path_base, &mut issues);
            for method in HTTP_METHODS {
                let Some(op) = path_obj.get_mut(*method).and_then(Value::as_object_mut) else {
                    continue;
                };
                let op_base = format!("paths.{path_key}.{method}");
                rewrite_aliases(op, OPERATION_ALIASES, &op_base, &mut issues);
                normalize_parameters_in(op, &op_base, &mut issues);
            }
        }
    }

    if let Some(comps) = root.get_mut("components").and_then(Value::as_object_mut) {
        if let Some(schemes) = comps
            .get_mut("securitySchemes")
            .and_then(Value::as_object_mut)
        {
            for (name, scheme) in schemes.iter_mut() {
                let Value::Object(obj) = scheme else {
                    continue;
                };
                let base = format!("components.securitySchemes.{name}");
                let ty = obj.get("type").and_then(Value::as_str).unwrap_or("");
                match ty {
                    "oauth2" => rewrite_aliases(obj, OAUTH2_SEC_ALIASES, &base, &mut issues),
                    "apiKey" | "http" => {
                        rewrite_aliases(obj, APIKEY_HTTP_SEC_ALIASES, &base, &mut issues)
                    }
                    _ => {}
                }
            }
        }
    }

    // Platform actions live under the x-overslash-platform_actions extension
    // (or its `platform_actions` alias, already rewritten above). Each entry
    // is an operation-shaped object, so operation-level aliases apply.
    if let Some(platform) = root
        .get_mut("x-overslash-platform_actions")
        .and_then(Value::as_object_mut)
    {
        for (action_key, action) in platform.iter_mut() {
            let Value::Object(obj) = action else {
                continue;
            };
            let base = format!("x-overslash-platform_actions.{action_key}");
            rewrite_aliases(obj, OPERATION_ALIASES, &base, &mut issues);
        }
    }

    issues
}

/// Lower a normalized OpenAPI document into a [`ServiceDefinition`].
///
/// Returns the compiled definition plus any non-fatal warnings. Fatal errors
/// return `Err`. This function does not enforce full OpenAPI 3.1 schema
/// compliance — it only extracts the bits the gateway cares about and rejects
/// inputs that violate gateway-specific constraints (e.g. `risk` not in
/// read/write/delete).
pub fn compile_service(
    doc: &Value,
) -> Result<(ServiceDefinition, Vec<ValidationIssue>), Vec<ValidationIssue>> {
    let mut errors: Vec<ValidationIssue> = Vec::new();
    let warnings: Vec<ValidationIssue> = Vec::new();

    let Some(root) = doc.as_object() else {
        errors.push(ValidationIssue::new(
            "openapi_parse_error",
            "document root must be an object",
            "",
        ));
        return Err(errors);
    };

    let info = root.get("info").and_then(Value::as_object);

    let key = info
        .and_then(|i| i.get("x-overslash-key"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let display_name = info
        .and_then(|i| i.get("title"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let description = info
        .and_then(|i| i.get("description"))
        .and_then(Value::as_str)
        .map(str::to_string);

    let category = info
        .and_then(|i| i.get("x-overslash-category"))
        .and_then(Value::as_str)
        .map(str::to_string);

    let hosts = extract_hosts(root.get("servers"));

    let auth = match extract_auth(root.get("components")) {
        Ok(a) => a,
        Err(mut es) => {
            errors.append(&mut es);
            Vec::new()
        }
    };

    let mut actions: HashMap<String, ServiceAction> = HashMap::new();
    if let Some(paths) = root.get("paths").and_then(Value::as_object) {
        for (path_key, path_item) in paths {
            let Some(path_obj) = path_item.as_object() else {
                continue;
            };
            let path_level_params = path_obj.get("parameters");
            for method in HTTP_METHODS {
                let Some(op) = path_obj.get(*method).and_then(Value::as_object) else {
                    continue;
                };
                match extract_http_action(path_key, method, op, path_level_params, &mut actions) {
                    Ok(()) => {}
                    Err(mut es) => errors.append(&mut es),
                }
            }
        }
    }

    if let Some(platform) = root
        .get("x-overslash-platform_actions")
        .and_then(Value::as_object)
    {
        for (action_key, action) in platform {
            let Some(obj) = action.as_object() else {
                errors.push(ValidationIssue::new(
                    "openapi_invalid",
                    "platform action must be an object",
                    format!("x-overslash-platform_actions.{action_key}"),
                ));
                continue;
            };
            match extract_platform_action(action_key, obj) {
                Ok(a) => {
                    actions.insert(action_key.clone(), a);
                }
                Err(mut es) => errors.append(&mut es),
            }
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    Ok((
        ServiceDefinition {
            key,
            display_name,
            description,
            hosts,
            category,
            auth,
            actions,
        },
        warnings,
    ))
}

// ── End-to-end tests (public API, YAML ↔ compile round-trips) ──────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Risk, ServiceAuth};
    use serde_json::json;

    #[test]
    fn compile_non_object_root_errors() {
        let err = compile_service(&json!([])).unwrap_err();
        assert_eq!(err[0].code, "openapi_parse_error");
    }

    #[test]
    fn compile_slack_fixture() {
        let mut v = json!({
            "openapi": "3.1.0",
            "info": {
                "title": "Slack",
                "x-overslash-key": "slack",
                "x-overslash-category": "chat"
            },
            "servers": [{"url": "https://slack.com"}, {"url": "https://api.slack.com"}],
            "components": {"securitySchemes": {
                "oauth": {
                    "type": "oauth2",
                    "x-overslash-provider": "slack",
                    "flows": {"authorizationCode": {
                        "authorizationUrl": "https://slack.com/oauth/v2/authorize",
                        "tokenUrl": "https://slack.com/api/oauth.v2.access",
                        "scopes": {"chat:write": "", "channels:read": ""}
                    }}
                },
                "token": {
                    "type": "apiKey", "in": "header", "name": "Authorization",
                    "x-overslash-prefix": "Bearer ",
                    "x-overslash-default_secret_name": "slack_token"
                }
            }},
            "paths": {
                "/api/chat.postMessage": {"post": {
                    "operationId": "send_message",
                    "summary": "Send a message to Slack channel {channel}",
                    "x-overslash-risk": "write",
                    "x-overslash-scope_param": "channel",
                    "requestBody": {"required": true, "content": {"application/json": {"schema": {
                        "type": "object", "required": ["channel", "text"],
                        "properties": {
                            "channel": {"type": "string", "description": "Channel ID"},
                            "text": {"type": "string", "description": "Message text"}
                        }
                    }}}}
                }},
                "/api/conversations.list": {"get": {
                    "operationId": "list_channels", "summary": "List Slack channels"
                }}
            }
        });
        let ns_issues = normalize_aliases(&mut v);
        assert!(ns_issues.is_empty(), "{ns_issues:?}");
        let (svc, warnings) = compile_service(&v).expect("compile ok");
        assert!(warnings.is_empty());
        assert_eq!(svc.key, "slack");
        assert_eq!(svc.display_name, "Slack");
        assert_eq!(svc.category.as_deref(), Some("chat"));
        assert_eq!(svc.hosts, vec!["slack.com", "api.slack.com"]);
        assert_eq!(svc.auth.len(), 2);

        let mut has_oauth = false;
        let mut has_apikey = false;
        for a in &svc.auth {
            match a {
                ServiceAuth::OAuth {
                    provider, scopes, ..
                } => {
                    has_oauth = true;
                    assert_eq!(provider, "slack");
                    assert!(scopes.contains(&"chat:write".to_string()));
                }
                ServiceAuth::ApiKey {
                    default_secret_name,
                    ..
                } => {
                    has_apikey = true;
                    assert_eq!(default_secret_name, "slack_token");
                }
            }
        }
        assert!(has_oauth && has_apikey);

        let send = svc.actions.get("send_message").expect("send_message");
        assert_eq!(send.method, "POST");
        assert_eq!(send.risk, Risk::Write);
        assert_eq!(send.scope_param.as_deref(), Some("channel"));
        assert!(send.params["channel"].required);
    }

    #[test]
    fn compile_platform_actions() {
        let doc = json!({
            "info": {"title": "Overslash", "x-overslash-key": "overslash", "x-overslash-category": "platform"},
            "x-overslash-platform_actions": {
                "manage_members": {"description": "Manage org members", "x-overslash-risk": "delete"}
            }
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.key, "overslash");
        assert!(svc.hosts.is_empty());
        let m = &svc.actions["manage_members"];
        assert!(m.method.is_empty());
        assert_eq!(m.risk, Risk::Delete);
    }

    // ── YAML public entry points ─────────────────────────────────────

    #[cfg(feature = "yaml")]
    #[test]
    fn yaml_round_trip_with_aliases() {
        // Fixture lives at src/openapi/test_fixtures/round_trip.yaml —
        // keeping representative YAML in a file beats escaping raw strings
        // inline and matches the style we use in overslash-api integration
        // tests (see tests/fixtures/openapi/).
        let src = include_str!("test_fixtures/round_trip.yaml");
        let mut v = parse_yaml(src).unwrap();
        let issues = normalize_aliases(&mut v);
        assert!(issues.is_empty(), "{issues:?}");
        let (svc, _) = compile_service(&v).unwrap();
        assert_eq!(svc.key, "slack");
        assert_eq!(svc.hosts, vec!["slack.com"]);
        let send = &svc.actions["send_message"];
        assert_eq!(send.risk, Risk::Write);
        assert_eq!(send.scope_param.as_deref(), Some("channel"));
        assert!(send.params["channel"].required);
    }

    #[cfg(feature = "yaml")]
    #[test]
    fn parse_yaml_malformed_input_returns_issue() {
        let bad = "foo: bar\n  baz: : :\n";
        let err = parse_yaml(bad).unwrap_err();
        assert_eq!(err.code, "openapi_parse_error");
        assert!(err.message.contains("parse"));
    }

    #[cfg(feature = "yaml")]
    #[test]
    fn to_yaml_string_round_trips_canonical_document() {
        let mut v = json!({
            "info": {"key": "svc", "title": "Svc"}
        });
        assert!(normalize_aliases(&mut v).is_empty());
        let yaml = to_yaml_string(&v).unwrap();
        let re = parse_yaml(&yaml).unwrap();
        assert_eq!(re["info"]["x-overslash-key"], "svc");
        assert_eq!(re["info"]["title"], "Svc");
    }
}
