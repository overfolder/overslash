//! JSON entry point — used by the three-tier registry CRUD (create_template /
//! update_template) where `auth` and `actions` are stored as `serde_json::Value`.
//!
//! This wraps [`super::core::validate_service_definition`] with a
//! deserialization pass. Failures in deserialization are surfaced as
//! `schema_error` issues so the caller still gets a structured report rather
//! than a raw serde error.
//!
//! ## Parse, don't validate
//!
//! [`parse_template_parts`] is the primary entry point: it returns the parsed
//! [`ServiceDefinition`] on success so callers can store the round-tripped,
//! guaranteed-valid JSON rather than the raw input.
//! [`validate_template_parts`] is a thin wrapper that discards the parsed
//! definition for callers that only need the report.

use std::collections::HashMap;

use serde_json::Value;

use crate::types::{ServiceAction, ServiceAuth, ServiceDefinition};

use super::{Issues, ValidationReport, core::validate_service_definition};

/// Parse JSON-encoded template parts into a validated [`ServiceDefinition`].
///
/// Returns `Ok((def, report))` when the input is well-formed and passes
/// validation. The report may still contain warnings.
/// Returns `Err(report)` when deserialization or validation fails — the report
/// contains the errors.
pub fn parse_template_parts(
    key: &str,
    display_name: &str,
    description: Option<&str>,
    category: Option<&str>,
    hosts: &[String],
    auth_json: &Value,
    actions_json: &Value,
) -> Result<(ServiceDefinition, ValidationReport), ValidationReport> {
    let mut issues = Issues::default();

    let auth: Vec<ServiceAuth> = match deserialize_auth(auth_json) {
        Ok(a) => a,
        Err(msg) => {
            issues.err(
                "schema_error",
                format!("auth is not well-formed: {msg}"),
                "auth",
            );
            return Err(issues.finish());
        }
    };

    let actions: HashMap<String, ServiceAction> = match deserialize_actions(actions_json) {
        Ok(a) => a,
        Err(msg) => {
            issues.err(
                "schema_error",
                format!("actions is not well-formed: {msg}"),
                "actions",
            );
            return Err(issues.finish());
        }
    };

    let def = ServiceDefinition {
        key: key.to_string(),
        display_name: display_name.to_string(),
        description: description.map(|s| s.to_string()),
        hosts: hosts.to_vec(),
        category: category.map(|s| s.to_string()),
        auth,
        actions,
    };

    // JSON inputs have already deduped at the serde_json::Map level, so
    // duplicate-key detection is a no-op here. Pass an empty slice.
    let report = validate_service_definition(&def, &[]);
    if report.valid {
        Ok((def, report))
    } else {
        Err(report)
    }
}

/// Validate the fields the CRUD endpoints hold in parts: the scalar metadata
/// plus the JSON-encoded `auth` and `actions` blobs.
///
/// This is a convenience wrapper around [`parse_template_parts`] for callers
/// that only need the validation report (e.g. the validate endpoint).
pub fn validate_template_parts(
    key: &str,
    display_name: &str,
    hosts: &[String],
    auth_json: &Value,
    actions_json: &Value,
) -> ValidationReport {
    match parse_template_parts(
        key,
        display_name,
        None,
        None,
        hosts,
        auth_json,
        actions_json,
    ) {
        Ok((_def, report)) => report,
        Err(report) => report,
    }
}

fn deserialize_auth(v: &Value) -> Result<Vec<ServiceAuth>, String> {
    if v.is_null() {
        return Ok(Vec::new());
    }
    if !v.is_array() {
        return Err("expected an array".into());
    }
    serde_json::from_value(v.clone()).map_err(|e| e.to_string())
}

fn deserialize_actions(v: &Value) -> Result<HashMap<String, ServiceAction>, String> {
    if v.is_null() {
        return Ok(HashMap::new());
    }
    if !v.is_object() {
        return Err("expected an object".into());
    }
    serde_json::from_value(v.clone()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn valid_json_template() {
        let report = validate_template_parts(
            "svc",
            "Service",
            &["api.example.com".into()],
            &json!([]),
            &json!({
                "list": {
                    "method": "GET",
                    "path": "/items",
                    "description": "List items",
                }
            }),
        );
        assert!(report.valid, "{:?}", report.errors);
    }

    #[test]
    fn parse_returns_definition_on_success() {
        let result = parse_template_parts(
            "svc",
            "Service",
            Some("A service"),
            Some("testing"),
            &["api.example.com".into()],
            &json!([]),
            &json!({
                "list": {
                    "method": "GET",
                    "path": "/items",
                    "description": "List items",
                }
            }),
        );
        let (def, report) = result.expect("should parse successfully");
        assert!(report.valid);
        assert_eq!(def.key, "svc");
        assert_eq!(def.display_name, "Service");
        assert_eq!(def.description.as_deref(), Some("A service"));
        assert_eq!(def.category.as_deref(), Some("testing"));
        assert_eq!(def.hosts, vec!["api.example.com"]);
        assert!(def.auth.is_empty());
        assert!(def.actions.contains_key("list"));
    }

    #[test]
    fn parse_returns_err_on_validation_failure() {
        let result = parse_template_parts(
            "", // invalid: empty key
            "Service",
            None,
            None,
            &["api.example.com".into()],
            &json!([]),
            &json!({}),
        );
        let report = result.unwrap_err();
        assert!(!report.valid);
        assert!(report.errors.iter().any(|e| e.code == "missing_field"));
    }

    #[test]
    fn parse_returns_err_on_schema_error() {
        let result = parse_template_parts(
            "svc",
            "Service",
            None,
            None,
            &["api.example.com".into()],
            &json!("not an array"),
            &json!({}),
        );
        let report = result.unwrap_err();
        assert!(!report.valid);
        assert!(report.errors.iter().any(|e| e.code == "schema_error"));
    }

    #[test]
    fn schema_error_on_malformed_auth() {
        let report = validate_template_parts(
            "svc",
            "Service",
            &["api.example.com".into()],
            &json!("not an array"),
            &json!({}),
        );
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.code == "schema_error" && e.path == "auth")
        );
    }

    #[test]
    fn schema_error_on_malformed_actions() {
        let report = validate_template_parts(
            "svc",
            "Service",
            &["api.example.com".into()],
            &json!([]),
            &json!("not an object"),
        );
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.code == "schema_error" && e.path == "actions")
        );
    }

    #[test]
    fn unknown_scope_param_propagates() {
        let report = validate_template_parts(
            "svc",
            "Service",
            &["api.example.com".into()],
            &json!([]),
            &json!({
                "get_item": {
                    "method": "GET",
                    "path": "/items/{id}",
                    "description": "Get {id}",
                    "scope_param": "missing",
                    "params": {
                        "id": {"type": "string", "required": true}
                    }
                }
            }),
        );
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.code == "unknown_scope_param")
        );
    }

    #[test]
    fn null_auth_and_actions_ok() {
        let report = validate_template_parts(
            "svc",
            "Service",
            &["api.example.com".into()],
            &Value::Null,
            &Value::Null,
        );
        // No actions + no auth is still valid (minimal template shape).
        assert!(report.valid);
    }
}
