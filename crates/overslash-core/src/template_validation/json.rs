//! JSON entry point — used by the three-tier registry CRUD (create_template /
//! update_template) where `auth` and `actions` are stored as `serde_json::Value`.
//!
//! This wraps [`super::core::validate_service_definition`] with a
//! deserialization pass. Failures in deserialization are surfaced as
//! `schema_error` issues so the caller still gets a structured report rather
//! than a raw serde error.

use std::collections::HashMap;

use serde_json::Value;

use crate::types::{ServiceAction, ServiceAuth, ServiceDefinition};

use super::{Issues, ValidationReport, core::validate_service_definition};

/// Validate the fields the CRUD endpoints hold in parts: the scalar metadata
/// plus the JSON-encoded `auth` and `actions` blobs.
pub fn validate_template_parts(
    key: &str,
    display_name: &str,
    hosts: &[String],
    auth_json: &Value,
    actions_json: &Value,
) -> ValidationReport {
    let mut issues = Issues::default();

    let auth: Vec<ServiceAuth> = match deserialize_auth(auth_json) {
        Ok(a) => a,
        Err(msg) => {
            issues.err(
                "schema_error",
                format!("auth is not well-formed: {msg}"),
                "auth",
            );
            return issues.finish();
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
            return issues.finish();
        }
    };

    let def = ServiceDefinition {
        key: key.to_string(),
        display_name: display_name.to_string(),
        description: None,
        hosts: hosts.to_vec(),
        category: None,
        auth,
        actions,
    };

    // JSON inputs have already deduped at the serde_json::Map level, so
    // duplicate-key detection is a no-op here. Pass an empty slice.
    validate_service_definition(&def, &[])
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
