//! YAML entry point — backs `POST /v1/templates/validate`.
//!
//! Accepts OpenAPI 3.1 YAML text with `x-overslash-*` vendor extensions (plus
//! their convenience aliases — see `crate::openapi`). Parses, normalizes, and
//! compiles into a `ServiceDefinition`, then runs the struct-level validator.
//!
//! The endpoint never returns a transport-level error for malformed YAML: all
//! parse errors, alias ambiguities, and compile-time rejections surface as
//! structured `ValidationIssue`s so the dashboard editor can render them
//! inline on every keystroke.

use crate::openapi;
use crate::types::ServiceDefinition;

use super::{Issues, ValidationReport, core::validate_service_definition};

/// Parse OpenAPI YAML source and validate the resulting service definition.
///
/// Always returns a `ValidationReport`. A parse error becomes a single
/// issue in the report (`openapi_parse_error`, `ambiguous_alias`,
/// `duplicate_operation_id`, or whatever the compiler surfaces) rather than
/// a transport error.
pub fn validate_template_yaml(source: &str) -> ValidationReport {
    // Pass 1: detect duplicate YAML mapping keys (shipped serde_yaml rejects
    // them at parse time and we surface them as structured issues).
    if let Err(e) = serde_yaml::from_str::<serde_yaml::Value>(source) {
        let msg = e.to_string();
        let mut issues = Issues::default();
        issues.err("yaml_parse", format!("could not parse YAML: {msg}"), "");
        return issues.finish();
    }

    // Pass 2: parse → normalize → compile through the openapi pipeline.
    let mut doc = match openapi::parse_yaml(source) {
        Ok(d) => d,
        Err(issue) => {
            let mut issues = Issues::default();
            issues.err(issue.code, issue.message, issue.path);
            return issues.finish();
        }
    };

    let ns_issues = openapi::normalize_aliases(&mut doc);
    if !ns_issues.is_empty() {
        let mut issues = Issues::default();
        for i in ns_issues {
            issues.err(i.code, i.message, i.path);
        }
        return issues.finish();
    }

    // Duplicate-operationId detection across all paths/methods. OpenAPI
    // allows the same operationId in different operations but that's a
    // collision for our action-key model — surface it as
    // `duplicate_operation_id`.
    let mut dup_issues = Issues::default();
    check_duplicate_operation_ids(&doc, &mut dup_issues);
    let dup_report = dup_issues.finish();
    if !dup_report.valid {
        return dup_report;
    }

    let def = match openapi::compile_service(&doc) {
        Ok((def, _warnings)) => def,
        Err(errors) => {
            let mut issues = Issues::default();
            for i in errors {
                issues.err(i.code, i.message, i.path);
            }
            return issues.finish();
        }
    };

    validate_service_definition(&def, &[])
}

/// Parse + alias-normalize + compile + validate an OpenAPI YAML source for
/// persistence. On success returns the normalized canonical `serde_json::Value`
/// (alias-free — suitable for storing in the DB) and the compiled
/// [`ServiceDefinition`]. On failure returns a structured `ValidationReport`
/// so the caller can surface it back to the client as-is.
pub fn parse_normalize_compile_yaml(
    source: &str,
) -> std::result::Result<(serde_json::Value, ServiceDefinition), ValidationReport> {
    let mut issues = Issues::default();

    // Raw YAML syntax pass first (serde_yaml catches duplicate mapping keys).
    if let Err(e) = serde_yaml::from_str::<serde_yaml::Value>(source) {
        issues.err("yaml_parse", format!("could not parse YAML: {e}"), "");
        return Err(issues.finish());
    }

    let mut doc = match openapi::parse_yaml(source) {
        Ok(d) => d,
        Err(i) => {
            issues.err(i.code, i.message, i.path);
            return Err(issues.finish());
        }
    };

    let alias_issues = openapi::normalize_aliases(&mut doc);
    if !alias_issues.is_empty() {
        for i in alias_issues {
            issues.err(i.code, i.message, i.path);
        }
        return Err(issues.finish());
    }

    let mut dup_issues = Issues::default();
    check_duplicate_operation_ids(&doc, &mut dup_issues);
    let dup_report = dup_issues.finish();
    if !dup_report.valid {
        return Err(dup_report);
    }

    let def = match openapi::compile_service(&doc) {
        Ok((def, _warnings)) => def,
        Err(errors) => {
            for i in errors {
                issues.err(i.code, i.message, i.path);
            }
            return Err(issues.finish());
        }
    };

    let report = validate_service_definition(&def, &[]);
    if !report.valid {
        return Err(report);
    }

    Ok((doc, def))
}

fn check_duplicate_operation_ids(doc: &serde_json::Value, issues: &mut Issues) {
    let Some(paths) = doc.get("paths").and_then(|v| v.as_object()) else {
        return;
    };
    let mut seen: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    const METHODS: &[&str] = &[
        "get", "put", "post", "delete", "options", "head", "patch", "trace",
    ];
    for (path_key, path_item) in paths {
        let Some(obj) = path_item.as_object() else {
            continue;
        };
        for m in METHODS {
            let Some(op) = obj.get(*m).and_then(|v| v.as_object()) else {
                continue;
            };
            let Some(op_id) = op.get("operationId").and_then(|v| v.as_str()) else {
                continue;
            };
            let here = format!("paths.{path_key}.{m}.operationId");
            if let Some(first) = seen.get(op_id) {
                issues.err(
                    "duplicate_operation_id",
                    format!(
                        "operationId {op_id:?} is used in multiple operations ({first} and {here})"
                    ),
                    here,
                );
            } else {
                seen.insert(op_id.to_string(), here);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_YAML: &str = r#"
openapi: 3.1.0
info:
  title: Service
  key: svc
servers:
  - url: https://api.example.com
components:
  securitySchemes:
    token:
      type: apiKey
      in: header
      name: Authorization
      x-overslash-prefix: "Bearer "
      default_secret_name: svc_token
paths:
  /items:
    get:
      operationId: list
      summary: List items
      risk: read
"#;

    #[test]
    fn valid_yaml_parses_clean() {
        let report = validate_template_yaml(VALID_YAML);
        assert!(report.valid, "errors: {:?}", report.errors);
    }

    #[test]
    fn yaml_parse_error_surfaces_as_issue() {
        let report = validate_template_yaml("key: svc\n  bad_indent: :::");
        assert!(!report.valid);
        assert_eq!(report.errors[0].code, "yaml_parse");
    }

    #[test]
    fn ambiguous_alias_reported() {
        let src = r#"
openapi: 3.1.0
info:
  title: Svc
  key: svc
  x-overslash-key: svc
servers:
  - url: https://api.example.com
"#;
        let report = validate_template_yaml(src);
        assert!(!report.valid);
        assert!(
            report.errors.iter().any(|e| e.code == "ambiguous_alias"),
            "expected ambiguous_alias error; got {:?}",
            report.errors
        );
    }

    #[test]
    fn duplicate_operation_id_reported() {
        let src = r#"
openapi: 3.1.0
info:
  title: Svc
  key: svc
servers:
  - url: https://api.example.com
paths:
  /a:
    get:
      operationId: same
      summary: a
  /b:
    get:
      operationId: same
      summary: b
"#;
        let report = validate_template_yaml(src);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.code == "duplicate_operation_id"),
            "expected duplicate_operation_id; got {:?}",
            report.errors
        );
    }

    #[test]
    fn missing_operation_id_reported() {
        let src = r#"
openapi: 3.1.0
info:
  title: Svc
  key: svc
servers:
  - url: https://api.example.com
paths:
  /a:
    get:
      summary: no id
"#;
        let report = validate_template_yaml(src);
        assert!(!report.valid);
        assert!(report.errors.iter().any(|e| e.code == "missing_field"));
    }

    #[test]
    fn shipped_services_validate_clean() {
        // Smoke test: every shipped services/*.yaml must validate through
        // the full openapi pipeline.
        let services_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("services");
        let entries = std::fs::read_dir(&services_dir).unwrap();
        let mut checked = 0;
        for entry in entries {
            let path = entry.unwrap().path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext != "yaml" && ext != "yml" {
                continue;
            }
            let content = std::fs::read_to_string(&path).unwrap();
            let report = validate_template_yaml(&content);
            assert!(
                report.valid,
                "shipped template {path:?} failed validation: {:?}",
                report.errors
            );
            checked += 1;
        }
        assert!(
            checked > 0,
            "no shipped templates found in {services_dir:?}"
        );
    }
}
