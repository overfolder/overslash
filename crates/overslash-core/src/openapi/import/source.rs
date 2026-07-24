//! Source format detection, parsing, and OpenAPI version checks.

use serde_json::{Map, Value};

use crate::template_validation::ValidationIssue;

use super::ImportWarning;

// ── format detection & parsing ───────────────────────────────────────

#[cfg(feature = "yaml")]
pub(super) fn parse_source(
    src: &str,
    content_type: Option<&str>,
) -> Result<Value, ValidationIssue> {
    let is_json = match content_type {
        Some(ct) if ct.contains("json") => true,
        Some(ct) if ct.contains("yaml") || ct.contains("yml") => false,
        _ => src
            .trim_start()
            .chars()
            .next()
            .is_some_and(|c| c == '{' || c == '['),
    };
    if is_json {
        serde_json::from_str::<Value>(src).map_err(|e| {
            ValidationIssue::new(
                "openapi_parse_error",
                format!("failed to parse JSON: {e}"),
                "",
            )
        })
    } else {
        crate::openapi::parse_yaml(src)
    }
}

pub(super) fn check_openapi_version(root: &Map<String, Value>, warnings: &mut Vec<ImportWarning>) {
    let v = root.get("openapi").and_then(Value::as_str).unwrap_or("");
    if v.is_empty() {
        warnings.push(ImportWarning::new(
            "openapi_version_missing",
            "source does not declare an OpenAPI version — assuming 3.1.0",
            "openapi",
        ));
    } else if v.starts_with("3.0") {
        warnings.push(ImportWarning::new(
            "openapi_3_0_source",
            format!(
                "source declares OpenAPI {v}; Overslash templates target 3.1.0 — \
                 schema objects using JSON-Schema-draft-04 semantics may not compile cleanly"
            ),
            "openapi",
        ));
    } else if !v.starts_with("3.") {
        warnings.push(ImportWarning::new(
            "openapi_unsupported_version",
            format!("OpenAPI version {v} is untested; attempting best-effort import"),
            "openapi",
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openapi::import::tests::base_doc;
    use crate::openapi::import::*;
    use serde_json::json;

    #[test]
    fn openapi_3_0_source_warns() {
        let mut doc = base_doc();
        doc["openapi"] = Value::String("3.0.3".into());
        let prep = prepare_from_value(doc, &ImportOptions::default());
        assert!(prep.warnings.iter().any(|w| w.code == "openapi_3_0_source"));
    }

    #[cfg(feature = "yaml")]
    #[test]
    fn parse_detects_json_vs_yaml() {
        let json_src = b"{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"x\"},\"paths\":{}}";
        let prep = prepare_import(
            json_src,
            Some("application/json"),
            &ImportOptions::default(),
        )
        .unwrap();
        assert_eq!(prep.doc["openapi"].as_str().unwrap(), "3.1.0");

        let yaml_src = b"openapi: 3.1.0\ninfo:\n  title: y\npaths: {}\n";
        let prep = prepare_import(
            yaml_src,
            Some("application/yaml"),
            &ImportOptions::default(),
        )
        .unwrap();
        assert_eq!(prep.doc["info"]["title"].as_str().unwrap(), "y");

        // No hint → heuristic on first non-whitespace char
        let prep = prepare_import(
            b"  { \"openapi\": \"3.1.0\", \"info\": {\"title\":\"h\"}, \"paths\": {} }",
            None,
            &ImportOptions::default(),
        )
        .unwrap();
        assert_eq!(prep.doc["info"]["title"].as_str().unwrap(), "h");
    }

    #[test]
    fn missing_openapi_version_emits_warning() {
        let doc = json!({
            "info": {"title": "No Version"},
            "paths": {}
        });
        let prep = prepare_from_value(doc, &ImportOptions::default());
        assert!(
            prep.warnings
                .iter()
                .any(|w| w.code == "openapi_version_missing")
        );
    }

    #[test]
    fn unsupported_openapi_version_warns_but_proceeds() {
        let doc = json!({
            "openapi": "2.0",
            "info": {"title": "Swagger v2"},
            "paths": {}
        });
        let prep = prepare_from_value(doc, &ImportOptions::default());
        assert!(
            prep.warnings
                .iter()
                .any(|w| w.code == "openapi_unsupported_version")
        );
    }

    #[cfg(feature = "yaml")]
    #[test]
    fn invalid_utf8_source_surfaces_structured_error() {
        let bad: &[u8] = &[0xff, 0xfe, 0xfd];
        let err = prepare_import(bad, None, &ImportOptions::default()).unwrap_err();
        assert_eq!(err.code, "openapi_parse_error");
        assert!(err.message.contains("UTF-8"));
    }

    #[cfg(feature = "yaml")]
    #[test]
    fn malformed_json_source_surfaces_structured_error() {
        let src = b"{ not valid json";
        let err =
            prepare_import(src, Some("application/json"), &ImportOptions::default()).unwrap_err();
        assert_eq!(err.code, "openapi_parse_error");
    }
}
