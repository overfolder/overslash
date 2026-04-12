//! YAML entry point — backs `POST /v1/templates/validate`.
//!
//! ## Duplicate-action-key detection
//!
//! Verified empirically (see the tests in this module): `serde_yaml 0.9`
//! rejects duplicate mapping keys at parse time with an error of the form
//! `"<parent>: duplicate entry with key \"<name>\""`. We exploit this: if the
//! initial `serde_yaml::from_str` fails AND the error text contains
//! `"duplicate entry with key"`, we report it as a structured
//! `duplicate_action_key` issue rather than a generic `yaml_parse`.
//!
//! If a future serde_yaml release changes the error text or begins silently
//! deduping, the fallback is to add `yaml-rust2` for this one pass — its
//! event-based API surfaces every key emission. We avoid textual scanning
//! because flow mappings, quoted keys, and block scalars make hand-parsing
//! unreliable. The test below locks in the current behavior so drift fails
//! loudly.

use crate::types::ServiceDefinition;

use super::{Issues, ValidationReport, core::validate_service_definition};

/// Parse YAML source and validate the resulting template definition.
///
/// Always returns a `ValidationReport`. A parse error becomes a single
/// error in the report (either `duplicate_action_key` when the serde_yaml
/// error identifies a duplicate, or `yaml_parse` otherwise) — the endpoint
/// never returns a transport-level error for malformed YAML, so the dashboard
/// editor can render the diagnostic inline on every keystroke.
pub fn validate_template_yaml(source: &str) -> ValidationReport {
    // Pass 1: parse into `serde_yaml::Value` so duplicate mapping keys fire
    // as errors. The typed parse below goes through `HashMap` which silently
    // dedupes — so without this pass, duplicate action keys would be lost.
    if let Err(e) = serde_yaml::from_str::<serde_yaml::Value>(source) {
        let msg = e.to_string();
        let mut issues = Issues::default();
        if let Some((parent, key)) = parse_duplicate_key_error(&msg) {
            // Only report as `duplicate_action_key` when the parent context
            // is the `actions` mapping. Duplicates at any other level (top-
            // level `key:`, `auth:`, etc.) fall through as generic
            // `yaml_parse` with the raw error text — which already includes
            // the duplicate key name and position.
            if parent.as_deref() == Some("actions") {
                issues.err(
                    "duplicate_action_key",
                    format!("action key {key:?} is defined more than once"),
                    format!("actions.{key}"),
                );
            } else {
                issues.err(
                    "yaml_parse",
                    format!("duplicate key {key:?} in the YAML document"),
                    parent.unwrap_or_default(),
                );
            }
        } else {
            issues.err("yaml_parse", format!("could not parse YAML: {msg}"), "");
        }
        return issues.finish();
    }

    // Pass 2: typed deserialization for everything else.
    let def: ServiceDefinition = match serde_yaml::from_str(source) {
        Ok(d) => d,
        Err(e) => {
            let mut issues = Issues::default();
            issues.err("yaml_parse", format!("could not parse YAML: {e}"), "");
            return issues.finish();
        }
    };

    // Duplicate detection already happened upstream, so pass empty.
    validate_service_definition(&def, &[])
}

/// Extract the parent context and key name from a `serde_yaml` duplicate-key
/// error string.
///
/// Expected format: `"<parent>: duplicate entry with key \"<name>\""`.
/// When the duplicate is at the top level, `parent` may be empty or missing.
///
/// Returns `(Some(parent) | None, key_name)` on match, or `None` if the
/// string doesn't look like a duplicate-key error at all.
fn parse_duplicate_key_error(s: &str) -> Option<(Option<String>, String)> {
    const NEEDLE: &str = "duplicate entry with key ";
    let idx = s.find(NEEDLE)?;
    let rest = &s[idx + NEEDLE.len()..];
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    let key = rest[..end].to_string();

    // Everything before the needle, minus trailing ": " separator.
    let prefix = s[..idx].trim_end_matches(": ");
    let parent = if prefix.is_empty() || prefix == s[..idx].trim() {
        // No parent context or it's the raw prefix itself.
        let trimmed = s[..idx].trim().trim_end_matches(':').trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    } else {
        Some(prefix.to_string())
    };

    Some((parent, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_YAML: &str = r#"
key: svc
display_name: Service
hosts: [api.example.com]
auth:
  - type: api_key
    default_secret_name: svc_token
    injection:
      as: header
      header_name: Authorization
      prefix: "Bearer "
actions:
  list:
    method: GET
    path: /items
    description: List items
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
    fn serde_yaml_rejects_duplicate_mapping_keys() {
        // Locks in the load-bearing assumption: serde_yaml 0.9 returns a
        // "duplicate entry with key ..." error on duplicate mapping keys.
        // If this test fails, see the duplicate-key detection rewrite in
        // yaml.rs.
        let src = r#"
actions:
  foo: 1
  foo: 2
"#;
        let err = serde_yaml::from_str::<serde_yaml::Value>(src).unwrap_err();
        assert!(
            err.to_string().contains("duplicate entry with key"),
            "serde_yaml error format changed; update yaml.rs. Got: {err}"
        );
    }

    #[test]
    fn parse_duplicate_key_error_extracts_parent_and_name() {
        let s = r#"actions: duplicate entry with key "foo" at line 3 column 1"#;
        let (parent, key) = parse_duplicate_key_error(s).unwrap();
        assert_eq!(parent.as_deref(), Some("actions"));
        assert_eq!(key, "foo");
    }

    #[test]
    fn parse_duplicate_key_error_top_level_has_no_parent() {
        // When the duplicate is at the YAML root, serde_yaml produces a
        // message with no explicit parent prefix.
        let s = r#"duplicate entry with key "key" at line 2 column 1"#;
        let (parent, key) = parse_duplicate_key_error(s).unwrap();
        assert!(parent.is_none(), "expected no parent, got {parent:?}");
        assert_eq!(key, "key");
    }

    #[test]
    fn parse_duplicate_key_error_non_match_returns_none() {
        assert!(parse_duplicate_key_error("something else went wrong").is_none());
    }

    #[test]
    fn top_level_duplicate_key_is_yaml_parse_not_action_duplicate() {
        // A duplicate top-level key (e.g. `key:` twice) must NOT be reported
        // as a `duplicate_action_key` — that code is reserved for the
        // `actions:` mapping. It should be a generic `yaml_parse` instead.
        let src = "key: svc\nkey: other\ndisplay_name: X\nhosts: []\n";
        let report = validate_template_yaml(src);
        assert!(!report.valid);
        assert!(
            report.errors.iter().any(|e| e.code == "yaml_parse"),
            "expected yaml_parse error for top-level duplicate; got {:?}",
            report.errors
        );
        assert!(
            !report
                .errors
                .iter()
                .any(|e| e.code == "duplicate_action_key"),
            "top-level duplicate must not be reported as duplicate_action_key"
        );
    }

    #[test]
    fn duplicate_action_key_reported() {
        let src = r#"
key: svc
display_name: Service
hosts: [api.example.com]
actions:
  foo:
    method: GET
    path: /foo
    description: foo
  foo:
    method: GET
    path: /bar
    description: bar
"#;
        let report = validate_template_yaml(src);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.code == "duplicate_action_key" && e.path == "actions.foo"),
            "expected duplicate_action_key error; got {:?}",
            report.errors
        );
    }

    #[test]
    fn shipped_services_validate_clean() {
        // Smoke test: every shipped services/*.yaml must validate.
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
