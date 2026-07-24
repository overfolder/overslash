//! YAML entry points: parse an authored OpenAPI document into the stored
//! `serde_json::Value` form, and serialize a normalized document back to YAML
//! for the dashboard editor.

use serde_json::Value;

use crate::template_validation::ValidationIssue;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openapi::{compile_service, normalize_aliases};
    use crate::types::Risk;
    use serde_json::json;

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
        assert_eq!(send.scope_param, "channel".into());
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
