use std::collections::HashMap;

/// Interpolate an action description template with parameter values.
///
/// Supports two forms:
/// - `{param}` — replaced with the stringified value of `param` from `params`.
///   Missing params are left as literal `{param}`.
/// - `[optional text with {param}]` — the bracketed segment is included only
///   when ALL `{param}` placeholders inside have present, non-null values.
///   Otherwise the entire segment (including brackets) is removed.
pub fn interpolate_description(
    template: &str,
    params: &HashMap<String, serde_json::Value>,
) -> String {
    // Pass 1: resolve [optional segments]
    let after_optionals = resolve_optional_segments(template, params);
    // Pass 2: substitute remaining {param} placeholders
    substitute_placeholders(&after_optionals, params)
}

/// Resolve `[...]` optional segments. Flat only — no nesting.
fn resolve_optional_segments(
    template: &str,
    params: &HashMap<String, serde_json::Value>,
) -> String {
    let mut result = String::with_capacity(template.len());
    let bytes = template.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if bytes[i] == b'[' {
            // Find matching close bracket
            if let Some(close) = find_closing_bracket(template, i) {
                let segment = &template[i + 1..close];
                // Check if all placeholders in this segment have values
                if all_placeholders_present(segment, params) {
                    // Keep the inner text (without brackets)
                    result.push_str(segment);
                }
                // Skip past the closing bracket
                i = close + 1;
            } else {
                // Unmatched bracket — keep as literal
                result.push('[');
                i += 1;
            }
        } else {
            let ch = template[i..].chars().next().unwrap();
            result.push(ch);
            i += ch.len_utf8();
        }
    }

    result
}

/// Find the index of the closing `]` for an opening `[` at `start`.
fn find_closing_bracket(template: &str, start: usize) -> Option<usize> {
    template[start + 1..]
        .find(']')
        .map(|offset| start + 1 + offset)
}

/// Check if every `{param}` placeholder in `segment` has a present, non-null value.
fn all_placeholders_present(segment: &str, params: &HashMap<String, serde_json::Value>) -> bool {
    let mut i = 0;
    let bytes = segment.as_bytes();

    while i < bytes.len() {
        if bytes[i] == b'{' {
            if let Some(close) = segment[i + 1..].find('}') {
                let key = &segment[i + 1..i + 1 + close];
                if !key.is_empty() && !is_value_present(params.get(key)) {
                    return false;
                }
                i = i + 1 + close + 1;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }

    true
}

/// A value is "present" if it exists and is not null.
fn is_value_present(value: Option<&serde_json::Value>) -> bool {
    matches!(value, Some(v) if !v.is_null())
}

/// Replace `{param}` placeholders with stringified values.
/// Missing params are left as literal `{param}`.
fn substitute_placeholders(text: &str, params: &HashMap<String, serde_json::Value>) -> String {
    let mut result = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'{' {
            if let Some(close) = text[i + 1..].find('}') {
                let key = &text[i + 1..i + 1 + close];
                if !key.is_empty() {
                    if let Some(value) = params.get(key) {
                        if !value.is_null() {
                            result.push_str(&value_to_string(value));
                            i = i + 1 + close + 1;
                            continue;
                        }
                    }
                }
                // No match — keep literal
                result.push('{');
                i += 1;
            } else {
                result.push('{');
                i += 1;
            }
        } else {
            let ch = text[i..].chars().next().unwrap();
            result.push(ch);
            i += ch.len_utf8();
        }
    }

    result
}

/// Convert a JSON value to a display string.
fn value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => String::new(),
        // Arrays and objects: compact JSON
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn params(pairs: &[(&str, serde_json::Value)]) -> HashMap<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn basic_substitution() {
        let p = params(&[
            ("title", json!("Fix bug")),
            ("repo", json!("overfolder/app")),
        ]);
        assert_eq!(
            interpolate_description("Create pull request '{title}' on {repo}", &p),
            "Create pull request 'Fix bug' on overfolder/app"
        );
    }

    #[test]
    fn optional_segment_kept() {
        let p = params(&[("repo", json!("overfolder/app")), ("state", json!("open"))]);
        assert_eq!(
            interpolate_description("List pull requests on {repo}[ with state {state}]", &p),
            "List pull requests on overfolder/app with state open"
        );
    }

    #[test]
    fn optional_segment_removed() {
        let p = params(&[("repo", json!("overfolder/app"))]);
        assert_eq!(
            interpolate_description("List pull requests on {repo}[ with state {state}]", &p),
            "List pull requests on overfolder/app"
        );
    }

    #[test]
    fn multiple_optional_segments() {
        let p = params(&[("repo", json!("r")), ("state", json!("open"))]);
        assert_eq!(
            interpolate_description("PRs on {repo}[ state {state}][ by {author}]", &p),
            "PRs on r state open"
        );
    }

    #[test]
    fn missing_param_left_literal() {
        let p = params(&[]);
        assert_eq!(interpolate_description("Hello {name}", &p), "Hello {name}");
    }

    #[test]
    fn null_treated_as_missing() {
        let p = params(&[("state", json!(null))]);
        assert_eq!(interpolate_description("List[ with {state}]", &p), "List");
    }

    #[test]
    fn empty_string_is_present() {
        let p = params(&[("tag", json!(""))]);
        assert_eq!(
            interpolate_description("Items[ tagged {tag}]", &p),
            "Items tagged "
        );
    }

    #[test]
    fn numeric_and_boolean_values() {
        let p = params(&[("count", json!(42)), ("active", json!(true))]);
        assert_eq!(
            interpolate_description("{count} items, active={active}", &p),
            "42 items, active=true"
        );
    }

    #[test]
    fn no_placeholders() {
        let p = params(&[("x", json!("y"))]);
        assert_eq!(
            interpolate_description("Static description", &p),
            "Static description"
        );
    }

    #[test]
    fn empty_template() {
        let p = params(&[]);
        assert_eq!(interpolate_description("", &p), "");
    }

    #[test]
    fn unmatched_bracket() {
        let p = params(&[("x", json!("1"))]);
        assert_eq!(
            interpolate_description("Hello [world {x}", &p),
            "Hello [world 1"
        );
    }

    #[test]
    fn optional_segment_multiple_params_partial() {
        // Optional segment requires ALL placeholders present
        let p = params(&[("a", json!("1"))]);
        assert_eq!(interpolate_description("Base[ {a} and {b}]", &p), "Base");
    }

    #[test]
    fn optional_segment_multiple_params_all_present() {
        let p = params(&[("a", json!("1")), ("b", json!("2"))]);
        assert_eq!(
            interpolate_description("Base[ {a} and {b}]", &p),
            "Base 1 and 2"
        );
    }
}
