use std::collections::HashMap;

use crate::description_grammar::find_closing_bracket;

/// Interpolate an action description template with parameter values.
///
/// Supports two forms:
/// - `{param}` — replaced with the stringified value of `param` from `params`.
///   A dotted key (`{query.database}`) descends into nested objects when no
///   param is named exactly that. Missing params are left as literal
///   `{param}`.
/// - `[optional text with {param}]` — the bracketed segment is included only
///   when ALL `{param}` placeholders inside have present, non-null values.
///   Otherwise the entire segment (including brackets) is removed.
pub fn interpolate_description(
    template: &str,
    params: &HashMap<String, serde_json::Value>,
) -> String {
    // Pass 1: resolve [optional segments]
    let after_optionals = resolve_optional_segments(template, params);
    // Pass 2: substitute remaining {param} placeholders (display-clamped:
    // long values are truncated with `…` for the human-readable surface).
    substitute_placeholders_display(&after_optionals, params)
}

/// Like [`interpolate_description`], but first checks a `resolved` map of
/// human-readable display names (e.g. resolved from API lookups). Resolved
/// values are wrapped in single quotes for clarity.
///
/// Falls back to raw param values when a key is not in the resolved map.
pub fn interpolate_description_with_resolved(
    template: &str,
    params: &HashMap<String, serde_json::Value>,
    resolved: &HashMap<String, String>,
) -> String {
    // Build a merged params map where resolved values override raw ones
    let mut display_params = params.clone();
    for (key, display_name) in resolved {
        display_params.insert(
            key.clone(),
            serde_json::Value::String(format!("'{display_name}'")),
        );
    }
    // Pass 1: resolve [optional segments] — use original params for presence checks,
    // but the display_params for substitution
    let after_optionals = resolve_optional_segments(template, params);
    // Pass 2: substitute with display-enriched values (display-clamped).
    substitute_placeholders_display(&after_optionals, &display_params)
}

/// Interpolate a template intended for non-display surfaces (email bodies,
/// notification text, etc.) using the same `{var}` + `[optional]` grammar as
/// [`interpolate_description`] but **without** the [`DISPLAY_MAX_CHARS`] cap
/// that would silently truncate long values. URLs, addresses and free-form
/// user content all survive intact.
pub fn interpolate_template(template: &str, params: &HashMap<String, serde_json::Value>) -> String {
    let after_optionals = resolve_optional_segments(template, params);
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

/// Look up a placeholder key in the param map.
///
/// An exact flat match wins first, so a param whose name literally contains a
/// dot keeps resolving to itself. Failing that the key is read as a dotted
/// path and descended through nested JSON objects — which is what lets a
/// resolver reach an id nested inside an object-valued body param
/// (`{query.database}` → `params["query"]["database"]`).
///
/// Objects only: no array indices, matching the path grammar
/// `crate::disclosure::apply_redactions` already uses. A path that doesn't
/// resolve returns `None`, and every caller renders the placeholder literally
/// exactly as it did before dotted keys were understood.
fn lookup<'a>(
    params: &'a HashMap<String, serde_json::Value>,
    key: &str,
) -> Option<&'a serde_json::Value> {
    if let Some(v) = params.get(key) {
        return Some(v);
    }
    let (head, rest) = key.split_once('.')?;
    let mut cur = params.get(head)?;
    for seg in rest.split('.') {
        cur = cur.as_object()?.get(seg)?;
    }
    Some(cur)
}

/// Check if every `{param}` placeholder in `segment` has a present, non-null value.
fn all_placeholders_present(segment: &str, params: &HashMap<String, serde_json::Value>) -> bool {
    let mut i = 0;
    let bytes = segment.as_bytes();

    while i < bytes.len() {
        if bytes[i] == b'{' {
            if let Some(close) = segment[i + 1..].find('}') {
                let key = &segment[i + 1..i + 1 + close];
                if !key.is_empty() && !is_value_present(lookup(params, key)) {
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
/// Missing params are left as literal `{param}`. Keys resolve through
/// [`lookup`], so a dotted key reaches into nested objects.
///
/// Substituted values pass through unmodified — long strings are
/// preserved as-is. This matters for non-display callers like the
/// resolver-URL builder in `services::param_resolver`, where truncating
/// a path segment (e.g. an OAuth-protected resource ID) would silently
/// produce a broken URL.
///
/// For the human-facing description surface use
/// [`substitute_placeholders_display`], which additionally clamps each
/// substituted value to [`DISPLAY_MAX_CHARS`] visible characters.
pub fn substitute_placeholders(text: &str, params: &HashMap<String, serde_json::Value>) -> String {
    substitute_with(text, params, value_to_string)
}

/// Same as [`substitute_placeholders`] but clamps each substituted value
/// to [`DISPLAY_MAX_CHARS`] visible characters with a trailing `…`.
/// Used by the description renderer so a 5KB message body can't blow
/// up the approval row, while leaving raw substitution paths untouched.
pub fn substitute_placeholders_display(
    text: &str,
    params: &HashMap<String, serde_json::Value>,
) -> String {
    substitute_with(text, params, |v| clamp_display(&value_to_string(v)))
}

fn substitute_with(
    text: &str,
    params: &HashMap<String, serde_json::Value>,
    fmt: impl Fn(&serde_json::Value) -> String,
) -> String {
    let mut result = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'{' {
            if let Some(close) = text[i + 1..].find('}') {
                let key = &text[i + 1..i + 1 + close];
                if !key.is_empty()
                    && let Some(value) = lookup(params, key)
                    && !value.is_null()
                {
                    result.push_str(&fmt(value));
                    i = i + 1 + close + 1;
                    continue;
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

/// Convert a JSON value to a display string. Lossless for primitives;
/// arrays/objects use compact JSON.
fn value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => String::new(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// Visible-character cap for any single substituted value in a rendered
/// description. Includes the `…` suffix when truncation kicks in.
const DISPLAY_MAX_CHARS: usize = 60;

fn clamp_display(s: &str) -> String {
    let count = s.chars().count();
    if count <= DISPLAY_MAX_CHARS {
        return s.to_string();
    }
    let mut out: String = s.chars().take(DISPLAY_MAX_CHARS - 1).collect();
    out.push('…');
    out
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

    // --- interpolate_description_with_resolved tests ---

    fn resolved(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn resolved_values_replace_raw_ids() {
        let p = params(&[
            ("calendarId", json!("abc123")),
            ("eventId", json!("evt456")),
        ]);
        let r = resolved(&[("calendarId", "Work"), ("eventId", "Team Standup")]);
        assert_eq!(
            interpolate_description_with_resolved(
                "Delete event {eventId} on calendar {calendarId}",
                &p,
                &r,
            ),
            "Delete event 'Team Standup' on calendar 'Work'"
        );
    }

    #[test]
    fn partial_resolution_falls_back() {
        let p = params(&[
            ("calendarId", json!("abc123")),
            ("eventId", json!("evt456")),
        ]);
        let r = resolved(&[("calendarId", "Work")]);
        assert_eq!(
            interpolate_description_with_resolved(
                "Get event {eventId} on calendar {calendarId}",
                &p,
                &r,
            ),
            "Get event evt456 on calendar 'Work'"
        );
    }

    #[test]
    fn no_resolved_values_same_as_basic() {
        let p = params(&[("repo", json!("overfolder/app"))]);
        let r = resolved(&[]);
        assert_eq!(
            interpolate_description_with_resolved("List issues on {repo}", &p, &r,),
            "List issues on overfolder/app"
        );
    }

    #[test]
    fn substitute_placeholders_does_not_clamp_long_values() {
        // Pinned behavior: the public substitution function must preserve
        // values verbatim. param_resolver builds resolver URLs through it
        // and would silently corrupt long path segments (UUIDs, OAuth
        // resource IDs) if clamping leaked in here. Use the
        // `_display` variant when you want truncation.
        let body = "a".repeat(500);
        let p = params(&[("text", json!(body))]);
        let out = substitute_placeholders("/files/{text}", &p);
        assert_eq!(out, format!("/files/{body}"));
        assert!(!out.contains('…'));
    }

    #[test]
    fn long_string_value_truncated_with_ellipsis() {
        let body = "a".repeat(200);
        let p = params(&[("text", json!(body))]);
        let out = interpolate_description("Send {text}", &p);
        // 60 visible chars: 59 'a' + '…'
        assert_eq!(out.chars().count(), "Send ".len() + 60);
        assert!(out.ends_with('…'));
        assert!(out.starts_with("Send aaaa"));
    }

    #[test]
    fn short_string_value_not_truncated() {
        let p = params(&[("text", json!("hello"))]);
        assert_eq!(interpolate_description("Send {text}", &p), "Send hello");
    }

    #[test]
    fn truncation_preserves_utf8_boundaries() {
        // 100 emoji, each ≥4 bytes — char-aware clamp must not split a
        // code point on truncation.
        let body = "🚀".repeat(100);
        let p = params(&[("text", json!(body))]);
        let out = interpolate_description("{text}", &p);
        assert_eq!(out.chars().count(), 60);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn interpolate_template_does_not_clamp_long_values() {
        // Email bodies and similar non-display surfaces must preserve full
        // values — a billing receipt URL is the canonical reason.
        let body = "a".repeat(200);
        let p = params(&[("url", json!(body))]);
        let out = interpolate_template("Click {url} to confirm", &p);
        assert_eq!(out, format!("Click {body} to confirm"));
        assert!(!out.contains('…'));
    }

    // --- dotted-path keys ---

    #[test]
    fn dotted_key_descends_into_nested_object() {
        // The export_query shape: the id lives inside an object-valued body
        // param, and the resolver URL has to reach it.
        let p = params(&[("query", json!({"database": 4, "type": "native"}))]);
        assert_eq!(
            substitute_placeholders("/api/database/{query.database}", &p),
            "/api/database/4"
        );
    }

    #[test]
    fn dotted_key_descends_several_levels() {
        let p = params(&[("a", json!({"b": {"c": "deep"}}))]);
        assert_eq!(interpolate_description("{a.b.c}", &p), "deep");
    }

    #[test]
    fn exact_key_containing_a_dot_wins_over_descent() {
        // A param literally named "a.b" must keep resolving to itself rather
        // than being reinterpreted as a path into "a".
        let p = params(&[("a.b", json!("flat")), ("a", json!({"b": "nested"}))]);
        assert_eq!(interpolate_description("{a.b}", &p), "flat");
    }

    #[test]
    fn dotted_key_with_missing_head_stays_literal() {
        let p = params(&[("other", json!({"database": 4}))]);
        assert_eq!(
            interpolate_description("{query.database}", &p),
            "{query.database}"
        );
    }

    #[test]
    fn dotted_key_through_a_non_object_stays_literal() {
        // Descending into a scalar (or an array — indices are deliberately
        // not part of the grammar) resolves to nothing.
        let p = params(&[("q", json!("SELECT 1")), ("arr", json!([{"x": 1}]))]);
        assert_eq!(interpolate_description("{q.database}", &p), "{q.database}");
        assert_eq!(interpolate_description("{arr.0.x}", &p), "{arr.0.x}");
    }

    #[test]
    fn dotted_key_null_leaf_stays_literal() {
        let p = params(&[("query", json!({"database": null}))]);
        assert_eq!(
            interpolate_description("{query.database}", &p),
            "{query.database}"
        );
    }

    #[test]
    fn optional_segment_sees_dotted_keys() {
        // The presence check and the substitution pass must agree, or a
        // segment would be dropped even though its placeholder resolves.
        let p = params(&[("query", json!({"database": 4}))]);
        assert_eq!(
            interpolate_description("Run SQL[ on database {query.database}]", &p),
            "Run SQL on database 4"
        );
        let p = params(&[("query", json!({"type": "native"}))]);
        assert_eq!(
            interpolate_description("Run SQL[ on database {query.database}]", &p),
            "Run SQL"
        );
    }

    #[test]
    fn interpolate_template_supports_optional_segments() {
        let p = params(&[("name", json!("Alice"))]);
        assert_eq!(
            interpolate_template("Hello {name}[, your code is {code}].", &p),
            "Hello Alice."
        );
    }

    #[test]
    fn resolved_with_optional_segments() {
        let p = params(&[("calendarId", json!("abc")), ("q", json!("meeting"))]);
        let r = resolved(&[("calendarId", "Work")]);
        assert_eq!(
            interpolate_description_with_resolved(
                "List events on {calendarId}[ matching '{q}']",
                &p,
                &r,
            ),
            "List events on 'Work' matching 'meeting'"
        );
    }
}
