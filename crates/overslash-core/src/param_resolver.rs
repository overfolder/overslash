use std::collections::HashMap;

use serde_json::Value;

use crate::description_grammar::iter_placeholders;

/// Extract a value from a JSON object using a dot-separated path.
///
/// Supports object keys (`summary`, `owner.login`) and numeric array indices (`items.0.name`).
/// Returns `None` if the path doesn't resolve or the leaf is null.
pub fn pick_value(json: &Value, dot_path: &str) -> Option<String> {
    let mut current = json;

    for segment in dot_path.split('.') {
        current = match current {
            Value::Object(map) => map.get(segment)?,
            Value::Array(arr) => {
                let idx: usize = segment.parse().ok()?;
                arr.get(idx)?
            }
            _ => return None,
        };
    }

    match current {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        other => Some(serde_json::to_string(other).unwrap_or_default()),
    }
}

/// Render a resolver `display` template against the resolver's JSON response.
///
/// Placeholders are dot-paths into the response (`{name}`, `{owner.login}`),
/// and `[...]` segments drop when any placeholder inside them is missing —
/// so `{name}[ ({phone})]` renders as bare `Sonia` for a contact with no
/// phone number on file, without leaving a dangling ` ()`.
///
/// A placeholder that survives outside a `[...]` segment but has no value
/// collapses to empty rather than leaking a literal `{name}` into an
/// approval. When nothing at all resolves the result is `None`, so the
/// caller falls back to the raw argument instead of showing a blank field.
pub fn render_display(template: &str, json: &Value) -> Option<String> {
    // `Null` (not a missing key) is what marks a placeholder absent for
    // `resolve_optional_segments` — it checks presence, and an empty string
    // would read as present and keep the bracketed segment.
    // An empty string means "not known" here, not "known to be empty" — a
    // resolver response that spells an absent field `""` rather than omitting
    // it must still drop its `[...]` segment instead of rendering ` ()`.
    let values: HashMap<String, Value> = iter_placeholders(template)
        .map(|(_, key)| {
            let value = pick_value(json, key)
                .filter(|v| !v.trim().is_empty())
                .map_or(Value::Null, Value::String);
            (key.to_string(), value)
        })
        .collect();

    let after_optionals = crate::description::resolve_optional_segments(template, &values);

    let mut out = String::with_capacity(after_optionals.len());
    let mut cursor = 0;
    for (span, key) in iter_placeholders(&after_optionals) {
        out.push_str(&after_optionals[cursor..span.start]);
        if let Some(Value::String(value)) = values.get(key) {
            out.push_str(value);
        }
        cursor = span.end;
    }
    out.push_str(&after_optionals[cursor..]);

    let trimmed = out.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn simple_key() {
        let json = json!({"summary": "Work Calendar"});
        assert_eq!(pick_value(&json, "summary"), Some("Work Calendar".into()));
    }

    #[test]
    fn nested_path() {
        let json = json!({"owner": {"login": "alice"}});
        assert_eq!(pick_value(&json, "owner.login"), Some("alice".into()));
    }

    #[test]
    fn array_index() {
        let json = json!({"items": [{"name": "first"}, {"name": "second"}]});
        assert_eq!(pick_value(&json, "items.0.name"), Some("first".into()));
        assert_eq!(pick_value(&json, "items.1.name"), Some("second".into()));
    }

    #[test]
    fn missing_key() {
        let json = json!({"summary": "Work"});
        assert_eq!(pick_value(&json, "title"), None);
    }

    #[test]
    fn null_value() {
        let json = json!({"summary": null});
        assert_eq!(pick_value(&json, "summary"), None);
    }

    #[test]
    fn numeric_value() {
        let json = json!({"count": 42});
        assert_eq!(pick_value(&json, "count"), Some("42".into()));
    }

    #[test]
    fn deeply_nested() {
        let json = json!({"a": {"b": {"c": {"d": "deep"}}}});
        assert_eq!(pick_value(&json, "a.b.c.d"), Some("deep".into()));
    }

    #[test]
    fn path_through_non_object() {
        let json = json!({"a": "string"});
        assert_eq!(pick_value(&json, "a.b"), None);
    }

    #[test]
    fn array_index_out_of_bounds() {
        let json = json!({"items": [1, 2]});
        assert_eq!(pick_value(&json, "items.5"), None);
    }

    // ── render_display ────────────────────────────────────────────────

    #[test]
    fn display_renders_name_and_phone() {
        let json = json!({"name": "Sonia Pérez", "phone": "+34600123456"});
        assert_eq!(
            render_display("{name}[ ({phone})]", &json).as_deref(),
            Some("Sonia Pérez (+34600123456)")
        );
    }

    /// The bracketed segment drops whole rather than leaving a dangling ` ()`.
    #[test]
    fn display_drops_the_optional_segment_when_its_value_is_missing() {
        let json = json!({"name": "Sonia Pérez"});
        assert_eq!(
            render_display("{name}[ ({phone})]", &json).as_deref(),
            Some("Sonia Pérez")
        );
    }

    /// An unresolved placeholder outside a `[...]` segment collapses to
    /// empty. Leaking a literal `{name}` into an approval would read as a
    /// contact actually named that.
    #[test]
    fn display_never_leaks_a_literal_placeholder() {
        let json = json!({"phone": "+34600123456"});
        assert_eq!(
            render_display("{name} ({phone})", &json).as_deref(),
            Some("(+34600123456)")
        );
    }

    /// Nothing resolved → `None`, so the caller shows the raw argument
    /// rather than a blank field.
    #[test]
    fn display_is_none_when_nothing_resolves() {
        let json = json!({"kind": "unknown"});
        assert_eq!(render_display("{name}[ ({phone})]", &json), None);
    }

    /// Servers spell "unknown" as `""` about as often as they omit the key.
    #[test]
    fn display_treats_an_empty_string_as_absent() {
        let json = json!({"name": "Sonia Pérez", "phone": ""});
        assert_eq!(
            render_display("{name}[ ({phone})]", &json).as_deref(),
            Some("Sonia Pérez")
        );
    }

    #[test]
    fn display_accepts_dotted_paths() {
        let json = json!({"contact": {"display": {"full": "Sonia"}}});
        assert_eq!(
            render_display("{contact.display.full}", &json).as_deref(),
            Some("Sonia")
        );
    }

    /// `pick: summary` normalizes to `display: "{summary}"`, so the two
    /// spellings must agree.
    #[test]
    fn pick_shorthand_matches_the_equivalent_display() {
        let json = json!({"summary": "Work Calendar"});
        assert_eq!(
            render_display("{summary}", &json).as_deref(),
            pick_value(&json, "summary").as_deref()
        );
    }

    #[test]
    fn empty_path_segment() {
        // Single top-level key that is empty string — unusual but valid JSON
        let json = json!({"": "empty key"});
        // dot_path "" splits to [""] which looks up "" key
        assert_eq!(pick_value(&json, ""), Some("empty key".into()));
    }
}
