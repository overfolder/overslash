use serde_json::Value;

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

    #[test]
    fn empty_path_segment() {
        // Single top-level key that is empty string — unusual but valid JSON
        let json = json!({"": "empty key"});
        // dot_path "" splits to [""] which looks up "" key
        assert_eq!(pick_value(&json, ""), Some("empty key".into()));
    }
}
