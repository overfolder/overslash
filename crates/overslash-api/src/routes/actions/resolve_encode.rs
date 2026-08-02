//! Body/query encoding helpers shared by the HTTP action shape of
//! `resolve_request`.
//!
//! Split out of `resolve.rs`.

/// Serialize one query param into zero or more URL-encoded `key=value`
/// pairs. Arrays expand to one pair per element (OpenAPI form/explode
/// style, e.g. Gmail's repeatable `labelIds`); an empty array emits
/// nothing. Nested arrays/objects inside an array fall through to their
/// JSON string encoding — templates only declare arrays of scalars, so
/// that case is a template bug, not a runtime one.
/// Insert `value` at a dotted path in a JSON body under construction,
/// creating intermediate objects as needed (`native.query` →
/// `{"native": {"query": value}}`). Template validation guarantees the first
/// segment collides with no flat body param; a non-object already present at
/// an intermediate key (two sql-field params can't exist, so only via a
/// caller-supplied conflicting value routed by an unrelated bug) is
/// overwritten rather than panicked on.
pub(super) fn insert_at_body_path(
    map: &mut serde_json::Map<String, serde_json::Value>,
    path: &str,
    value: serde_json::Value,
) {
    let mut segments = path.split('.').peekable();
    let mut cur = map;
    while let Some(seg) = segments.next() {
        if segments.peek().is_none() {
            cur.insert(seg.to_string(), value);
            return;
        }
        let entry = cur
            .entry(seg.to_string())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        if !entry.is_object() {
            *entry = serde_json::Value::Object(serde_json::Map::new());
        }
        cur = entry.as_object_mut().expect("just ensured object");
    }
}

pub(super) fn encode_query_param(key: &str, value: &serde_json::Value) -> Vec<String> {
    let encode = |v: &serde_json::Value| {
        let val = v.as_str().unwrap_or(&v.to_string()).to_string();
        format!("{key}={}", urlencoding::encode(&val))
    };
    match value {
        serde_json::Value::Array(items) => items.iter().map(encode).collect(),
        other => vec![encode(other)],
    }
}

#[cfg(test)]
mod tests {
    use super::{encode_query_param, insert_at_body_path};
    use serde_json::json;

    /// D43 body nesting: a sql-field path creates intermediate objects and
    /// coexists with flat keys under the same parent.
    #[test]
    fn insert_at_body_path_nests_and_merges() {
        let mut map = serde_json::Map::new();
        map.insert("database".to_string(), json!(5));
        insert_at_body_path(&mut map, "native.query", json!("SELECT 1"));
        insert_at_body_path(&mut map, "native.template-tags", json!({}));
        assert_eq!(
            serde_json::Value::Object(map),
            json!({
                "database": 5,
                "native": { "query": "SELECT 1", "template-tags": {} }
            })
        );

        // Single-segment path behaves like a flat insert.
        let mut map = serde_json::Map::new();
        insert_at_body_path(&mut map, "query", json!("SELECT 1"));
        assert_eq!(
            serde_json::Value::Object(map),
            json!({ "query": "SELECT 1" })
        );
    }

    #[test]
    fn array_expands_to_repeated_pairs() {
        assert_eq!(
            encode_query_param("labelIds", &json!(["INBOX", "UNREAD"])),
            vec!["labelIds=INBOX", "labelIds=UNREAD"]
        );
    }

    #[test]
    fn scalars_produce_single_pair() {
        assert_eq!(encode_query_param("q", &json!("hello")), vec!["q=hello"]);
        assert_eq!(
            encode_query_param("maxResults", &json!(50)),
            vec!["maxResults=50"]
        );
        assert_eq!(
            encode_query_param("includeSpamTrash", &json!(true)),
            vec!["includeSpamTrash=true"]
        );
    }

    #[test]
    fn empty_array_emits_nothing() {
        assert_eq!(
            encode_query_param("labelIds", &json!([])),
            Vec::<String>::new()
        );
    }

    #[test]
    fn elements_are_url_encoded() {
        assert_eq!(
            encode_query_param("q", &json!(["a b&c", "d=e"])),
            vec!["q=a%20b%26c", "q=d%3De"]
        );
    }
}
