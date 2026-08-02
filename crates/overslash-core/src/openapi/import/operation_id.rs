//! Synthesis of `{method}_{path_slug}` ids for operations without an
//! `operationId`.

use std::collections::HashSet;

use serde_json::{Map, Value};

use crate::openapi::alias::HTTP_METHODS;

use super::ImportWarning;

// ── operationId synthesis ────────────────────────────────────────────

pub(super) fn synthesize_operation_ids(
    root: &mut Map<String, Value>,
    warnings: &mut Vec<ImportWarning>,
) {
    let Some(paths) = root.get_mut("paths").and_then(Value::as_object_mut) else {
        return;
    };
    let mut seen: HashSet<String> = HashSet::new();
    // Two passes: first collect pre-existing ids so synthesized ones don't
    // collide with them; then fill in missing ids.
    for path_item in paths.values() {
        let Some(obj) = path_item.as_object() else {
            continue;
        };
        for m in HTTP_METHODS {
            let Some(op) = obj.get(*m).and_then(Value::as_object) else {
                continue;
            };
            if let Some(id) = op.get("operationId").and_then(Value::as_str) {
                seen.insert(id.to_string());
            }
        }
    }
    for (path_key, path_item) in paths.iter_mut() {
        let Some(obj) = path_item.as_object_mut() else {
            continue;
        };
        for m in HTTP_METHODS {
            let Some(op) = obj.get_mut(*m).and_then(Value::as_object_mut) else {
                continue;
            };
            if op.contains_key("operationId") {
                continue;
            }
            let candidate = synthesize_id(m, path_key, &seen);
            warnings.push(ImportWarning::new(
                "derived_operation_id",
                format!(
                    "operationId synthesized for {} {path_key}",
                    m.to_uppercase()
                ),
                format!("paths.{path_key}.{m}.operationId"),
            ));
            seen.insert(candidate.clone());
            op.insert("operationId".to_string(), Value::String(candidate));
        }
    }
}

fn synthesize_id(method: &str, path: &str, seen: &HashSet<String>) -> String {
    let base = format!("{method}{}", path_slug(path));
    let mut candidate = base.clone();
    let mut suffix = 2;
    while seen.contains(&candidate) {
        candidate = format!("{base}_{suffix}");
        suffix += 1;
    }
    candidate
}

pub(super) fn path_slug(path: &str) -> String {
    let mut out = String::new();
    for ch in path.chars() {
        match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' => out.push(ch.to_ascii_lowercase()),
            '_' => out.push('_'),
            '/' | '{' | '}' | '-' | '.' | ':' if !out.ends_with('_') && !out.is_empty() => {
                out.push('_');
            }
            '/' | '{' | '}' | '-' | '.' | ':' => {}
            _ => {}
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    if out.is_empty() {
        "_root".to_string()
    } else {
        format!("_{out}")
    }
}

#[cfg(test)]
mod tests {
    use crate::openapi::import::tests::base_doc;
    use crate::openapi::import::{ImportOptions, prepare_from_value};
    use serde_json::json;

    #[test]
    fn synthesizes_missing_operation_ids() {
        let prep = prepare_from_value(base_doc(), &ImportOptions::default());
        let post = &prep.doc["paths"]["/widgets"]["post"]["operationId"];
        assert_eq!(post.as_str().unwrap(), "post_widgets");
    }

    #[test]
    fn synthesized_ids_are_unique_when_colliding() {
        // Two operations that would otherwise synthesize the same id.
        let doc = json!({
            "openapi": "3.1.0",
            "info": {"title": "X", "x-overslash-key": "x"},
            "paths": {
                "/a": { "get": {"summary": "a"} },
                "/a/": { "get": {"summary": "a-with-slash"} }
            }
        });
        let prep = prepare_from_value(doc, &ImportOptions::default());
        let ids: Vec<String> = prep
            .operations
            .iter()
            .map(|o| o.operation_id.clone())
            .collect();
        assert_eq!(ids.len(), 2);
        // Ensure distinct ids even when path slugs collide.
        assert_ne!(ids[0], ids[1]);
    }
}
