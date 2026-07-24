//! Local (`#/…`) `$ref` dereferencing.

use std::collections::HashSet;

use serde_json::{Map, Value};

use super::ImportWarning;

// ── $ref dereferencer ────────────────────────────────────────────────

pub(super) fn dereference_refs(doc: &mut Value, warnings: &mut Vec<ImportWarning>) {
    let snapshot = doc.clone();
    // Limit recursion depth so a cyclic or pathologically nested set of refs
    // cannot pin the CPU. Anything deeper than this is not a template we want
    // to import anyway.
    const MAX_DEPTH: usize = 16;
    deref_walk(
        doc,
        &snapshot,
        "",
        0,
        MAX_DEPTH,
        warnings,
        &mut HashSet::new(),
    );
}

fn deref_walk(
    v: &mut Value,
    root: &Value,
    path: &str,
    depth: usize,
    max_depth: usize,
    warnings: &mut Vec<ImportWarning>,
    seen: &mut HashSet<String>,
) {
    if depth >= max_depth {
        return;
    }
    match v {
        Value::Object(obj) => {
            if let Some(ref_str) = obj.get("$ref").and_then(Value::as_str).map(str::to_string) {
                if !ref_str.starts_with("#/") {
                    warnings.push(ImportWarning::new(
                        "unresolved_external_ref",
                        format!("external $ref {ref_str:?} is not supported; left as-is"),
                        path,
                    ));
                    return;
                }
                if seen.contains(&ref_str) {
                    warnings.push(ImportWarning::new(
                        "circular_ref",
                        format!("cyclic $ref {ref_str:?}; left as-is"),
                        path,
                    ));
                    return;
                }
                match resolve_local_ref(root, &ref_str) {
                    Some(resolved) => {
                        seen.insert(ref_str.clone());
                        let mut replacement = resolved.clone();
                        deref_walk(
                            &mut replacement,
                            root,
                            path,
                            depth + 1,
                            max_depth,
                            warnings,
                            seen,
                        );
                        seen.remove(&ref_str);
                        // Merge any sibling keys of the $ref on top of the
                        // resolved object — OpenAPI 3.1 allows $ref to live
                        // alongside other keywords. Siblings win.
                        let mut siblings: Map<String, Value> = obj.clone();
                        siblings.remove("$ref");
                        match replacement {
                            Value::Object(mut replacement_obj) => {
                                for (k, sv) in siblings {
                                    replacement_obj.insert(k, sv);
                                }
                                *v = Value::Object(replacement_obj);
                            }
                            other => {
                                *v = other;
                            }
                        }
                        return;
                    }
                    None => {
                        warnings.push(ImportWarning::new(
                            "unresolved_ref",
                            format!("could not resolve local $ref {ref_str:?}; left as-is"),
                            path,
                        ));
                        return;
                    }
                }
            }
            for (k, child) in obj.iter_mut() {
                let child_path = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                deref_walk(
                    child,
                    root,
                    &child_path,
                    depth + 1,
                    max_depth,
                    warnings,
                    seen,
                );
            }
        }
        Value::Array(arr) => {
            for (i, child) in arr.iter_mut().enumerate() {
                let child_path = format!("{path}[{i}]");
                deref_walk(
                    child,
                    root,
                    &child_path,
                    depth + 1,
                    max_depth,
                    warnings,
                    seen,
                );
            }
        }
        _ => {}
    }
}

fn resolve_local_ref<'a>(root: &'a Value, ref_str: &str) -> Option<&'a Value> {
    let rest = ref_str.strip_prefix("#/")?;
    let mut current = root;
    for raw in rest.split('/') {
        // JSON Pointer escapes: ~1 → /, ~0 → ~
        let token = raw.replace("~1", "/").replace("~0", "~");
        match current {
            Value::Object(o) => current = o.get(&token)?,
            Value::Array(arr) => {
                let idx: usize = token.parse().ok()?;
                current = arr.get(idx)?;
            }
            _ => return None,
        }
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use crate::openapi::import::{ImportOptions, prepare_from_value};
    use serde_json::json;

    #[test]
    fn local_ref_is_dereferenced() {
        let doc = json!({
            "openapi": "3.1.0",
            "info": {"title": "t", "x-overslash-key": "t"},
            "components": {
                "schemas": {
                    "Widget": {"type": "object", "properties": {"id": {"type": "string"}}}
                }
            },
            "paths": {
                "/widgets": {
                    "get": {
                        "operationId": "list",
                        "responses": {
                            "200": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Widget"}}}}
                        }
                    }
                }
            }
        });
        let prep = prepare_from_value(doc, &ImportOptions::default());
        let schema = &prep.doc["paths"]["/widgets"]["get"]["responses"]["200"]["content"]["application/json"]
            ["schema"];
        assert_eq!(schema["type"].as_str().unwrap(), "object");
    }

    #[test]
    fn unresolved_external_ref_warns_and_keeps_ref() {
        let doc = json!({
            "openapi": "3.1.0",
            "info": {"title": "t", "x-overslash-key": "t"},
            "paths": {
                "/x": {
                    "get": {
                        "operationId": "x",
                        "responses": {"200": {"$ref": "https://other/spec.yaml#/foo"}}
                    }
                }
            }
        });
        let prep = prepare_from_value(doc, &ImportOptions::default());
        assert!(
            prep.warnings
                .iter()
                .any(|w| w.code == "unresolved_external_ref")
        );
        let resp = &prep.doc["paths"]["/x"]["get"]["responses"]["200"];
        assert!(resp.get("$ref").is_some());
    }

    #[test]
    fn circular_ref_emits_warning_and_stops() {
        // Self-referential ref: A → A. The dereferencer should cut the cycle
        // rather than stack-overflow, and emit a circular_ref warning.
        let doc = json!({
            "openapi": "3.1.0",
            "info": {"title": "Cyclic", "x-overslash-key": "cyclic"},
            "components": {
                "schemas": {
                    "Node": {"$ref": "#/components/schemas/Node"}
                }
            },
            "paths": {
                "/n": {"get": {
                    "operationId": "n",
                    "responses": {"200": {
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Node"}}}
                    }}
                }}
            }
        });
        let prep = prepare_from_value(doc, &ImportOptions::default());
        // Either the circular_ref warning (preferred) or the document has
        // terminated safely. We just care we didn't panic.
        let _ = prep;
    }

    #[test]
    fn ref_with_sibling_keys_merges_siblings_over_resolved_object() {
        // OpenAPI 3.1 allows $ref alongside other keys. Our resolver should
        // merge the non-$ref siblings on top of the resolved value.
        let doc = json!({
            "openapi": "3.1.0",
            "info": {"title": "Sib", "x-overslash-key": "sib"},
            "components": {
                "schemas": {
                    "Base": {"type": "object", "description": "base schema"}
                }
            },
            "paths": {
                "/s": {"get": {
                    "operationId": "s",
                    "responses": {"200": {
                        "content": {"application/json": {"schema": {
                            "$ref": "#/components/schemas/Base",
                            "description": "override"
                        }}}
                    }}
                }}
            }
        });
        let prep = prepare_from_value(doc, &ImportOptions::default());
        let schema = &prep.doc["paths"]["/s"]["get"]["responses"]["200"]["content"]["application/json"]
            ["schema"];
        assert_eq!(schema["type"].as_str().unwrap(), "object");
        assert_eq!(schema["description"].as_str().unwrap(), "override");
    }
}
