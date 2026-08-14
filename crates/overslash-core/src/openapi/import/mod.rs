//! OpenAPI 3.x import → canonical service-template document.
//!
//! The template format is already an OpenAPI 3.1 superset with `x-overslash-*`
//! vendor extensions, so "import" is a pre-processing problem rather than a
//! translation: accept whatever the user has, lower it to something the rest
//! of the pipeline can eat, and surface every dropped feature as a warning so
//! the caller can decide what to edit.
//!
//! This module is pure — no I/O. Callers that want to resolve a URL should
//! fetch the bytes (with SSRF guards and size limits) in the API layer and
//! then hand them to [`prepare_import`].
//!
//! Steps:
//!  1. Parse YAML or JSON into a `serde_json::Value`.
//!  2. Derive `{method}_{path_slug}` ids for operations missing an
//!     `operationId` so every operation has a stable handle.
//!  3. Dereference local `$ref`s (no remote refs) so downstream alias
//!     normalization and compilation see flat shapes.
//!  4. Apply user-supplied overrides (`key`, `display_name`).
//!  5. Filter paths/methods to the user-selected subset (if any).
//!  6. Enumerate every operation for the response — including ones that
//!     were filtered out — so the UI can show a checkbox tree.

use std::collections::HashSet;

use serde_json::{Map, Value};

use crate::template_validation::ValidationIssue;

use crate::openapi::alias::HTTP_METHODS;

mod deref;
mod operation_id;
mod options;
mod overrides;
mod source;

pub use options::{ImportOptions, ImportPreparation, ImportWarning, OperationInfo};

use deref::dereference_refs;
use operation_id::{path_slug, synthesize_operation_ids};
use overrides::apply_overrides;
use source::check_openapi_version;
#[cfg(feature = "yaml")]
use source::parse_source;

/// Raw-bytes entry point. Detects format (YAML vs JSON) from the optional
/// `content_type` hint, falling back to a heuristic on the first non-
/// whitespace byte.
#[cfg(feature = "yaml")]
pub fn prepare_import(
    bytes: &[u8],
    content_type: Option<&str>,
    opts: &ImportOptions,
) -> Result<ImportPreparation, ValidationIssue> {
    let src = std::str::from_utf8(bytes).map_err(|e| {
        ValidationIssue::new(
            "openapi_parse_error",
            format!("source is not valid UTF-8: {e}"),
            "",
        )
    })?;
    let doc = parse_source(src, content_type)?;
    Ok(prepare_from_value(doc, opts))
}

/// Lower-level entry point when the caller has already parsed the source.
pub fn prepare_from_value(mut doc: Value, opts: &ImportOptions) -> ImportPreparation {
    let mut warnings: Vec<ImportWarning> = Vec::new();

    if let Value::Object(ref mut root) = doc {
        check_openapi_version(root, &mut warnings);
        apply_overrides(root, opts, &mut warnings);
        synthesize_operation_ids(root, &mut warnings);
    }

    dereference_refs(&mut doc, &mut warnings);

    let operations = collect_operations(&doc, opts.include_operations.as_ref());

    if let Value::Object(ref mut root) = doc
        && let Some(filter) = opts.include_operations.as_ref()
    {
        filter_paths(root, filter);
    }

    ImportPreparation {
        doc,
        warnings,
        operations,
    }
}

// ── operation enumeration + filtering ────────────────────────────────

fn collect_operations(doc: &Value, filter: Option<&HashSet<String>>) -> Vec<OperationInfo> {
    let mut out = Vec::new();
    let Some(paths) = doc.get("paths").and_then(Value::as_object) else {
        return out;
    };
    for (path_key, path_item) in paths {
        let Some(obj) = path_item.as_object() else {
            continue;
        };
        for m in HTTP_METHODS {
            let Some(op) = obj.get(*m).and_then(Value::as_object) else {
                continue;
            };
            let op_id = op
                .get("operationId")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let summary = op
                .get("summary")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| {
                    op.get("description")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                });
            let included = match filter {
                None => true,
                Some(set) => set.contains(&op_id),
            };
            // Heuristic: if the id looks like our synthesis pattern
            // (method + '_' + path-slug), flag it as synthesized.
            let synthesized_id = !op_id.is_empty()
                && op_id.starts_with(&format!("{m}_"))
                && looks_like_path_slug(&op_id[m.len() + 1..], path_key);
            out.push(OperationInfo {
                operation_id: op_id,
                method: (*m).to_string(),
                path: path_key.clone(),
                summary,
                included,
                synthesized_id,
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.method.cmp(&b.method)));
    out
}

fn looks_like_path_slug(tail: &str, path: &str) -> bool {
    let expected = path_slug(path);
    let expected_trimmed = expected.trim_start_matches('_');
    !expected_trimmed.is_empty() && tail == expected_trimmed
}

fn filter_paths(root: &mut Map<String, Value>, include: &HashSet<String>) {
    let Some(paths) = root.get_mut("paths").and_then(Value::as_object_mut) else {
        return;
    };
    // For each path, drop methods whose operationId is not in the include
    // set. Paths with no surviving operations are dropped entirely.
    let path_keys: Vec<String> = paths.keys().cloned().collect();
    for pk in path_keys {
        let Some(pv) = paths.get_mut(&pk).and_then(Value::as_object_mut) else {
            continue;
        };
        let method_keys: Vec<String> = pv.keys().cloned().collect();
        for mk in method_keys {
            if !HTTP_METHODS.contains(&mk.as_str()) {
                continue;
            }
            let op_id = pv
                .get(&mk)
                .and_then(Value::as_object)
                .and_then(|o| o.get("operationId"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if !include.contains(&op_id) {
                pv.remove(&mk);
            }
        }
        let still_has_ops = HTTP_METHODS.iter().any(|m| pv.contains_key(*m));
        if !still_has_ops {
            paths.remove(&pk);
        }
    }
}

// ── tests (must remain at end of file per clippy::items_after_test_module) ─

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub(super) fn base_doc() -> Value {
        json!({
            "openapi": "3.1.0",
            "info": {"title": "Widgets"},
            "servers": [{"url": "https://api.example.com"}],
            "paths": {
                "/widgets": {
                    "get": {"operationId": "list_widgets", "summary": "List"},
                    "post": {"summary": "Create"}
                },
                "/widgets/{id}": {
                    "get": {"operationId": "get_widget"}
                }
            }
        })
    }

    #[test]
    fn collect_operations_returns_all_with_included_flag() {
        let mut include = HashSet::new();
        include.insert("list_widgets".to_string());
        let opts = ImportOptions {
            include_operations: Some(include),
            ..Default::default()
        };
        let prep = prepare_from_value(base_doc(), &opts);
        assert_eq!(prep.operations.len(), 3);
        let list = prep
            .operations
            .iter()
            .find(|o| o.operation_id == "list_widgets")
            .unwrap();
        assert!(list.included);
        let get = prep
            .operations
            .iter()
            .find(|o| o.operation_id == "get_widget")
            .unwrap();
        assert!(!get.included);
    }

    #[test]
    fn filter_drops_unselected_methods_and_empty_paths() {
        let mut include = HashSet::new();
        include.insert("list_widgets".to_string());
        let opts = ImportOptions {
            include_operations: Some(include),
            ..Default::default()
        };
        let prep = prepare_from_value(base_doc(), &opts);
        let paths = prep.doc["paths"].as_object().unwrap();
        assert!(paths.contains_key("/widgets"));
        assert!(!paths.contains_key("/widgets/{id}"));
        let widgets = &paths["/widgets"];
        assert!(widgets.get("get").is_some());
        assert!(widgets.get("post").is_none());
    }

    #[test]
    fn filter_with_empty_set_drops_all_paths() {
        let opts = ImportOptions {
            include_operations: Some(HashSet::new()),
            ..Default::default()
        };
        let prep = prepare_from_value(base_doc(), &opts);
        assert!(
            prep.doc["paths"]
                .as_object()
                .map(|o| o.is_empty())
                .unwrap_or(true),
            "paths should be empty after filtering with empty include set"
        );
        // All operations still surface, just none marked included.
        assert!(prep.operations.iter().all(|o| !o.included));
    }

    #[test]
    fn collect_operations_sorts_by_path_then_method() {
        let doc = json!({
            "openapi": "3.1.0",
            "info": {"title": "Z", "x-overslash-key": "z"},
            "paths": {
                "/b": {"get": {"operationId": "b_get"}, "post": {"operationId": "b_post"}},
                "/a": {"get": {"operationId": "a_get"}}
            }
        });
        let prep = prepare_from_value(doc, &ImportOptions::default());
        let ordered: Vec<(String, String)> = prep
            .operations
            .iter()
            .map(|o| (o.path.clone(), o.method.clone()))
            .collect();
        assert_eq!(
            ordered,
            vec![
                ("/a".to_string(), "get".to_string()),
                ("/b".to_string(), "get".to_string()),
                ("/b".to_string(), "post".to_string()),
            ]
        );
    }
}
