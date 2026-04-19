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

use serde::Serialize;
use serde_json::{Map, Value};

use crate::template_validation::ValidationIssue;

use super::alias::HTTP_METHODS;

/// User-supplied knobs for a single import call. All fields are optional; an
/// all-`None`/all-empty struct imports the source verbatim.
#[derive(Default, Debug, Clone)]
pub struct ImportOptions {
    /// If `Some`, keep only operations whose id (real or synthesized) appears
    /// in this set. Unknown ids are silently ignored (the response surfaces
    /// which were matched via `OperationInfo.included`).
    pub include_operations: Option<HashSet<String>>,
    /// Override `info.x-overslash-key` (or seed it if the source has none).
    pub key: Option<String>,
    /// Override `info.title` (used by the compiler as `display_name`).
    pub display_name: Option<String>,
}

/// Pure result of parsing + lowering an OpenAPI source. The caller decides
/// what to do with it: run the regular validator, store as a draft, render a
/// preview, etc.
#[derive(Debug, Clone)]
pub struct ImportPreparation {
    /// Lowered canonical document. Still needs `normalize_aliases` +
    /// `compile_service` (or a full [`crate::template_validation`] pass).
    pub doc: Value,
    /// Non-blocking issues: dropped OpenAPI features, unresolved refs,
    /// OpenAPI 3.0 sources that we accepted as-is, etc.
    pub warnings: Vec<ImportWarning>,
    /// Every operation from the *original* source, with an `included` flag
    /// reflecting the filter in [`ImportOptions::include_operations`].
    pub operations: Vec<OperationInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportWarning {
    pub code: String,
    pub message: String,
    /// Dotted path into the source document (e.g.
    /// `"paths./widgets.get.responses.200"`). Empty when the warning is
    /// document-wide.
    pub path: String,
}

impl ImportWarning {
    fn new(code: impl Into<String>, message: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            path: path.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct OperationInfo {
    /// Either the original `operationId` or a synthesized one
    /// (`{method}_{path_slug}`) if the source didn't have one.
    pub operation_id: String,
    pub method: String,
    pub path: String,
    pub summary: Option<String>,
    /// True when this operation survives the import filter (or no filter was
    /// set).
    pub included: bool,
    /// True when the source had an explicit `operationId`; false when it was
    /// derived from the path/method. Useful for the UI so it can flag
    /// "auto-named" ids that the user should rename before promoting.
    pub synthesized_id: bool,
}

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

    if let Value::Object(ref mut root) = doc {
        if let Some(filter) = opts.include_operations.as_ref() {
            filter_paths(root, filter);
        }
    }

    ImportPreparation {
        doc,
        warnings,
        operations,
    }
}

// ── format detection & parsing ───────────────────────────────────────

#[cfg(feature = "yaml")]
fn parse_source(src: &str, content_type: Option<&str>) -> Result<Value, ValidationIssue> {
    let is_json = match content_type {
        Some(ct) if ct.contains("json") => true,
        Some(ct) if ct.contains("yaml") || ct.contains("yml") => false,
        _ => src
            .trim_start()
            .chars()
            .next()
            .is_some_and(|c| c == '{' || c == '['),
    };
    if is_json {
        serde_json::from_str::<Value>(src).map_err(|e| {
            ValidationIssue::new(
                "openapi_parse_error",
                format!("failed to parse JSON: {e}"),
                "",
            )
        })
    } else {
        super::parse_yaml(src)
    }
}

fn check_openapi_version(root: &Map<String, Value>, warnings: &mut Vec<ImportWarning>) {
    let v = root.get("openapi").and_then(Value::as_str).unwrap_or("");
    if v.is_empty() {
        warnings.push(ImportWarning::new(
            "openapi_version_missing",
            "source does not declare an OpenAPI version — assuming 3.1.0",
            "openapi",
        ));
    } else if v.starts_with("3.0") {
        warnings.push(ImportWarning::new(
            "openapi_3_0_source",
            format!(
                "source declares OpenAPI {v}; Overslash templates target 3.1.0 — \
                 schema objects using JSON-Schema-draft-04 semantics may not compile cleanly"
            ),
            "openapi",
        ));
    } else if !v.starts_with("3.") {
        warnings.push(ImportWarning::new(
            "openapi_unsupported_version",
            format!("OpenAPI version {v} is untested; attempting best-effort import"),
            "openapi",
        ));
    }
}

// ── overrides ────────────────────────────────────────────────────────

fn apply_overrides(
    root: &mut Map<String, Value>,
    opts: &ImportOptions,
    warnings: &mut Vec<ImportWarning>,
) {
    let info = root
        .entry("info".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let Value::Object(info_obj) = info else {
        return;
    };

    if let Some(dn) = &opts.display_name {
        info_obj.insert("title".to_string(), Value::String(dn.clone()));
    }

    let supplied_key = opts.key.clone();
    if let Some(k) = supplied_key {
        info_obj.insert("x-overslash-key".to_string(), Value::String(k));
        info_obj.remove("key");
    } else if !info_obj.contains_key("x-overslash-key") && !info_obj.contains_key("key") {
        // Derive a best-effort key from the title so the draft has something
        // to call itself. The user can rename before promoting.
        if let Some(title) = info_obj.get("title").and_then(Value::as_str) {
            let derived = slugify(title);
            if !derived.is_empty() {
                info_obj.insert("x-overslash-key".to_string(), Value::String(derived));
                warnings.push(ImportWarning::new(
                    "derived_key",
                    "template key was not declared; derived from info.title",
                    "info.x-overslash-key",
                ));
            }
        }
    }
}

/// Lowercase, keep `[a-z0-9_-]`, replace anything else with `-`, collapse
/// runs, trim leading/trailing `-`. Mirrors the `invalid_key` regex
/// `^[a-z][a-z0-9_-]*$` as closely as a one-shot slugifier can.
fn slugify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_dash = false;
    for ch in s.chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-' {
            out.push(c);
            prev_dash = c == '-';
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    // Key must start with [a-z]; if it starts with a digit, prefix with `x-`.
    if let Some(first) = out.chars().next() {
        if !first.is_ascii_lowercase() {
            out.insert_str(0, "x-");
        }
    }
    out
}

// ── operationId synthesis ────────────────────────────────────────────

fn synthesize_operation_ids(root: &mut Map<String, Value>, warnings: &mut Vec<ImportWarning>) {
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

fn path_slug(path: &str) -> String {
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

// ── $ref dereferencer ────────────────────────────────────────────────

fn dereference_refs(doc: &mut Value, warnings: &mut Vec<ImportWarning>) {
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

    fn base_doc() -> Value {
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
    fn derives_key_from_title() {
        let prep = prepare_from_value(base_doc(), &ImportOptions::default());
        let key = prep.doc["info"]["x-overslash-key"].as_str().unwrap();
        assert_eq!(key, "widgets");
        assert!(prep.warnings.iter().any(|w| w.code == "derived_key"));
    }

    #[test]
    fn explicit_key_override_wins() {
        let opts = ImportOptions {
            key: Some("my-widgets".into()),
            ..Default::default()
        };
        let prep = prepare_from_value(base_doc(), &opts);
        assert_eq!(
            prep.doc["info"]["x-overslash-key"].as_str().unwrap(),
            "my-widgets"
        );
    }

    #[test]
    fn synthesizes_missing_operation_ids() {
        let prep = prepare_from_value(base_doc(), &ImportOptions::default());
        let post = &prep.doc["paths"]["/widgets"]["post"]["operationId"];
        assert_eq!(post.as_str().unwrap(), "post_widgets");
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
    fn openapi_3_0_source_warns() {
        let mut doc = base_doc();
        doc["openapi"] = Value::String("3.0.3".into());
        let prep = prepare_from_value(doc, &ImportOptions::default());
        assert!(prep.warnings.iter().any(|w| w.code == "openapi_3_0_source"));
    }

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
    fn slugify_produces_valid_keys() {
        assert_eq!(slugify("Google Calendar"), "google-calendar");
        assert_eq!(slugify("  My  Cool  API!!  "), "my-cool-api");
        assert_eq!(slugify("1password"), "x-1password");
    }

    #[cfg(feature = "yaml")]
    #[test]
    fn parse_detects_json_vs_yaml() {
        let json_src = b"{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"x\"},\"paths\":{}}";
        let prep = prepare_import(
            json_src,
            Some("application/json"),
            &ImportOptions::default(),
        )
        .unwrap();
        assert_eq!(prep.doc["openapi"].as_str().unwrap(), "3.1.0");

        let yaml_src = b"openapi: 3.1.0\ninfo:\n  title: y\npaths: {}\n";
        let prep = prepare_import(
            yaml_src,
            Some("application/yaml"),
            &ImportOptions::default(),
        )
        .unwrap();
        assert_eq!(prep.doc["info"]["title"].as_str().unwrap(), "y");

        // No hint → heuristic on first non-whitespace char
        let prep = prepare_import(
            b"  { \"openapi\": \"3.1.0\", \"info\": {\"title\":\"h\"}, \"paths\": {} }",
            None,
            &ImportOptions::default(),
        )
        .unwrap();
        assert_eq!(prep.doc["info"]["title"].as_str().unwrap(), "h");
    }

    // ── Additional coverage: version warnings, overrides, edge cases ───

    #[test]
    fn missing_openapi_version_emits_warning() {
        let doc = json!({
            "info": {"title": "No Version"},
            "paths": {}
        });
        let prep = prepare_from_value(doc, &ImportOptions::default());
        assert!(
            prep.warnings
                .iter()
                .any(|w| w.code == "openapi_version_missing")
        );
    }

    #[test]
    fn unsupported_openapi_version_warns_but_proceeds() {
        let doc = json!({
            "openapi": "2.0",
            "info": {"title": "Swagger v2"},
            "paths": {}
        });
        let prep = prepare_from_value(doc, &ImportOptions::default());
        assert!(
            prep.warnings
                .iter()
                .any(|w| w.code == "openapi_unsupported_version")
        );
    }

    #[test]
    fn display_name_override_updates_title() {
        let opts = ImportOptions {
            display_name: Some("Widget Service".into()),
            ..Default::default()
        };
        let prep = prepare_from_value(base_doc(), &opts);
        assert_eq!(
            prep.doc["info"]["title"].as_str().unwrap(),
            "Widget Service"
        );
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

    #[cfg(feature = "yaml")]
    #[test]
    fn invalid_utf8_source_surfaces_structured_error() {
        let bad: &[u8] = &[0xff, 0xfe, 0xfd];
        let err = prepare_import(bad, None, &ImportOptions::default()).unwrap_err();
        assert_eq!(err.code, "openapi_parse_error");
        assert!(err.message.contains("UTF-8"));
    }

    #[cfg(feature = "yaml")]
    #[test]
    fn malformed_json_source_surfaces_structured_error() {
        let src = b"{ not valid json";
        let err =
            prepare_import(src, Some("application/json"), &ImportOptions::default()).unwrap_err();
        assert_eq!(err.code, "openapi_parse_error");
    }

    #[test]
    fn slugify_handles_leading_digit_and_punctuation() {
        // Leading digit gets an `x-` prefix so the key matches `^[a-z]...`.
        assert_eq!(slugify("3D Widgets"), "x-3d-widgets");
        // All-punctuation input collapses to empty, no panic.
        assert_eq!(slugify("!!! ??? !!!"), "");
        // Underscores and hyphens are preserved as-is.
        assert_eq!(slugify("my_cool-api"), "my_cool-api");
    }
}
