//! Pure helpers for "configurable detail disclosure" (SPEC §N).
//!
//! Approvals and audit rows can surface a curated, human-readable slice of
//! the outbound request — extracted at resolve time from a structured
//! projection of the resolved request via jq filters declared on the
//! template (`x-overslash-disclose`). A companion path list
//! (`x-overslash-redact`) strips sensitive values from the raw-payload blob
//! before it's persisted to `approvals.action_detail`.
//!
//! This module is kept jq-free so it stays usable from `overslash-cli` and
//! any WASM context. The jq orchestration lives in
//! `overslash-api::services::disclosure`; it reads the projection this
//! module builds.

use std::collections::{BTreeSet, HashMap};

use serde_json::{Map, Value};

use crate::types::ActionRequest;

/// Sentinel string written in place of redacted values.
pub const REDACTED: &str = "[REDACTED]";

/// Build the jq input: `{ method, url, params, body, resolved }`.
///
/// `body` is parsed as JSON when the request `Content-Type` is a JSON media
/// type (`application/json`, `application/…+json`); otherwise it's carried
/// through as the raw string. `None` body → `Value::Null`.
///
/// `params` is the original, post-resolution parameter map so filters can
/// reference path/query args without re-parsing the URL.
///
/// `resolved` is the display-name map produced by the template's `resolve`
/// declarations (param name → human-readable string, e.g. a Drive `fileId`
/// → the file's name). Only successfully resolved params appear, so filters
/// should fall back explicitly: `.resolved.fileId // .params.fileId`.
/// Resolution runs once, at resolve time, and rides in the request metadata —
/// so a delete action's audit-write disclosure still names the object even
/// though it no longer exists upstream.
pub fn build_jq_input(
    req: &ActionRequest,
    params: &HashMap<String, Value>,
    resolved: &HashMap<String, String>,
) -> Value {
    let body = match req.body.as_deref() {
        None => Value::Null,
        Some(raw) => {
            if is_json_content_type(&req.headers) {
                serde_json::from_str::<Value>(raw)
                    .unwrap_or_else(|_| Value::String(raw.to_string()))
            } else {
                Value::String(raw.to_string())
            }
        }
    };
    let params_json = {
        let mut m = Map::with_capacity(params.len());
        for (k, v) in params {
            m.insert(k.clone(), v.clone());
        }
        Value::Object(m)
    };
    let resolved_json = {
        let mut m = Map::with_capacity(resolved.len());
        for (k, v) in resolved {
            m.insert(k.clone(), Value::String(v.clone()));
        }
        Value::Object(m)
    };
    let mut root = Map::with_capacity(5);
    root.insert("method".into(), Value::String(req.method.clone()));
    root.insert("url".into(), Value::String(req.url.clone()));
    root.insert("params".into(), params_json);
    root.insert("body".into(), body);
    root.insert("resolved".into(), resolved_json);
    Value::Object(root)
}

fn is_json_content_type(headers: &HashMap<String, String>) -> bool {
    let v = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.to_ascii_lowercase())
        .unwrap_or_default();
    // "application/json" or "application/vnd.api+json" etc.
    v.starts_with("application/json") || (v.starts_with("application/") && v.contains("+json"))
}

/// Replace every value addressed by a dotted path in `redact_paths` with the
/// `REDACTED` sentinel. Paths that don't resolve are silently ignored — the
/// extension is declarative, not assertive.
///
/// Path grammar is the same dotted form used in extension parsing:
/// `body.api_key`, `params.userId`. Paths can only address the projection
/// keys produced by [`build_jq_input`] — currently `method`, `url`,
/// `params`, `body`, and `resolved`. Headers are intentionally not exposed: Mode C
/// OAuth auth injects plaintext access tokens into the header map at this
/// point, and surfacing them through either `disclose` or `redact` would
/// risk leaks. Array indices are not supported (templates should redact
/// whole fields, not individual array elements).
///
/// `json_string_params` names the params that declared `contentMediaType:
/// application/json`, and a path may descend *through* one: the string is
/// parsed, redacted inside, and re-serialized. Without that, a
/// `redact: [params.params_json.access_hash]` silently does nothing and the
/// secret lands on `approvals.action_detail`, `audit_log.detail` and the
/// inline `pending_approval` envelope — a lost redaction, which is the one
/// failure mode here that is worse than a noisy one.
///
/// It is **declaration-driven, never a guess**: a string that merely looks
/// like JSON is left alone. This walker mutates, and one that descended on a
/// hunch would rewrite unrelated fields. The re-serialized blob differs from
/// the wire value, which is correct — this is the display projection, and it
/// is already not byte-identical the moment anything in it is redacted.
///
/// The set covers both projection roots, because a body param and its
/// `params.*` twin share a name.
pub fn apply_redactions(
    value: &mut Value,
    redact_paths: &[String],
    json_string_params: &BTreeSet<String>,
) {
    for path in redact_paths {
        let segments: Vec<&str> = path.split('.').collect();
        redact_at(value, &segments, json_string_params);
    }
}

fn redact_at(value: &mut Value, segments: &[&str], json_string_params: &BTreeSet<String>) {
    let Some((head, rest)) = segments.split_first() else {
        return;
    };
    let Value::Object(map) = value else { return };
    if rest.is_empty() {
        if map.contains_key(*head) {
            map.insert((*head).to_string(), Value::String(REDACTED.to_string()));
        }
        return;
    }
    let Some(child) = map.get_mut(*head) else {
        return;
    };
    // Descend through a declared JSON-carrying string. Only here, only for a
    // declared param, and only when the path actually continues into it —
    // nothing is parsed to answer a question nobody asked.
    if let Value::String(text) = child
        && json_string_params.contains(*head)
        && let Ok(mut inner) = serde_json::from_str::<Value>(text)
    {
        redact_at(&mut inner, rest, json_string_params);
        if let Ok(reserialized) = serde_json::to_string(&inner) {
            *child = Value::String(reserialized);
        }
        return;
    }
    redact_at(child, rest, json_string_params);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// No param declares a JSON-carrying string — the state every template was
    /// in before `contentMediaType` existed, and still the common case.
    pub(super) fn no_json_params() -> BTreeSet<String> {
        BTreeSet::new()
    }

    fn req(method: &str, url: &str, headers: &[(&str, &str)], body: Option<&str>) -> ActionRequest {
        let mut h = HashMap::new();
        for (k, v) in headers {
            h.insert((*k).to_string(), (*v).to_string());
        }
        ActionRequest {
            method: method.to_string(),
            url: url.to_string(),
            headers: h,
            body: body.map(str::to_string),
            secrets: Vec::new(),
        }
    }

    #[test]
    fn build_jq_input_json_body_is_parsed() {
        let r = req(
            "POST",
            "https://x/y",
            &[("Content-Type", "application/json")],
            Some(r##"{"channel":"#general","text":"hi"}"##),
        );
        let v = build_jq_input(&r, &HashMap::new(), &HashMap::new());
        assert_eq!(v["body"]["channel"], "#general");
        assert_eq!(v["body"]["text"], "hi");
    }

    #[test]
    fn build_jq_input_vendor_json_content_type_is_parsed() {
        let r = req(
            "POST",
            "https://x",
            &[("Content-Type", "application/vnd.api+json")],
            Some(r#"{"a":1}"#),
        );
        let v = build_jq_input(&r, &HashMap::new(), &HashMap::new());
        assert_eq!(v["body"]["a"], 1);
    }

    #[test]
    fn build_jq_input_non_json_body_is_string() {
        let r = req(
            "POST",
            "https://x",
            &[("Content-Type", "application/x-www-form-urlencoded")],
            Some("a=1&b=2"),
        );
        let v = build_jq_input(&r, &HashMap::new(), &HashMap::new());
        assert_eq!(v["body"], "a=1&b=2");
    }

    #[test]
    fn build_jq_input_no_body_is_null() {
        let r = req("GET", "https://x", &[], None);
        let v = build_jq_input(&r, &HashMap::new(), &HashMap::new());
        assert!(v["body"].is_null());
    }

    #[test]
    fn build_jq_input_includes_params() {
        let r = req("GET", "https://x", &[], None);
        let mut p = HashMap::new();
        p.insert("userId".into(), json!("alice"));
        let v = build_jq_input(&r, &p, &HashMap::new());
        assert_eq!(v["params"]["userId"], "alice");
        assert_eq!(v["resolved"], json!({}), "no resolvers → empty object");
    }

    #[test]
    fn build_jq_input_includes_resolved_display_names() {
        let r = req("DELETE", "https://x/files/f-123", &[], None);
        let mut p = HashMap::new();
        p.insert("fileId".into(), json!("f-123"));
        let mut resolved = HashMap::new();
        resolved.insert("fileId".to_string(), "Q3 Budget.xlsx".to_string());
        let v = build_jq_input(&r, &p, &resolved);
        assert_eq!(v["resolved"]["fileId"], "Q3 Budget.xlsx");
        // The raw param is still there for `// .params.fileId` fallbacks.
        assert_eq!(v["params"]["fileId"], "f-123");
    }

    #[test]
    fn build_jq_input_case_insensitive_content_type_header() {
        let r = req(
            "POST",
            "https://x",
            &[("content-type", "APPLICATION/JSON; charset=utf-8")],
            Some(r#"{"a":1}"#),
        );
        let v = build_jq_input(&r, &HashMap::new(), &HashMap::new());
        assert_eq!(v["body"]["a"], 1);
    }

    #[test]
    fn apply_redactions_nested_body_field() {
        let mut v = json!({"body": {"api_key": "sk_123", "other": "ok"}});
        apply_redactions(&mut v, &["body.api_key".into()], &no_json_params());
        assert_eq!(v["body"]["api_key"], REDACTED);
        assert_eq!(v["body"]["other"], "ok");
    }

    #[test]
    fn apply_redactions_top_level_field() {
        let mut v = json!({"url": "https://x", "params": {"token": "abc"}});
        apply_redactions(&mut v, &["params.token".into()], &no_json_params());
        assert_eq!(v["params"]["token"], REDACTED);
    }

    #[test]
    fn apply_redactions_missing_path_is_silent_noop() {
        let mut v = json!({"body": {"a": 1}});
        apply_redactions(
            &mut v,
            &["body.nonexistent".into(), "headers.x".into()],
            &no_json_params(),
        );
        assert_eq!(v["body"]["a"], 1);
    }

    #[test]
    fn apply_redactions_multiple_paths() {
        // Shape mirrors what `build_jq_input` actually produces in
        // production: method/url/params/body/resolved (no headers — they're
        // deliberately kept out of the projection so Mode C OAuth tokens
        // don't leak).
        let mut v = json!({
            "method": "POST",
            "url": "https://x",
            "params": {"token": "pt"},
            "body": {"a": "1", "b": "2"},
            "resolved": {},
        });
        apply_redactions(
            &mut v,
            &["body.a".into(), "params.token".into()],
            &no_json_params(),
        );
        assert_eq!(v["body"]["a"], REDACTED);
        assert_eq!(v["body"]["b"], "2");
        assert_eq!(v["params"]["token"], REDACTED);
    }
}

#[cfg(test)]
mod json_string_redaction_tests {
    use super::tests::no_json_params;
    use super::*;
    use serde_json::json;

    fn declared(name: &str) -> BTreeSet<String> {
        BTreeSet::from([name.to_string()])
    }

    #[test]
    fn a_path_descends_through_a_declared_json_string() {
        // Before this, `redact: [params.params_json.access_hash]` silently did
        // nothing and the secret landed on the approval row in the clear.
        let mut v = json!({
            "params": { "params_json": r#"{"peer":"me","access_hash":"s3cret"}"# }
        });
        apply_redactions(
            &mut v,
            &["params.params_json.access_hash".into()],
            &declared("params_json"),
        );
        let inner: Value =
            serde_json::from_str(v["params"]["params_json"].as_str().unwrap()).unwrap();
        assert_eq!(inner["access_hash"], REDACTED);
        assert_eq!(inner["peer"], "me", "siblings survive");
    }

    #[test]
    fn an_undeclared_string_is_never_descended_into() {
        // This walker mutates. One that descended because a value *looked*
        // like JSON would rewrite fields no template ever named.
        let raw = r#"{"peer":"me","access_hash":"s3cret"}"#;
        let mut v = json!({ "params": { "params_json": raw } });
        apply_redactions(
            &mut v,
            &["params.params_json.access_hash".into()],
            &no_json_params(),
        );
        assert_eq!(v["params"]["params_json"], raw, "left byte-identical");
    }

    #[test]
    fn a_declared_string_that_is_not_json_is_left_alone() {
        let mut v = json!({ "params": { "params_json": "not json at all" } });
        apply_redactions(
            &mut v,
            &["params.params_json.secret".into()],
            &declared("params_json"),
        );
        assert_eq!(v["params"]["params_json"], "not json at all");
    }

    #[test]
    fn redacting_the_whole_field_still_replaces_the_string() {
        // The path stops *at* the param rather than descending, so the ordinary
        // leaf rule applies and the entire blob goes.
        let mut v = json!({ "params": { "params_json": r#"{"a":1}"# } });
        apply_redactions(
            &mut v,
            &["params.params_json".into()],
            &declared("params_json"),
        );
        assert_eq!(v["params"]["params_json"], REDACTED);
    }

    #[test]
    fn both_projection_roots_are_covered_by_one_set() {
        // A body param and its `params.*` twin share a name, which is why the
        // set is keyed by param name rather than by full path.
        let blob = r#"{"token":"t"}"#;
        let mut v = json!({ "params": { "payload": blob }, "body": { "payload": blob } });
        apply_redactions(
            &mut v,
            &["params.payload.token".into(), "body.payload.token".into()],
            &declared("payload"),
        );
        for root in ["params", "body"] {
            let inner: Value = serde_json::from_str(v[root]["payload"].as_str().unwrap()).unwrap();
            assert_eq!(inner["token"], REDACTED, "{root} root");
        }
    }
}
