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

use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::types::ActionRequest;

/// Sentinel string written in place of redacted values.
pub const REDACTED: &str = "[REDACTED]";

/// Build the jq input: `{ method, url, params, body }`.
///
/// `body` is parsed as JSON when the request `Content-Type` is a JSON media
/// type (`application/json`, `application/…+json`); otherwise it's carried
/// through as the raw string. `None` body → `Value::Null`.
///
/// `params` is the original, post-resolution parameter map so filters can
/// reference path/query args without re-parsing the URL.
pub fn build_jq_input(req: &ActionRequest, params: &HashMap<String, Value>) -> Value {
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
    let mut root = Map::with_capacity(4);
    root.insert("method".into(), Value::String(req.method.clone()));
    root.insert("url".into(), Value::String(req.url.clone()));
    root.insert("params".into(), params_json);
    root.insert("body".into(), body);
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
/// `params`, and `body`. Headers are intentionally not exposed: Mode C
/// OAuth auth injects plaintext access tokens into the header map at this
/// point, and surfacing them through either `disclose` or `redact` would
/// risk leaks. Array indices are not supported (templates should redact
/// whole fields, not individual array elements).
pub fn apply_redactions(value: &mut Value, redact_paths: &[String]) {
    for path in redact_paths {
        let segments: Vec<&str> = path.split('.').collect();
        redact_at(value, &segments);
    }
}

fn redact_at(value: &mut Value, segments: &[&str]) {
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
    if let Some(child) = map.get_mut(*head) {
        redact_at(child, rest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
        let v = build_jq_input(&r, &HashMap::new());
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
        let v = build_jq_input(&r, &HashMap::new());
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
        let v = build_jq_input(&r, &HashMap::new());
        assert_eq!(v["body"], "a=1&b=2");
    }

    #[test]
    fn build_jq_input_no_body_is_null() {
        let r = req("GET", "https://x", &[], None);
        let v = build_jq_input(&r, &HashMap::new());
        assert!(v["body"].is_null());
    }

    #[test]
    fn build_jq_input_includes_params() {
        let r = req("GET", "https://x", &[], None);
        let mut p = HashMap::new();
        p.insert("userId".into(), json!("alice"));
        let v = build_jq_input(&r, &p);
        assert_eq!(v["params"]["userId"], "alice");
    }

    #[test]
    fn build_jq_input_case_insensitive_content_type_header() {
        let r = req(
            "POST",
            "https://x",
            &[("content-type", "APPLICATION/JSON; charset=utf-8")],
            Some(r#"{"a":1}"#),
        );
        let v = build_jq_input(&r, &HashMap::new());
        assert_eq!(v["body"]["a"], 1);
    }

    #[test]
    fn apply_redactions_nested_body_field() {
        let mut v = json!({"body": {"api_key": "sk_123", "other": "ok"}});
        apply_redactions(&mut v, &["body.api_key".into()]);
        assert_eq!(v["body"]["api_key"], REDACTED);
        assert_eq!(v["body"]["other"], "ok");
    }

    #[test]
    fn apply_redactions_top_level_field() {
        let mut v = json!({"url": "https://x", "params": {"token": "abc"}});
        apply_redactions(&mut v, &["params.token".into()]);
        assert_eq!(v["params"]["token"], REDACTED);
    }

    #[test]
    fn apply_redactions_missing_path_is_silent_noop() {
        let mut v = json!({"body": {"a": 1}});
        apply_redactions(&mut v, &["body.nonexistent".into(), "headers.x".into()]);
        assert_eq!(v["body"]["a"], 1);
    }

    #[test]
    fn apply_redactions_multiple_paths() {
        // Shape mirrors what `build_jq_input` actually produces in
        // production: method/url/params/body (no headers — they're
        // deliberately kept out of the projection so Mode C OAuth tokens
        // don't leak).
        let mut v = json!({
            "method": "POST",
            "url": "https://x",
            "params": {"token": "pt"},
            "body": {"a": "1", "b": "2"},
        });
        apply_redactions(&mut v, &["body.a".into(), "params.token".into()]);
        assert_eq!(v["body"]["a"], REDACTED);
        assert_eq!(v["body"]["b"], "2");
        assert_eq!(v["params"]["token"], REDACTED);
    }
}
