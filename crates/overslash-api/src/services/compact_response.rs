//! Compact `ActionResult` rendering for context-constrained consumers
//! (chiefly the MCP `overslash_call` / `overslash_read` tools).
//!
//! The full [`ActionResult`] shape — status, headers, raw stringified body,
//! duration — is fine for the dashboard and direct REST callers, but it
//! burns LLM context: response headers are almost never useful to the
//! agent, the body arrives as a JSON-string-of-JSON (double-escaped), and
//! a large upstream payload (Gmail message list, Drive search) blows past
//! a reasonable per-tool-result budget.
//!
//! [`compact`] returns a `serde_json::Value` that:
//!   - drops `headers` entirely
//!   - upgrades `body` from a JSON string to a parsed object when the
//!     payload deserializes, falling back to the raw string otherwise
//!   - prefers `filtered_body` over `body` when both are present (the
//!     caller asked for the filter, that's what they want to see)
//!   - shrinks the resulting JSON to roughly [`COMPACT_BUDGET_BYTES`] by
//!     truncating long strings and large arrays/objects in place, adding
//!     a `_truncated: true` / `_hint` marker at the top level
//!
//! Verbose mode (the existing shape) stays available via the `verbose`
//! flag on the HTTP API request and the matching MCP tool argument.

use overslash_core::types::{ActionResult, FilteredBody};
use serde_json::{Map, Value, json};

/// Target ceiling for the serialized compact `result` payload. Picked to
/// fit a couple of tool results into an LLM turn without blowing context;
/// callers needing more can re-issue with `verbose: true`.
pub const COMPACT_BUDGET_BYTES: usize = 8 * 1024;

/// Conservative upper bound on the bytes the truncation marker
/// (`"_truncated": true, "_hint": "…"`) adds to the serialized envelope.
/// Subtracted from the working budget so the final output, marker
/// included, still fits inside [`COMPACT_BUDGET_BYTES`].
const MARKER_RESERVE_BYTES: usize = 128;

const MAX_STRING_CHARS: usize = 200;
const MAX_ARRAY_ITEMS: usize = 10;
const MAX_OBJECT_KEYS: usize = 20;

/// Build the compact view of an [`ActionResult`]. Pure — no I/O, no
/// allocations on the hot path beyond the JSON tree itself.
pub fn compact(result: &ActionResult) -> Value {
    let mut out = Map::new();
    out.insert("status_code".into(), json!(result.status_code));
    out.insert("duration_ms".into(), json!(result.duration_ms));
    out.insert("body".into(), select_body(result));

    let mut value = Value::Object(out);
    // Reserve room for the truncation marker upfront so its bytes can't
    // push the final output back over `COMPACT_BUDGET_BYTES`.
    let working_budget = COMPACT_BUDGET_BYTES.saturating_sub(MARKER_RESERVE_BYTES);
    if shrink_to_budget(&mut value, working_budget) {
        if let Some(obj) = value.as_object_mut() {
            obj.insert("_truncated".into(), Value::Bool(true));
            obj.insert(
                "_hint".into(),
                Value::String("pass verbose=true to see the full response".into()),
            );
        }
    }
    value
}

/// Choose the body to surface and parse it. `filtered_body` wins when
/// present because the caller explicitly asked for it.
fn select_body(result: &ActionResult) -> Value {
    if let Some(filtered) = result.filtered_body.as_ref() {
        return filtered_body_to_value(filtered);
    }
    if result.body.is_empty() {
        return Value::Null;
    }
    match serde_json::from_str::<Value>(&result.body) {
        Ok(v) => v,
        Err(_) => Value::String(result.body.clone()),
    }
}

fn filtered_body_to_value(fb: &FilteredBody) -> Value {
    match fb {
        FilteredBody::Ok { values, .. } => {
            // The jq filter is a stream: collapse the single-output case
            // to that one value (overwhelmingly common), keep multi-output
            // as an array.
            match values.as_slice() {
                [single] => single.clone(),
                many => Value::Array(many.to_vec()),
            }
        }
        // Errors stay structured so the agent can branch on `kind`.
        FilteredBody::Error { kind, message, .. } => json!({
            "filter_error": {
                "kind": kind,
                "message": message,
            }
        }),
    }
}

/// Reduce `value` in place until its compact JSON serialization fits in
/// `budget` bytes. Returns `true` when at least one truncation step ran.
///
/// Strategy: snapshot the original body once, then on each pass apply
/// increasingly aggressive limits to a *fresh clone* of that snapshot
/// before swapping it back in. Cloning per pass means the sentinel
/// markers added on pass N never pollute pass N+1's element counts —
/// the dropped-count printed in `"…+N more items"` always reflects how
/// many items were dropped from the *original* tree, not from the
/// already-truncated tree.
///
/// As a final guardrail, if even the most aggressive limits leave us
/// over budget (e.g. a single multi-MB string), the body is replaced
/// with a placeholder. The function never panics or loops unboundedly.
fn shrink_to_budget(value: &mut Value, budget: usize) -> bool {
    if serialized_len(value) <= budget {
        return false;
    }

    let passes: &[(usize, usize, usize)] = &[
        (MAX_STRING_CHARS, MAX_ARRAY_ITEMS, MAX_OBJECT_KEYS),
        (100, 5, 10),
        (40, 3, 5),
    ];

    let Some(original_body) = value.as_object().and_then(|m| m.get("body")).cloned() else {
        return false;
    };

    let mut touched = false;
    for &(max_str, max_arr, max_obj) in passes {
        let mut candidate = original_body.clone();
        let shrank = truncate(&mut candidate, max_str, max_arr, max_obj);
        if let Some(obj) = value.as_object_mut() {
            obj.insert("body".into(), candidate);
        }
        touched |= shrank;
        if serialized_len(value) <= budget {
            return touched;
        }
    }

    // Last resort: drop the body and leave a sentinel so the agent sees
    // *something* and knows to retry with `verbose: true`.
    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "body".into(),
            Value::String("<response too large for compact view>".into()),
        );
    }
    true
}

fn serialized_len(value: &Value) -> usize {
    serde_json::to_string(value).map(|s| s.len()).unwrap_or(0)
}

/// Walk `value` and truncate any string/array/object that exceeds the
/// passed-in limits. Returns `true` when something actually shrank — used
/// to flag `_truncated` at the envelope level.
fn truncate(value: &mut Value, max_str: usize, max_arr: usize, max_obj: usize) -> bool {
    match value {
        Value::String(s) => truncate_string(s, max_str),
        Value::Array(items) => {
            let mut touched = false;
            for item in items.iter_mut() {
                if truncate(item, max_str, max_arr, max_obj) {
                    touched = true;
                }
            }
            if items.len() > max_arr {
                let dropped = items.len() - max_arr;
                items.truncate(max_arr);
                items.push(Value::String(format!("…+{dropped} more items")));
                touched = true;
            }
            touched
        }
        Value::Object(map) => {
            let mut touched = false;
            for (_k, v) in map.iter_mut() {
                if truncate(v, max_str, max_arr, max_obj) {
                    touched = true;
                }
            }
            if map.len() > max_obj {
                let keys: Vec<String> = map.keys().skip(max_obj).cloned().collect();
                let dropped = keys.len();
                for k in keys {
                    map.remove(&k);
                }
                map.insert("…".into(), Value::String(format!("+{dropped} more keys")));
                touched = true;
            }
            touched
        }
        _ => false,
    }
}

fn truncate_string(s: &mut String, max_chars: usize) -> bool {
    if s.chars().count() <= max_chars {
        return false;
    }
    let cut: String = s.chars().take(max_chars).collect();
    *s = format!("{cut}… [truncated]");
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn base(body: &str) -> ActionResult {
        ActionResult {
            status_code: 200,
            headers: {
                let mut h = HashMap::new();
                h.insert("content-type".into(), "application/json".into());
                h.insert("server".into(), "ESF".into());
                h
            },
            body: body.into(),
            duration_ms: 42,
            filtered_body: None,
        }
    }

    #[test]
    fn drops_headers_and_parses_json_body() {
        let r = base(r#"{"drafts":[{"id":"abc"}],"resultSizeEstimate":1}"#);
        let v = compact(&r);
        assert_eq!(v["status_code"], 200);
        assert_eq!(v["duration_ms"], 42);
        assert!(v.get("headers").is_none(), "headers must be dropped");
        assert_eq!(v["body"]["drafts"][0]["id"], "abc");
        assert_eq!(v["body"]["resultSizeEstimate"], 1);
        assert!(v.get("_truncated").is_none());
    }

    #[test]
    fn non_json_body_kept_as_string() {
        let r = base("OK");
        let v = compact(&r);
        assert_eq!(v["body"], "OK");
    }

    #[test]
    fn empty_body_is_null() {
        let r = base("");
        let v = compact(&r);
        assert_eq!(v["body"], Value::Null);
    }

    #[test]
    fn large_body_is_truncated_under_budget() {
        // 100 KB-ish array of small objects.
        let items: Vec<Value> = (0..2_000)
            .map(|i| json!({"id": format!("s:{i}"), "subject": "hello world".repeat(5)}))
            .collect();
        let body = serde_json::to_string(&Value::Array(items)).unwrap();
        assert!(
            body.len() > 50_000,
            "body should be big enough to force a crop"
        );

        let r = base(&body);
        let v = compact(&r);
        let serialized_len = serde_json::to_string(&v).unwrap().len();
        assert!(
            serialized_len <= COMPACT_BUDGET_BYTES,
            "compact result was {serialized_len} bytes, budget {COMPACT_BUDGET_BYTES}"
        );
        assert_eq!(v["_truncated"], true);
        assert!(v["_hint"].as_str().unwrap().contains("verbose=true"));
    }

    #[test]
    fn filtered_body_takes_precedence_over_raw_body() {
        let mut r = base(r#"{"raw":"original"}"#);
        r.filtered_body = Some(FilteredBody::Ok {
            lang: "jq".into(),
            values: vec![json!({"picked": "yes"})],
            original_bytes: 100,
            filtered_bytes: 20,
        });
        let v = compact(&r);
        assert_eq!(v["body"], json!({"picked": "yes"}));
    }

    #[test]
    fn filter_error_surfaces_as_structured_object() {
        let mut r = base("not json");
        r.filtered_body = Some(FilteredBody::Error {
            lang: "jq".into(),
            kind: overslash_core::types::FilterErrorKind::BodyNotJson,
            message: "upstream body wasn't json".into(),
            original_bytes: 8,
        });
        let v = compact(&r);
        let err = &v["body"]["filter_error"];
        assert_eq!(err["kind"], "body_not_json");
        assert_eq!(err["message"], "upstream body wasn't json");
    }

    #[test]
    fn long_string_body_is_truncated() {
        let big = "x".repeat(50_000);
        let r = base(&big);
        let v = compact(&r);
        let serialized_len = serde_json::to_string(&v).unwrap().len();
        assert!(
            serialized_len <= COMPACT_BUDGET_BYTES,
            "compact result was {serialized_len} bytes"
        );
        assert_eq!(v["_truncated"], true);
    }

    /// Regression — a body that's just barely over budget on pass 1 used
    /// to overflow after the `_truncated` / `_hint` marker fields were
    /// appended. Reserving marker bytes upfront keeps the final
    /// serialization inside the budget.
    #[test]
    fn marker_does_not_push_output_back_over_budget() {
        // Pick a size that lands the pass-1 truncated body just under the
        // raw budget but would overflow once the ~80-byte marker is added.
        let chunk = "a".repeat(180); // each item ~190 bytes serialized
        let items: Vec<Value> = (0..100).map(|_| Value::String(chunk.clone())).collect();
        let body = serde_json::to_string(&Value::Array(items)).unwrap();
        let r = base(&body);
        let v = compact(&r);
        let final_len = serde_json::to_string(&v).unwrap().len();
        assert!(
            final_len <= COMPACT_BUDGET_BYTES,
            "marker overflow regression: final {final_len} > budget {COMPACT_BUDGET_BYTES}"
        );
        assert_eq!(v["_truncated"], true);
    }

    /// Regression — when multiple shrink passes ran in sequence, the
    /// per-pass mutation polluted the next pass's counts: the sentinel
    /// items / `"…"` key inserted by pass N inflated pass N+1's
    /// `dropped` counter, so the printed `+N more` was wrong. Cloning
    /// the original body per pass keeps the dropped count accurate.
    #[test]
    fn dropped_count_reflects_original_size_across_passes() {
        // 1000 small items, big enough to force a shrink beyond pass 1's
        // limit of 10 items. We don't assert the exact pass that wins,
        // only that the printed "+N more items" equals (original − kept)
        // — never `kept + sentinel − new_kept`.
        let items: Vec<Value> = (0..1_000).map(|i| json!({"id": i})).collect();
        let body = serde_json::to_string(&Value::Array(items)).unwrap();
        let r = base(&body);
        let v = compact(&r);

        let arr = v["body"].as_array().expect("body should still be an array");
        // Last element is the sentinel.
        let sentinel = arr.last().and_then(Value::as_str).expect("sentinel");
        let dropped: usize = sentinel
            .trim_start_matches('…')
            .trim_start_matches('+')
            .split_whitespace()
            .next()
            .and_then(|n| n.parse().ok())
            .expect("parseable dropped count");
        let kept = arr.len() - 1; // minus sentinel
        assert_eq!(
            kept + dropped,
            1_000,
            "dropped({dropped}) + kept({kept}) must equal the original 1000"
        );
    }
}
