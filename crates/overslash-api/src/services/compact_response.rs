//! Compact `ActionResult` rendering for context-constrained consumers
//! (chiefly the MCP `overslash_call` / `overslash_read` tools).
//!
//! The full [`ActionResult`] shape — status, headers, raw stringified body,
//! duration — is fine for the dashboard and direct REST callers, but it
//! burns LLM context: most response headers are useless to the agent, the
//! body arrives as a JSON-string-of-JSON (double-escaped), and a large
//! upstream payload (Gmail message list, Drive search) blows past a
//! reasonable per-tool-result budget.
//!
//! [`compact`] returns a `serde_json::Value` that:
//!   - keeps only the [`PRESERVED_HEADERS`] subset and drops the rest
//!   - upgrades `body` from a JSON string to a parsed object when the
//!     payload deserializes, falling back to the raw string otherwise
//!   - prefers `filtered_body` over `body` when both are present (the
//!     caller asked for the filter, that's what they want to see)
//!   - shrinks the resulting JSON to roughly [`COMPACT_BUDGET_BYTES`] by
//!     truncating long strings and large arrays/objects in place, adding a
//!     `_truncated: {dropped: [...]}` / `_hint` marker at the top level
//!
//! Verbose mode (the existing shape) stays available via the `verbose`
//! flag on the HTTP API request and the matching MCP tool argument.
//!
//! # Never eat the cursor
//!
//! Everything this module drops it drops on purpose, with one class of
//! exception it must never make: the means to fetch the next page. Compact is
//! the *default* on MCP, so a render that discards a `Link: rel="next"` or a
//! `nextPageToken` does not merely shorten a response — it makes a paginated
//! endpoint unpageable, and says nothing about it. Three rules follow, and
//! each has a test:
//!
//!   1. Pagination headers survive ([`PRESERVED_HEADERS`]).
//!   2. When an object exceeds the key cap, continuation keys are kept first
//!      and the rows second ([`keep_rank`]) — never whatever sorts earliest.
//!   3. A cursor value is not string-truncated ([`MAX_CURSOR_VALUE_CHARS`]);
//!      half a page token is as useless as none.
//!
//! When a rule cannot be honoured — a header too large to carry, a cursor the
//! cap could not save — the thing that went is *named* in `_truncated.dropped`
//! rather than vanishing silently.

use overslash_core::types::{ActionResult, FilteredBody};
use serde_json::{Map, Value, json};
use std::collections::HashMap;

/// Target ceiling for the serialized compact `result` payload. Picked to
/// fit a couple of tool results into an LLM turn without blowing context;
/// callers needing more can re-issue with `verbose: true`.
pub const COMPACT_BUDGET_BYTES: usize = 8 * 1024;

/// Conservative upper bound on the bytes appended to the envelope *after*
/// the budget check has run. Subtracted from the working budget so the final
/// output still fits inside [`COMPACT_BUDGET_BYTES`].
///
/// It covers two fields, not three: the `_hint` prose, and the `_full_result`
/// descriptor ([`attach_full_result`]) — an absolute download URL plus an
/// RFC-3339 expiry. The `_truncated` marker used to be counted here too, but
/// it is now built inside [`shrink_to_budget`] and measured with the rest of
/// the candidate, which is what lets its `dropped` list grow without anyone
/// re-tuning a reserve. `marker_does_not_push_output_back_over_budget` is what
/// catches an under-estimate here.
const MARKER_RESERVE_BYTES: usize = 512;

const MAX_STRING_CHARS: usize = 200;
const MAX_ARRAY_ITEMS: usize = 10;
const MAX_OBJECT_KEYS: usize = 20;

/// Response headers that survive the compact render, lowercase. Everything
/// else is dropped exactly as before — `server`, `date` and `x-frame-options`
/// buy an agent nothing and the whole point of this shape is to be small.
///
/// `link` is the reason this list exists at all: RFC 8288 `rel="next"` is how
/// GitHub and every other Link-paginated API says where the next page is, and
/// dropping the header made those endpoints unpageable over MCP. The other two
/// are the common non-standard spellings that carry the same information.
///
/// Order is load-bearing — it is the order [`MAX_PRESERVED_HEADER_BYTES`] is
/// spent in, so the most useful header wins the space.
const PRESERVED_HEADERS: &[&str] = &["link", "x-next-page", "x-total-count"];

/// Total bytes the preserved headers may claim out of [`COMPACT_BUDGET_BYTES`].
///
/// They are inserted before the body is shrunk and therefore compete with it,
/// so this bounds how far a pathological header can starve the payload. A
/// header that does not fit is **dropped whole and named**, never cropped: a
/// URL cut mid-query-string is the same silent cursor loss this module exists
/// to prevent, except harder to notice.
const MAX_PRESERVED_HEADER_BYTES: usize = 1024;

/// Keys whose *purpose* is continuation — the vocabulary an agent needs to ask
/// for page two. Matched after [`normalize_key`], so `nextPageToken`,
/// `next_page_token` and `next-page-token` are one entry.
///
/// Deliberately narrow. `limit`, `count`, `total`, `page` and `offset` are
/// absent: they are ordinary field names in enough upstream payloads that
/// promoting them would evict real data on a false positive, and none of them
/// is what you need to fetch the next page.
const CURSOR_KEYS: &[&str] = &[
    "next",
    "nextpage",
    "nextpagetoken",
    "nextpageurl",
    "nextpagelink",
    "nexttoken",
    "nextcursor",
    "nexturl",
    "nextlink",
    "nextoffset",
    "cursor",
    "startcursor",
    "endcursor",
    "aftercursor",
    "pagetoken",
    "continuationtoken",
    "continuation",
    "scrollid",
    "paging",
    "pagination",
    "pageinfo",
    "links",
    "hasmore",
    "hasnext",
    "hasnextpage",
    "moreresults",
];

/// A "cursor" longer than this is not a cursor. The string-truncation
/// exemption exists so a real page token survives the 40-char crop of the most
/// aggressive pass; it is not a licence for an arbitrary blob to sit unbounded
/// inside the budget under a well-chosen key name.
const MAX_CURSOR_VALUE_CHARS: usize = 1024;

/// Cap on `_truncated.dropped`. The same cursor key shed from 200 row objects
/// is one fact, not two hundred — entries are deduped before this bites, and
/// this bounds what is left.
const MAX_DROPPED_ENTRIES: usize = 10;

/// Build the compact view of an [`ActionResult`]. Pure — no I/O, no
/// allocations on the hot path beyond the JSON tree itself.
pub fn compact(result: &ActionResult) -> Value {
    let mut out = Map::new();
    out.insert("status_code".into(), json!(result.status_code));
    out.insert("duration_ms".into(), json!(result.duration_ms));

    // Headers go in *before* the shrink so their bytes are measured with
    // everything else rather than guessed at.
    let (headers, header_drops) = preserved_headers(&result.headers);
    if !headers.is_empty() {
        out.insert("headers".into(), Value::Object(headers));
    }
    out.insert("body".into(), select_body(result));

    let mut value = Value::Object(out);
    // Reserve room for the post-hoc `_hint` / `_full_result` fields so their
    // bytes can't push the final output back over `COMPACT_BUDGET_BYTES`.
    let working_budget = COMPACT_BUDGET_BYTES.saturating_sub(MARKER_RESERVE_BYTES);
    if shrink_to_budget(&mut value, working_budget, &header_drops)
        && let Some(obj) = value.as_object_mut()
    {
        obj.insert("_hint".into(), Value::String(HINT_NO_STORED_RESULT.into()));
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

/// Lowercase and strip `_` / `-`, collapsing the spellings an upstream may
/// pick for the same idea (`nextPageToken`, `next_page_token`, `_links`).
fn normalize_key(key: &str) -> String {
    key.chars()
        .filter(|c| *c != '_' && *c != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_cursor_key(key: &str) -> bool {
    let normalized = normalize_key(key);
    CURSOR_KEYS.contains(&normalized.as_str())
}

/// Pick the [`PRESERVED_HEADERS`] out of an upstream response, in that
/// slice's order, until [`MAX_PRESERVED_HEADER_BYTES`] is spent.
///
/// Returns the retained map (lowercase keys) plus the names that were present
/// and could not be carried, so the caller can name them in the marker instead
/// of dropping them silently. Lookup is case-insensitive: `HeaderName::as_str`
/// is always lowercase on the HTTP runtime, but the synthesized `ActionResult`s
/// (`deliver: "url"`, platform actions, stored replays) make no such promise.
fn preserved_headers(headers: &HashMap<String, String>) -> (Map<String, Value>, Vec<String>) {
    let mut kept = Map::new();
    let mut dropped = Vec::new();
    let mut spent = 0usize;

    for name in PRESERVED_HEADERS {
        let Some(value) = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
        else {
            continue;
        };
        if spent + value.len() > MAX_PRESERVED_HEADER_BYTES {
            dropped.push(format!("response header: {name} (too large)"));
            continue;
        }
        spent += value.len();
        kept.insert((*name).to_string(), Value::String(value.clone()));
    }

    (kept, dropped)
}

/// Reduce `value` in place until its compact JSON serialization fits in
/// `budget` bytes. Returns `true` when the envelope carries a `_truncated`
/// marker on the way out — which is also the caller's signal to add `_hint`.
///
/// Strategy: snapshot the original body once, then on each pass apply
/// increasingly aggressive limits to a *fresh clone* of that snapshot
/// before swapping it back in. Cloning per pass means the sentinel
/// markers added on pass N never pollute pass N+1's element counts —
/// the dropped-count printed in `"…+N more items"` always reflects how
/// many items were dropped from the *original* tree, not from the
/// already-truncated tree. The `_truncated` marker is rebuilt per pass for
/// the same reason, and inserted before the pass is measured, so its own
/// bytes are inside the budget rather than charged to a fixed reserve.
///
/// As a final guardrail, if even the most aggressive limits leave us
/// over budget (e.g. a single multi-MB string), the body is replaced
/// with a placeholder. The function never panics or loops unboundedly.
///
/// `header_drops` are load-bearing losses decided before this ran. They are
/// enough on their own to mark the envelope: a response whose body fit but
/// whose `Link` header did not is still a response missing the way forward.
fn shrink_to_budget(value: &mut Value, budget: usize, header_drops: &[String]) -> bool {
    if serialized_len(value) <= budget {
        if header_drops.is_empty() {
            return false;
        }
        set_marker(value, header_drops.to_vec());
        return true;
    }

    let passes: &[(usize, usize, usize)] = &[
        (MAX_STRING_CHARS, MAX_ARRAY_ITEMS, MAX_OBJECT_KEYS),
        (100, 5, 10),
        (40, 3, 5),
    ];

    let Some(original_body) = value.as_object().and_then(|m| m.get("body")).cloned() else {
        if header_drops.is_empty() {
            return false;
        }
        set_marker(value, header_drops.to_vec());
        return true;
    };

    for &(max_str, max_arr, max_obj) in passes {
        let mut candidate = original_body.clone();
        let mut dropped = header_drops.to_vec();
        truncate(
            &mut candidate,
            None,
            max_str,
            max_arr,
            max_obj,
            &mut dropped,
        );
        if let Some(obj) = value.as_object_mut() {
            obj.insert("body".into(), candidate);
        }
        set_marker(value, dropped);
        if serialized_len(value) <= budget {
            return true;
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
    let mut dropped = header_drops.to_vec();
    dropped.push("body (too large for compact view)".into());
    set_marker(value, dropped);
    true
}

/// Stamp `_truncated` onto the envelope, replacing any marker a previous pass
/// left behind.
///
/// The marker is an **object**, and its presence — not its value — is what says
/// the response was cropped. It carries the one thing the old `true` could not:
/// the names of the load-bearing pieces that went, so an agent that came for a
/// cursor learns the cursor is gone instead of trusting a short answer.
fn set_marker(value: &mut Value, dropped: Vec<String>) {
    let Some(obj) = value.as_object_mut() else {
        return;
    };
    let mut seen: Vec<String> = Vec::new();
    for d in dropped {
        if !seen.contains(&d) {
            seen.push(d);
        }
        if seen.len() == MAX_DROPPED_ENTRIES {
            break;
        }
    }
    obj.insert("_truncated".into(), json!({ "dropped": seen }));
}

fn serialized_len(value: &Value) -> usize {
    serde_json::to_string(value).map(|s| s.len()).unwrap_or(0)
}

/// Clamp a key to a length worth printing in the marker, on a char boundary.
/// Upstream key names are short; a pathological one must not be able to spend
/// the marker's whole byte allowance on its own.
fn label(key: &str) -> String {
    if key.chars().count() <= 60 {
        return key.to_string();
    }
    key.chars().take(60).collect::<String>() + "…"
}

/// Rank a key for survival when its object exceeds the key cap. Lower wins.
///
/// This is the whole answer to "the cap kept the alphabetically first 20".
/// `Value::Object` is a `BTreeMap` (no `preserve_order` in the workspace), so
/// iteration order is sort order, and a `nextPageToken` lost to anything
/// spelled `a`–`m` purely on where it fell in the alphabet. Ranking by what a
/// key *is* rather than what it is called makes the cap mean something:
///
///   0. the continuation vocabulary — without it there is no next page;
///   1. a non-empty array — the rows the agent actually asked for. This is
///      also why `metadata` no longer beats `rows` to the budget;
///   2. everything else, still in `BTreeMap` order so the choice is
///      deterministic for byte-identical inputs.
fn keep_rank(key: &str, value: &Value) -> u8 {
    if is_cursor_key(key) {
        return 0;
    }
    match value {
        Value::Array(items) if !items.is_empty() => 1,
        _ => 2,
    }
}

/// Walk `value` and truncate any string/array/object that exceeds the
/// passed-in limits. Returns `true` when something actually shrank.
///
/// `key` is the name this value was reached under (`None` at the root), which
/// is what lets a cursor string escape the crop. `dropped` accumulates the
/// load-bearing losses for the marker.
fn truncate(
    value: &mut Value,
    key: Option<&str>,
    max_str: usize,
    max_arr: usize,
    max_obj: usize,
    dropped: &mut Vec<String>,
) -> bool {
    match value {
        Value::String(s) => {
            // A page token cropped at 200 chars — or 40, on the last pass — is
            // as useless as one that was never sent, and worse, it *looks*
            // usable. Exempt it, bounded so the exemption can't be abused by a
            // multi-KB blob under a cursor-shaped name.
            if let Some(k) = key
                && is_cursor_key(k)
            {
                if s.chars().count() <= MAX_CURSOR_VALUE_CHARS {
                    return false;
                }
                dropped.push(format!("cursor key: {} (value too large)", label(k)));
            }
            truncate_string(s, max_str)
        }
        Value::Array(items) => {
            let mut touched = false;
            for item in items.iter_mut() {
                if truncate(item, None, max_str, max_arr, max_obj, dropped) {
                    touched = true;
                }
            }
            if items.len() > max_arr {
                let count = items.len() - max_arr;
                items.truncate(max_arr);
                items.push(Value::String(format!("…+{count} more items")));
                touched = true;
            }
            touched
        }
        Value::Object(map) => {
            let mut touched = false;
            for (k, v) in map.iter_mut() {
                if truncate(v, Some(k), max_str, max_arr, max_obj, dropped) {
                    touched = true;
                }
            }
            if map.len() > max_obj {
                // Rank first, original order second: a total, stable order
                // over which the `max_obj` survivors are chosen. The keys are
                // only cloned on this branch — the common case never pays for
                // an ordering it does not use.
                let mut ranked: Vec<(u8, usize, String)> = map
                    .iter()
                    .enumerate()
                    .map(|(i, (k, v))| (keep_rank(k, v), i, k.clone()))
                    .collect();
                ranked.sort();
                let count = ranked.len() - max_obj;
                for (rank, _, k) in ranked.split_off(max_obj) {
                    if rank == 0 {
                        dropped.push(format!("cursor key: {}", label(&k)));
                    }
                    map.remove(&k);
                }
                map.insert("…".into(), Value::String(format!("+{count} more keys")));
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

/// The hint on a truncated result whose full body was *not* stored — result
/// storage is off, or the body is over `call_result_max_bytes`.
///
/// Leads with narrowing, not widening. This marker is the only in-band signal
/// an agent gets that a response was cropped, and pointing it solely at
/// `verbose=true` taught exactly the wrong reflex: re-issue the same
/// over-broad call and pull the whole payload into context. The cheaper
/// answers — the action's own paging parameters, or a `filter` that projects
/// the fields actually wanted — come first; `verbose` stays the fallback for
/// when the full body really is what's needed.
pub const HINT_NO_STORED_RESULT: &str = "narrow with the action's paging params or a jq \
filter, or pass verbose=true for the full body";

/// The hint when the full result *is* stored and reachable at
/// `_full_result.download_url`.
///
/// Same ordering rule as [`HINT_NO_STORED_RESULT`] — narrowing still beats
/// pulling the whole payload into context, so it stays first. What changes is
/// the fallback: the stored copy is free, whereas `verbose=true` is a field on
/// a *new* `CallRequest` and therefore pays for the upstream call a second
/// time. Naming that cost is the point; the pre-D61 wording recommended the
/// expensive option without saying it was one.
pub const HINT_STORED_RESULT: &str = "narrow with the action's paging params or a jq filter, \
or fetch the full result from _full_result.download_url — it is already stored, so that \
costs no second upstream call (verbose=true re-runs the call instead)";

/// Stamp a stored-result descriptor onto a compact envelope and upgrade the
/// hint to match.
///
/// Split from [`compact`] rather than folded into it so this module stays pure:
/// minting the descriptor needs a database write, and [`compact`] is the piece
/// worth keeping trivially unit-testable. Callers stamp only when a store
/// actually succeeded, so `_full_result` present always means re-fetchable —
/// an agent never chases a dangling URL.
pub fn attach_full_result(value: &mut Value, download_url: &str, expires_at: &str) {
    let Some(obj) = value.as_object_mut() else {
        return;
    };
    obj.insert(
        "_full_result".into(),
        json!({ "download_url": download_url, "expires_at": expires_at }),
    );
    obj.insert("_hint".into(), Value::String(HINT_STORED_RESULT.into()));
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A body big enough to force at least one shrink pass, built from an
    /// object whose keys all sort *before* `nextPageToken`.
    fn padded_object(pad_keys: usize, extra: &[(&str, Value)]) -> String {
        let mut obj = Map::new();
        for i in 0..pad_keys {
            obj.insert(format!("field_{i:02}"), json!("v".repeat(400)));
        }
        for (k, v) in extra {
            obj.insert((*k).to_string(), v.clone());
        }
        serde_json::to_string(&Value::Object(obj)).unwrap()
    }

    #[test]
    fn drops_non_pagination_headers_and_parses_json_body() {
        let r = base(r#"{"drafts":[{"id":"abc"}],"resultSizeEstimate":1}"#);
        let v = compact(&r);
        assert_eq!(v["status_code"], 200);
        assert_eq!(v["duration_ms"], 42);
        assert!(
            v.get("headers").is_none(),
            "content-type/server carry nothing an agent can act on: {v}"
        );
        assert_eq!(v["body"]["drafts"][0]["id"], "abc");
        assert_eq!(v["body"]["resultSizeEstimate"], 1);
        assert!(v.get("_truncated").is_none());
    }

    /// The headline of this module's pagination contract: an RFC 8288
    /// `rel="next"` is how a Link-paginated API says where page two is, and
    /// compact used to drop it wholesale — which made those endpoints
    /// unpageable from MCP, silently.
    #[test]
    fn link_header_survives_compact() {
        let link = "<https://api.example.com/items?page=2>; rel=\"next\"";
        let mut r = base(r#"{"items":[1,2,3]}"#);
        r.headers.insert("link".into(), link.into());

        let v = compact(&r);
        assert_eq!(v["headers"]["link"], link);
        assert!(
            v["headers"].get("content-type").is_none(),
            "only the pagination subset survives: {}",
            v["headers"]
        );
        assert!(v.get("_truncated").is_none(), "nothing was cropped: {v}");
    }

    /// `HeaderName::as_str` is lowercase on the HTTP runtime, but the
    /// synthesized `ActionResult`s make no such promise.
    #[test]
    fn header_lookup_is_case_insensitive() {
        let mut r = base("{}");
        r.headers
            .insert("Link".into(), "<https://x.test/2>; rel=\"next\"".into());
        let v = compact(&r);
        assert_eq!(v["headers"]["link"], "<https://x.test/2>; rel=\"next\"");
    }

    /// An oversized header is dropped whole and named, never cropped — half a
    /// URL is worse than none, because it looks usable. And the marker appears
    /// even though the *body* fit: something load-bearing still went.
    #[test]
    fn oversized_preserved_header_is_dropped_and_named() {
        let mut r = base(r#"{"ok":true}"#);
        r.headers
            .insert("link".into(), "x".repeat(MAX_PRESERVED_HEADER_BYTES + 1));

        let v = compact(&r);
        assert!(v.get("headers").is_none(), "{v}");
        assert_eq!(v["body"]["ok"], true, "the body itself was fine: {v}");
        let dropped = v["_truncated"]["dropped"].as_array().expect("dropped list");
        assert!(
            dropped
                .iter()
                .any(|d| d.as_str().unwrap().contains("response header: link")),
            "the marker must name it: {v}"
        );
        assert!(v["_hint"].is_string(), "{v}");
    }

    /// Bug 2. `Value::Object` is a `BTreeMap`, so the key cap used to keep the
    /// alphabetically first 20 — and `nextPageToken` lost to anything spelled
    /// `a`–`m`. Thirty `field_NN` keys all sort before it; the cursor must
    /// still be there.
    #[test]
    fn cursor_key_survives_the_object_cap() {
        let body = padded_object(30, &[("nextPageToken", json!("CURSOR-abc-123"))]);
        let v = compact(&base(&body));

        assert_eq!(
            v["body"]["nextPageToken"], "CURSOR-abc-123",
            "the cap dropped the cursor: {}",
            v["body"]
        );
        assert!(
            v["body"].get("…").is_some(),
            "the cap should have fired at all: {}",
            v["body"]
        );
        assert_eq!(
            v["_truncated"]["dropped"],
            json!([]),
            "nothing load-bearing was lost, so nothing should be named: {v}"
        );
    }

    /// The other half of bug 2, and the mechanism behind "the truncator spends
    /// its budget on metadata before it reaches the rows": `meta_*` sorts
    /// before `rows`, so alphabetical order fed the descriptors and starved
    /// the data. Ranking by shape puts the collection ahead of the scalars.
    #[test]
    fn arrays_outrank_scalar_metadata_in_the_key_cap() {
        let rows: Vec<Value> = (0..5).map(|i| json!({"id": i})).collect();
        let body = padded_object(25, &[("rows", json!(rows))]);
        let v = compact(&base(&body));

        let kept = v["body"]["rows"].as_array().expect("rows must survive");
        assert_eq!(kept.len(), 5, "{}", v["body"]);
    }

    /// A page token cropped at 200 chars — or 40, on the most aggressive pass
    /// — is as useless as one that was never sent, and worse, it looks usable.
    #[test]
    fn cursor_value_survives_the_most_aggressive_pass() {
        let token = "T".repeat(300);
        let mut v = json!({ "nextPageToken": token, "note": "n".repeat(300) });
        let mut dropped = Vec::new();
        truncate(&mut v, None, 40, 3, 5, &mut dropped);

        assert_eq!(v["nextPageToken"], token, "the cursor was cropped");
        assert!(
            v["note"].as_str().unwrap().ends_with("… [truncated]"),
            "an ordinary string still crops: {}",
            v["note"]
        );
        assert!(dropped.is_empty(), "{dropped:?}");
    }

    /// The exemption is bounded — it is not a licence for an arbitrary blob to
    /// sit unbounded inside the budget under a cursor-shaped name.
    #[test]
    fn cursor_value_over_the_ceiling_is_truncated_and_named() {
        let mut v = json!({ "nextPageToken": "T".repeat(MAX_CURSOR_VALUE_CHARS + 1) });
        let mut dropped = Vec::new();
        truncate(&mut v, None, 40, 3, 5, &mut dropped);

        assert!(
            v["nextPageToken"]
                .as_str()
                .unwrap()
                .ends_with("… [truncated]"),
            "{}",
            v["nextPageToken"]
        );
        assert_eq!(
            dropped,
            vec!["cursor key: nextPageToken (value too large)".to_string()]
        );
    }

    /// Priority is a preference, not a guarantee: an object carrying more
    /// cursor keys than the cap allows still loses some. What must not happen
    /// is losing them silently.
    #[test]
    fn marker_names_a_cursor_the_cap_could_not_save() {
        let mut obj = Map::new();
        for k in [
            "cursor",
            "nextCursor",
            "nextLink",
            "nextPage",
            "nextToken",
            "nextUrl",
            "pageToken",
            "pagination",
        ] {
            obj.insert(k.into(), json!("v"));
        }
        let mut v = Value::Object(obj);
        let mut dropped = Vec::new();
        truncate(&mut v, None, 200, 10, 5, &mut dropped);

        assert_eq!(dropped.len(), 3, "8 cursor keys, cap 5: {dropped:?}");
        assert!(
            dropped.iter().all(|d| d.starts_with("cursor key: ")),
            "{dropped:?}"
        );
    }

    /// The same cursor shed from two hundred row objects is one fact, not two
    /// hundred, and the list is bounded either way.
    #[test]
    fn dropped_list_is_deduped_and_bounded() {
        let mut v = json!({ "body": Value::Null });

        set_marker(&mut v, vec!["cursor key: nextPageToken".into(); 50]);
        assert_eq!(
            v["_truncated"]["dropped"],
            json!(["cursor key: nextPageToken"])
        );

        let many: Vec<String> = (0..MAX_DROPPED_ENTRIES + 5)
            .map(|i| format!("cursor key: k{i}"))
            .collect();
        set_marker(&mut v, many);
        assert_eq!(
            v["_truncated"]["dropped"].as_array().unwrap().len(),
            MAX_DROPPED_ENTRIES
        );
    }

    /// The marker is an object whose *presence* means "cropped". `_truncated:
    /// true` could only say that something went; this says what.
    #[test]
    fn truncated_marker_is_an_object_carrying_a_dropped_list() {
        let big = "x".repeat(50_000);
        let v = compact(&base(&big));
        assert!(v["_truncated"].is_object(), "{}", v["_truncated"]);
        assert!(v["_truncated"]["dropped"].is_array(), "{}", v["_truncated"]);
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
        assert!(v["_truncated"].is_object());
        assert!(v["_hint"].as_str().unwrap().contains("verbose=true"));
    }

    /// Preserved headers are inserted before the shrink measures, so they
    /// compete with the body for the budget instead of overflowing it.
    #[test]
    fn preserved_header_bytes_are_inside_the_budget() {
        let items: Vec<Value> = (0..2_000)
            .map(|i| json!({"id": format!("s:{i}"), "subject": "hello world".repeat(5)}))
            .collect();
        let mut r = base(&serde_json::to_string(&Value::Array(items)).unwrap());
        r.headers.insert(
            "link".into(),
            format!("<https://x.test/2?c={}>", "p".repeat(900)),
        );

        let v = compact(&r);
        assert!(v["headers"]["link"].is_string(), "{v}");
        let len = serde_json::to_string(&v).unwrap().len();
        assert!(
            len <= COMPACT_BUDGET_BYTES,
            "header pushed the envelope over budget: {len} > {COMPACT_BUDGET_BYTES}"
        );
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
        assert!(v["_truncated"].is_object());
    }

    /// The unstored hint leads with narrowing rather than widening: pointing a
    /// cropped response solely at `verbose=true` teaches the reflex of
    /// re-issuing the same over-broad call and pulling the whole payload into
    /// context.
    #[test]
    fn unstored_hint_leads_with_narrowing() {
        let big = "x".repeat(50_000);
        let r = base(&big);
        let v = compact(&r);
        let hint = v["_hint"].as_str().expect("hint");
        assert!(
            hint.starts_with("narrow with"),
            "narrowing must come first: {hint}"
        );
        let narrow = hint.find("narrow").expect("names narrowing");
        let verbose = hint.find("verbose").expect("names verbose as fallback");
        assert!(narrow < verbose, "verbose must stay the fallback: {hint}");
    }

    /// `attach_full_result` upgrades both the descriptor and the hint, and the
    /// result stays inside the budget — the marker reserve exists to cover
    /// these bytes, which are stamped *after* the shrink has measured.
    #[test]
    fn attaching_full_result_upgrades_hint_and_stays_in_budget() {
        let items: Vec<Value> = (0..2_000)
            .map(|i| json!({"id": format!("s:{i}"), "subject": "hello world".repeat(5)}))
            .collect();
        let body = serde_json::to_string(&Value::Array(items)).unwrap();
        let r = base(&body);
        let mut v = compact(&r);
        assert!(v["_truncated"].is_object());

        attach_full_result(
            &mut v,
            "https://api.overslash.com/v1/downloads/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "2026-08-11T12:34:56Z",
        );

        assert!(v["_full_result"]["download_url"].as_str().is_some());
        assert_eq!(v["_full_result"]["expires_at"], "2026-08-11T12:34:56Z");
        let hint = v["_hint"].as_str().expect("hint");
        assert!(
            hint.contains("_full_result.download_url"),
            "hint must point at the stored bytes: {hint}"
        );
        // The stored copy is free and `verbose=true` is not. Saying so is the
        // whole reason this wording differs from the unstored one.
        assert!(
            hint.contains("no second upstream call"),
            "hint must say the stored copy is free: {hint}"
        );
        assert!(
            hint.contains("re-runs the call"),
            "hint must name what verbose costs: {hint}"
        );
        // Narrowing still leads, same rule as the unstored hint.
        assert!(hint.starts_with("narrow with"), "{hint}");

        let len = serde_json::to_string(&v).unwrap().len();
        assert!(
            len <= COMPACT_BUDGET_BYTES,
            "descriptor pushed the envelope over budget: {len} > {COMPACT_BUDGET_BYTES}"
        );
    }

    /// Regression — a body that's just barely over budget on pass 1 used
    /// to overflow after the `_truncated` / `_hint` marker fields were
    /// appended. `_truncated` is now built inside the shrink and measured with
    /// the candidate; the reserve covers what is still stamped afterwards.
    #[test]
    fn marker_does_not_push_output_back_over_budget() {
        // Pick a size that lands the pass-1 truncated body just under the
        // raw budget but would overflow once the marker is added.
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
        assert!(v["_truncated"].is_object());
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
        let count: usize = sentinel
            .trim_start_matches('…')
            .trim_start_matches('+')
            .split_whitespace()
            .next()
            .and_then(|n| n.parse().ok())
            .expect("parseable dropped count");
        let kept = arr.len() - 1; // minus sentinel
        assert_eq!(
            kept + count,
            1_000,
            "dropped({count}) + kept({kept}) must equal the original 1000"
        );
    }
}
