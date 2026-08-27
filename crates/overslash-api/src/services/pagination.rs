//! The next page, in the caller's vocabulary rather than the upstream's.
//!
//! `x-overslash-pagination` says how an action pages
//! ([`PaginationSpec`](overslash_core::types::PaginationSpec)). This module is
//! the half that runs: given that declaration, the arguments a call actually
//! went out with, and the response that came back, it produces the marker a
//! paged result carries out.
//!
//! ```json
//! "_pagination": {
//!   "has_more": true,
//!   "next": {
//!     "service": "gmail",
//!     "action": "list_messages",
//!     "params": { "pageToken": "CAUQ…", "maxResults": 100 }
//!   }
//! }
//! ```
//!
//! # Why an arg map and not a token
//!
//! `next.params` is spelled in the action's own parameter names, ready to merge
//! into the params that were just sent. The alternative — an opaque token the
//! gateway mints and later decodes — hides the upstream's vocabulary more
//! thoroughly, and pays for it: a decode path, a tamper surface, and a
//! reserved argument that appears in no action's declared schema, so the API
//! Explorer cannot replay it and `validate_args` would have to learn about it.
//! An arg map needs none of that, and an agent reading one can see what it is
//! about to ask for.
//!
//! It carries the paging **delta**, not the whole effective argument set. The
//! caller merges. That keeps the marker small inside an 8 KB compact budget,
//! and keeps resolved instance-config pins and filter arguments from being
//! echoed back into a model's context on every page.
//!
//! # Nothing here follows a page
//!
//! [`next_page`] reads. It never calls. A gateway that looped would multiply
//! latency, approvals and the size cap by a page count nobody chose, and would
//! have to guess when to stop — a question about the caller's task, which is
//! the one thing this side of the wire does not know.
//!
//! # Read before the render, never after
//!
//! The continuation is taken from [`ActionResult::body`] and
//! [`ActionResult::headers`] — the bytes as they arrived. Not from
//! `filtered_body`, so a jq filter that projects the rows out does not also
//! cost the caller the page; and not from the compact render, whose whole job
//! is to drop things (D74 keeps cursors *survivable* there, which is a weaker
//! promise than reading them upstream of it).

use std::collections::HashMap;

use overslash_core::types::{ActionResult, NextStyle, PaginationSpec, dotted};
use serde_json::{Map, Value, json};

/// Longest continuation value carried into the marker.
///
/// Mirrors `compact_response::MAX_CURSOR_VALUE_CHARS` deliberately: a value
/// this module would emit and that module would then have to crop is worse
/// than one never emitted, because half a cursor looks usable. Beyond this it
/// is not a page token, it is a payload wearing one's name.
const MAX_CURSOR_VALUE_CHARS: usize = 1024;

/// Everything the marker needs, carried on a stored replay payload.
///
/// A stored call is a *resolved* request — a URL, headers, a body — and the
/// action key and argument map that produced it are gone by then. That is the
/// same fact D56 hit with the timeout cascade, and this is the same answer:
/// store what replay cannot re-derive. Without it, a paged action called
/// `execution: "async"` or routed through an approval would come back with no
/// `next` at all, and the caller would have no way to tell that from a last
/// page — which is the confusion this whole feature exists to remove.
///
/// `None` on every payload written before this existed, and on every action
/// that declares no pagination. Both replay exactly as they did.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredPagination {
    pub spec: PaginationSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default)]
    pub params: HashMap<String, Value>,
}

impl StoredPagination {
    /// Stamp `_pagination` into an already-rendered result object.
    ///
    /// The stored paths render verbose JSON directly rather than going through
    /// `render_stored`, so this is their equivalent of the insert that function
    /// makes — placed beside the `streamed_originally` stamp for the same
    /// reason, since that is where a stored result is already annotated.
    pub fn stamp(&self, rendered: &mut Value, result: &ActionResult) {
        let Some(obj) = rendered.as_object_mut() else {
            return;
        };
        obj.insert(
            "_pagination".into(),
            next_page(
                &self.spec,
                self.service.as_deref(),
                self.action.as_deref(),
                &self.params,
                result,
            ),
        );
    }
}

/// What an action's pagination declaration produced for one response.
///
/// `has_more == false` with no `next` is a real answer, not an empty one: it
/// is how a caller tells "this was the last page" from "the gateway lost the
/// cursor". Emitting nothing would collapse those two, which is the confusion
/// D74 exists to prevent one layer down.
pub fn next_page(
    spec: &PaginationSpec,
    service: Option<&str>,
    action: Option<&str>,
    sent: &HashMap<String, Value>,
    result: &ActionResult,
) -> Value {
    // A failed call has no page two, and whatever sits in an error body is not
    // a cursor. Offering one here would send the caller round again for the
    // same error.
    if result.status_code >= 400 {
        return json!({ "has_more": false });
    }

    let body = serde_json::from_str::<Value>(&result.body).unwrap_or(Value::Null);
    let params = continuation_params(spec, sent, &body, result);

    let Some(params) = params else {
        return json!({ "has_more": false });
    };
    if !has_more(spec, &body, sent, &params) {
        return json!({ "has_more": false });
    }

    let mut next = Map::new();
    if let Some(service) = service {
        next.insert("service".into(), json!(service));
    }
    if let Some(action) = action {
        next.insert("action".into(), json!(action));
    }
    next.insert("params".into(), Value::Object(params));

    json!({ "has_more": true, "next": Value::Object(next) })
}

/// The arguments that differ between this call and the next one.
fn continuation_params(
    spec: &PaginationSpec,
    sent: &HashMap<String, Value>,
    body: &Value,
    result: &ActionResult,
) -> Option<Map<String, Value>> {
    let mut params = Map::new();

    match spec.next.style {
        NextStyle::Cursor => {
            let from = spec.next.from.as_ref()?;
            let param = spec.next.param.as_ref()?;
            let cursor = scalar(dotted(body, from)?)?;
            // An upstream at the end of a collection commonly sends the cursor
            // key with an empty string rather than omitting it. That is "no
            // more pages" spelled awkwardly, not a cursor.
            if cursor.is_empty() || cursor.chars().count() > MAX_CURSOR_VALUE_CHARS {
                return None;
            }
            params.insert(param.clone(), json!(cursor));
        }
        NextStyle::Offset => {
            let param = spec.next.param.as_ref()?;
            let step = page_size(spec, sent)?;
            let current = sent.get(param).and_then(number).unwrap_or(0);
            params.insert(param.clone(), json!(current + step));
        }
        NextStyle::Page => {
            let param = spec.next.param.as_ref()?;
            // Page ordinals are the one place the corpus disagrees about the
            // origin: WhatsApp counts from 0, GitHub from 1. The parameter's
            // declared `default:` is the template's statement of which, and
            // `apply_defaults` has already merged it into `sent` — which is why
            // `check_pagination` refuses a `page` style whose parameter
            // declares none, and why this can stop rather than guess.
            //
            // Stopping, deliberately, and *not* `unwrap_or(0)` the way the
            // `offset` arm above can afford to. An offset of 0 means "from the
            // start" in every API that has offsets. A page of 0 does not: guess
            // it against a 1-based upstream and the "next" page is the one just
            // fetched, so a caller following `next` re-reads page one forever.
            // A traversal that stops early is a bounded mistake; one that never
            // terminates is not.
            let current = sent.get(param).and_then(number)?;
            params.insert(param.clone(), json!(current + 1));
        }
        NextStyle::Link => {
            let url = link_next(result.headers.iter())?;
            params = declared_query_params(&url, sent);
            if params.is_empty() {
                return None;
            }
        }
    }

    // Carry the page size forward when the caller chose one, so page two is
    // the same size as page one. A size that came from the template's own
    // default is left out: `apply_defaults` will put it back, and repeating it
    // spends bytes to say what the action already says.
    //
    // Not for `link`, whose next-URL already states the whole next request —
    // re-adding a size it did not change would put a parameter in the delta
    // that is not a delta.
    if spec.next.style != NextStyle::Link
        && let Some(page_size) = spec.page_size.as_ref()
        && let Some(sent_size) = sent.get(&page_size.param)
        && !params.contains_key(&page_size.param)
    {
        params.insert(page_size.param.clone(), sent_size.clone());
    }

    Some(params)
}

/// Whether the page just returned has a successor.
///
/// An explicit flag from the upstream wins. Failing that, a cursor-styled
/// response that produced a cursor *is* the answer — an upstream that sends
/// one is saying there is more. The arithmetic styles have nothing to read, so
/// they compare the rows returned against the page asked for, and where even
/// that is unavailable they say yes: one wasted empty call at the end of a
/// traversal is the cheaper mistake than stopping a page early and reporting a
/// partial answer as complete.
fn has_more(
    spec: &PaginationSpec,
    body: &Value,
    sent: &HashMap<String, Value>,
    next_params: &Map<String, Value>,
) -> bool {
    if let Some(path) = spec.has_more.as_ref() {
        return match dotted(body, path) {
            Some(Value::Bool(b)) => *b,
            // A path that names nothing is a template statement about a body
            // shape the upstream did not send. Falling through to the
            // structural answer beats treating a mis-authored path as "done".
            _ => structural_has_more(spec, body, sent, next_params),
        };
    }
    structural_has_more(spec, body, sent, next_params)
}

fn structural_has_more(
    spec: &PaginationSpec,
    body: &Value,
    sent: &HashMap<String, Value>,
    next_params: &Map<String, Value>,
) -> bool {
    if !spec.next.style.is_arithmetic() {
        // Cursor and Link both got this far only by producing a continuation.
        return !next_params.is_empty();
    }
    let (Some(items), Some(asked)) = (spec.items.as_ref(), page_size(spec, sent)) else {
        return true;
    };
    match dotted(body, items).and_then(Value::as_array) {
        Some(rows) => rows.len() as i64 >= asked,
        // Same reasoning as a mis-authored `has_more`: a path that resolves to
        // nothing is a fact about the template, not about the collection.
        None => true,
    }
}

/// The page size this call actually used — the caller's, else the parameter's
/// declared default, which `apply_defaults` has already merged into `sent` by
/// the time anything here runs.
fn page_size(spec: &PaginationSpec, sent: &HashMap<String, Value>) -> Option<i64> {
    let page_size = spec.page_size.as_ref()?;
    sent.get(&page_size.param)
        .and_then(number)
        .or(page_size.default)
}

/// RFC 8288: pick the URL of the `rel="next"` link.
///
/// `Link` legally repeats, and D74 made `http_caller` fold repeated field lines
/// with `", "` per RFC 9110 §5.3 rather than keeping only the last — so the
/// links of a multi-line header are all here, in one string, and splitting on
/// `,` between `<…>` groups reaches every one of them.
fn link_next<'a, I>(headers: I) -> Option<String>
where
    I: Iterator<Item = (&'a String, &'a String)>,
{
    let value = headers
        .filter(|(k, _)| k.eq_ignore_ascii_case("link"))
        .map(|(_, v)| v.as_str())
        .next()?;

    for link in split_links(value) {
        // `continue`, never `?`. A segment that is not bracketed at all is one
        // segment we cannot read, and bailing here would abandon the rest of
        // the header — including a `rel="next"` sitting right after it. That is
        // the silent cursor loss this module exists to prevent, arrived at from
        // the other direction.
        let Some((url, params)) = link.split_once('>') else {
            continue;
        };
        let Some(url) = url.trim().strip_prefix('<') else {
            continue;
        };
        if params
            .split(';')
            .filter_map(|p| p.split_once('='))
            .any(|(k, v)| k.trim() == "rel" && v.trim().trim_matches('"') == "next")
        {
            return Some(url.to_string());
        }
    }
    None
}

/// Split a `Link` field value on the commas that separate links, not the ones
/// inside a URL's query string.
fn split_links(value: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (i, c) in value.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                out.push(&value[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&value[start..]);
    out
}

/// Lift out of a `rel="next"` URL only the query parameters the caller could
/// have sent in the first place.
///
/// The upstream's next-URL is a second way to address the same endpoint, and
/// adopting it wholesale would let a response introduce arguments the action
/// never declared. Intersecting it with what was actually sent keeps the
/// continuation inside the action's own contract — and keeps a parameter whose
/// value did not change out of the marker.
fn declared_query_params(url: &str, sent: &HashMap<String, Value>) -> Map<String, Value> {
    let mut out = Map::new();
    let Some((_, query)) = url.split_once('?') else {
        return out;
    };
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        let (k, v) = (percent_decode(k), percent_decode(v));
        let Some(previous) = sent.get(&k) else {
            continue;
        };
        // Numbers stay numbers: `page=2` coming back as `"2"` would be typed
        // differently from the `2` the caller sent, and `coerce_args` should
        // not have to undo a round trip this module introduced.
        let value = match previous {
            Value::Number(_) => v.parse::<i64>().map(Value::from).unwrap_or(json!(v)),
            _ => json!(v),
        };
        if &value != previous {
            out.insert(k, value);
        }
    }
    out
}

/// Query-string decoding: `+` is a space before percent-decoding runs, so a
/// literal plus (`%2B`) survives. `urlencoding::encode` is what
/// `resolve_encode` used on the way out, and this is its inverse.
fn percent_decode(s: &str) -> String {
    let spaced = s.replace('+', " ");
    urlencoding::decode(&spaced)
        .map(|c| c.into_owned())
        .unwrap_or(spaced)
}

/// A continuation value the caller can echo back. Numbers and booleans are
/// stringified because that is what an upstream that sent one in JSON expects
/// back in a query string; anything structural is not a cursor.
fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// A page size or offset as the caller may have spelled it. `coerce_args` has
/// already typed a declared integer parameter by the time this runs, but a
/// stored replay and a platform action reach here by other roads.
fn number(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use overslash_core::types::{NextSpec, PageSize};

    fn result(status: u16, body: Value, headers: &[(&str, &str)]) -> ActionResult {
        ActionResult {
            status_code: status,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.to_string(),
            duration_ms: 1,
            filtered_body: None,
        }
    }

    fn sent(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    fn cursor_spec() -> PaginationSpec {
        PaginationSpec {
            page_size: Some(PageSize {
                param: "maxResults".into(),
                default: Some(100),
                max: Some(500),
            }),
            next: NextSpec {
                style: NextStyle::Cursor,
                param: Some("pageToken".into()),
                from: Some("nextPageToken".into()),
            },
            items: Some("messages".into()),
            has_more: None,
        }
    }

    #[test]
    fn cursor_becomes_a_ready_to_call_arg_map() {
        let marker = next_page(
            &cursor_spec(),
            Some("gmail"),
            Some("list_messages"),
            &sent(&[("maxResults", json!(50)), ("q", json!("in:inbox"))]),
            &result(
                200,
                json!({"messages": [{"id": "a"}], "nextPageToken": "CAUQ"}),
                &[],
            ),
        );
        assert_eq!(
            marker,
            json!({
                "has_more": true,
                "next": {
                    "service": "gmail",
                    "action": "list_messages",
                    "params": {"pageToken": "CAUQ", "maxResults": 50}
                }
            })
        );
    }

    /// The delta, not the world: a filter argument the caller sent is its own
    /// to carry forward, and repeating it here would spend budget saying what
    /// the caller already knows.
    #[test]
    fn the_arg_map_carries_only_what_changes() {
        let marker = next_page(
            &cursor_spec(),
            Some("gmail"),
            Some("list_messages"),
            &sent(&[("q", json!("in:inbox")), ("userId", json!("me"))]),
            &result(200, json!({"nextPageToken": "CAUQ"}), &[]),
        );
        let params = marker["next"]["params"].as_object().unwrap();
        assert_eq!(params.len(), 1, "only the cursor changed: {params:?}");
        assert_eq!(params["pageToken"], json!("CAUQ"));
    }

    #[test]
    fn a_missing_or_empty_cursor_is_the_last_page() {
        for body in [json!({"messages": []}), json!({"nextPageToken": ""})] {
            assert_eq!(
                next_page(
                    &cursor_spec(),
                    Some("gmail"),
                    Some("list_messages"),
                    &sent(&[]),
                    &result(200, body.clone(), &[]),
                ),
                json!({"has_more": false}),
                "body {body} should read as the last page"
            );
        }
    }

    /// Half a page token is worse than none: it looks usable and 404s.
    #[test]
    fn an_implausibly_long_cursor_is_refused_whole() {
        let marker = next_page(
            &cursor_spec(),
            Some("gmail"),
            Some("list_messages"),
            &sent(&[]),
            &result(200, json!({"nextPageToken": "x".repeat(2000)}), &[]),
        );
        assert_eq!(marker, json!({"has_more": false}));
    }

    #[test]
    fn an_upstream_error_offers_no_next_page() {
        let marker = next_page(
            &cursor_spec(),
            Some("gmail"),
            Some("list_messages"),
            &sent(&[]),
            &result(429, json!({"nextPageToken": "CAUQ"}), &[]),
        );
        assert_eq!(marker, json!({"has_more": false}));
    }

    fn offset_spec() -> PaginationSpec {
        PaginationSpec {
            page_size: Some(PageSize {
                param: "limit".into(),
                default: Some(50),
                max: None,
            }),
            next: NextSpec {
                style: NextStyle::Offset,
                param: Some("offset".into()),
                from: None,
            },
            items: Some("data".into()),
            has_more: None,
        }
    }

    #[test]
    fn offset_advances_by_the_page_size_actually_used() {
        let rows: Vec<Value> = (0..20).map(|i| json!({"i": i})).collect();
        let marker = next_page(
            &offset_spec(),
            Some("metabase"),
            Some("search"),
            &sent(&[("limit", json!(20)), ("offset", json!(40))]),
            &result(200, json!({"data": rows}), &[]),
        );
        assert_eq!(marker["next"]["params"], json!({"offset": 60, "limit": 20}));
    }

    /// No offset sent means page one, which starts at zero — not "unknown".
    #[test]
    fn offset_starts_from_zero_and_uses_the_declared_default() {
        let rows: Vec<Value> = (0..50).map(|i| json!({"i": i})).collect();
        let marker = next_page(
            &offset_spec(),
            Some("metabase"),
            Some("search"),
            &sent(&[]),
            &result(200, json!({"data": rows}), &[]),
        );
        assert_eq!(marker["next"]["params"], json!({"offset": 50}));
    }

    #[test]
    fn an_underfull_page_is_the_last_one() {
        let marker = next_page(
            &offset_spec(),
            Some("metabase"),
            Some("search"),
            &sent(&[("limit", json!(20))]),
            &result(200, json!({"data": [{"i": 1}, {"i": 2}]}), &[]),
        );
        assert_eq!(marker, json!({"has_more": false}));
    }

    /// An explicit flag from the upstream outranks counting rows.
    #[test]
    fn an_explicit_has_more_wins_over_the_row_count() {
        let mut spec = offset_spec();
        spec.has_more = Some("has_more".into());
        let full: Vec<Value> = (0..50).map(|i| json!({"i": i})).collect();
        let marker = next_page(
            &spec,
            Some("stripe"),
            Some("list_charges"),
            &sent(&[]),
            &result(200, json!({"data": full, "has_more": false}), &[]),
        );
        assert_eq!(
            marker,
            json!({"has_more": false}),
            "a full page the upstream calls the last is the last"
        );
    }

    #[test]
    fn page_increments_what_was_sent() {
        let spec = PaginationSpec {
            page_size: Some(PageSize {
                param: "limit".into(),
                default: Some(20),
                max: None,
            }),
            next: NextSpec {
                style: NextStyle::Page,
                param: Some("page".into()),
                from: None,
            },
            items: Some("messages".into()),
            has_more: None,
        };
        let rows: Vec<Value> = (0..20).map(|i| json!({"i": i})).collect();
        let marker = next_page(
            &spec,
            Some("whatsapp"),
            Some("list_messages"),
            &sent(&[("page", json!(0)), ("limit", json!(20))]),
            &result(200, json!({"messages": rows}), &[]),
        );
        assert_eq!(marker["next"]["params"], json!({"page": 1, "limit": 20}));
    }

    /// The asymmetry with `offset` is deliberate, and this is what it buys. An
    /// offset of 0 means "from the start" everywhere; a page of 0 does not, so
    /// guessing it against a 1-based upstream would make `next` point at the
    /// page just fetched and loop a follower forever. `check_pagination`
    /// refuses a `page` style whose parameter declares no origin, so reaching
    /// here means something stripped it — and stopping early is the bounded
    /// mistake.
    #[test]
    fn page_refuses_to_guess_an_origin_it_was_not_given() {
        let spec = PaginationSpec {
            page_size: Some(PageSize {
                param: "limit".into(),
                default: Some(20),
                max: None,
            }),
            next: NextSpec {
                style: NextStyle::Page,
                param: Some("page".into()),
                from: None,
            },
            items: Some("messages".into()),
            has_more: None,
        };
        let rows: Vec<Value> = (0..20).map(|i| json!({"i": i})).collect();
        let marker = next_page(
            &spec,
            Some("whatsapp"),
            Some("list_messages"),
            // No `page` sent and none defaulted in — the case validation exists
            // to prevent.
            &sent(&[("limit", json!(20))]),
            &result(200, json!({"messages": rows}), &[]),
        );
        assert_eq!(marker, json!({"has_more": false}));
    }

    fn link_spec() -> PaginationSpec {
        PaginationSpec {
            page_size: Some(PageSize {
                param: "per_page".into(),
                default: Some(30),
                max: Some(100),
            }),
            next: NextSpec {
                style: NextStyle::Link,
                param: None,
                from: None,
            },
            items: None,
            has_more: None,
        }
    }

    #[test]
    fn link_lifts_only_the_params_the_call_already_carried() {
        let link = "<https://api.github.com/user/repos?page=2&per_page=30&secret=nope>; rel=\"next\", \
                    <https://api.github.com/user/repos?page=9>; rel=\"last\"";
        let marker = next_page(
            &link_spec(),
            Some("github"),
            Some("list_repos"),
            &sent(&[("page", json!(1)), ("per_page", json!(30))]),
            &result(200, json!([{"id": 1}]), &[("link", link)]),
        );
        assert_eq!(
            marker["next"]["params"],
            json!({"page": 2}),
            "`secret` was never ours to send, and `per_page` did not change"
        );
    }

    /// A URL whose query holds a comma must not be split at it.
    #[test]
    fn link_splits_between_links_not_inside_one() {
        let link = "<https://api.example.com/items?ids=1,2,3&page=2>; rel=\"next\"";
        let marker = next_page(
            &link_spec(),
            Some("github"),
            Some("list_repos"),
            &sent(&[("page", json!(1))]),
            &result(200, json!([]), &[("link", link)]),
        );
        assert_eq!(marker["next"]["params"], json!({"page": 2}));
    }

    #[test]
    fn a_link_header_without_a_next_relation_is_the_last_page() {
        let link = "<https://api.github.com/user/repos?page=1>; rel=\"prev\"";
        let marker = next_page(
            &link_spec(),
            Some("github"),
            Some("list_repos"),
            &sent(&[("page", json!(2))]),
            &result(200, json!([]), &[("Link", link)]),
        );
        assert_eq!(marker, json!({"has_more": false}));
    }

    /// D74 folds repeated `Link` lines with `", "`, so both relations arrive in
    /// one string and `rel="next"` must still be found after the first entry.
    #[test]
    fn link_finds_next_behind_a_folded_first_relation() {
        let link = "<https://api.github.com/user/repos?page=1>; rel=\"prev\", \
                    <https://api.github.com/user/repos?page=3>; rel=\"next\"";
        let marker = next_page(
            &link_spec(),
            Some("github"),
            Some("list_repos"),
            &sent(&[("page", json!(2))]),
            &result(200, json!([]), &[("link", link)]),
        );
        assert_eq!(marker["next"]["params"], json!({"page": 3}));
    }

    /// A segment we cannot read is one segment, not the end of the header.
    #[test]
    fn link_skips_a_malformed_segment_and_keeps_looking() {
        let link = "garbage-without-brackets, \
                    <https://api.github.com/user/repos?page=4>; rel=\"next\"";
        let marker = next_page(
            &link_spec(),
            Some("github"),
            Some("list_repos"),
            &sent(&[("page", json!(3))]),
            &result(200, json!([]), &[("link", link)]),
        );
        assert_eq!(
            marker["next"]["params"],
            json!({"page": 4}),
            "a broken first segment must not abandon the rest of the header"
        );
    }

    #[test]
    fn link_percent_decodes_and_keeps_the_callers_types() {
        let link = "<https://api.example.com/s?q=two+words&page=2>; rel=\"next\"";
        let marker = next_page(
            &link_spec(),
            Some("github"),
            Some("list_repos"),
            &sent(&[("page", json!(1)), ("q", json!("one word"))]),
            &result(200, json!([]), &[("link", link)]),
        );
        assert_eq!(
            marker["next"]["params"],
            json!({"page": 2, "q": "two words"}),
            "page stays a number, q comes back decoded"
        );
    }

    /// The header is what carries the page here, so a response with no `Link`
    /// is the end of the collection however full its body looks.
    #[test]
    fn link_with_no_header_is_the_last_page() {
        let marker = next_page(
            &link_spec(),
            Some("github"),
            Some("list_repos"),
            &sent(&[("page", json!(1))]),
            &result(200, json!([{"id": 1}]), &[]),
        );
        assert_eq!(marker, json!({"has_more": false}));
    }

    /// An arithmetic style with nothing to count by errs toward offering the
    /// page: one wasted empty call beats reporting a partial answer as whole.
    #[test]
    fn an_arithmetic_style_with_no_items_path_keeps_offering() {
        let mut spec = offset_spec();
        spec.items = None;
        let marker = next_page(
            &spec,
            Some("outlook"),
            Some("list_messages"),
            &sent(&[("limit", json!(10))]),
            &result(200, json!({"value": []}), &[]),
        );
        assert_eq!(marker["has_more"], json!(true));
    }

    /// The cursor is read from `body`, which survives a filter that projects it
    /// away — the filter shapes what the caller *sees*, not what it can reach.
    #[test]
    fn a_filter_that_drops_the_cursor_does_not_drop_the_page() {
        let mut r = result(
            200,
            json!({"messages": [{"id": "a"}], "nextPageToken": "CAUQ"}),
            &[],
        );
        r.filtered_body = Some(overslash_core::types::FilteredBody::Ok {
            lang: "jq".into(),
            values: vec![json!([{"id": "a"}])],
            original_bytes: 64,
            filtered_bytes: 16,
        });
        let marker = next_page(
            &cursor_spec(),
            Some("gmail"),
            Some("list_messages"),
            &sent(&[]),
            &r,
        );
        assert_eq!(marker["next"]["params"]["pageToken"], json!("CAUQ"));
    }

    /// The stored paths render verbose JSON directly instead of going through
    /// `render_stored`, so this is their equivalent of the insert that function
    /// makes. Without it an async or replayed call to a paged action comes back
    /// with no `next` — indistinguishable, to whoever polls, from a last page.
    #[test]
    fn a_stored_declaration_stamps_the_same_marker_onto_a_rendered_result() {
        let stored = StoredPagination {
            spec: cursor_spec(),
            service: Some("gmail".into()),
            action: Some("list_messages".into()),
            params: sent(&[("maxResults", json!(10))]),
        };
        let r = result(200, json!({"nextPageToken": "CAUQ"}), &[]);
        let mut rendered = serde_json::to_value(&r).unwrap();
        stored.stamp(&mut rendered, &r);
        assert_eq!(
            rendered["_pagination"],
            next_page(
                &cursor_spec(),
                Some("gmail"),
                Some("list_messages"),
                &sent(&[("maxResults", json!(10))]),
                &r
            ),
            "a stored replay and its inline twin must produce the identical marker"
        );
    }

    /// Old rows deserialize without the field and replay exactly as they did.
    #[test]
    fn a_stored_declaration_round_trips_through_json() {
        let stored = StoredPagination {
            spec: cursor_spec(),
            service: Some("gmail".into()),
            action: Some("list_messages".into()),
            params: sent(&[("maxResults", json!(10))]),
        };
        let wire = serde_json::to_value(&stored).unwrap();
        let back: StoredPagination = serde_json::from_value(wire).unwrap();
        assert_eq!(back.spec, stored.spec);
        assert_eq!(back.params, stored.params);
        assert!(
            serde_json::from_value::<Option<StoredPagination>>(Value::Null)
                .unwrap()
                .is_none(),
            "a payload written before this field existed must still parse"
        );
    }

    #[test]
    fn a_non_json_body_is_simply_unpaged() {
        let mut r = result(200, json!(null), &[]);
        r.body = "not json at all".into();
        assert_eq!(
            next_page(&cursor_spec(), Some("s"), Some("a"), &sent(&[]), &r),
            json!({"has_more": false})
        );
    }
}
