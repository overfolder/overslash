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
    // An MCP action's body is the gateway's envelope, not the tool's payload.
    // The declaration addresses the payload — see `mcp_payload`.
    let body = mcp_payload(&body).unwrap_or(body);
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

/// The JSON an MCP action's pagination paths address.
///
/// `mcp_caller::invoke` wraps every tool result in a stable envelope —
/// `{runtime, tool, structured, content, is_error}` — so `result.body` for an
/// MCP action is the gateway's bookkeeping, not the payload a template author
/// is looking at when they write `from: response_metadata.next_cursor`. Left
/// alone, every MCP declaration in the corpus would have to spell a
/// `structured.` prefix nobody reading Slack's or HubSpot's docs would expect,
/// and would still find nothing on a server that emits its JSON only as a text
/// block — reporting `has_more: false` on a collection that has more, which is
/// the exact "partial answer that reads as a complete one" this key exists to
/// end.
///
/// So the projection is D55's, the one `param_resolver::resolver_body` already
/// applies to `resolve:` paths: `structuredContent` when the server sends it,
/// otherwise the first text content block parsed as JSON. `pick:` and `from:`
/// then mean the same thing against the same server, which is the only answer
/// a template author can hold in their head.
///
/// All three envelope keys are required before anything is unwrapped. An
/// upstream that happens to return a `runtime` field is an HTTP body like any
/// other, and its own `structured` key — if it has one — is data, not a frame.
fn mcp_payload(body: &Value) -> Option<Value> {
    let obj = body.as_object()?;
    if obj.get("runtime").and_then(Value::as_str) != Some("mcp")
        || !obj.contains_key("tool")
        || !obj.contains_key("is_error")
    {
        return None;
    }
    if let Some(structured) = obj.get("structured")
        && !structured.is_null()
    {
        return Some(structured.clone());
    }
    let text = obj
        .get("content")?
        .as_array()?
        .iter()
        .find_map(|block| block.get("text").and_then(Value::as_str))?;
    serde_json::from_str(text).ok()
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
            // Two places a whole next URL can live, and the declaration picks
            // one: `from` reads it out of the body at that path, absent reads
            // the RFC 8288 header. Either way what comes back is a URL, and the
            // same extraction runs over it.
            let url = match spec.next.from.as_ref() {
                Some(path) => {
                    let url = scalar(dotted(body, path)?)?;
                    // An upstream at the end of a collection commonly sends the
                    // key as an empty string rather than omitting it — "no more
                    // pages" spelled awkwardly, not a URL. (The header arm needs
                    // no such check: `link_next` only returns a URL it found.)
                    if url.is_empty() {
                        return None;
                    }
                    url
                }
                None => link_next(result.headers.iter())?,
            };
            // Deliberately no length ceiling on the URL itself, in either arm.
            // `MAX_CURSOR_VALUE_CHARS` bounds a value that is *carried into the
            // marker*; a next URL is parsed and thrown away, and only the keys
            // lifted out of it survive — so the cap belongs on those, and
            // `declared_query_params` applies it there. Capping the URL would
            // have punished exactly the callers this style serves: Shortcut
            // echoes the caller's whole percent-encoded search expression back
            // inside its next URL, so a long-but-legitimate `query` would push
            // it past any ceiling and stop the traversal with `has_more: false`
            // — a partial answer that reads as a complete one, which is the
            // failure this module exists to end.
            params = declared_query_params(&url, sent, spec.next.param.as_deref());
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

/// Lift out of a next URL only the query parameters the caller could have sent
/// in the first place, plus the one continuation key `allow_unsent` names.
///
/// The upstream's next-URL is a second way to address the same endpoint, and
/// adopting it wholesale would let a response introduce arguments the action
/// never declared. Intersecting it with what was actually sent keeps the
/// continuation inside the action's own contract — and keeps a parameter whose
/// value did not change out of the marker.
///
/// `allow_unsent` is the deliberate hole in that intersection, and it is one
/// key wide: `next.param` on a `link` spec, which the template author wrote
/// down, and which `check_pagination` has already refused unless the action
/// declares it.
fn declared_query_params(
    url: &str,
    sent: &HashMap<String, Value>,
    allow_unsent: Option<&str>,
) -> Map<String, Value> {
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
            // A key the call did not send is a key the next URL would be
            // *introducing*, and an upstream does not get to add arguments the
            // caller never chose. The one exception is the continuation the
            // declaration names: it appears for the first time on page two by
            // definition, so requiring it to have been sent would be requiring
            // the cursor to predate itself.
            //
            // This is the one value here that reaches the marker without the
            // caller having chosen it, so it carries the cursor arm's ceiling:
            // past that it is not a continuation, it is a payload wearing one's
            // name. It also stays a string rather than being parsed like the
            // branch below, and for the reason that branch cannot apply — there
            // is no previously-sent value to take a type from. `coerce_args`
            // parses it back on replay if the parameter is numeric.
            if allow_unsent == Some(k.as_str())
                && !v.is_empty()
                && v.chars().count() <= MAX_CURSOR_VALUE_CHARS
            {
                out.insert(k, json!(v));
            }
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
mod tests;
