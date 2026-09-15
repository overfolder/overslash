//! Tests for [`super::next_page`] and the per-style continuation arms.
//!
//! Split out of `mod.rs` to keep both halves navigable — the file is
//! overwhelmingly tests, and the gate that caps a source file at a thousand
//! lines does not distinguish.

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

// ── the MCP envelope ──

fn envelope(structured: Value, content: Value) -> ActionResult {
    result(
        200,
        json!({
            "runtime": "mcp",
            "tool": "list_channels",
            "structured": structured,
            "content": content,
            "is_error": false,
        }),
        &[],
    )
}

fn slack_spec() -> PaginationSpec {
    PaginationSpec {
        page_size: Some(PageSize {
            param: "limit".into(),
            default: None,
            max: Some(1000),
        }),
        next: NextSpec {
            style: NextStyle::Cursor,
            param: Some("cursor".into()),
            from: Some("response_metadata.next_cursor".into()),
        },
        items: Some("channels".into()),
        has_more: None,
    }
}

fn slack_payload() -> Value {
    json!({
        "channels": [{"id": "C1"}],
        "response_metadata": {"next_cursor": "dGVhbTpD"},
    })
}

fn expected_slack_marker() -> Value {
    json!({
        "has_more": true,
        "next": {
            "service": "slack",
            "action": "list_channels",
            "params": {"cursor": "dGVhbTpD"},
        }
    })
}

/// The declaration names the tool's own payload, so the envelope the
/// gateway wraps it in has to be unwrapped before a path resolves.
#[test]
fn an_mcp_cursor_is_read_from_structured_content() {
    assert_eq!(
        next_page(
            &slack_spec(),
            Some("slack"),
            Some("list_channels"),
            &sent(&[]),
            &envelope(slack_payload(), json!(null)),
        ),
        expected_slack_marker()
    );
}

/// D55's fallback, for the same reason `resolver_body` has it: servers
/// disagree about emitting `structuredContent` for the same tool, and a
/// template author writing `from:` should not have to know which.
#[test]
fn an_mcp_cursor_is_read_from_a_json_text_block() {
    assert_eq!(
        next_page(
            &slack_spec(),
            Some("slack"),
            Some("list_channels"),
            &sent(&[]),
            &envelope(
                json!(null),
                json!([{"type": "text", "text": slack_payload().to_string()}]),
            ),
        ),
        expected_slack_marker()
    );
}

/// `items` addresses the payload too — an arithmetic style comparing rows
/// against the page asked for must count the tool's rows, not the two keys
/// of an envelope.
#[test]
fn an_mcp_items_path_addresses_the_tools_own_payload() {
    let spec = PaginationSpec {
        page_size: Some(PageSize {
            param: "limit".into(),
            default: None,
            max: None,
        }),
        next: NextSpec {
            style: NextStyle::Offset,
            param: Some("offset".into()),
            from: None,
        },
        items: Some("results".into()),
        has_more: None,
    };
    let underfull = envelope(json!({"results": [{"id": 1}]}), json!(null));
    assert_eq!(
        next_page(
            &spec,
            Some("hubspot"),
            Some("search_owners"),
            &sent(&[("limit", json!(25))]),
            &underfull,
        ),
        json!({"has_more": false}),
        "one row against a page of 25 is the last page"
    );
}

/// Unwrapping on the `runtime` key alone would reframe an HTTP body that
/// happens to carry one. All three envelope keys, or it is just a body.
#[test]
fn an_http_body_carrying_a_runtime_key_is_left_alone() {
    let spec = PaginationSpec {
        next: NextSpec {
            style: NextStyle::Cursor,
            param: Some("cursor".into()),
            from: Some("next".into()),
        },
        ..slack_spec()
    };
    let body = json!({
        "runtime": "mcp",
        "structured": {"next": "not-the-cursor"},
        "next": "the-cursor",
    });
    assert_eq!(
        next_page(
            &spec,
            Some("s"),
            Some("a"),
            &sent(&[]),
            &result(200, body, &[])
        ),
        json!({
            "has_more": true,
            "next": {"service": "s", "action": "a", "params": {"cursor": "the-cursor"}}
        })
    );
}

/// A tool that answers in prose has no page to hand back, and an envelope
/// whose text block is not JSON must not be mistaken for one.
#[test]
fn an_mcp_result_with_no_json_payload_is_simply_unpaged() {
    assert_eq!(
        next_page(
            &slack_spec(),
            Some("slack"),
            Some("list_channels"),
            &sent(&[]),
            &envelope(
                json!(null),
                json!([{"type": "text", "text": "no channels"}])
            ),
        ),
        json!({"has_more": false})
    );
}

// ---------------------------------------------------------------------------
// `link` with the next URL in the body.
//
// Shortcut's search answers `{total, data, next}`, where `next` is a whole URL
// path and query string — `/api/v3/search/stories?query=…&page_size=25&next=<token>`
// — while the `next` *request* parameter takes only the bare token. Echoing the
// body value back the way a cursor would sends a URL where a token belongs, so
// the URL is parsed and the declared keys lifted out of it, exactly as for a
// `Link` header.
// ---------------------------------------------------------------------------

/// `from` names the body path; `param` names the one key the URL may introduce
/// that page one never sent.
fn body_link_spec() -> PaginationSpec {
    PaginationSpec {
        page_size: Some(PageSize {
            param: "page_size".into(),
            default: Some(25),
            max: Some(250),
        }),
        next: NextSpec {
            style: NextStyle::Link,
            param: Some("next".into()),
            from: Some("next".into()),
        },
        items: Some("data".into()),
        has_more: None,
    }
}

#[test]
fn link_reads_the_next_url_out_of_the_body_when_from_names_a_path() {
    let marker = next_page(
        &body_link_spec(),
        Some("shortcut"),
        Some("search_stories"),
        &sent(&[("query", json!("state:open")), ("page_size", json!(25))]),
        &result(
            200,
            json!({
                "total": 812,
                "data": [{"id": 1}],
                "next": "/api/v3/search/stories?query=state%3Aopen&page_size=25&next=a8acc65~24",
            }),
            &[],
        ),
    );
    assert_eq!(
        marker,
        json!({
            "has_more": true,
            "next": {
                "service": "shortcut",
                "action": "search_stories",
                "params": {"next": "a8acc65~24"}
            }
        }),
        "only the continuation changed — query and page_size came back identical"
    );
}

/// The whole point of `next.param` on a `link` spec: the continuation key is
/// absent from page one's request by definition, and the ordinary
/// "must have been sent" rule would drop it and report the collection finished.
#[test]
fn link_lifts_the_declared_continuation_although_page_one_never_sent_it() {
    let mut spec = body_link_spec();
    spec.next.param = None;
    let sent = sent(&[("query", json!("state:open")), ("page_size", json!(25))]);
    let result = result(
        200,
        json!({"data": [{"id": 1}], "next": "/api/v3/search/stories?query=state%3Aopen&page_size=25&next=a8acc65~24"}),
        &[],
    );

    assert_eq!(
        next_page(&spec, None, None, &sent, &result),
        json!({"has_more": false}),
        "without `param` the unsent key is dropped and nothing is left to change"
    );
    assert_eq!(
        next_page(&body_link_spec(), None, None, &sent, &result)["next"]["params"],
        json!({"next": "a8acc65~24"}),
    );
}

/// `allow_unsent` is one key wide. A next URL that tries to introduce anything
/// else the caller did not send is still ignored.
#[test]
fn a_body_next_url_cannot_introduce_arguments_the_caller_never_chose() {
    let marker = next_page(
        &body_link_spec(),
        None,
        None,
        &sent(&[("query", json!("state:open")), ("page_size", json!(25))]),
        &result(
            200,
            json!({"data": [], "next": "/api/v3/search/stories?query=state%3Aopen&detail=full&owner_id=someone&next=tok"}),
            &[],
        ),
    );
    assert_eq!(
        marker["next"]["params"],
        json!({"next": "tok"}),
        "detail and owner_id were never sent and are not the declared continuation"
    );
}

/// Shortcut sends `next: null` on the last page. Nothing to parse is the end of
/// the collection, however full `data` looks.
#[test]
fn a_null_body_next_is_the_last_page() {
    assert_eq!(
        next_page(
            &body_link_spec(),
            None,
            None,
            &sent(&[("page_size", json!(25))]),
            &result(200, json!({"data": [{"id": 1}], "next": null}), &[]),
        ),
        json!({"has_more": false})
    );
}

/// Same ceiling a cursor gets, and for the same reason.
#[test]
fn an_implausibly_long_body_next_url_is_refused_whole() {
    let url = format!("/api/v3/search/stories?next={}", "x".repeat(2000));
    assert_eq!(
        next_page(
            &body_link_spec(),
            None,
            None,
            &sent(&[("page_size", json!(25))]),
            &result(200, json!({"data": [], "next": url}), &[]),
        ),
        json!({"has_more": false})
    );
}

/// `from` only redirects where the URL is read from. With none, `link` is the
/// header style it has always been — a body key called `next` is just data.
#[test]
fn a_link_spec_without_from_still_reads_the_header_and_ignores_the_body() {
    let spec = link_spec();
    assert_eq!(
        next_page(
            &spec,
            None,
            None,
            &sent(&[("page", json!(1))]),
            &result(200, json!({"next": "/nope?page=9"}), &[]),
        ),
        json!({"has_more": false})
    );
    let marker = next_page(
        &spec,
        None,
        None,
        &sent(&[("page", json!(1))]),
        &result(
            200,
            json!({"next": "/nope?page=9"}),
            &[("link", "<https://api.github.com/r?page=2>; rel=\"next\"")],
        ),
    );
    assert_eq!(marker["next"]["params"], json!({"page": 2}));
}

/// An MCP tool has no headers, but it does have a payload — so the body form
/// works there, addressing the tool's own JSON exactly as a `cursor` `from`
/// would.
#[test]
fn a_body_next_url_is_read_through_the_mcp_envelope() {
    let marker = next_page(
        &body_link_spec(),
        Some("some_mcp"),
        Some("search_things"),
        &sent(&[("query", json!("x"))]),
        &envelope(
            json!({"data": [{"id": 1}], "next": "/things?query=x&next=tok"}),
            json!([]),
        ),
    );
    assert_eq!(marker["next"]["params"], json!({"next": "tok"}));
}
