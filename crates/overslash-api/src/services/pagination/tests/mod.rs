//! Tests for [`super::next_page`] and the per-style continuation arms.
//!
//! A directory rather than one file, for the reason the old header gave and
//! the thousand-line gate then enforced: the module is overwhelmingly tests,
//! and they divide cleanly by what they exercise. This file holds the fixtures
//! every arm shares and the arms themselves — `cursor`, `offset`, `page`, and
//! `link` reading the RFC 8288 header. The two seams that carry fixtures of
//! their own live next door.

mod body_link;
mod mcp_envelope;

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

/// An MCP result envelope. Shared: the `link` seam next door reads a body
/// next URL through one, so the fixture cannot live in either seam alone.
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
