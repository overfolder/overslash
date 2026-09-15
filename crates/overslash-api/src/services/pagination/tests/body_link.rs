//! `link` with the next URL in the body.
//!
//! Shortcut's search answers `{total, data, next}`, where `next` is a whole URL
//! path and query string — `/api/v3/search/stories?query=…&page_size=25&next=<token>`
//! — while the `next` *request* parameter takes only the bare token. Echoing the
//! body value back the way a cursor would sends a URL where a token belongs, so
//! the URL is parsed and the declared keys lifted out of it, exactly as for a
//! `Link` header.

use super::*;

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

/// The ceiling is on the key that reaches the marker, not on the URL it came
/// out of. An implausibly long *continuation* is refused, for the cursor arm's
/// reason: past that it is a payload wearing a cursor's name.
#[test]
fn an_implausibly_long_lifted_continuation_is_refused() {
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

/// …but a *long URL* carrying a short continuation still pages. Shortcut
/// echoes the caller's whole search expression back inside its next URL, so a
/// ceiling on the URL would stop a traversal because the query was wordy —
/// reporting a partial answer as a complete one.
#[test]
fn a_long_next_url_with_a_short_continuation_still_pages() {
    let long_query = "x".repeat(4000);
    let sent = sent(&[
        ("query", json!(long_query.clone())),
        ("page_size", json!(25)),
    ]);
    let url = format!("/api/v3/search/stories?query={long_query}&page_size=25&next=tok");
    let marker = next_page(
        &body_link_spec(),
        None,
        None,
        &sent,
        &result(200, json!({"data": [{"id": 1}], "next": url}), &[]),
    );
    assert_eq!(marker["next"]["params"], json!({"next": "tok"}));
}

/// The header arm never had a ceiling and must not have grown one: GitHub's
/// `Link` URLs carry whatever query the caller sent.
#[test]
fn a_long_link_header_url_still_pages() {
    let long_q = "x".repeat(4000);
    let link = format!("<https://api.github.com/s?q={long_q}&page=2>; rel=\"next\"");
    let marker = next_page(
        &link_spec(),
        None,
        None,
        &sent(&[("page", json!(1)), ("q", json!(long_q))]),
        &result(200, json!([]), &[("link", &link)]),
    );
    assert_eq!(marker["next"]["params"], json!({"page": 2}));
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

// --- the continuation is checked on every hop, not just the first ----------
//
// Which side of `declared_query_params`' sent/unsent split the continuation
// falls on changes with the hop: page one never sent it, page two merged it
// back in. These pin the second hop, where an earlier version of the guard
// did not run at all.

/// Shortcut's last page ends `…&next=`. On hop one that is caught as "no more
/// pages spelled awkwardly"; on hop two the key *has* been sent, and an empty
/// value that merely differs from the previous token must not read as a page.
#[test]
fn an_emptied_continuation_is_the_last_page_on_the_second_hop_too() {
    assert_eq!(
        next_page(
            &body_link_spec(),
            None,
            None,
            &sent(&[("query", json!("x")), ("next", json!("tok1"))]),
            &result(
                200,
                json!({"data": [{"id": 9}], "next": "/api/v3/search/stories?query=x&next="}),
                &[],
            ),
        ),
        json!({"has_more": false}),
    );
}

/// Same for the ceiling.
#[test]
fn an_oversized_continuation_is_refused_on_the_second_hop_too() {
    let url = format!("/api/v3/search/stories?query=x&next={}", "y".repeat(2000));
    assert_eq!(
        next_page(
            &body_link_spec(),
            None,
            None,
            &sent(&[("query", json!("x")), ("next", json!("tok1"))]),
            &result(200, json!({"data": [], "next": url}), &[]),
        ),
        json!({"has_more": false}),
    );
}

/// A refused continuation stops the traversal whole. Offering the other keys
/// the next URL happened to change — an upstream-clamped `page_size`, say —
/// would hand back a `next` that re-issues the page just fetched.
#[test]
fn a_refused_continuation_takes_the_whole_marker_with_it() {
    assert_eq!(
        next_page(
            &body_link_spec(),
            None,
            None,
            &sent(&[("page_size", json!(25)), ("next", json!("tok1"))]),
            &result(
                200,
                json!({"data": [{"id": 9}], "next": "/api/v3/search/stories?page_size=100&next="}),
                &[],
            ),
        ),
        json!({"has_more": false}),
        "page_size changed, but without a cursor the next call is this one"
    );
}

/// An upstream handing back the token it was just given is at the end or
/// looping. Either way the next call is the one just made.
#[test]
fn a_repeated_continuation_is_not_a_next_page() {
    assert_eq!(
        next_page(
            &body_link_spec(),
            None,
            None,
            &sent(&[("query", json!("x")), ("next", json!("tok1"))]),
            &result(
                200,
                json!({"data": [{"id": 9}], "next": "/api/v3/search/stories?query=x&next=tok1"}),
                &[],
            ),
        ),
        json!({"has_more": false}),
    );
}

/// The repeat above survived an earlier version of this check by accident:
/// dropping the echoed key left nothing else in the delta, so the marker was
/// empty and `next_page` refused it on that ground instead. Change a second
/// key in the same next URL — an upstream clamping `page_size` is the ordinary
/// way it happens — and the delta is no longer empty. The token is not lost
/// from the call it would compose, either: hop two has it in `sent`, and a
/// marker is a delta over those arguments. It is the *same* token, which is
/// what makes the next call the one just made.
#[test]
fn a_repeated_continuation_refuses_even_when_another_key_moved() {
    assert_eq!(
        next_page(
            &body_link_spec(),
            None,
            None,
            &sent(&[("page_size", json!(25)), ("next", json!("tok1"))]),
            &result(
                200,
                json!({"data": [{"id": 9}], "next": "/api/v3/search/stories?page_size=100&next=tok1"}),
                &[],
            ),
        ),
        json!({"has_more": false}),
        "page_size moved, but the continuation is spent, so this next re-reads the page just fetched"
    );
}

/// A next URL that simply omits the declared key. `?query=x&next=` already
/// stopped the traversal; `?query=x` says strictly less and must not say more.
/// Without the check the changed `page_size` composes a marker on its own, and
/// a marker is a delta over the arguments the caller already holds — which
/// from hop two include the spent token, so the next call is the one just made.
#[test]
fn a_next_url_omitting_the_declared_continuation_is_the_last_page() {
    assert_eq!(
        next_page(
            &body_link_spec(),
            None,
            None,
            &sent(&[("page_size", json!(25)), ("next", json!("tok1"))]),
            &result(
                200,
                json!({"data": [{"id": 9}], "next": "/api/v3/search/stories?page_size=100"}),
                &[],
            ),
        ),
        json!({"has_more": false}),
        "no continuation in the URL, so the page_size delta is not a next page"
    );
}

/// The same on hop one, where the caller never sent the key either. Nothing
/// downstream would supply it, so the marker would page one forever.
#[test]
fn a_first_hop_next_url_omitting_the_continuation_is_the_last_page() {
    assert_eq!(
        next_page(
            &body_link_spec(),
            None,
            None,
            &sent(&[("page_size", json!(25))]),
            &result(
                200,
                json!({"data": [{"id": 9}], "next": "/api/v3/search/stories?page_size=100"}),
                &[],
            ),
        ),
        json!({"has_more": false}),
    );
}

/// The bound on that check: it asks for the continuation only when the spec
/// declared one. A bare `link` names no key — GitHub advances through `page`,
/// an ordinary declared parameter — so requiring one would stop every
/// header-style traversal on page one. Pinned here because the check sits in
/// the shared helper both arms call.
#[test]
fn a_header_link_declaring_no_param_still_pages_without_one() {
    let marker = next_page(
        &link_spec(),
        None,
        None,
        &sent(&[("page", json!(1))]),
        &result(
            200,
            json!({}),
            &[("link", "<https://api.github.com/r?page=2>; rel=\"next\"")],
        ),
    );
    assert_eq!(marker["next"]["params"], json!({"page": 2}));
}

/// The ordinary case it all sits around: hop two advancing to hop three.
#[test]
fn a_fresh_continuation_pages_on_from_the_second_hop() {
    let marker = next_page(
        &body_link_spec(),
        None,
        None,
        &sent(&[("query", json!("x")), ("next", json!("tok1"))]),
        &result(
            200,
            json!({"data": [{"id": 9}], "next": "/api/v3/search/stories?query=x&next=tok2"}),
            &[],
        ),
    );
    assert_eq!(marker["next"]["params"], json!({"next": "tok2"}));
}
