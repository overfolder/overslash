//! Pagination over the MCP envelope.
//!
//! An MCP tool answers with a result envelope rather than a bare body, so every
//! path that reads a cursor, an items list or a next URL has to reach through
//! it first — and must not do so for an HTTP body that merely happens to carry
//! a `runtime` key.

use super::*;

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
