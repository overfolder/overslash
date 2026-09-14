//! One vocabulary for paging, over the many an upstream may pick.
//!
//! The shipped corpus spells page size six ways (`per_page`, `limit`,
//! `page_size`, `maxResults`, `pageSize`, `$top`) and continuation six more
//! (`cursor`, `start_cursor`, `pageToken`, `offset`, `$skip`, `page`, plus the
//! RFC 8288 `Link` header). None of that is Overslash's vocabulary — it is
//! whatever each upstream happened to choose — and an agent that has to learn
//! all of it before it can ask for page two mostly does not ask.
//!
//! [`PaginationSpec`] is the `x-overslash-pagination` operation extension
//! parsed. It says two things, and deliberately no more:
//!
//!   1. **Which declared parameter bounds a page**, and what the bound should
//!      be when the caller omits it ([`PageSize`]). This is the half that stops
//!      an unbounded list from blowing the response cap.
//!   2. **How to find the way to the next page** ([`NextSpec`]), so the gateway
//!      can hand the caller a ready-to-call arg map in place of the upstream's
//!      spelling.
//!
//! It does not describe the page *contents*: [`PaginationSpec::items`] exists
//! only so a style with no explicit continuation value can tell a full page
//! from a last one, and nothing reads the rows themselves.
//!
//! # Nothing here loops
//!
//! The gateway never follows a page on the caller's behalf. Every call stays
//! one call — bounded by the same timeout, the same size cap and the same
//! approval — and the continuation is *offered*, not taken. Whether page two
//! is worth fetching is a question about the agent's task, which the gateway
//! is in the worst position to answer.

use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// `x-overslash-pagination` on an operation or an MCP tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaginationSpec {
    /// The parameter that bounds one page, and the bound to inject when the
    /// caller names none. Optional because an upstream may page without
    /// letting anyone choose the size (a fixed 100-per-page endpoint still
    /// has a cursor worth surfacing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<PageSize>,
    /// How to reach page two.
    pub next: NextSpec,
    /// Dotted path to the principal collection in the response body.
    ///
    /// Used only to decide `has_more` for the arithmetic styles, where the
    /// upstream sends no cursor and no flag: a page that came back full is
    /// assumed to have a successor, an underfull one is the last. Absent, and
    /// with no [`has_more`](Self::has_more) either, those styles offer the
    /// next page unconditionally — an extra empty call at the end of a
    /// traversal, which is the cheaper error than stopping one page early.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<String>,
    /// Dotted path to an explicit boolean the upstream already sends
    /// (`has_more`, `hasNextPage`, `is_last`-inverted upstreams excepted).
    /// Outranks every inference when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub has_more: Option<String>,
}

/// The parameter that bounds one page.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PageSize {
    /// Name of a parameter the action already declares. Validation refuses a
    /// name the action does not carry: a page size the request cannot express
    /// is a page size that does nothing.
    pub param: String,
    /// The bound to use when the caller omits the parameter.
    ///
    /// This does not introduce a second injection mechanism. At compile time
    /// it seeds the parameter's own `default:` when it has none, so the value
    /// flows through `validate_input::apply_defaults` exactly like a
    /// hand-authored default — and shows up on `/v1/search` rows for the same
    /// reason. A parameter that already declares `default:` keeps it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<i64>,
    /// The largest page the upstream accepts, as documented by the upstream.
    ///
    /// Declarative: it bounds [`default`](Self::default) at validation time
    /// and tells a human reading the action what the ceiling is. The gateway
    /// does **not** clamp a caller who asks for more — upstreams reject or
    /// clamp an oversized page themselves, and silently rewriting an explicit
    /// argument is the kind of help that is indistinguishable from a bug.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
}

/// How the next page is named, and where its name is found.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NextSpec {
    pub style: NextStyle,
    /// The request parameter the continuation value goes into. Required for
    /// every style but [`NextStyle::Link`], which carries a whole URL and
    /// therefore names its own parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    /// Dotted path to the continuation value in the response body. Required
    /// for [`NextStyle::Cursor`] and meaningless for the others, whose value
    /// is computed from the request rather than read from the response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

/// The four families the whole corpus reduces to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NextStyle {
    /// An opaque value the upstream mints and the caller echoes back. Slack's
    /// `cursor`, Notion's `start_cursor`, Google's `pageToken` — one family
    /// wearing three names.
    Cursor,
    /// A row offset the caller advances by the page size. HubSpot's `offset`,
    /// Outlook's `$skip`, Metabase's `offset`.
    Offset,
    /// A page ordinal the caller increments. WhatsApp's `page`.
    Page,
    /// RFC 8288 `Link: <…>; rel="next"`. The response names the whole next
    /// URL; the gateway lifts out the query parameters the action declares and
    /// leaves the rest, so the continuation stays inside the action's own
    /// contract instead of becoming a second way to address the upstream.
    ///
    /// Impossible on an MCP tool, which has no response headers.
    Link,
}

impl NextStyle {
    pub fn as_str(self) -> &'static str {
        match self {
            NextStyle::Cursor => "cursor",
            NextStyle::Offset => "offset",
            NextStyle::Page => "page",
            NextStyle::Link => "link",
        }
    }

    /// Whether the continuation value is read out of the response (`cursor`)
    /// or computed from the request that was just sent (`offset`, `page`).
    /// [`NextStyle::Link`] is neither: it reads a header and rewrites params.
    pub fn is_arithmetic(self) -> bool {
        matches!(self, NextStyle::Offset | NextStyle::Page)
    }
}

impl FromStr for NextStyle {
    type Err = ();

    /// Parses the same lowercase spellings serde accepts. Exists so the
    /// template extractor can report an unrecognized style as a validation
    /// issue naming the four legal ones, rather than surfacing a serde error
    /// with no path — the shape [`ExecutionMode`](super::ExecutionMode) uses.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "cursor" => Ok(NextStyle::Cursor),
            "offset" => Ok(NextStyle::Offset),
            "page" => Ok(NextStyle::Page),
            "link" => Ok(NextStyle::Link),
            _ => Err(()),
        }
    }
}

/// Follow a dotted path into a JSON value. No array indexing and no wildcards:
/// every continuation key in the corpus sits at a fixed scalar position, and a
/// path grammar rich enough to need a parser is a path grammar rich enough to
/// be wrong in a template nobody notices.
pub fn dotted<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = value;
    for segment in path.split('.') {
        if segment.is_empty() {
            return None;
        }
        cur = cur.get(segment)?;
    }
    Some(cur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dotted_walks_nested_objects() {
        let v = json!({"response_metadata": {"next_cursor": "abc"}, "top": 1});
        assert_eq!(dotted(&v, "top"), Some(&json!(1)));
        assert_eq!(
            dotted(&v, "response_metadata.next_cursor"),
            Some(&json!("abc"))
        );
        assert_eq!(dotted(&v, "response_metadata.missing"), None);
        assert_eq!(dotted(&v, "missing.next_cursor"), None);
    }

    #[test]
    fn dotted_refuses_empty_segments() {
        let v = json!({"a": {"b": 1}});
        assert_eq!(dotted(&v, ""), None);
        assert_eq!(dotted(&v, "a..b"), None);
    }

    #[test]
    fn style_round_trips_through_serde_and_str() {
        for style in [
            NextStyle::Cursor,
            NextStyle::Offset,
            NextStyle::Page,
            NextStyle::Link,
        ] {
            assert_eq!(NextStyle::from_str(style.as_str()), Ok(style));
            let wire = serde_json::to_value(style).unwrap();
            assert_eq!(wire, json!(style.as_str()));
            assert_eq!(
                serde_json::from_value::<NextStyle>(wire).unwrap(),
                style,
                "serde and as_str must agree, or a persisted spec reads back wrong"
            );
        }
    }

    #[test]
    fn optional_fields_are_omitted_on_the_wire() {
        let spec = PaginationSpec {
            page_size: None,
            next: NextSpec {
                style: NextStyle::Link,
                param: None,
                from: None,
            },
            items: None,
            has_more: None,
        };
        assert_eq!(
            serde_json::to_value(&spec).unwrap(),
            json!({"next": {"style": "link"}})
        );
    }
}
