//! The descent: where in a document each object stands.
//!
//! One recursion carrying a [`Node`] down subsumes a separate "stray key" sweep.
//! Anything the position map does not name degrades to [`Pos::Other`], and
//! nothing is read at `Pos::Other`, so a stray extension is reported by the same
//! rule that reports a misplaced one.

use serde_json::Value;

use crate::template_validation::ValidationIssue;

use super::super::alias::HTTP_METHODS;
use super::super::ext::{Ext, PREFIX, Pos, SchemeKind};
use super::rules::check_keys;
use super::{STOP, join};

/// Where the recursion currently stands. Most nodes are an object at a real
/// [`Pos`]; the rest are the containers and structural hops between them.
///
/// A single recursion carrying this down subsumes a separate "stray key" sweep:
/// anything the map below does not name degrades to [`Pos::Other`], and nothing
/// is read at `Pos::Other`, so a stray extension is reported by the same rule
/// that reports a misplaced one.
#[derive(Debug, Clone, Copy)]
pub(super) enum Node {
    /// An object interpreted at this position.
    At(Pos),
    /// A map whose *values* are objects at this position (`paths`,
    /// `x-overslash-platform_actions`, a `properties` block). Its own keys are
    /// author-chosen names, so they are checked at [`Pos::Other`].
    MapOf(Pos),
    /// `components.securitySchemes` — like [`Node::MapOf`], but each value's
    /// position depends on its own `type`.
    SecuritySchemes,
    /// A structural hop with no position of its own, named by the key that must
    /// appear inside it to continue.
    Hop(&'static str, &'static Node),
    /// A map keyed by something we do not enumerate — a media type — whose every
    /// value continues at the same node.
    AnyOf(&'static Node),
}

// The requestBody chain, spelled out so `child` can return a `&'static Node`.
// `params::collect_body_parameters` reads extensions from the *top-level*
// properties of the JSON body schema and nowhere deeper, which is exactly the
// depth this chain reaches.
const BODY_PROPERTIES: Node = Node::MapOf(Pos::BodyProperty);
const BODY_SCHEMA: Node = Node::Hop("properties", &BODY_PROPERTIES);
const BODY_MEDIA_TYPE: Node = Node::Hop("schema", &BODY_SCHEMA);
const BODY_CONTENT: Node = Node::AnyOf(&BODY_MEDIA_TYPE);
const REQUEST_BODY: Node = Node::Hop("content", &BODY_CONTENT);

const TOOL_PROPERTIES: Node = Node::MapOf(Pos::McpToolProperty);
const INPUT_SCHEMA: Node = Node::Hop("properties", &TOOL_PROPERTIES);

pub(super) fn walk(v: &Value, node: Node, path: &str, out: &mut Vec<ValidationIssue>) {
    // An array carries its node through: a `parameters[]` entry and a `tools[]`
    // entry are each objects at the position named for the array.
    if let Value::Array(items) = v {
        for (i, item) in items.iter().enumerate() {
            walk(item, node, &format!("{path}[{i}]"), out);
        }
        return;
    }
    let Value::Object(obj) = v else { return };

    match node {
        Node::At(pos) => {
            check_keys(obj, pos, path, out);
            for (k, child) in obj {
                if let Some(next) = child_node(pos, k) {
                    walk(child, next, &join(path, k), out);
                }
            }
        }
        Node::MapOf(pos) => {
            // The map's own keys are names the author chose (a path, a property,
            // an action key), so only the prefixed rules can apply to them.
            check_keys(obj, Pos::Other, path, out);
            for (k, child) in obj {
                // `STOP` is deliberately *not* consulted here. It exists to stop
                // the walk descending into author-supplied data, and every entry
                // in it is a schema keyword — which is what these keys are not. A
                // body property may legitimately be named `default` or `enum`, and
                // `collect_body_parameters` reads its extensions like any other's,
                // so skipping it would blind the lint at a position that is read.
                if k.starts_with(PREFIX) {
                    continue;
                }
                walk(child, Node::At(pos), &join(path, k), out);
            }
        }
        Node::SecuritySchemes => {
            check_keys(obj, Pos::Other, path, out);
            for (k, child) in obj {
                if k.starts_with(PREFIX) {
                    continue;
                }
                let kind = child
                    .as_object()
                    .map(SchemeKind::of)
                    .unwrap_or(SchemeKind::Unknown);
                walk(
                    child,
                    Node::At(Pos::SecurityScheme(kind)),
                    &join(path, k),
                    out,
                );
            }
        }
        Node::Hop(expect, next) => {
            check_keys(obj, Pos::Other, path, out);
            for (k, child) in obj {
                if k == expect {
                    walk(child, *next, &join(path, k), out);
                } else if !k.starts_with(PREFIX) && !STOP.contains(&k.as_str()) {
                    walk(child, Node::At(Pos::Other), &join(path, k), out);
                }
            }
        }
        Node::AnyOf(next) => {
            check_keys(obj, Pos::Other, path, out);
            for (k, child) in obj {
                if k.starts_with(PREFIX) || STOP.contains(&k.as_str()) {
                    continue;
                }
                walk(child, *next, &join(path, k), out);
            }
        }
    }
}

/// The position map: given a parent position and one of its keys, where does
/// that key's value stand? `None` means "do not descend".
///
/// Read this side by side with [`normalize_aliases`](super::normalize_aliases) —
/// it visits the same places, and the two drifting apart is itself a bug.
fn child_node(pos: Pos, key: &str) -> Option<Node> {
    // Never descend into an extension's own value: `x-overslash-template`'s
    // `{lang, expr}` and `x-overslash-secrets`' declaration maps are
    // extension-internal shapes whose contents the extractors already check
    // precisely. The two exceptions are containers holding real template
    // structure, and they are named explicitly below.
    if STOP.contains(&key) {
        return None;
    }
    let structural = match (pos, key) {
        (Pos::Root, "info") => Node::At(Pos::Info),
        (Pos::Root, "paths") => Node::MapOf(Pos::PathItem),
        (Pos::Root, "components") => Node::At(Pos::Components),
        (Pos::Root, k) if k == Ext::Mcp.key() => Node::At(Pos::McpBlock),
        (Pos::Root, k) if k == Ext::PlatformActions.key() => Node::MapOf(Pos::PlatformAction),

        (Pos::PathItem, "parameters") => Node::At(Pos::Parameter),
        (Pos::PathItem, m) if HTTP_METHODS.contains(&m) => Node::At(Pos::Operation),

        (Pos::Operation, "parameters") => Node::At(Pos::Parameter),
        (Pos::Operation, "requestBody") => REQUEST_BODY,

        (Pos::Components, "securitySchemes") => Node::SecuritySchemes,

        (Pos::McpBlock, "auth") => Node::At(Pos::McpAuth),
        (Pos::McpBlock, "tools") => Node::At(Pos::McpTool),
        (Pos::McpBlock, "discovered_tools") => Node::At(Pos::McpToolDiscovered),

        (Pos::McpTool | Pos::McpToolDiscovered, "input_schema") => INPUT_SCHEMA,

        (Pos::PlatformAction, "params") => Node::MapOf(Pos::PlatformActionParam),

        // Everything else keeps sweeping at `Pos::Other`, where nothing is read
        // — which is what makes a stray extension in a `responses` entry or a
        // `components.schemas` subtree a finding rather than a blind spot.
        (_, k) if k.starts_with(PREFIX) => return None,
        _ => Node::At(Pos::Other),
    };
    Some(structural)
}
