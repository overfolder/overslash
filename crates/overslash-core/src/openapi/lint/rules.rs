//! The four rules, applied to one object's keys.
//!
//! Order matters: the first match wins, so the most specific message is the one
//! the author sees.

use serde_json::{Map, Value};

use crate::template_validation::ValidationIssue;

use super::super::ext::{self, Ext, PREFIX, Pos};
use super::super::validate_input::closest_match;
use super::vocab::{alias_table, allowed_plain};
use super::{LEGACY_SUPPRESSED, STOP, join};

pub(super) fn check_keys(
    obj: &Map<String, Value>,
    pos: Pos,
    path: &str,
    out: &mut Vec<ValidationIssue>,
) {
    for key in obj.keys() {
        if STOP.contains(&key.as_str()) {
            continue;
        }
        let at = join(path, key);
        if let Some(name) = key.strip_prefix(PREFIX) {
            check_prefixed(key, name, pos, at, out);
        } else if !key.starts_with("x-") {
            // A foreign vendor extension (`x-amazon-…`, `x-ms-…`) is ignored on
            // purpose: it belongs to whoever wrote the spec we imported, and
            // saying so on every operation would bury our own findings.
            check_bare(key, pos, at, out);
        }
    }
}

/// Rules A and B: an `x-overslash-*` key is either unknown everywhere, or known
/// and read somewhere other than here.
fn check_prefixed(key: &str, name: &str, pos: Pos, at: String, out: &mut Vec<ValidationIssue>) {
    if LEGACY_SUPPRESSED.contains(&key) {
        return;
    }
    match Ext::from_key(key) {
        None => {
            let suggestion = closest_match(
                name,
                ext::ALL.iter().map(|e| {
                    e.key()
                        .strip_prefix(PREFIX)
                        .expect("every Ext key carries the prefix")
                }),
            )
            .map(|s| format!("; did you mean `{PREFIX}{s}`?"))
            .unwrap_or_default();
            out.push(ValidationIssue::new(
                "unknown_extension",
                format!("`{key}` is not an Overslash extension and is ignored{suggestion}"),
                at,
            ));
        }
        Some(e) if !ext::reads_at(e, pos) => {
            out.push(ValidationIssue::new(
                "misplaced_extension",
                format!(
                    "`{key}` is ignored on {}; it is read on {}",
                    pos.describe(),
                    describe_positions(e)
                ),
                at,
            ));
        }
        Some(_) => {}
    }
}

/// Rules C and D, for a key with no prefix.
///
/// The bare analysis is deliberately narrower than the prefixed one. At an
/// open-world position the keys are JSON Schema vocabulary, and a data field
/// legitimately named `risk` or `template` must not be reported — so only rule C
/// runs there, and only for a name whose extension is genuinely read at that
/// exact position, where the surrounding keys are schema keywords rather than
/// field names.
fn check_bare(key: &str, pos: Pos, at: String, out: &mut Vec<ValidationIssue>) {
    let closed = allowed_plain(pos);

    // A position's own plain fields win over the extension vocabulary. Some
    // names appear in both: `x-overslash-mcp.auth.provider` is a real, read field
    // of the auth block *and* `provider` is the alias of an `oauth2` scheme's
    // `x-overslash-provider`. Checking the allow-list first is what keeps the
    // former from being reported as a misplaced instance of the latter.
    if closed.is_some_and(|allowed| allowed.contains(&key)) {
        return;
    }

    if let Some(e) = ext_from_bare(key) {
        if alias_table(pos).iter().any(|a| a.alias == key) {
            // Normalization owns this spelling here. If it survived to the lint
            // the object carried both forms, which `ambiguous_alias` already
            // reported as an error.
            return;
        }
        if ext::reads_at(e, pos) {
            out.push(ValidationIssue::new(
                "unprefixed_alias_ignored",
                format!(
                    "`{key}` is read on {} only as `{}` — the unprefixed spelling is not \
                     rewritten at this position",
                    pos.describe(),
                    e.key()
                ),
                at,
            ));
            return;
        }
        if closed.is_some() {
            out.push(ValidationIssue::new(
                "misplaced_extension",
                format!(
                    "`{key}` is ignored on {}; `{}` is read on {}",
                    pos.describe(),
                    e.key(),
                    describe_positions(e)
                ),
                at,
            ));
        }
        return;
    }

    let Some(allowed) = closed else { return };
    // A pasted MCP snapshot carries the wire spelling, and `lower_mcp_tool`
    // reads the snake_case one — so the tool compiles with no parameters at all.
    if matches!(pos, Pos::McpTool | Pos::McpToolDiscovered)
        && matches!(key, "inputSchema" | "outputSchema")
    {
        let snake = if key == "inputSchema" {
            "input_schema"
        } else {
            "output_schema"
        };
        out.push(ValidationIssue::new(
            "unknown_template_key",
            format!(
                "`{key}` is ignored — MCP wire fields are snake_case in a template; \
                 write `{snake}`"
            ),
            at,
        ));
        return;
    }
    let suggestion = closest_match(
        key,
        allowed
            .iter()
            .copied()
            .chain(alias_table(pos).iter().map(|a| a.alias)),
    )
    .map(|s| format!("; did you mean `{s}`?"))
    .unwrap_or_default();
    out.push(ValidationIssue::new(
        "unknown_template_key",
        format!("`{key}` is not read on {}{suggestion}", pos.describe()),
        at,
    ));
}

/// Resolve a bare key to the extension it would name.
///
/// Every alias in [`alias`](super::alias) is exactly its canonical spelling with
/// the prefix removed, so this needs no second name list — and cannot drift from
/// one.
fn ext_from_bare(key: &str) -> Option<Ext> {
    Ext::from_key(&format!("{PREFIX}{key}"))
}

fn describe_positions(e: Ext) -> String {
    let names: Vec<&str> = e.positions().iter().map(|p| p.describe()).collect();
    match names.as_slice() {
        [] => "nothing".to_string(),
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}
