//! System-derived metadata tags: the flat, searchable projection of facts
//! Overslash already computes while gating a call.
//!
//! A tag is `namespace:value` — `sql:write`, `table:warehouse/public.orders`,
//! `service:metabase`, `host:metabase.acme.internal`. Tags are stored as
//! `text[]` on approvals, executions and audit rows, and the audit log is
//! searchable by them (`GET /v1/audit?tag=`).
//!
//! # Guarantees
//!
//! - **Every tag is system-derived.** Nothing here accepts caller input, so a
//!   tag never needs to be distrusted and there is no namespace to defend
//!   against spoofing. If caller-supplied tags are ever added they must land
//!   in their own reserved namespace, not alongside these.
//! - **Bounded.** Tag arrays are capped ([`MAX_TAGS`]) and so is each tag
//!   ([`MAX_TAG_LEN`]). A statement referencing a thousand columns cannot turn
//!   one audit row into a thousand-element array.
//! - **Honest about truncation.** When a cap drops entries the array gains a
//!   `truncated:*` sentinel, so a clipped row never reads as a complete one.
//!
//! # Non-guarantees
//!
//! Tags are a *search index*, not a record. They deliberately flatten away
//! detail — [`crate::sql_policy::WriteReason::ParseError`]'s message, the
//! exact statement node — which keeps its home in `audit_log.detail`.

use crate::sql_policy::{SqlAnalysis, SqlClass, WriteReason};

/// Maximum tags on one row. Beyond this the array is clipped and gains
/// `truncated:tags`.
pub const MAX_TAGS: usize = 64;

/// Maximum bytes in one tag. Relation and column identifiers are
/// user-controlled and Postgres allows 63 bytes per identifier, so a
/// schema-qualified name plus a db label fits comfortably; this is a backstop
/// against pathological quoted identifiers.
pub const MAX_TAG_LEN: usize = 128;

/// Maximum `table:` + `table_mut:` tags from one statement. A join across more
/// relations than this is real but rare, and the sentinel records the clip.
///
/// Deliberately set so `MAX_TABLE_TAGS + MAX_COLUMN_TAGS` plus the handful of
/// scalar tags still fits [`MAX_TAGS`]: a statement that maxes out both should
/// report `truncated:table` / `truncated:column` — which say *what* was lost —
/// rather than have [`clamp`] swallow the tail under a generic sentinel.
pub const MAX_TABLE_TAGS: usize = 24;

/// Maximum `column:` tags from one statement. `SELECT` lists routinely run
/// long, so this caps sooner than the fact set does.
pub const MAX_COLUMN_TAGS: usize = 24;

/// Build one `namespace:value` tag.
///
/// The value is lowercased and sanitized: `:` would fake a second namespace
/// and whitespace would make the tag untypable in the search bar, so both
/// collapse to `-`. `/` and `.` survive — `table:` tags mirror the `table=`
/// permission-key shape (`{db}/{schema}.{relation}`), and a tag that agreed
/// with the key it came from is worth more than one that did not.
pub fn tag(namespace: &str, value: &str) -> String {
    let mut out = String::with_capacity(namespace.len() + 1 + value.len());
    out.push_str(namespace);
    out.push(':');
    for c in value.chars() {
        if c == ':' || c.is_whitespace() || c.is_control() {
            out.push('-');
        } else {
            out.extend(c.to_lowercase());
        }
    }
    truncate_on_char_boundary(out, MAX_TAG_LEN)
}

/// Tags for one analyzed SQL statement.
///
/// `db_label` is the raw label from the instance's `sql_databases` config —
/// the same string the `table=` permission keys were minted from. It is run
/// through the same sanitizer those keys use, so a `table:` tag and the
/// `table=` key it came from name the database identically.
pub fn sql_tags(db_label: &str, analysis: &SqlAnalysis) -> Vec<String> {
    let db_label = &crate::permissions::sanitize_db_label(db_label);
    let mut tags = Vec::new();

    tags.push(tag(
        "sql",
        match analysis.class {
            SqlClass::Read => "read",
            SqlClass::Write => "write",
        },
    ));

    if let Some(reason) = &analysis.write_reason {
        tags.push(tag("sql_reason", reason.tag()));
        // The two reasons carrying a bounded, low-cardinality payload get it
        // promoted to its own tag — "show me everything that classified write
        // because it was an INSERT" is a question worth being able to ask.
        // `ParseError`'s message is unbounded and stays in `detail` only.
        match reason {
            WriteReason::Statement(node) => tags.push(tag("sql_stmt", node)),
            WriteReason::UnsupportedDialect(dialect) => tags.push(tag("sql_dialect", dialect)),
            _ => {}
        }
    }

    // Only the false case is tagged: absence means the table lists are
    // complete, which is the overwhelmingly common case and not worth a tag
    // on every row.
    if !analysis.tables_exhaustive {
        tags.push(tag("sql_exhaustive", "false"));
    }

    tags.push(tag("db", db_label));

    let mut table_tags: Vec<String> = analysis
        .read_tables
        .iter()
        .map(|t| tag("table", &format!("{db_label}/{t}")))
        .chain(
            analysis
                .mut_tables
                .iter()
                .map(|t| tag("table_mut", &format!("{db_label}/{t}"))),
        )
        .collect();
    if take_capped(&mut table_tags, MAX_TABLE_TAGS) {
        tags.push(tag("truncated", "table"));
    }
    tags.append(&mut table_tags);

    let mut column_tags: Vec<String> = analysis
        .columns
        .iter()
        .map(|c| {
            if c == "*" {
                tag("column_star", db_label)
            } else {
                tag("column", &format!("{db_label}/{c}"))
            }
        })
        .collect();
    if take_capped(&mut column_tags, MAX_COLUMN_TAGS) {
        tags.push(tag("truncated", "column"));
    }
    tags.append(&mut column_tags);

    clamp(tags)
}

/// Append the post-dispatch outcome to a tag set.
///
/// Separate from tag *minting* because an approval is created before anything
/// is dispatched — only the audit row written afterwards knows how the call
/// actually went. Both the inline call path and the replay path go through
/// here so `outcome:` means the same thing on either.
pub fn with_outcome(mut tags: Vec<String>, is_error: bool) -> Vec<String> {
    tags.push(tag("outcome", if is_error { "error" } else { "ok" }));
    clamp(tags)
}

/// Dedupe (order-preserving) and cap a tag list before it is persisted.
///
/// Call this on the final assembled list — [`sql_tags`] already clamps its own
/// output, but a caller merging SQL tags with call-context tags must clamp the
/// union or the caps do not hold.
pub fn clamp(tags: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<String> = tags
        .into_iter()
        .filter(|t| seen.insert(t.clone()))
        .collect();
    if out.len() > MAX_TAGS {
        // Leave room for the sentinel so the row still fits the cap.
        out.truncate(MAX_TAGS - 1);
        out.push(tag("truncated", "tags"));
    }
    out
}

/// Truncate `v` to `max` entries in place. Returns whether anything was dropped.
fn take_capped(v: &mut Vec<String>, max: usize) -> bool {
    if v.len() > max {
        v.truncate(max);
        true
    } else {
        false
    }
}

/// Truncate to at most `max` **bytes**, snapping down to a char boundary.
///
/// Table and column identifiers are exactly the strings that carry non-ASCII,
/// so a raw `&s[..max]` here would panic on real input (CLAUDE.md rule 5).
fn truncate_on_char_boundary(mut s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    let mut n = max;
    while n > 0 && !s.is_char_boundary(n) {
        n -= 1;
    }
    s.truncate(n);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analysis(class: SqlClass, reason: Option<WriteReason>) -> SqlAnalysis {
        SqlAnalysis {
            class,
            write_reason: reason,
            read_tables: vec![],
            mut_tables: vec![],
            columns: vec![],
            tables_exhaustive: true,
        }
    }

    #[test]
    fn tag_lowercases_and_sanitizes() {
        assert_eq!(tag("service", "MetaBase"), "service:metabase");
        assert_eq!(tag("instance", "Prod Warehouse"), "instance:prod-warehouse");
        // A `:` in the value would fake a second namespace.
        assert_eq!(tag("host", "db:5432"), "host:db-5432");
        // `/` and `.` survive so table tags mirror permission-key shape.
        assert_eq!(tag("table", "wh/public.orders"), "table:wh/public.orders");
    }

    #[test]
    fn tag_truncates_on_a_char_boundary() {
        // A multi-byte identifier long enough to be cut mid-codepoint by a
        // naive byte slice.
        let long = "é".repeat(MAX_TAG_LEN);
        let t = tag("table", &long);
        assert!(t.len() <= MAX_TAG_LEN);
        // The real assertion is that we got here at all — a raw byte slice
        // would have panicked — but confirm the result is still valid UTF-8
        // ending on a whole character.
        assert!(t.ends_with('é'));
    }

    #[test]
    fn read_statement_tags_class_and_db_only() {
        let tags = sql_tags("warehouse", &analysis(SqlClass::Read, None));
        assert_eq!(tags, vec!["sql:read", "db:warehouse"]);
    }

    #[test]
    fn write_reason_payload_is_promoted() {
        let tags = sql_tags(
            "wh",
            &analysis(
                SqlClass::Write,
                Some(WriteReason::Statement("InsertStmt".into())),
            ),
        );
        assert!(tags.contains(&"sql:write".to_string()));
        assert!(tags.contains(&"sql_reason:statement".to_string()));
        assert!(tags.contains(&"sql_stmt:insertstmt".to_string()));

        let tags = sql_tags(
            "wh",
            &analysis(
                SqlClass::Write,
                Some(WriteReason::UnsupportedDialect("MySQL".into())),
            ),
        );
        assert!(tags.contains(&"sql_dialect:mysql".to_string()));
    }

    #[test]
    fn parse_error_message_is_not_promoted() {
        // Unbounded payload — the tag records only that it happened; the
        // message stays in audit detail.
        let tags = sql_tags(
            "wh",
            &analysis(
                SqlClass::Write,
                Some(WriteReason::ParseError(
                    "syntax error at or near \"slect\"".into(),
                )),
            ),
        );
        assert!(tags.contains(&"sql_reason:parse_error".to_string()));
        assert!(tags.iter().all(|t| !t.contains("slect")));
    }

    #[test]
    fn non_exhaustive_is_tagged_but_exhaustive_is_not() {
        let mut a = analysis(SqlClass::Write, Some(WriteReason::WritableCte));
        assert!(!sql_tags("wh", &a).contains(&"sql_exhaustive:false".to_string()));
        a.tables_exhaustive = false;
        assert!(sql_tags("wh", &a).contains(&"sql_exhaustive:false".to_string()));
    }

    #[test]
    fn tables_and_columns_carry_the_db_label() {
        let mut a = analysis(SqlClass::Write, Some(WriteReason::WritableCte));
        a.read_tables = vec!["public.orders".into()];
        a.mut_tables = vec!["public.audit".into()];
        a.columns = vec!["email".into(), "*".into()];
        let tags = sql_tags("wh", &a);
        assert!(tags.contains(&"table:wh/public.orders".to_string()));
        assert!(tags.contains(&"table_mut:wh/public.audit".to_string()));
        assert!(tags.contains(&"column:wh/email".to_string()));
        // `*` cannot be a `column:` value without a glob deny also matching
        // everything — it gets its own namespace, matching `column_star=`.
        assert!(tags.contains(&"column_star:wh".to_string()));
    }

    #[test]
    fn a_relation_both_read_and_mutated_gets_both_tags() {
        let mut a = analysis(
            SqlClass::Write,
            Some(WriteReason::Statement("UpdateStmt".into())),
        );
        a.read_tables = vec!["orders".into()];
        a.mut_tables = vec!["orders".into()];
        let tags = sql_tags("wh", &a);
        assert!(tags.contains(&"table:wh/orders".to_string()));
        assert!(tags.contains(&"table_mut:wh/orders".to_string()));
    }

    #[test]
    fn column_overflow_is_capped_and_announced() {
        let mut a = analysis(SqlClass::Read, None);
        a.columns = (0..MAX_COLUMN_TAGS + 10).map(|i| format!("c{i}")).collect();
        let tags = sql_tags("wh", &a);
        assert!(tags.contains(&"truncated:column".to_string()));
        assert_eq!(
            tags.iter().filter(|t| t.starts_with("column:")).count(),
            MAX_COLUMN_TAGS
        );
    }

    #[test]
    fn table_overflow_is_capped_and_announced() {
        let mut a = analysis(SqlClass::Read, None);
        a.read_tables = (0..MAX_TABLE_TAGS + 5).map(|i| format!("t{i}")).collect();
        let tags = sql_tags("wh", &a);
        assert!(tags.contains(&"truncated:table".to_string()));
        assert_eq!(
            tags.iter().filter(|t| t.starts_with("table:")).count(),
            MAX_TABLE_TAGS
        );
    }

    #[test]
    fn clamp_dedupes_preserving_order() {
        let out = clamp(vec![
            "sql:read".into(),
            "db:wh".into(),
            "sql:read".into(),
            "table:wh/orders".into(),
        ]);
        assert_eq!(out, vec!["sql:read", "db:wh", "table:wh/orders"]);
    }

    #[test]
    fn clamp_caps_the_union_and_announces_it() {
        let out = clamp((0..MAX_TAGS + 20).map(|i| format!("x:{i}")).collect());
        assert_eq!(out.len(), MAX_TAGS);
        assert_eq!(out.last().unwrap(), "truncated:tags");
    }

    #[test]
    fn both_caps_maxed_still_fits_the_total_cap() {
        // The per-kind caps exist so a statement that maxes out both reports
        // `truncated:table` / `truncated:column` — which name what was lost —
        // instead of having clamp() swallow the tail under `truncated:tags`.
        let mut a = analysis(SqlClass::Read, None);
        a.read_tables = (0..MAX_TABLE_TAGS + 5).map(|i| format!("t{i}")).collect();
        a.columns = (0..MAX_COLUMN_TAGS + 5).map(|i| format!("c{i}")).collect();
        let tags = sql_tags("wh", &a);
        assert!(tags.len() <= MAX_TAGS);
        assert!(tags.contains(&"truncated:table".to_string()));
        assert!(tags.contains(&"truncated:column".to_string()));
        assert!(!tags.contains(&"truncated:tags".to_string()));
    }

    #[test]
    fn db_label_is_sanitized_like_the_permission_key() {
        // `/` would silently change the tag's shape — `table:a/b/orders` reads
        // as db `a` with relation `b/orders`.
        let mut a = analysis(SqlClass::Read, None);
        a.read_tables = vec!["orders".into()];
        let tags = sql_tags("prod/warehouse", &a);
        assert!(tags.contains(&"db:prod-warehouse".to_string()));
        assert!(tags.contains(&"table:prod-warehouse/orders".to_string()));
    }
}
