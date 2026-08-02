//! Classification entry points: [`available`], [`extract_sql`] and the two
//! [`analyze`] arms — the real parser-backed one under the `sql_policy`
//! feature, the fail-closed stub without it.

use std::collections::HashMap;

use super::types::SqlAnalysis;
#[cfg(not(feature = "sql_policy"))]
use super::types::WriteReason;

/// Whether this build carries the parser.
pub const fn available() -> bool {
    cfg!(feature = "sql_policy")
}

/// Locate the SQL string for an action's nominated sql-field param within
/// the caller's (already validated) params.
///
/// `sql_field` is the dotted body path from `x-overslash-sql-field`. For a
/// string param the value *is* the SQL (the path only directs body
/// assembly); for an object param the path's tail descends into the
/// caller-supplied object (`native.query` on param `native` reads
/// `params["native"]["query"]`).
///
/// Returns `None` when the param is present but the SQL string cannot be
/// located (wrong shape, missing nested field, non-string leaf) — callers
/// must fail closed on that. A wholly absent param is the caller's
/// "not supplied" case and is checked before calling this.
pub fn extract_sql<'a>(
    param_name: &str,
    sql_field: &str,
    params: &'a HashMap<String, serde_json::Value>,
) -> Option<&'a str> {
    let value = params.get(param_name)?;
    if let Some(s) = value.as_str() {
        return Some(s);
    }
    // Object param: descend by the path tail (validation guarantees the
    // path's first segment is the param name).
    let mut cur = value;
    for seg in sql_field.split('.').skip(1) {
        cur = cur.get(seg)?;
    }
    cur.as_str()
}

/// Classify `sql`, fail-closed. See the module docs for the guarantees.
#[cfg(not(feature = "sql_policy"))]
pub fn analyze(_sql: &str) -> SqlAnalysis {
    SqlAnalysis::write(
        WriteReason::Unavailable,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        false,
    )
}

/// Classify `sql`, fail-closed. See the module docs for the guarantees.
#[cfg(feature = "sql_policy")]
pub fn analyze(sql: &str) -> SqlAnalysis {
    imp::analyze(sql)
}

#[cfg(feature = "sql_policy")]
mod imp {
    use crate::sql_policy::types::{SqlAnalysis, SqlClass, WriteReason};
    use pg_query::NodeRef;
    use pg_query::protobuf::node::Node as NodeEnum;

    pub(super) fn analyze(sql: &str) -> SqlAnalysis {
        let result = match pg_query::parse(sql) {
            Ok(r) => r,
            Err(e) => {
                return SqlAnalysis::write(
                    WriteReason::ParseError(e.to_string()),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    false,
                );
            }
        };

        // Everything below reads the same collections. The parser tags each
        // referenced relation with its context; select-context relations are
        // reads, DML/DDL-context relations are mutation targets (the D43
        // `table=` / `table_mut=` split). A relation in both contexts
        // (`INSERT INTO a SELECT * FROM a`) lands in both lists.
        let read_tables = dedup(result.select_tables());
        let mut_tables = dedup(
            result
                .dml_tables()
                .into_iter()
                .chain(result.ddl_tables())
                .collect(),
        );
        let walk = walk_tree(&result);
        let columns = walk.columns;
        let exhaustive = !walk.opaque;

        let stmts: Vec<&NodeEnum> = result
            .protobuf
            .stmts
            .iter()
            .filter_map(|raw| raw.stmt.as_ref().and_then(|n| n.node.as_ref()))
            .collect();

        if stmts.is_empty() {
            return SqlAnalysis::write(
                WriteReason::EmptyInput,
                read_tables,
                mut_tables,
                columns,
                true,
            );
        }
        if stmts.len() > 1 {
            return SqlAnalysis::write(
                WriteReason::MultiStatement(stmts.len()),
                read_tables,
                mut_tables,
                columns,
                exhaustive,
            );
        }

        let top = stmts[0];
        if !matches!(top, NodeEnum::SelectStmt(_)) {
            return SqlAnalysis::write(
                WriteReason::Statement(node_variant_name(top)),
                read_tables,
                mut_tables,
                columns,
                exhaustive,
            );
        }

        // Top-level SELECT. Refuse the shapes that write through it, in
        // order of least-surprising diagnosis.
        if walk.nested_dml || !mut_tables.is_empty() {
            return SqlAnalysis::write(
                WriteReason::WritableCte,
                read_tables,
                mut_tables,
                columns,
                exhaustive,
            );
        }
        if walk.select_into {
            return SqlAnalysis::write(
                WriteReason::SelectInto,
                read_tables,
                mut_tables,
                columns,
                exhaustive,
            );
        }
        if walk.row_locking {
            return SqlAnalysis::write(
                WriteReason::RowLocking,
                read_tables,
                mut_tables,
                columns,
                exhaustive,
            );
        }

        SqlAnalysis {
            class: SqlClass::Read,
            write_reason: None,
            read_tables,
            mut_tables,
            columns,
            tables_exhaustive: exhaustive,
        }
    }

    struct WalkFacts {
        columns: Vec<String>,
        /// Insert/Update/Delete/Merge anywhere in the tree (top-level DML is
        /// caught earlier by the statement match; this flags CTE/sub-select
        /// DML under a SELECT).
        nested_dml: bool,
        select_into: bool,
        row_locking: bool,
        /// DO/CALL/EXECUTE bodies reference relations the parse tree cannot
        /// enumerate.
        opaque: bool,
    }

    /// One deep traversal collecting everything the classifier needs. Uses
    /// the crate's own `nodes()` iterator (the traversal behind `tables()`),
    /// plus direct field checks on each `SelectStmt` for the clauses the
    /// iterator may not surface as nodes (`into_clause`, `locking_clause`).
    fn walk_tree(result: &pg_query::ParseResult) -> WalkFacts {
        let mut facts = WalkFacts {
            columns: Vec::new(),
            nested_dml: false,
            select_into: false,
            row_locking: false,
            opaque: false,
        };
        let mut seen_cols = std::collections::HashSet::new();

        for (node, _depth, _context, _has_filter) in result.protobuf.nodes() {
            match node {
                NodeRef::ColumnRef(c) => {
                    let ident = c
                        .fields
                        .last()
                        .and_then(|f| f.node.as_ref())
                        .map(|n| match n {
                            NodeEnum::String(s) => s.sval.clone(),
                            NodeEnum::AStar(_) => "*".to_string(),
                            other => format!("{other:?}"),
                        });
                    if let Some(ident) = ident
                        && seen_cols.insert(ident.clone())
                    {
                        facts.columns.push(ident);
                    }
                }
                NodeRef::InsertStmt(_)
                | NodeRef::UpdateStmt(_)
                | NodeRef::DeleteStmt(_)
                | NodeRef::MergeStmt(_) => facts.nested_dml = true,
                NodeRef::SelectStmt(s) => {
                    if s.into_clause.is_some() {
                        facts.select_into = true;
                    }
                    if !s.locking_clause.is_empty() {
                        facts.row_locking = true;
                    }
                }
                NodeRef::DoStmt(_) | NodeRef::CallStmt(_) | NodeRef::ExecuteStmt(_) => {
                    facts.opaque = true;
                }
                _ => {}
            }
        }

        // `nodes()` yields nested nodes; make sure the *top-level* statements
        // themselves are also inspected (the iterator's root set differs by
        // crate version — belt and suspenders, it dedups via the flags).
        for raw in &result.protobuf.stmts {
            match raw.stmt.as_ref().and_then(|n| n.node.as_ref()) {
                Some(NodeEnum::SelectStmt(s)) => {
                    if s.into_clause.is_some() {
                        facts.select_into = true;
                    }
                    if !s.locking_clause.is_empty() {
                        facts.row_locking = true;
                    }
                }
                Some(NodeEnum::DoStmt(_) | NodeEnum::CallStmt(_) | NodeEnum::ExecuteStmt(_)) => {
                    facts.opaque = true;
                }
                _ => {}
            }
        }

        facts
    }

    /// The protobuf variant name of a statement node (`"InsertStmt"`, …),
    /// used only for audit strings.
    fn node_variant_name(node: &NodeEnum) -> String {
        let dbg = format!("{node:?}");
        dbg.split(['(', ' '])
            .next()
            .unwrap_or("Unknown")
            .to_string()
    }

    fn dedup(items: Vec<String>) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        items
            .into_iter()
            .filter(|t| seen.insert(t.clone()))
            .collect()
    }
}

#[cfg(all(test, not(feature = "sql_policy")))]
mod stub_tests {
    use super::*;
    use crate::sql_policy::SqlClass;

    #[test]
    fn analyze_without_feature_fails_closed() {
        assert!(!available());
        let a = analyze("SELECT 1");
        assert_eq!(a.class, SqlClass::Write);
        assert_eq!(a.write_reason, Some(WriteReason::Unavailable));
        assert!(a.read_tables.is_empty());
        assert!(a.mut_tables.is_empty());
        assert!(a.columns.is_empty());
        assert!(!a.tables_exhaustive);
    }
}

#[cfg(test)]
mod extract_tests {
    use super::*;

    fn params(v: serde_json::Value) -> HashMap<String, serde_json::Value> {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn extract_sql_reads_a_string_param_directly() {
        let p = params(serde_json::json!({ "query": "SELECT 1", "database": 5 }));
        // Placement mode: the path directs body assembly, not extraction.
        assert_eq!(extract_sql("query", "native.query", &p), Some("SELECT 1"));
        assert_eq!(extract_sql("query", "query", &p), Some("SELECT 1"));
    }

    #[test]
    fn extract_sql_descends_into_an_object_param() {
        let p = params(serde_json::json!({ "native": { "query": "SELECT 2" } }));
        assert_eq!(extract_sql("native", "native.query", &p), Some("SELECT 2"));
        // Deeper nesting follows every tail segment.
        let p = params(serde_json::json!({ "native": { "inner": { "q": "SELECT 3" } } }));
        assert_eq!(
            extract_sql("native", "native.inner.q", &p),
            Some("SELECT 3")
        );
    }

    #[test]
    fn extract_sql_refuses_wrong_shapes() {
        // Absent param.
        let p = params(serde_json::json!({}));
        assert_eq!(extract_sql("query", "query", &p), None);
        // Non-string leaf.
        let p = params(serde_json::json!({ "native": { "query": 42 } }));
        assert_eq!(extract_sql("native", "native.query", &p), None);
        // Missing nested field.
        let p = params(serde_json::json!({ "native": {} }));
        assert_eq!(extract_sql("native", "native.query", &p), None);
        // Numeric param where a string/object is expected.
        let p = params(serde_json::json!({ "query": 7 }));
        assert_eq!(extract_sql("query", "query", &p), None);
    }
}

#[cfg(all(test, feature = "sql_policy"))]
mod tests {
    use super::*;
    use crate::sql_policy::{SqlClass, WriteReason};

    /// Expected classification for one case of the matrix.
    enum Expect {
        Read,
        /// Write with the given `WriteReason::tag()`.
        Write(&'static str),
    }
    use Expect::{Read, Write};

    #[test]
    fn classification_matrix() {
        // (case, sql, expected class, expected read tables, expected
        // mutation-target tables — None = don't assert)
        #[allow(clippy::type_complexity)]
        let cases: &[(&str, &str, Expect, Option<&[&str]>, Option<&[&str]>)] = &[
            // --- reads (mutation targets always empty) ---
            (
                "plain select",
                "SELECT id, name FROM public.orders",
                Read,
                Some(&["public.orders"]),
                Some(&[]),
            ),
            (
                "select star",
                "SELECT * FROM orders",
                Read,
                Some(&["orders"]),
                Some(&[]),
            ),
            (
                "qualified star",
                "SELECT t.* FROM orders t",
                Read,
                Some(&["orders"]),
                Some(&[]),
            ),
            (
                "read-only cte",
                "WITH r AS (SELECT id FROM public.orders) SELECT * FROM r",
                Read,
                Some(&["public.orders"]), // CTE name excluded
                Some(&[]),
            ),
            (
                "join",
                "SELECT o.id FROM orders o JOIN public.users u ON u.id = o.user_id",
                Read,
                Some(&["orders", "public.users"]),
                Some(&[]),
            ),
            ("constant select", "SELECT 1", Read, Some(&[]), Some(&[])),
            (
                "comments",
                "/* c */ SELECT id FROM orders -- trailing",
                Read,
                Some(&["orders"]),
                Some(&[]),
            ),
            (
                "quoted mixed case",
                "SELECT \"Id\" FROM \"Orders\"",
                Read,
                Some(&["Orders"]),
                Some(&[]),
            ),
            (
                "unquoted uppercase folds",
                "SELECT ID FROM ORDERS",
                Read,
                Some(&["orders"]),
                Some(&[]),
            ),
            // Documented limitation: volatile functions classify read.
            (
                "volatile function",
                "SELECT nextval('order_seq')",
                Read,
                Some(&[]),
                Some(&[]),
            ),
            (
                "subquery",
                "SELECT * FROM (SELECT id FROM orders) s",
                Read,
                Some(&["orders"]),
                Some(&[]),
            ),
            (
                "view reads as its own name",
                "SELECT * FROM reporting.orders_view",
                Read,
                Some(&["reporting.orders_view"]),
                Some(&[]),
            ),
            (
                "union",
                "SELECT id FROM a UNION SELECT id FROM b",
                Read,
                Some(&["a", "b"]),
                Some(&[]),
            ),
            (
                "trailing semicolon",
                "SELECT 1;",
                Read,
                Some(&[]),
                Some(&[]),
            ),
            // --- DML: the target is a mutation, tables it reads stay reads ---
            (
                "insert",
                "INSERT INTO orders (id) VALUES (1)",
                Write("statement"),
                Some(&[]),
                Some(&["orders"]),
            ),
            (
                "update",
                "UPDATE public.orders SET x = 1",
                Write("statement"),
                Some(&[]),
                Some(&["public.orders"]),
            ),
            (
                "delete",
                "DELETE FROM orders",
                Write("statement"),
                Some(&[]),
                Some(&["orders"]),
            ),
            (
                "insert from select",
                "INSERT INTO archive SELECT * FROM public.orders",
                Write("statement"),
                Some(&["public.orders"]),
                Some(&["archive"]),
            ),
            (
                "merge",
                "MERGE INTO orders o USING s ON o.id = s.id WHEN MATCHED THEN DO NOTHING",
                Write("statement"),
                None,
                Some(&["orders"]),
            ),
            (
                "truncate",
                "TRUNCATE orders",
                Write("statement"),
                Some(&[]),
                Some(&["orders"]),
            ),
            // --- DDL ---
            (
                "drop table",
                "DROP TABLE orders",
                Write("statement"),
                Some(&[]),
                Some(&["orders"]),
            ),
            (
                "create table",
                "CREATE TABLE t (id int)",
                Write("statement"),
                Some(&[]),
                Some(&["t"]),
            ),
            (
                "alter table",
                "ALTER TABLE orders ADD COLUMN x int",
                Write("statement"),
                Some(&[]),
                Some(&["orders"]),
            ),
            (
                "create table as",
                "CREATE TABLE t AS SELECT * FROM orders",
                Write("statement"),
                Some(&["orders"]),
                Some(&["t"]),
            ),
            (
                "grant",
                "GRANT SELECT ON orders TO joe",
                Write("statement"),
                None,
                None,
            ),
            // --- SELECT shapes that write ---
            (
                "select into",
                "SELECT id INTO backup FROM orders",
                Write("select_into"),
                Some(&["orders"]),
                None,
            ),
            (
                "writable cte delete",
                "WITH d AS (DELETE FROM orders RETURNING id) SELECT * FROM d",
                Write("writable_cte"),
                Some(&[]),
                Some(&["orders"]),
            ),
            (
                "writable cte insert",
                "WITH i AS (INSERT INTO audit_log (x) VALUES (1) RETURNING id) SELECT 1",
                Write("writable_cte"),
                Some(&[]),
                Some(&["audit_log"]),
            ),
            (
                "for update",
                "SELECT * FROM orders FOR UPDATE",
                Write("row_locking"),
                Some(&["orders"]),
                Some(&[]),
            ),
            (
                "nested for update",
                "SELECT * FROM (SELECT id FROM orders FOR UPDATE) s",
                Write("row_locking"),
                Some(&["orders"]),
                Some(&[]),
            ),
            (
                "for share",
                "SELECT * FROM orders FOR SHARE",
                Write("row_locking"),
                None,
                None,
            ),
            // --- COPY, both directions (context pinned by observation) ---
            (
                "copy out",
                "COPY orders TO '/tmp/x.csv'",
                Write("statement"),
                None,
                None,
            ),
            (
                "copy in",
                "COPY orders FROM '/tmp/x.csv'",
                Write("statement"),
                None,
                None,
            ),
            // --- opaque bodies ---
            (
                "do block",
                "DO $$ BEGIN DELETE FROM orders; END $$",
                Write("statement"),
                None,
                None,
            ),
            (
                "call",
                "CALL do_maintenance()",
                Write("statement"),
                None,
                None,
            ),
            // --- utility statements: fail-closed, no whitelist ---
            (
                "explain",
                "EXPLAIN SELECT * FROM orders",
                Write("statement"),
                None,
                None,
            ),
            (
                "explain analyze dml",
                "EXPLAIN ANALYZE DELETE FROM orders",
                Write("statement"),
                None,
                None,
            ),
            (
                "set",
                "SET search_path TO evil",
                Write("statement"),
                None,
                None,
            ),
            (
                "show",
                "SHOW server_version",
                Write("statement"),
                None,
                None,
            ),
            ("vacuum", "VACUUM orders", Write("statement"), None, None),
            (
                "prepare",
                "PREPARE p AS SELECT 1",
                Write("statement"),
                None,
                None,
            ),
            // --- multi-statement ---
            (
                "multi",
                "SELECT 1; DROP TABLE orders",
                Write("multi_statement"),
                Some(&[]),
                Some(&["orders"]),
            ),
            (
                "multi prepared",
                "PREPARE p AS SELECT 1; EXECUTE p",
                Write("multi_statement"),
                None,
                None,
            ),
            (
                "multi comment obfuscation",
                "SELECT 1/*\n*/; DELETE FROM orders",
                Write("multi_statement"),
                Some(&[]),
                Some(&["orders"]),
            ),
            // --- empty / broken ---
            ("empty", "", Write("empty_input"), Some(&[]), Some(&[])),
            (
                "comment only",
                "-- only a comment",
                Write("empty_input"),
                Some(&[]),
                Some(&[]),
            ),
            (
                "typo",
                "SELEC id FROM orders",
                Write("parse_error"),
                Some(&[]),
                Some(&[]),
            ),
            (
                "mysql backticks",
                "SELECT * FROM `orders`",
                Write("parse_error"),
                Some(&[]),
                Some(&[]),
            ),
            (
                "metabase template var",
                "SELECT * FROM orders WHERE id = {{id}}",
                Write("parse_error"),
                Some(&[]),
                Some(&[]),
            ),
        ];

        for (name, sql, expect, read_tables, mut_tables) in cases {
            let a = analyze(sql);
            match expect {
                Read => {
                    assert_eq!(
                        a.class,
                        SqlClass::Read,
                        "{name}: expected Read, got {:?}",
                        a.write_reason
                    );
                    assert_eq!(a.write_reason, None, "{name}");
                }
                Write(tag) => {
                    assert_eq!(
                        a.class,
                        SqlClass::Write,
                        "{name}: expected Write, classified Read"
                    );
                    let got = a.write_reason.as_ref().map(WriteReason::tag);
                    assert_eq!(got, Some(*tag), "{name}: wrong write reason");
                }
            }
            for (kind, want, got) in [
                ("read", read_tables, &a.read_tables),
                ("mut", mut_tables, &a.mut_tables),
            ] {
                if let Some(want) = want {
                    let mut got = got.clone();
                    got.sort();
                    let mut want: Vec<String> = want.iter().map(|s| s.to_string()).collect();
                    want.sort();
                    assert_eq!(got, want, "{name}: {kind}-table set mismatch");
                }
            }
        }
    }

    #[test]
    fn columns_surface_star_as_literal() {
        let a = analyze("SELECT * FROM orders");
        assert_eq!(a.columns, vec!["*"]);

        let a = analyze("SELECT t.* FROM orders t");
        assert_eq!(a.columns, vec!["*"]);

        let a = analyze("SELECT id, o.total FROM orders o WHERE region = 'eu'");
        let mut cols = a.columns.clone();
        cols.sort();
        assert_eq!(cols, vec!["id", "region", "total"]);
    }

    #[test]
    fn statement_write_reason_names_the_node() {
        let a = analyze("INSERT INTO orders (id) VALUES (1)");
        assert_eq!(
            a.write_reason,
            Some(WriteReason::Statement("InsertStmt".into()))
        );
        let a = analyze("EXPLAIN SELECT 1");
        assert_eq!(
            a.write_reason,
            Some(WriteReason::Statement("ExplainStmt".into()))
        );
    }

    #[test]
    fn opaque_bodies_are_not_exhaustive() {
        for sql in [
            "DO $$ BEGIN DELETE FROM orders; END $$",
            "CALL do_maintenance()",
        ] {
            let a = analyze(sql);
            assert!(
                !a.tables_exhaustive,
                "{sql}: DO/CALL bodies cannot be enumerated"
            );
        }
        // A parse failure is never exhaustive either.
        assert!(!analyze("SELEC 1").tables_exhaustive);
        // A plain read is.
        assert!(analyze("SELECT id FROM orders").tables_exhaustive);
    }

    #[test]
    fn available_reports_feature() {
        assert!(available());
    }
}
