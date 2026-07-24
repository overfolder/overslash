//! D42 SQL content policy: classify a SQL string as read or write and
//! enumerate the relations (and column identifiers) it references.
//!
//! The parser is Postgres's own (`pg_query` — Rust bindings over libpg_query),
//! gated behind the `sql_policy` Cargo feature because it adds a C-toolchain
//! build dependency and binary weight. The types here are compiled
//! unconditionally so callers never need `cfg` branches; compiled without the
//! feature, [`analyze`] **fails closed** — everything classifies as a write on
//! unknown tables, so risk elevates and only an explicit all-tables grant
//! covers the call.
//!
//! What this module guarantees is deliberately asymmetric (D42):
//!
//! - **Read vs write** is enforceable: `SELECT`/read-only-`WITH` → read;
//!   DML/DDL/`TRUNCATE`/`COPY`, multi-statement input, writable CTEs,
//!   `DO`/`CALL`, utility statements, or anything unparseable → write.
//! - **Table names** are enforceable: referenced relations become per-table
//!   permission keys (see `PermissionKey::from_sql_analysis`).
//! - **Column names are detection only**: the parse yields *referenced
//!   identifiers*, not resolved columns. `SELECT *` (and `t.*`) surface the
//!   literal `"*"`, so a deny-`*` rule fails closed and forces explicit
//!   enumeration — but views/CTEs hide base-table columns from any parser, so
//!   true column masking (PII) is the database's / Metabase's job, never
//!   promised here.
//!
//! Documented non-guarantees: volatile functions inside a SELECT
//! (`SELECT nextval('s')`) classify read — function-level policy is out of
//! scope, DB grants own it; Metabase `{{template_vars}}` do not parse and
//! therefore classify write; a read-only upstream key remains the backstop
//! regardless (belt and suspenders).

use std::collections::HashMap;

use crate::types::service::Risk;

/// Read-or-write verdict for one SQL string.
///
/// Deliberately not [`Risk`]: the classifier never has grounds to assert
/// `Delete` (`DROP` and `DELETE` are both just "not a read"), and callers
/// merge with [`Risk::max_severity`], so a template-declared `delete` risk
/// survives the merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlClass {
    Read,
    Write,
}

impl SqlClass {
    /// The risk floor this verdict imposes.
    pub fn as_risk(self) -> Risk {
        match self {
            SqlClass::Read => Risk::Read,
            SqlClass::Write => Risk::Write,
        }
    }
}

/// Why a statement classified as write. Carried into tracing/audit so an
/// operator can see *which* fail-closed rule fired, not just "write".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteReason {
    /// Compiled without the `sql_policy` feature — nothing was parsed.
    Unavailable,
    /// The nominated database resolves to a dialect this build cannot parse.
    UnsupportedDialect(String),
    ParseError(String),
    /// Zero parsed statements (empty or comment-only input). Nothing would
    /// execute, but an empty query attests nothing and costs nothing to gate.
    EmptyInput,
    /// More than one statement; the count is the number parsed.
    MultiStatement(usize),
    /// A top-level statement other than a plain `SELECT`; carries the parse
    /// node name (`"InsertStmt"`, `"ExplainStmt"`, `"VariableSetStmt"`, …).
    Statement(String),
    /// DML/DDL nested under a top-level `SELECT` (writable CTE or sub-select
    /// data modification).
    WritableCte,
    /// `SELECT … INTO t` / `CREATE TABLE … AS` shape under a SELECT.
    SelectInto,
    /// `FOR UPDATE` / `FOR NO KEY UPDATE` / `FOR SHARE` / `FOR KEY SHARE` at
    /// any depth: acquires row locks that block writers — the SELECT whose
    /// purpose is to precede a write.
    RowLocking,
}

impl WriteReason {
    /// Short machine-readable tag for audit/tracing fields.
    pub fn tag(&self) -> &'static str {
        match self {
            WriteReason::Unavailable => "unavailable",
            WriteReason::UnsupportedDialect(_) => "unsupported_dialect",
            WriteReason::ParseError(_) => "parse_error",
            WriteReason::EmptyInput => "empty_input",
            WriteReason::MultiStatement(_) => "multi_statement",
            WriteReason::Statement(_) => "statement",
            WriteReason::WritableCte => "writable_cte",
            WriteReason::SelectInto => "select_into",
            WriteReason::RowLocking => "row_locking",
        }
    }
}

/// The outcome of analyzing one SQL string.
#[derive(Debug, Clone)]
pub struct SqlAnalysis {
    pub class: SqlClass,
    /// `None` iff `class == Read`.
    pub write_reason: Option<WriteReason>,
    /// Relations referenced in **read (select) context**, exactly as the
    /// parser reports them: `"public.orders"` when the SQL schema-qualified
    /// the name, `"orders"` when it did not (unquoted identifiers arrive
    /// already lowercased by Postgres's lexer; quoted identifiers keep their
    /// case). CTE names are excluded. Order-preserving, deduped.
    pub read_tables: Vec<String>,
    /// Relations that are **mutation targets** (DML/DDL context): the table
    /// an INSERT/UPDATE/DELETE/MERGE lands on, a DROP/ALTER/TRUNCATE target,
    /// a `CREATE TABLE … AS` / `SELECT INTO` destination. Same normalization
    /// as [`read_tables`](Self::read_tables). A relation both read and
    /// mutated in one statement appears in both lists.
    pub mut_tables: Vec<String>,
    /// Referenced column identifiers (the last segment of each column
    /// reference). `*` and `t.*` both surface as the literal `"*"`.
    /// Order-preserving, deduped.
    pub columns: Vec<String>,
    /// `false` when the statement may touch relations not listed above
    /// (parse failure, `DO`/`CALL`/`EXECUTE` bodies, feature off,
    /// unsupported dialect). Callers must then emit the all-tables sentinel
    /// permission key — mutation-shaped, because every such case also
    /// classifies write.
    pub tables_exhaustive: bool,
}

impl SqlAnalysis {
    fn write(
        reason: WriteReason,
        read_tables: Vec<String>,
        mut_tables: Vec<String>,
        columns: Vec<String>,
        exhaustive: bool,
    ) -> Self {
        SqlAnalysis {
            class: SqlClass::Write,
            write_reason: Some(reason),
            read_tables,
            mut_tables,
            columns,
            tables_exhaustive: exhaustive,
        }
    }
}

/// Reserved instance-config key (D38 `components.x-overslash-config`) whose
/// value is a JSON object *string* mapping the db-key produced by an action's
/// `x-overslash-sql-database` jq expression to a dialect + audit label:
/// `{ "5": {"dialect": "postgres", "label": "reveni-prod"} }`.
pub const SQL_DATABASES_CONFIG_KEY: &str = "sql_databases";

/// One entry of the `sql_databases` instance-config map.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SqlDatabaseEntry {
    /// Parser dialect. `None` → `"postgres"` (D42 fail-closed default).
    #[serde(default)]
    pub dialect: Option<String>,
    /// Human label for audit + permission keys. `None` → the db-key itself.
    #[serde(default)]
    pub label: Option<String>,
}

/// Parse the `sql_databases` config value. `Err` carries a short description
/// of the malformation; the call site falls back to postgres/label-from-key
/// and warns.
pub fn parse_sql_databases(raw: &str) -> Result<HashMap<String, SqlDatabaseEntry>, String> {
    serde_json::from_str(raw).map_err(|e| e.to_string())
}

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
    use super::{SqlAnalysis, SqlClass, WriteReason};
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

    #[test]
    fn parse_sql_databases_shapes() {
        let map = parse_sql_databases(r#"{"5": {"dialect": "postgres", "label": "reveni-prod"}}"#)
            .expect("valid map");
        let e = &map["5"];
        assert_eq!(e.dialect.as_deref(), Some("postgres"));
        assert_eq!(e.label.as_deref(), Some("reveni-prod"));

        // Entries may omit both fields.
        let map = parse_sql_databases(r#"{"7": {}}"#).expect("empty entry");
        assert!(map["7"].dialect.is_none());

        assert!(parse_sql_databases("not json").is_err());
        assert!(parse_sql_databases(r#"["a"]"#).is_err());
    }
}
