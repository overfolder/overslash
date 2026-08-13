//! Walking a Postgres parse tree: the classifier's verdict order, the single
//! traversal that feeds it, and the completeness oracle that keeps the D69
//! function screen honest.
//!
//! Split out of `analyze.rs`, which keeps the entry points and the shapes
//! callers see; everything here is about `pg_query`'s tree and is compiled
//! only with the `sql_policy` feature.

use crate::sql_policy::functions;
use crate::sql_policy::types::{SqlAnalysis, SqlClass, WriteReason};
use pg_query::NodeRef;
use pg_query::protobuf::node::Node as NodeEnum;

/// Parse `sql` and rule on it. The order of the refusals below is the order
/// a reader should meet them: least-surprising diagnosis first.
pub(super) fn analyze(sql: &str, extra_safe: &[String]) -> SqlAnalysis {
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

    // D69: a read is only a read while every function it calls is one.
    // `tables_exhaustive` drops with it — `nextval` touches a sequence,
    // `dblink` another database, a UDF body anything at all, and none of
    // that is in the relation lists above.
    //
    // The screen is only as good as the enumeration, so the enumeration
    // is checked against the tree before it is trusted: a call the walk
    // never reached is a call nothing screened, and that fails closed
    // rather than passing as a read.
    let mut offenders: Vec<String> = walk
        .functions
        .iter()
        .filter(|f| !functions::is_safe(f, extra_safe))
        .cloned()
        .collect();
    if walk.call_sites.len() < count_func_calls(&result) {
        offenders.push(functions::UNENUMERATED.to_string());
    }
    if !offenders.is_empty() {
        return SqlAnalysis::write(
            WriteReason::UnsafeFunction(functions::describe(&offenders)),
            read_tables,
            mut_tables,
            columns,
            false,
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
    /// Every function invoked anywhere in the tree, in source order,
    /// deduped by name. Dotted names arrive joined (`pg_catalog.lower`).
    functions: Vec<String>,
    /// How many *distinct* `FuncCall` nodes the walk reached. Compared
    /// against the tree's own count to prove the walk missed none —
    /// counted by address, not by name, because the name list is deduped
    /// and the re-rooting below may reach one node by two paths.
    call_sites: std::collections::HashSet<usize>,
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
        functions: Vec::new(),
        call_sites: std::collections::HashSet::new(),
        nested_dml: false,
        select_into: false,
        row_locking: false,
        opaque: false,
    };
    let mut seen_cols = std::collections::HashSet::new();
    let mut seen_fns = std::collections::HashSet::new();

    // `nodes()` is a hand-written field list per node type and skips
    // several positions outright. Rather than accept the blind spots,
    // re-root the walk at each field it drops — `blind_spots` returns
    // them and this loop keeps draining until nothing new turns up.
    // `count_func_calls` is the backstop for the ones nobody has found.
    let mut roots: Vec<&NodeEnum> = result
        .protobuf
        .stmts
        .iter()
        .filter_map(|raw| raw.stmt.as_ref().and_then(|n| n.node.as_ref()))
        .collect();
    let mut walked = Vec::new();
    let mut seen_roots = std::collections::HashSet::new();
    while let Some(root) = roots.pop() {
        if !seen_roots.insert(std::ptr::from_ref(root) as usize) {
            continue;
        }
        for (node, depth, context, has_filter) in root.nodes() {
            roots.extend(blind_spots(node));
            walked.push((node, depth, context, has_filter));
        }
    }

    for (node, _depth, _context, _has_filter) in walked {
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
            NodeRef::FuncCall(f) => {
                facts.call_sites.insert(std::ptr::from_ref(f) as usize);
                let name = f
                    .funcname
                    .iter()
                    .filter_map(|n| match n.node.as_ref() {
                        Some(NodeEnum::String(s)) => Some(s.sval.as_str()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join(".");
                if !name.is_empty() && seen_fns.insert(name.clone()) {
                    facts.functions.push(name);
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

/// The child nodes `pg_query`'s `nodes()` iterator does not descend
/// into, so [`walk_tree`] can re-root at them.
///
/// Every entry here was found by the `no_call_hides_from_the_walk` test,
/// not by reading the crate — that test is the specification and this is
/// the fix. Closing them is about *precision*: without it a perfectly
/// ordinary `DISTINCT ON (date_trunc(…))` trips the completeness oracle
/// and fails closed with a reason no one can act on.
fn blind_spots(node: NodeRef<'_>) -> Vec<&NodeEnum> {
    fn one(n: &Option<Box<pg_query::protobuf::Node>>) -> Option<&NodeEnum> {
        n.as_ref()?.node.as_ref()
    }
    fn many(ns: &[pg_query::protobuf::Node]) -> impl Iterator<Item = &NodeEnum> {
        ns.iter().filter_map(|n| n.node.as_ref())
    }

    let mut out: Vec<&NodeEnum> = Vec::new();
    match node {
        NodeRef::SelectStmt(s) => {
            out.extend(many(&s.distinct_clause));
            out.extend(many(&s.window_clause));
            out.extend(s.values_lists.iter().filter_map(|n| n.node.as_ref()));
            out.extend(one(&s.limit_count));
            out.extend(one(&s.limit_offset));
        }
        NodeRef::FuncCall(f) => {
            out.extend(many(&f.agg_order));
            out.extend(one(&f.agg_filter));
            if let Some(w) = f.over.as_ref() {
                out.extend(many(&w.partition_clause));
                out.extend(many(&w.order_clause));
                out.extend(one(&w.start_offset));
                out.extend(one(&w.end_offset));
            }
        }
        NodeRef::WindowDef(w) => {
            out.extend(many(&w.partition_clause));
            out.extend(many(&w.order_clause));
            out.extend(one(&w.start_offset));
            out.extend(one(&w.end_offset));
        }
        NodeRef::AIndirection(i) => {
            out.extend(one(&i.arg));
            out.extend(many(&i.indirection));
        }
        NodeRef::AIndices(i) => {
            out.extend(one(&i.lidx));
            out.extend(one(&i.uidx));
        }
        NodeRef::AArrayExpr(a) => out.extend(many(&a.elements)),
        NodeRef::List(l) => out.extend(many(&l.items)),
        _ => {}
    }
    out
}

/// How many `FuncCall` nodes the parse tree actually contains.
///
/// [`walk_tree`] enumerates function calls through `pg_query`'s `nodes()`
/// iterator, which the crate documents as covering only "a subset of
/// nodes" — it is a hand-written per-variant field list, and it really
/// does miss positions (a `LIMIT`, a `VALUES` row, an aggregate's
/// `FILTER`). For a *table* enumeration that is a known imprecision; for
/// the D69 function gate it would be a bypass, since a call the walk
/// never sees is a call that never gets screened.
///
/// So the walk is checked rather than trusted. `prost` derives `Debug`
/// structurally over every field of every message, so the rendered tree
/// contains one `FuncCall {` for each call, wherever it sits — counting
/// them is a completeness oracle that does not depend on anyone's field
/// audit staying correct across a `pg_query` upgrade. It is rendered
/// through a counting sink, so nothing is allocated.
///
/// Counting a marker in rendered text over-counts when a string literal
/// spells the marker, which fails the statement closed. That direction is
/// the safe one and the query is absurd; the alternatives — parsing the
/// render, or hand-walking 250 node types — cost more than the nuisance.
pub(super) fn count_func_calls(result: &pg_query::ParseResult) -> usize {
    use std::fmt::Write as _;

    /// Counts non-overlapping occurrences of `NEEDLE` in whatever is
    /// written through it, across chunk boundaries, storing nothing.
    struct Counting {
        matched: usize,
        count: usize,
    }
    const NEEDLE: &[u8] = b"FuncCall {";

    impl std::fmt::Write for Counting {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            for &b in s.as_bytes() {
                // No self-overlap in NEEDLE, so a miss restarts at 0
                // (or 1, when the byte itself opens a new candidate).
                if b == NEEDLE[self.matched] {
                    self.matched += 1;
                    if self.matched == NEEDLE.len() {
                        self.count += 1;
                        self.matched = 0;
                    }
                } else {
                    self.matched = usize::from(b == NEEDLE[0]);
                }
            }
            Ok(())
        }
    }

    let mut sink = Counting {
        matched: 0,
        count: 0,
    };
    let _ = write!(sink, "{:?}", result.protobuf);
    sink.count
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

/// How many distinct calls [`walk_tree`] reached. Test-only accessor;
/// `analyze` reads the same number off `WalkFacts`.
#[cfg(test)]
pub(super) fn walk_call_sites(result: &pg_query::ParseResult) -> usize {
    walk_tree(result).call_sites.len()
}

fn dedup(items: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    items
        .into_iter()
        .filter(|t| seen.insert(t.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The D69 gate is only as good as the enumeration behind it: a call the
    /// walk never reaches is a call nothing screens. `pg_query`'s `nodes()`
    /// iterator documents itself as partial and really is — every position
    /// below once hid a `nextval` from an earlier draft of this walk. Any new
    /// hiding place is a *bypass*, so this list only ever grows.
    #[test]
    fn no_call_hides_from_the_walk() {
        let cases = [
            ("fn arg of fn", "SELECT abs(nextval('s'))"),
            (
                "case branch",
                "SELECT CASE WHEN x THEN nextval('s') ELSE 0 END FROM t",
            ),
            ("where clause", "SELECT id FROM t WHERE nextval('s') > 1"),
            (
                "having",
                "SELECT count(*) FROM t GROUP BY a HAVING nextval('s') > 1",
            ),
            ("order by", "SELECT id FROM t ORDER BY nextval('s')"),
            (
                "cte body",
                "WITH c AS (SELECT nextval('s')) SELECT * FROM c",
            ),
            (
                "subquery in where",
                "SELECT id FROM t WHERE id IN (SELECT nextval('s'))",
            ),
            ("scalar subquery", "SELECT (SELECT nextval('s')) AS x"),
            (
                "window frame",
                "SELECT sum(x) OVER (ORDER BY nextval('s')) FROM t",
            ),
            (
                "lateral join",
                "SELECT * FROM t, LATERAL (SELECT nextval('s')) l",
            ),
            ("union arm", "SELECT 1 UNION SELECT nextval('s')"),
            ("array subscript", "SELECT (ARRAY[nextval('s')])[1]"),
            ("cast operand", "SELECT nextval('s')::text"),
            ("coalesce", "SELECT coalesce(nextval('s'), 0)"),
            (
                "filter clause",
                "SELECT count(*) FILTER (WHERE nextval('s') > 1) FROM t",
            ),
            ("group by", "SELECT count(*) FROM t GROUP BY nextval('s')"),
            ("limit", "SELECT id FROM t LIMIT nextval('s')"),
            ("values", "SELECT * FROM (VALUES (nextval('s'))) v"),
            ("join on", "SELECT * FROM a JOIN b ON a.id = nextval('s')"),
            ("distinct on", "SELECT DISTINCT ON (nextval('s')) id FROM t"),
            ("in a not", "SELECT id FROM t WHERE NOT (nextval('s') > 1)"),
            ("row expr", "SELECT ROW(nextval('s'), 1)"),
            ("aggregate arg", "SELECT max(nextval('s')) FROM t"),
            ("op operand", "SELECT 1 + nextval('s')"),
            (
                "between",
                "SELECT id FROM t WHERE id BETWEEN 1 AND nextval('s')",
            ),
            ("json path", "SELECT jsonb_build_object('k', nextval('s'))"),
            ("nested deep", "SELECT abs(abs(abs(abs(nextval('s')))))"),
        ];
        let mut leaks = vec![];
        let mut oracle_only = vec![];
        for (name, sql) in cases {
            let a = analyze(sql, &[]);
            if a.class != SqlClass::Write {
                leaks.push(name);
                continue;
            }
            // Classifying write via the oracle rather than by naming the
            // function means the walk still cannot see this position. Safe,
            // but imprecise — the reason is unactionable, so `blind_spots`
            // should grow to cover it.
            if let Some(WriteReason::UnsafeFunction(detail)) = &a.write_reason
                && !detail.contains("nextval")
            {
                oracle_only.push(name);
            }
        }
        assert!(leaks.is_empty(), "nextval classified read in: {leaks:?}");
        assert!(
            oracle_only.is_empty(),
            "walk missed the call (only the oracle caught it) in: {oracle_only:?}"
        );
    }

    /// The oracle's own test: blind the walk and it must still fail closed.
    /// Without this, a walk that silently stopped finding anything would
    /// leave the oracle passing vacuously.
    /// The oracle counts a marker in rendered text, so a string literal
    /// spelling that marker inflates the count and the statement fails
    /// closed. Pinned rather than fixed: the direction is safe, the query is
    /// absurd, and the alternatives (parsing the render, or hand-walking 250
    /// node types) cost far more than the nuisance.

    #[test]
    fn a_literal_spelling_the_marker_fails_closed() {
        let a = analyze("SELECT 'FuncCall {' AS x", &[]);
        assert_eq!(a.class, SqlClass::Write);
        assert!(!a.tables_exhaustive);
    }

    #[test]
    fn the_completeness_oracle_counts_every_call() {
        let cases = [
            ("plain", "SELECT count(*) FROM t", 1),
            ("nested", "SELECT abs(abs(count(*))) FROM t", 3),
            ("repeat", "SELECT f(x), f(y), f(z) FROM t", 3),
            ("in a limit", "SELECT id FROM t LIMIT nextval('s')", 1),
            ("none at all", "SELECT id FROM t WHERE a = 1", 0),
            (
                "spread around",
                "SELECT count(*) FILTER (WHERE lower(a) = 'x') FROM t \
                 GROUP BY date_trunc('day', b) LIMIT abs(1)",
                4,
            ),
        ];
        for (name, sql, want) in cases {
            let parsed = pg_query::parse(sql).expect(name);
            assert_eq!(count_func_calls(&parsed), want, "{name}");
            // And the walk agrees, which is what makes the comparison in
            // `analyze` meaningful rather than vacuous.
            assert_eq!(
                walk_call_sites(&parsed),
                want,
                "{name}: the walk undercounts"
            );
        }
    }
}
