//! Verdict types for the SQL content policy: [`SqlClass`], [`WriteReason`]
//! and the [`SqlAnalysis`] the classifier returns. Compiled unconditionally
//! (see the module docs) so callers never need `cfg` branches.

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
    pub(super) fn write(
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
