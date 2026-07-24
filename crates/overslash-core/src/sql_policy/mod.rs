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

mod analyze;
mod config;
mod types;

pub use analyze::{analyze, available, extract_sql};
pub use config::{SQL_DATABASES_CONFIG_KEY, SqlDatabaseEntry, parse_sql_databases};
pub use types::{SqlAnalysis, SqlClass, WriteReason};
