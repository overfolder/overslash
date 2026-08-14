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
//! - **Function calls are screened by name** (D69): a `SELECT` stays read only
//!   while every function it calls is on the safe list (`functions.rs`) —
//!   `pg_catalog`'s IMMUTABLE/STABLE set, a short VOLATILE-but-harmless
//!   carve-out (`pg_sleep`, `random`, …), plus whatever the database's
//!   `safe_functions` config adds. Anything else classifies write **and**
//!   drops `tables_exhaustive`, because a `nextval`, a `dblink`, or any UDF
//!   reaches relations the parse tree cannot name. The screen is only as
//!   good as the enumeration behind it, so the enumeration is *checked*
//!   against the tree's own `FuncCall` count rather than trusted — a call the
//!   walk could not reach fails the statement closed.
//!
//! Documented non-guarantees: an unlisted-but-harmless function (a PostGIS
//! `st_*`, an extension) classifies write until an operator lists it — the
//! fail-closed direction, fixed by config rather than a release; the safe list
//! trusts a *name*, so a function shadowing a catalog name from earlier on the
//! `search_path` inherits its listing; **operators are not screened**, so a
//! user-defined operator backed by a volatile function is not caught (its
//! function name never appears as a call); Metabase `{{template_vars}}` do not
//! parse and therefore classify write; a read-only upstream key remains the
//! backstop regardless (belt and suspenders).

mod analyze;
mod config;
mod types;

// Only the classifier reads these, and only it is feature-gated.
#[cfg(feature = "sql_policy")]
mod catalog_functions;
#[cfg(feature = "sql_policy")]
mod functions;
#[cfg(feature = "sql_policy")]
mod walk;

pub use analyze::{analyze, available, extract_sql};
pub use config::{SQL_DATABASES_CONFIG_KEY, SqlDatabaseEntry, parse_sql_databases};
pub use types::{SqlAnalysis, SqlClass, WriteReason};
