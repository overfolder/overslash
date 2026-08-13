//! D69 function-level policy: which functions a `SELECT` may call and still
//! classify read.
//!
//! Two lists, because volatility answers most of the question but not all of
//! it:
//!
//! - [`catalog_functions::CATALOG_SAFE`] — generated from `pg_catalog`, every
//!   IMMUTABLE or STABLE function. Postgres's own contract is that those
//!   "cannot modify the database", so the catalog decides the bulk of the
//!   list and we hand-curate nothing it already knows. That single rule keeps
//!   `nextval`, `setval`, `set_config`, `pg_read_file`, `lo_import`, `dblink`
//!   and `pg_terminate_backend` out without naming any of them.
//! - [`VOLATILE_SAFE`] — the handful that are VOLATILE and still harmless.
//!   `pg_sleep` is the reason this list exists: it burns wall-clock in the
//!   caller's own session and touches nothing, but Postgres marks it `v`
//!   exactly like `nextval`, so a volatility rule alone would refuse it.
//!
//! Everything else — an unlisted builtin, an extension, a user-defined
//! function, anything schema-qualified outside `pg_catalog` — is not safe.
//! That is the fail-closed default the rest of this module already takes for
//! parse errors and `DO`/`CALL` bodies, and it is the only defensible one: a
//! UDF body is invisible to the parser and may do anything at all.
//!
//! The trust here is by *name*, which is the honest limit: a function in a
//! schema earlier on the caller's `search_path` can shadow a catalog name and
//! inherit its listing. A read-only upstream credential remains the backstop
//! (see the module docs), and DB grants own the last word.

use super::catalog_functions::CATALOG_SAFE;

/// VOLATILE `pg_catalog` functions with no side effect outside the calling
/// session. Sorted; kept short on purpose — every addition needs a reason
/// that survives the question "what can this change?".
static VOLATILE_SAFE: &[&str] = &[
    // Reads the wall clock mid-statement.
    "clock_timestamp",
    // PRNG output; no catalog, no storage.
    "gen_random_uuid",
    // Sleeps in the caller's own backend. Costs wall-clock, changes nothing.
    "pg_sleep",
    "pg_sleep_for",
    "pg_sleep_until",
    // PRNG; advances session-local seed state only.
    "random",
    "random_normal",
    // Wall clock again, as text.
    "timeofday",
];

/// How many offending names [`describe`] names before it gives up counting.
const MAX_NAMED: usize = 5;

/// Stands in for a function call the tree contains but the walk never
/// reached, so the audit reason says *why* a query with no visibly unsafe
/// call still classified write. Not a legal SQL identifier, so it can never
/// collide with a real name or be vouched for by config.
pub(super) const UNENUMERATED: &str = "<unenumerated call>";

/// Strip the one qualification that means "the builtin". Anything still
/// carrying a `.` is schema-qualified outside `pg_catalog` and is deliberately
/// left with its dots so it can never match a bare list entry.
fn normalize(name: &str) -> &str {
    name.strip_prefix("pg_catalog.").unwrap_or(name)
}

/// Is this function call allowed to leave a `SELECT` classified read?
///
/// Compared **exactly**, never case-folded: Postgres's lexer already
/// lowercases unquoted identifiers, so `COUNT(*)` arrives as `count`, while a
/// quoted `"COUNT"` really is a different function and correctly misses.
///
/// `extra` is the database's `safe_functions` config (D69), normalized the
/// same way so an operator may write either `unaccent` or `pg_catalog.foo`.
pub(super) fn is_safe(name: &str, extra: &[String]) -> bool {
    let name = normalize(name);
    CATALOG_SAFE.binary_search(&name).is_ok()
        || VOLATILE_SAFE.binary_search(&name).is_ok()
        || extra.iter().any(|e| normalize(e) == name)
}

/// The `WriteReason::UnsafeFunction` payload: the offending names, capped so
/// one pathological query cannot bloat every audit row it touches.
pub(super) fn describe(offenders: &[String]) -> String {
    let mut out = offenders
        .iter()
        .take(MAX_NAMED)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if offenders.len() > MAX_NAMED {
        out.push_str(&format!(" (+{} more)", offenders.len() - MAX_NAMED));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both lists are binary-searched, so byte order is load-bearing. The
    /// generator emits Postgres's `ORDER BY` under C collation, which agrees
    /// with Rust's — this is what catches the day it does not.
    #[test]
    fn lists_are_byte_sorted() {
        assert!(CATALOG_SAFE.is_sorted(), "CATALOG_SAFE must be sorted");
        assert!(VOLATILE_SAFE.is_sorted(), "VOLATILE_SAFE must be sorted");
    }

    /// A name that is already IMMUTABLE/STABLE does not belong in the hand
    /// list; if the generator starts emitting one, the carve-out entry is
    /// dead weight and its justifying comment is now wrong.
    #[test]
    fn volatile_carve_out_does_not_shadow_the_catalog() {
        for name in VOLATILE_SAFE {
            assert!(
                CATALOG_SAFE.binary_search(name).is_err(),
                "{name} is already in CATALOG_SAFE — drop the carve-out entry"
            );
        }
    }

    #[test]
    fn the_dangerous_builtins_never_made_the_list() {
        for name in [
            "nextval",
            "setval",
            "set_config",
            "pg_read_file",
            "pg_read_binary_file",
            "pg_ls_dir",
            "pg_stat_file",
            "lo_import",
            "lo_export",
            "lowrite",
            "pg_terminate_backend",
            "pg_cancel_backend",
            "pg_reload_conf",
            "query_to_xml",
            // STABLE, but reads a relation named at runtime — invisible to
            // the table enumeration, so the generator subtracts it.
            "table_to_xml",
            "schema_to_xml",
            "database_to_xml",
            // STABLE, but assigns a transaction id.
            "txid_current",
            "pg_current_xact_id",
        ] {
            assert!(!is_safe(name, &[]), "{name} must not be safe");
        }
    }

    #[test]
    fn ordinary_analytics_functions_are_safe() {
        for name in [
            "count",
            "sum",
            "avg",
            "min",
            "max",
            "lower",
            "upper",
            "substring",
            "date_trunc",
            "to_char",
            "extract",
            "round",
            "jsonb_agg",
            "row_number",
            "rank",
        ] {
            assert!(is_safe(name, &[]), "{name} must be safe");
        }
        // The whole point of the carve-out.
        assert!(is_safe("pg_sleep", &[]));
        assert!(is_safe("random", &[]));
    }

    #[test]
    fn pg_catalog_qualification_is_stripped_but_other_schemas_are_not() {
        assert!(is_safe("pg_catalog.lower", &[]));
        assert!(!is_safe("public.lower", &[]));
        assert!(!is_safe("public.count", &[]));
    }

    #[test]
    fn comparison_is_case_sensitive() {
        assert!(is_safe("count", &[]));
        // A quoted "COUNT" is a genuinely different function in Postgres.
        assert!(!is_safe("COUNT", &[]));
    }

    #[test]
    fn config_widens_the_list_and_normalizes_the_same_way() {
        let extra = vec!["st_area".to_string(), "pg_catalog.nextval".to_string()];
        assert!(is_safe("st_area", &extra));
        assert!(is_safe("nextval", &extra));
        assert!(is_safe("pg_catalog.nextval", &extra));
        assert!(!is_safe("st_area", &[]));
        // Still schema-qualified elsewhere: the operator listed the builtin,
        // not somebody's `public.nextval`.
        assert!(!is_safe("public.nextval", &extra));
    }

    #[test]
    fn describe_caps_the_payload() {
        let few: Vec<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
        assert_eq!(describe(&few), "a, b");

        let many: Vec<String> = (0..8).map(|i| format!("f{i}")).collect();
        assert_eq!(describe(&many), "f0, f1, f2, f3, f4 (+3 more)");
    }
}
