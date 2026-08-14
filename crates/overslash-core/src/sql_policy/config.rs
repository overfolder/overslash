//! The `sql_databases` instance-config entry: which parser dialect and audit
//! label each db-key nominated by `x-overslash-sql-database` resolves to.

use std::collections::HashMap;

/// Reserved instance-config key (D38 `components.x-overslash-config`) whose
/// value is a JSON object *string* mapping the db-key produced by an action's
/// `x-overslash-sql-database` jq expression to a dialect + audit label:
/// `{ "5": {"dialect": "postgres", "label": "reveni-prod"} }`.
///
/// An entry may also carry `safe_functions` (D69) — the extension and
/// in-house function names this particular database vouches for, on top of
/// the shipped safe list.
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
    /// D69: extra function names a `SELECT` may call on this database and
    /// still classify read — the PostGIS `st_*`, the `unaccent`, the in-house
    /// UDF that the shipped `pg_catalog` list cannot know about. Absent means
    /// empty: the shipped list, nothing more.
    ///
    /// This widens the read/write boundary, so it is deliberately per
    /// database rather than global — vouching for `unaccent` on the reporting
    /// replica says nothing about the production one.
    #[serde(default)]
    pub safe_functions: Vec<String>,
}

/// Parse the `sql_databases` config value. `Err` carries a short description
/// of the malformation; the call site falls back to postgres/label-from-key
/// and warns.
pub fn parse_sql_databases(raw: &str) -> Result<HashMap<String, SqlDatabaseEntry>, String> {
    serde_json::from_str(raw).map_err(|e| e.to_string())
}

#[cfg(all(test, feature = "sql_policy"))]
mod tests {
    use super::*;

    #[test]
    fn parse_sql_databases_shapes() {
        let map = parse_sql_databases(r#"{"5": {"dialect": "postgres", "label": "reveni-prod"}}"#)
            .expect("valid map");
        let e = &map["5"];
        assert_eq!(e.dialect.as_deref(), Some("postgres"));
        assert_eq!(e.label.as_deref(), Some("reveni-prod"));

        let map = parse_sql_databases(
            r#"{"5": {"label": "reveni-prod", "safe_functions": ["st_area", "unaccent"]}}"#,
        )
        .expect("valid map");
        assert_eq!(map["5"].safe_functions, ["st_area", "unaccent"]);

        // Entries may omit every field; `safe_functions` absent is the
        // shipped list and nothing more, never a parse error.
        let map = parse_sql_databases(r#"{"7": {}}"#).expect("empty entry");
        assert!(map["7"].dialect.is_none());
        assert!(map["7"].safe_functions.is_empty());

        assert!(parse_sql_databases("not json").is_err());
        assert!(parse_sql_databases(r#"["a"]"#).is_err());
    }
}
