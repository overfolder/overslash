//! The `sql_databases` instance-config entry: which parser dialect and audit
//! label each db-key nominated by `x-overslash-sql-database` resolves to.

use std::collections::HashMap;

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

        // Entries may omit both fields.
        let map = parse_sql_databases(r#"{"7": {}}"#).expect("empty entry");
        assert!(map["7"].dialect.is_none());

        assert!(parse_sql_databases("not json").is_err());
        assert!(parse_sql_databases(r#"["a"]"#).is_err());
    }
}
