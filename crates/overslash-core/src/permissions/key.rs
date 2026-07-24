use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::describe::dedup_preserving;
use crate::types::service::ScopeParams;

/// A derived permission key from an action request.
///
/// Two formats depending on call shape (SPEC §8):
/// - Service + defined action: `{service}:{action}:{arg}`
/// - Service + HTTP verb: `{service}:{METHOD}:{path}` (with the synthetic
///   `http` pseudo-service, the `path` segment is `host[:port]/path?query`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionKey(pub String);

/// A parsed permission key with its structural components exposed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedKey {
    pub key: String,
    pub service: String,
    pub action: String,
    /// The third segment verbatim, `label=value` included. Surfaces that match
    /// or display the raw key use this; surfaces that want the two halves read
    /// [`label`](Self::label) and [`value`](Self::value).
    pub arg: String,
    /// The scope label when the arg carries one (`recipient` in
    /// `email:send:recipient=jane@example.com`). `None` for a bare arg — every
    /// key written before labels existed, and every rule an operator types by
    /// hand.
    ///
    /// A label is not a param name: `to`, `cc`, and `bcc` all file under
    /// `recipient`, which is no param at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The arg with any `label=` prefix stripped.
    pub value: String,
}

/// A suggested tier of permission keys at a specific broadness level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuggestedTier {
    pub keys: Vec<String>,
    pub description: String,
}

impl PermissionKey {
    /// Derive permission keys from a Service + HTTP verb request (SPEC §8).
    /// Format: `{service}:{METHOD}:{path}` — host is omitted because the
    /// service instance bounds it via `svc.hosts`.
    ///
    /// The method is normalized to uppercase so `"post"` and `"POST"` both
    /// match a rule like `github:POST:/**`. Permission rules are written
    /// with uppercase methods by convention; without normalization, a
    /// caller using lowercase would silently fail authorization.
    pub fn from_service_http(service_key: &str, method: &str, path: &str) -> Vec<Self> {
        let method = method.to_ascii_uppercase();
        vec![Self(format!("{service_key}:{method}:{path}"))]
    }

    /// Derive permission keys from a service action request.
    /// Format: `{service}:{action}:{label}={value}`, where the label and value
    /// come from `scope_param`. An unscoped action derives `{service}:{action}:*`.
    ///
    /// Two fan-outs happen here, and both exist so a grant can be about one
    /// concrete thing rather than the whole action:
    ///
    /// - An **array-valued** param yields one key per element instead of
    ///   stringifying the array. A send to two recipients derives two keys, so
    ///   `email:send:*@example.com` covers the internal one while the external
    ///   one bubbles as an approval naming only itself. Without it the arg
    ///   would be the JSON literal `["a@b.com","c@d.com"]` — unmatchable by any
    ///   rule and unreadable by any human.
    /// - **Several scoped params** each contribute their values. `to`, `cc`,
    ///   and `bcc` all mint keys, so a bcc to an outsider is gated exactly like
    ///   a to.
    ///
    /// The label is what decides whether two params share a namespace: authored
    /// as `to:recipient`/`cc:recipient` they collapse into one
    /// `recipient=<addr>` key (one approval for an address on both headers);
    /// authored bare they stay distinguishable as `to=`/`cc=`.
    ///
    /// Keys are deduped (order-preserving) so a repeated value does not raise
    /// the same approval twice. No values at all — every scoped param missing,
    /// or all of them empty arrays — falls back to `*`.
    pub fn from_service_action(
        service_key: &str,
        action_key: &str,
        scope_param: &ScopeParams,
        params: &HashMap<String, serde_json::Value>,
    ) -> Vec<Self> {
        let mut seen = std::collections::HashSet::new();
        let keys: Vec<Self> = scope_param
            .refs()
            .iter()
            .flat_map(|r| {
                let values: Vec<String> = match params.get(&r.param) {
                    Some(serde_json::Value::Array(items)) => {
                        items.iter().map(Self::scope_arg).collect()
                    }
                    Some(v) => vec![Self::scope_arg(v)],
                    None => Vec::new(),
                };
                let label = r.label.clone();
                values
                    .into_iter()
                    .map(move |v| format!("{service_key}:{action_key}:{label}={v}"))
            })
            .filter(|k| seen.insert(k.clone()))
            .map(Self)
            .collect();
        if keys.is_empty() {
            return vec![Self(format!("{service_key}:{action_key}:*"))];
        }
        keys
    }

    /// Render one `scope_param` value as the `{arg}` segment. Strings pass
    /// through unquoted; anything else falls back to its JSON form.
    fn scope_arg(v: &serde_json::Value) -> String {
        match v.as_str() {
            Some(s) => s.to_string(),
            None => v.to_string(),
        }
    }

    /// D42/D43 per-table keys for one analyzed SQL statement, split by
    /// context: `{service}:{action}:table={label}/{relation}` per relation
    /// read (select context) and `{service}:{action}:table_mut={label}/
    /// {relation}` per **mutation target** (DML/DDL context), plus the
    /// **sentinel** `table_mut={label}/*` when the statement's relations
    /// cannot be exhaustively enumerated (parse failure, `DO`/`CALL`
    /// bodies, the parser compiled out, an unsupported dialect — all of
    /// which also classify write, hence the mutation-shaped sentinel).
    ///
    /// The split is what keeps Allow & Remember honest: a rule remembered
    /// from a read approval (`table=…`) never covers a later mutation of
    /// the same table, and asymmetric policies ("read anything, write only
    /// scratch") become expressible. The **value-only** compat form
    /// (`{service}:{action}:{label-less value}`, D40) covers both labels —
    /// "this table, read or write" — and is the ladder's middle rung.
    ///
    /// Relations come verbatim from the parser: schema-qualified iff the SQL
    /// qualified them, unquoted identifiers already lowercased, quoted ones
    /// case-preserved. No `search_path` guessing — a rule for
    /// `…/public.orders` does not cover an unqualified `orders`; operators
    /// grant both spellings or require agents to schema-qualify. A view is
    /// gated as its own name.
    ///
    /// Glob shapes that fall out (`*` does not span `/`):
    /// - `…:table=reveni-prod/*` — read every table in one DB;
    /// - `…:table_mut=reveni-prod/*` — mutate anything there (covers the
    ///   sentinel too, deliberately: whoever may mutate the whole DB may
    ///   run statements the parser cannot enumerate);
    /// - `…:table=reveni-prod/public.*` — one schema (`*` spans `.`);
    /// - `…:reveni-prod/public.orders` — value-only: this table, either way;
    /// - `{service}:{action}:*` does **not** cover table keys — action-wide
    ///   grants over SQL actions are written `{service}:{action}:**`.
    pub fn from_sql_analysis(
        service_key: &str,
        action_key: &str,
        db_label: &str,
        analysis: &crate::sql_policy::SqlAnalysis,
    ) -> Vec<Self> {
        let label = sanitize_db_label(db_label);
        let mut keys: Vec<Self> = dedup_preserving(
            analysis
                .read_tables
                .iter()
                .map(|t| format!("{service_key}:{action_key}:table={label}/{t}"))
                .chain(
                    analysis
                        .mut_tables
                        .iter()
                        .map(|t| format!("{service_key}:{action_key}:table_mut={label}/{t}")),
                ),
        )
        .into_iter()
        .map(Self)
        .collect();
        if !analysis.tables_exhaustive {
            let sentinel = Self(format!("{service_key}:{action_key}:table_mut={label}/*"));
            if !keys.contains(&sentinel) {
                keys.push(sentinel);
            }
        }
        keys
    }

    /// D42 column keys for one analyzed SQL statement — **deny-screen only**,
    /// never required to be covered by an allow rule (a parser sees
    /// *referenced identifiers*, not resolved columns, so allow semantics
    /// would be security theater; see the sql_policy module docs).
    ///
    /// Named columns mint `{service}:{action}:column={label}/{identifier}`.
    /// A star select (`*` / `t.*`) mints `{service}:{action}:column_star={label}`
    /// as its own label instead of a `column=` key, because a glob pattern
    /// cannot name the literal `*` without also matching everything — this
    /// way "force explicit enumeration" is the typable deny rule
    /// `{service}:*:column_star=*`, and per-column denies stay independent
    /// (`{service}:*:column=*/ssn`).
    pub fn from_sql_columns(
        service_key: &str,
        action_key: &str,
        db_label: &str,
        analysis: &crate::sql_policy::SqlAnalysis,
    ) -> Vec<Self> {
        let label = sanitize_db_label(db_label);
        dedup_preserving(analysis.columns.iter().map(|c| {
            if c == "*" {
                format!("{service_key}:{action_key}:column_star={label}")
            } else {
                format!("{service_key}:{action_key}:column={label}/{c}")
            }
        }))
        .into_iter()
        .map(Self)
        .collect()
    }
}

/// `/` separates the DB label from the relation and `=` separates the scope
/// label from the value, so a config-supplied label containing either would
/// silently change the key shape; whitespace would make keys untypable.
/// All three collapse to `-`.
fn sanitize_db_label(label: &str) -> String {
    label
        .chars()
        .map(|c| {
            if c == '/' || c == '=' || c.is_whitespace() {
                '-'
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions::matching::rule_matches;

    #[test]
    fn derive_keys_from_service_http() {
        let keys = PermissionKey::from_service_http("github", "POST", "/repos/x/pulls");
        assert_eq!(keys[0].0, "github:POST:/repos/x/pulls");
    }

    #[test]
    fn derive_keys_for_http_pseudo_service_via_service_http() {
        // The synthetic `http` pseudo-service uses the same `from_service_http`
        // builder. The path segment carries `host[:port]/path?query` (no
        // leading `/`) so the produced key matches the legacy raw-HTTP shape.
        let keys = PermissionKey::from_service_http("http", "POST", "api.github.com/repos/x/pulls");
        assert_eq!(keys[0].0, "http:POST:api.github.com/repos/x/pulls");
    }

    #[test]
    fn derive_keys_from_service_http_uppercases_method() {
        let keys = PermissionKey::from_service_http("github", "post", "/repos/x/pulls");
        assert_eq!(keys[0].0, "github:POST:/repos/x/pulls");
    }

    #[test]
    fn service_action_with_scope_param() {
        let mut params = HashMap::new();
        params.insert(
            "repo".to_string(),
            serde_json::Value::String("overfolder/backend".to_string()),
        );
        let keys = PermissionKey::from_service_action(
            "github",
            "create_pull_request",
            &"repo".into(),
            &params,
        );
        assert_eq!(
            keys[0].0,
            "github:create_pull_request:repo=overfolder/backend"
        );
    }

    #[test]
    fn service_action_array_scope_param_fans_out_per_element() {
        let mut params = HashMap::new();
        params.insert(
            "to".to_string(),
            serde_json::json!(["a@example.com", "b@example.org"]),
        );
        let keys = PermissionKey::from_service_action("email", "send", &"to".into(), &params);
        assert_eq!(
            keys.iter().map(|k| k.0.as_str()).collect::<Vec<_>>(),
            vec!["email:send:to=a@example.com", "email:send:to=b@example.org"]
        );
    }

    /// A grant scoped to one domain covers only the recipients in it; the rest
    /// stay uncovered and bubble as an approval naming just them.
    #[test]
    fn domain_scoped_rule_covers_only_matching_recipients() {
        let mut params = HashMap::new();
        params.insert(
            "to".to_string(),
            serde_json::json!(["a@example.com", "b@example.org"]),
        );
        let keys = PermissionKey::from_service_action("email", "send", &"to".into(), &params);
        let covered: Vec<&str> = keys
            .iter()
            .filter(|k| rule_matches("email:send:*@example.com", &k.0))
            .map(|k| k.0.as_str())
            .collect();
        assert_eq!(covered, vec!["email:send:to=a@example.com"]);
    }

    #[test]
    fn service_action_array_scope_param_dedups_repeated_elements() {
        let mut params = HashMap::new();
        params.insert("to".to_string(), serde_json::json!(["a@b.com", "a@b.com"]));
        let keys = PermissionKey::from_service_action("email", "send", &"to".into(), &params);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, "email:send:to=a@b.com");
    }

    #[test]
    fn service_action_empty_array_scope_param_falls_back_to_wildcard() {
        // No recipient carries no scope, so the key is as broad as a missing
        // param — and a domain-scoped rule therefore does not cover it.
        let mut params = HashMap::new();
        params.insert("to".to_string(), serde_json::json!([]));
        let keys = PermissionKey::from_service_action("email", "send", &"to".into(), &params);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, "email:send:*");
        assert!(!rule_matches("email:send:*@example.com", &keys[0].0));
    }

    #[test]
    fn service_action_scope_param_missing_value() {
        let params = HashMap::new();
        let keys = PermissionKey::from_service_action(
            "github",
            "create_pull_request",
            &"repo".into(),
            &params,
        );
        assert_eq!(keys[0].0, "github:create_pull_request:*");
    }

    #[test]
    fn service_action_no_scope_param() {
        let params = HashMap::new();
        let keys = PermissionKey::from_service_action(
            "github",
            "list_repos",
            &ScopeParams::default(),
            &params,
        );
        assert_eq!(keys[0].0, "github:list_repos:*");
    }

    /// Recipient params: a shared label puts every header in one namespace,
    /// so the same address on `to` and `cc` is one key — one approval to
    /// resolve, not two for what a human reads as a single decision.
    fn recipient_scope() -> ScopeParams {
        ScopeParams::parse_list(["to:recipient", "cc:recipient", "bcc:recipient"]).unwrap()
    }

    fn recipients(
        to: serde_json::Value,
        cc: serde_json::Value,
        bcc: serde_json::Value,
    ) -> HashMap<String, serde_json::Value> {
        HashMap::from([
            ("to".to_string(), to),
            ("cc".to_string(), cc),
            ("bcc".to_string(), bcc),
        ])
    }

    #[test]
    fn shared_label_unions_every_scoped_param() {
        let params = recipients(
            serde_json::json!(["a@example.com"]),
            serde_json::json!(["b@example.com"]),
            serde_json::json!(["c@example.net"]),
        );
        let keys = PermissionKey::from_service_action("email", "send", &recipient_scope(), &params);
        assert_eq!(
            keys.iter().map(|k| k.0.as_str()).collect::<Vec<_>>(),
            vec![
                "email:send:recipient=a@example.com",
                "email:send:recipient=b@example.com",
                "email:send:recipient=c@example.net"
            ]
        );
    }

    #[test]
    fn shared_label_collapses_an_address_on_two_headers() {
        let params = recipients(
            serde_json::json!(["a@example.com"]),
            serde_json::json!(["a@example.com"]),
            serde_json::json!([]),
        );
        let keys = PermissionKey::from_service_action("email", "send", &recipient_scope(), &params);
        assert_eq!(
            keys.iter().map(|k| k.0.as_str()).collect::<Vec<_>>(),
            vec!["email:send:recipient=a@example.com"]
        );
    }

    /// Without a shared label the params keep their own namespaces — which is
    /// the point of making the label author-controlled rather than implicit.
    #[test]
    fn unlabelled_params_keep_distinct_namespaces() {
        let params = recipients(
            serde_json::json!(["a@example.com"]),
            serde_json::json!(["a@example.com"]),
            serde_json::json!([]),
        );
        let scope = ScopeParams::parse_list(["to", "cc", "bcc"]).unwrap();
        let keys = PermissionKey::from_service_action("email", "send", &scope, &params);
        assert_eq!(
            keys.iter().map(|k| k.0.as_str()).collect::<Vec<_>>(),
            vec!["email:send:to=a@example.com", "email:send:cc=a@example.com"]
        );
    }

    #[test]
    fn scoped_params_absent_from_the_call_contribute_nothing() {
        // Only `to` was supplied; cc/bcc are simply not in the args.
        let mut params = HashMap::new();
        params.insert("to".to_string(), serde_json::json!(["a@example.com"]));
        let keys = PermissionKey::from_service_action("email", "send", &recipient_scope(), &params);
        assert_eq!(
            keys.iter().map(|k| k.0.as_str()).collect::<Vec<_>>(),
            vec!["email:send:recipient=a@example.com"]
        );
    }

    #[test]
    fn every_scoped_param_empty_falls_back_to_wildcard() {
        let params = recipients(
            serde_json::json!([]),
            serde_json::json!([]),
            serde_json::json!([]),
        );
        let keys = PermissionKey::from_service_action("email", "send", &recipient_scope(), &params);
        assert_eq!(
            keys.iter().map(|k| k.0.as_str()).collect::<Vec<_>>(),
            vec!["email:send:*"]
        );
    }

    #[test]
    fn scalar_and_array_scoped_params_mix() {
        let mut params = HashMap::new();
        params.insert("to".to_string(), serde_json::json!("a@example.com"));
        params.insert("cc".to_string(), serde_json::json!(["b@example.com"]));
        let keys = PermissionKey::from_service_action("email", "send", &recipient_scope(), &params);
        assert_eq!(
            keys.iter().map(|k| k.0.as_str()).collect::<Vec<_>>(),
            vec![
                "email:send:recipient=a@example.com",
                "email:send:recipient=b@example.com"
            ]
        );
    }

    // ── D42 SQL-policy keys ──────────────────────────────────────────────

    fn analysis(
        read_tables: &[&str],
        mut_tables: &[&str],
        columns: &[&str],
        exhaustive: bool,
    ) -> crate::sql_policy::SqlAnalysis {
        crate::sql_policy::SqlAnalysis {
            class: crate::sql_policy::SqlClass::Read,
            write_reason: None,
            read_tables: read_tables.iter().map(|s| s.to_string()).collect(),
            mut_tables: mut_tables.iter().map(|s| s.to_string()).collect(),
            columns: columns.iter().map(|s| s.to_string()).collect(),
            tables_exhaustive: exhaustive,
        }
    }

    #[test]
    fn sql_table_keys_enumerate_split_and_dedup() {
        // INSERT INTO archive SELECT … FROM public.orders JOIN users —
        // read-context relations mint `table=`, the mutation target mints
        // `table_mut=`, duplicates collapse.
        let a = analysis(
            &["public.orders", "users", "public.orders"],
            &["archive"],
            &[],
            true,
        );
        let keys = PermissionKey::from_sql_analysis("metabase", "run_query", "reveni-prod", &a);
        assert_eq!(
            keys.iter().map(|k| k.0.as_str()).collect::<Vec<_>>(),
            vec![
                "metabase:run_query:table=reveni-prod/public.orders",
                "metabase:run_query:table=reveni-prod/users",
                "metabase:run_query:table_mut=reveni-prod/archive",
            ]
        );
        // A relation both read and mutated appears under both labels.
        let a = analysis(&["a"], &["a"], &[], true);
        let keys = PermissionKey::from_sql_analysis("m", "q", "db", &a);
        assert_eq!(
            keys.iter().map(|k| k.0.as_str()).collect::<Vec<_>>(),
            vec!["m:q:table=db/a", "m:q:table_mut=db/a"]
        );
    }

    #[test]
    fn sql_table_keys_emit_mut_sentinel_when_not_exhaustive() {
        // The sentinel is mutation-shaped: every non-exhaustive case also
        // classifies write, so only a mutate-anything (or broader) grant
        // covers it.
        let a = analysis(&["orders"], &[], &[], false);
        let keys = PermissionKey::from_sql_analysis("metabase", "run_query", "prod", &a);
        assert_eq!(
            keys.iter().map(|k| k.0.as_str()).collect::<Vec<_>>(),
            vec![
                "metabase:run_query:table=prod/orders",
                "metabase:run_query:table_mut=prod/*",
            ]
        );
        // No tables at all (feature off / parse error) → sentinel only.
        let a = analysis(&[], &[], &[], false);
        let keys = PermissionKey::from_sql_analysis("metabase", "run_query", "prod", &a);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, "metabase:run_query:table_mut=prod/*");
    }

    #[test]
    fn sql_db_label_is_sanitized() {
        let a = analysis(&["t"], &[], &[], true);
        let keys = PermissionKey::from_sql_analysis("m", "q", "a/b=c d", &a);
        assert_eq!(keys[0].0, "m:q:table=a-b-c-d/t");
    }

    #[test]
    fn sql_column_keys_split_star_from_named() {
        let a = analysis(&[], &[], &["*", "id", "ssn", "id"], true);
        let keys = PermissionKey::from_sql_columns("metabase", "run_query", "prod", &a);
        assert_eq!(
            keys.iter().map(|k| k.0.as_str()).collect::<Vec<_>>(),
            vec![
                "metabase:run_query:column_star=prod",
                "metabase:run_query:column=prod/id",
                "metabase:run_query:column=prod/ssn",
            ]
        );
    }
}
