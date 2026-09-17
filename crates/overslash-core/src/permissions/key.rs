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
    /// When the database resolved to a name *and* an id, the label is the
    /// alternation group [`DbLabel`] builds, so each shape below is matched
    /// under either spelling.
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
        db: &DbLabel,
        analysis: &crate::sql_policy::SqlAnalysis,
    ) -> Vec<Self> {
        let label = db.component();
        let mut keys: Vec<Self> = dedup_preserving(
            analysis
                .read_tables
                .iter()
                .map(|t| {
                    let t = sanitize_key_component(t);
                    format!("{service_key}:{action_key}:table={label}/{t}")
                })
                .chain(analysis.mut_tables.iter().map(|t| {
                    let t = sanitize_key_component(t);
                    format!("{service_key}:{action_key}:table_mut={label}/{t}")
                })),
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
        db: &DbLabel,
        analysis: &crate::sql_policy::SqlAnalysis,
    ) -> Vec<Self> {
        let label = db.component();
        dedup_preserving(analysis.columns.iter().map(|c| {
            if c == "*" {
                format!("{service_key}:{action_key}:column_star={label}")
            } else {
                let c = sanitize_key_component(c);
                format!("{service_key}:{action_key}:column={label}/{c}")
            }
        }))
        .into_iter()
        .map(Self)
        .collect()
    }
}

/// Longest sanitized DB label. Sized so `db:{label}` still fits
/// [`crate::tags::MAX_TAG_LEN`], which keeps the scalar `db:` tag a verbatim
/// copy of the key's label rather than a truncated prefix of it. (`table:` and
/// `column:` tags can still clip on a long *relation* — they always could;
/// tags are a search index, not a record.)
const MAX_DB_LABEL_LEN: usize = crate::tags::MAX_TAG_LEN - "db:".len();

/// Collapse the characters that would change a key's **shape** rather than
/// just its text.
///
/// `/` separates the DB label from the relation and `=` separates the scope
/// label from the value, so a value containing either would silently re-slice
/// the key. `{`, `}` and `,` are glob alternation (see [`DbLabel`]), so a value
/// carrying them could forge or corrupt a brace group. Whitespace would make
/// keys untypable. All collapse to `-`.
///
/// Note `*`, `?` and `[` are *not* collapsed: they have always been
/// pattern-significant here, rules are written with them deliberately, and
/// stripping them now would silently re-target existing grants.
fn sanitize_key_component(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '/' || c == '=' || c == '{' || c == '}' || c == ',' || c.is_whitespace() {
                '-'
            } else {
                c
            }
        })
        .collect()
}

/// Sanitize a DB label: [`sanitize_key_component`], lowercased and length-capped.
///
/// Lowercasing exists because [`crate::tags::tag`] lowercases and this does not
/// — harmless while labels were numeric ids, but a database named
/// `Reveni Transactional` would otherwise tag as `db:reveni-transactional`
/// while keying as `table=Reveni-Transactional/…`, breaking the tag/key mirror
/// the two are supposed to hold. It also makes a grant survive an admin merely
/// re-capitalizing the name upstream.
fn sanitize_db_label(label: &str) -> String {
    let lowered: String = sanitize_key_component(label)
        .chars()
        .flat_map(|c| c.to_lowercase())
        .collect();
    crate::tags::truncate_on_char_boundary(lowered, MAX_DB_LABEL_LEN)
}

/// The database component of a SQL permission key: every spelling one call may
/// be granted under.
///
/// A Metabase statement against database `4` named `reveni-transactional`
/// should be grantable as either — the name is what a reviewer can judge, the
/// id is what survives an upstream rename. So the key carries both and matches
/// on either, rendered in the alternation syntax the rule engine already
/// speaks: `table={reveni-transactional,4}/public.orders`.
///
/// This is what lets the name reach permission keys at all. Keyed on the name
/// alone, a rename upstream would orphan every grant and a resolver timeout
/// would silently re-target one (the objection D42 raised, and the reason the
/// label was pinned in operator config); keyed on both, neither can happen and
/// D40's one-way compat rule holds — an existing `table=4/…` rule keeps
/// matching. [`super::matching::match_forms`] expands the group, so *allow*
/// sees one requirement with several acceptable spellings while *deny* fires
/// on any of them. Minting two separate keys instead would demand a grant on
/// both spellings, which is the opposite of what alternation means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbLabel {
    name: String,
    id: Option<String>,
}

impl DbLabel {
    /// Build from the human label and the raw upstream key it resolved from.
    ///
    /// Each side is sanitized independently, *before* the group is assembled,
    /// so neither can inject the separators the group is made of. When the two
    /// collapse to the same string the label stays single-valued — no
    /// `{prod,prod}`, and no braces around a lone value.
    pub fn new(name: &str, id: Option<&str>) -> Self {
        let name = sanitize_db_label(name);
        let id = id
            .map(sanitize_db_label)
            .filter(|i| !i.is_empty() && *i != name);
        Self { name, id }
    }

    /// The single human spelling — what tags and the audit `sql.db` carry.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The upstream id, when it differs from the name. Audit `sql.db_id`.
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    /// The key's database component: `name`, or `{name,id}` when both exist.
    fn component(&self) -> String {
        match &self.id {
            Some(id) => format!("{{{},{}}}", self.name, id),
            None => self.name.clone(),
        }
    }
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
        let keys = PermissionKey::from_sql_analysis(
            "metabase",
            "run_query",
            &DbLabel::new("reveni-prod", None),
            &a,
        );
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
        let keys = PermissionKey::from_sql_analysis("m", "q", &DbLabel::new("db", None), &a);
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
        let keys = PermissionKey::from_sql_analysis(
            "metabase",
            "run_query",
            &DbLabel::new("prod", None),
            &a,
        );
        assert_eq!(
            keys.iter().map(|k| k.0.as_str()).collect::<Vec<_>>(),
            vec![
                "metabase:run_query:table=prod/orders",
                "metabase:run_query:table_mut=prod/*",
            ]
        );
        // No tables at all (feature off / parse error) → sentinel only.
        let a = analysis(&[], &[], &[], false);
        let keys = PermissionKey::from_sql_analysis(
            "metabase",
            "run_query",
            &DbLabel::new("prod", None),
            &a,
        );
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, "metabase:run_query:table_mut=prod/*");
    }

    #[test]
    fn sql_db_label_is_sanitized() {
        let a = analysis(&["t"], &[], &[], true);
        let keys = PermissionKey::from_sql_analysis("m", "q", &DbLabel::new("a/b=c d", None), &a);
        assert_eq!(keys[0].0, "m:q:table=a-b-c-d/t");
    }

    #[test]
    fn db_label_alternates_the_name_and_the_id() {
        // The whole point: one call, grantable under either spelling, so a
        // rename upstream cannot orphan a grant written on the old name and a
        // pre-existing id-written grant keeps matching (D40).
        let a = analysis(&["public.orders"], &[], &[], true);
        let db = DbLabel::new("reveni-transactional", Some("4"));
        let keys = PermissionKey::from_sql_analysis("metabase", "run_query", &db, &a);
        assert_eq!(
            keys[0].0,
            "metabase:run_query:table={reveni-transactional,4}/public.orders"
        );
        assert_eq!(db.name(), "reveni-transactional");
        assert_eq!(db.id(), Some("4"));
    }

    #[test]
    fn db_label_collapses_when_the_name_is_the_id() {
        // No pin and no resolver answer: the name *is* the raw key, so there
        // is nothing to alternate and the key must not grow braces around a
        // lone value — `{4,4}` would be noise every reviewer has to decode.
        let a = analysis(&["t"], &[], &[], true);
        let db = DbLabel::new("4", Some("4"));
        assert_eq!(db.id(), None);
        let keys = PermissionKey::from_sql_analysis("m", "q", &db, &a);
        assert_eq!(keys[0].0, "m:q:table=4/t");
    }

    #[test]
    fn a_database_name_cannot_forge_a_brace_group() {
        // `,` is far likelier in a real database name than `/` or `=` ever
        // were, and an unsanitized one would split the group it sits in —
        // turning one alternation into two spellings nobody granted.
        let a = analysis(&["t"], &[], &[], true);
        let db = DbLabel::new("Reveni, EU {prod}", Some("4"));
        assert_eq!(db.name(), "reveni--eu--prod-");
        let keys = PermissionKey::from_sql_analysis("m", "q", &db, &a);
        assert_eq!(keys[0].0, "m:q:table={reveni--eu--prod-,4}/t");
    }

    #[test]
    fn db_label_lowercases_so_tag_and_key_agree() {
        // `tags::tag` lowercases and this did not; with numeric ids that never
        // showed, but a mixed-case name would tag one way and key another.
        assert_eq!(
            DbLabel::new("Reveni-Transactional", None).name(),
            "reveni-transactional"
        );
        // And a pathological name cannot make the `db:` tag a truncated
        // prefix of the key's label.
        let long = "x".repeat(400);
        assert_eq!(DbLabel::new(&long, None).name().len(), MAX_DB_LABEL_LEN);
    }

    #[test]
    fn sql_relation_identifiers_are_sanitized_too() {
        // A quoted Postgres identifier may legally contain the brace syntax.
        let a = analysis(&["public.or{de,rs}"], &[], &[], true);
        let db = DbLabel::new("prod", None);
        let keys = PermissionKey::from_sql_analysis("m", "q", &db, &a);
        assert_eq!(keys[0].0, "m:q:table=prod/public.or-de-rs-");
    }

    #[test]
    fn sql_column_keys_split_star_from_named() {
        let a = analysis(&[], &[], &["*", "id", "ssn", "id"], true);
        let keys = PermissionKey::from_sql_columns(
            "metabase",
            "run_query",
            &DbLabel::new("prod", None),
            &a,
        );
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
