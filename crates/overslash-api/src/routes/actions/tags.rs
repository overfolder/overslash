//! Call-context metadata tags: the non-SQL half of the tag vocabulary.
//!
//! [`overslash_core::tags`] owns the format and the SQL facts; this module
//! answers the questions that need the resolved request in hand — which
//! service, which instance, which account, which host, which dispatch fork.
//!
//! Tags are minted once per gated call and then persisted three times: on the
//! approval, on the execution copied from it, and on the audit rows for both.
//! Nothing here reads caller-supplied input, so a tag is always a fact
//! Overslash established, never a claim the caller made.

pub(super) use overslash_core::tags::with_outcome;
use overslash_core::tags::{clamp, sql_tags, tag};
use overslash_core::types::service::Risk;

use super::dto::{BindingFacts, ResolvedMeta, SqlPolicyOutcome};

/// Which dispatch fork ran. The four are separately observable because they
/// fail in different ways — an MCP tool's in-band error and an upstream 5xx
/// are not the same incident, and before tagging existed only the buffered
/// HTTP fork recorded anything at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Transport {
    Http,
    Stream,
    Mcp,
    Platform,
}

impl Transport {
    /// Which fork *will* run, derived from the resolved request.
    ///
    /// The approval is minted before dispatch and the audit row after it, so
    /// both need this answer; deriving it in one place is what keeps an
    /// approval's `transport:` tag from disagreeing with its execution's.
    pub(super) fn of(meta: &ResolvedMeta, prefer_stream: bool) -> Self {
        if meta.mcp_target.is_some() {
            Transport::Mcp
        } else if meta.platform_target.is_some() {
            Transport::Platform
        } else if prefer_stream {
            Transport::Stream
        } else {
            Transport::Http
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Transport::Http => "http",
            Transport::Stream => "stream",
            Transport::Mcp => "mcp",
            Transport::Platform => "platform",
        }
    }
}

/// Execution mode (SPEC §8): raw HTTP, connection-based, or service+action.
fn mode_tag(meta: &ResolvedMeta) -> &'static str {
    match &meta.service_scope {
        // `service: "http"` is the raw-HTTP pseudo-service (Mode A).
        Some(s) if s.service_key == "http" => "a",
        // A verb shape against a real service is connection-based (Mode B);
        // a named action is the full service+action shape (Mode C).
        Some(s) if s.http_verb.is_some() => "b",
        Some(_) => "c",
        None => "a",
    }
}

/// Host of the upstream this call targets. Absent for the platform runtime,
/// which makes no outgoing call at all.
fn host_of(url: &str) -> Option<String> {
    // The resolved URL is already absolute for every shape that has one; a
    // relative or malformed URL simply yields no host tag rather than a
    // misleading one.
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
}

/// Mint the full tag set for one gated call.
///
/// `url` is the resolved upstream URL (empty for platform/MCP-less shapes).
/// `outcome` is appended by the audit-write sites, which are the only ones
/// that know whether the call succeeded — approvals are minted before dispatch.
pub(super) fn call_tags(
    meta: &ResolvedMeta,
    sql: Option<&SqlPolicyOutcome>,
    effective: Risk,
    transport: Transport,
    url: &str,
) -> Vec<String> {
    let mut tags = Vec::new();

    if let Some(scope) = &meta.service_scope {
        tags.push(tag("service", &scope.service_key));
        // The verb shape has no action key; its method+path is the identity,
        // and `method:` below already carries the useful half.
        if !scope.action_key.is_empty() {
            tags.push(tag("action", &scope.action_key));
        }
    }

    let BindingFacts {
        template_key,
        instance_name,
        principal,
    } = &meta.binding;
    if let Some(t) = template_key {
        tags.push(tag("template", t));
    }
    if let Some(i) = instance_name {
        tags.push(tag("instance", i));
    }
    if let Some(p) = principal {
        tags.push(tag("connection", p));
    }

    if let Some(h) = host_of(url) {
        tags.push(tag("host", &h));
    }

    let method = meta
        .service_scope
        .as_ref()
        .and_then(|s| s.http_verb.as_ref())
        .map(|v| v.method.clone());
    if let Some(m) = method {
        tags.push(tag("method", &m));
    }

    tags.push(tag("mode", mode_tag(meta)));
    tags.push(tag("transport", transport.as_str()));
    // The *effective* risk — after the SQL classifier merged into the
    // template's declared risk. Tagging the declared one would say `read` for
    // a `dynamic` action carrying an UPDATE.
    tags.push(tag("risk", &effective.to_string()));

    if let Some(sp) = sql {
        tags.extend(sql_tags(&sp.db_label, &sp.analysis));
    }

    clamp(tags)
}

/// The `sql` audit block for one evaluated policy outcome: the DB label, the
/// classification, which fail-closed rule fired (for writes), and the relations
/// and columns the statement referenced. The raw query itself travels via the
/// template's `disclose` filters.
///
/// This is the *record*; the metadata tags minted alongside it are the search
/// index. The two differ on purpose — `reason_detail` carries the unbounded
/// payload (a parse error's message, the parse-node name) that `write_reason`'s
/// short tag flattens away and that a tag has no business holding.
pub(super) fn sql_audit_block(sp: &SqlPolicyOutcome) -> serde_json::Value {
    use overslash_core::sql_policy::WriteReason;
    let a = &sp.analysis;
    serde_json::json!({
        "db": sp.db_label,
        "classified": sp.floor.to_string(),
        "write_reason": a.write_reason.as_ref().map(|r| r.tag()),
        "reason_detail": a.write_reason.as_ref().and_then(|r| match r {
            WriteReason::UnsupportedDialect(s) | WriteReason::ParseError(s)
            | WriteReason::Statement(s) | WriteReason::UnsafeFunction(s) => Some(s.clone()),
            WriteReason::MultiStatement(n) => Some(n.to_string()),
            _ => None,
        }),
        "read_tables": a.read_tables,
        "mut_tables": a.mut_tables,
        "columns": a.columns,
        "tables_exhaustive": a.tables_exhaustive,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::actions::dto::{HttpVerb, ServiceScope};

    fn meta(scope: Option<ServiceScope>, binding: BindingFacts) -> ResolvedMeta {
        ResolvedMeta {
            action_timeout_ms: None,
            service_timeout_ms: None,
            description: None,
            service_scope: scope,
            risk: None,
            disclose: Vec::new(),
            redact: Vec::new(),
            oauth_injected: false,
            download: None,
            params: Default::default(),
            resolved: Default::default(),
            canonical: Default::default(),
            mcp_target: None,
            platform_target: None,
            instance_id: None,
            binding,
        }
    }

    fn action_scope() -> ServiceScope {
        ServiceScope {
            service_key: "metabase".into(),
            action_key: "run_native_query".into(),
            scope_param: Default::default(),
            http_verb: None,
        }
    }

    #[test]
    fn service_action_shape_tags_mode_c() {
        let tags = call_tags(
            &meta(Some(action_scope()), BindingFacts::default()),
            None,
            Risk::Read,
            Transport::Http,
            "https://metabase.acme.internal/api/dataset",
        );
        assert!(tags.contains(&"service:metabase".to_string()));
        assert!(tags.contains(&"action:run_native_query".to_string()));
        assert!(tags.contains(&"host:metabase.acme.internal".to_string()));
        assert!(tags.contains(&"mode:c".to_string()));
        assert!(tags.contains(&"transport:http".to_string()));
        assert!(tags.contains(&"risk:read".to_string()));
    }

    #[test]
    fn raw_http_is_mode_a_and_verb_shape_is_mode_b() {
        let raw = ServiceScope {
            service_key: "http".into(),
            action_key: String::new(),
            scope_param: Default::default(),
            http_verb: Some(HttpVerb {
                method: "POST".into(),
                path: "/x".into(),
            }),
        };
        let tags = call_tags(
            &meta(Some(raw), BindingFacts::default()),
            None,
            Risk::Write,
            Transport::Http,
            "https://api.example.com/x",
        );
        assert!(tags.contains(&"mode:a".to_string()));
        assert!(tags.contains(&"method:post".to_string()));
        // The verb shape has no action key — it must not emit an empty tag.
        assert!(tags.iter().all(|t| t != "action:"));

        let verb = ServiceScope {
            service_key: "github".into(),
            action_key: String::new(),
            scope_param: Default::default(),
            http_verb: Some(HttpVerb {
                method: "GET".into(),
                path: "/repos".into(),
            }),
        };
        let tags = call_tags(
            &meta(Some(verb), BindingFacts::default()),
            None,
            Risk::Read,
            Transport::Http,
            "https://api.github.com/repos",
        );
        assert!(tags.contains(&"mode:b".to_string()));
    }

    #[test]
    fn binding_facts_become_tags() {
        let binding = BindingFacts {
            template_key: Some("metabase".into()),
            instance_name: Some("Prod Warehouse".into()),
            principal: Some("analytics@acme.com".into()),
        };
        let tags = call_tags(
            &meta(Some(action_scope()), binding),
            None,
            Risk::Read,
            Transport::Http,
            "https://metabase.acme.internal/api/dataset",
        );
        assert!(tags.contains(&"template:metabase".to_string()));
        assert!(tags.contains(&"instance:prod-warehouse".to_string()));
        assert!(tags.contains(&"connection:analytics@acme.com".to_string()));
    }

    #[test]
    fn platform_shape_emits_no_host() {
        let tags = call_tags(
            &meta(Some(action_scope()), BindingFacts::default()),
            None,
            Risk::Read,
            Transport::Platform,
            "",
        );
        assert!(tags.iter().all(|t| !t.starts_with("host:")));
        assert!(tags.contains(&"transport:platform".to_string()));
    }

    #[test]
    fn sql_facts_merge_in() {
        use overslash_core::sql_policy::{SqlAnalysis, SqlClass, WriteReason};
        let sp = SqlPolicyOutcome {
            floor: Risk::Write,
            table_keys: Vec::new(),
            column_keys: Vec::new(),
            db_label: "warehouse".into(),
            analysis: SqlAnalysis {
                class: SqlClass::Write,
                write_reason: Some(WriteReason::WritableCte),
                read_tables: vec!["public.orders".into()],
                mut_tables: vec!["public.audit".into()],
                columns: vec!["email".into()],
                tables_exhaustive: true,
            },
        };
        let tags = call_tags(
            &meta(Some(action_scope()), BindingFacts::default()),
            Some(&sp),
            Risk::Write,
            Transport::Http,
            "https://metabase.acme.internal/api/dataset",
        );
        assert!(tags.contains(&"sql:write".to_string()));
        assert!(tags.contains(&"sql_reason:writable_cte".to_string()));
        assert!(tags.contains(&"db:warehouse".to_string()));
        assert!(tags.contains(&"table:warehouse/public.orders".to_string()));
        assert!(tags.contains(&"table_mut:warehouse/public.audit".to_string()));
        assert!(tags.contains(&"column:warehouse/email".to_string()));
        // Effective risk, not the classifier floor in isolation.
        assert!(tags.contains(&"risk:write".to_string()));
    }

    #[test]
    fn outcome_is_appended_once() {
        let tags = with_outcome(vec!["service:metabase".into()], true);
        assert!(tags.contains(&"outcome:error".to_string()));
        let tags = with_outcome(tags, true);
        assert_eq!(
            tags.iter().filter(|t| t.starts_with("outcome:")).count(),
            1,
            "clamp() dedupes, so re-tagging the same outcome must not double it"
        );
    }
}
