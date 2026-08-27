//! `x-overslash-resolve` validation.
//!
//! Split out of `action.rs` because resolver rules span two scopes: most are
//! intra-action (placeholders name params on the same action), but the target
//! rules need the whole `ServiceDefinition` — the declared target has to match
//! the service runtime, and an MCP `tool:` has to name a sibling read tool.

use std::collections::HashMap;

use crate::description_grammar::{iter_placeholders, validate_flat_brackets};
use crate::template_validation::Issues;
use crate::types::{ActionParam, ParamResolver, Runtime, ServiceDefinition};

use super::action::{has_unclosed_brace, param_ident_resolvable};

/// Above this, a `scope`-bearing resolver earns a `resolver_cache_ttl_wide`
/// warning. Mirrors the deployment's default ceiling for the same case, so the
/// linter names exactly the values that would be clamped anyway.
const SCOPE_TTL_WARN_SECS: u64 = 300;

/// Intra-action resolver checks: the target and projection are each declared
/// exactly once, and every `{param}` placeholder names a param on this action.
///
/// The cross-action check — that `tool` names a sibling `risk: read` action —
/// needs the whole service and lives in [`check_resolver_targets`].
pub(super) fn check_resolver(
    resolver: &ParamResolver,
    param_name: &str,
    all_params: &HashMap<String, ActionParam>,
    base: &str,
    issues: &mut Issues,
) {
    if !resolver.has_one_target() {
        issues.err(
            "invalid_resolver_target",
            "resolver must declare exactly one of `get` (HTTP) or `tool` (MCP)",
            format!("{base}.resolve"),
        );
    }
    if resolver.get.is_some() && !resolver.args.is_empty() {
        issues.err(
            "invalid_resolver_target",
            "resolver.args applies to `tool` resolvers only; an HTTP `get` resolver \
             interpolates its placeholders into the path",
            format!("{base}.resolve.args"),
        );
    }

    // A resolver that canonicalizes the permission key is doing authorization
    // work, so a wide reuse window means a grant can be matched against a
    // mapping that is minutes out of date while the request still carries the
    // caller's raw argument. A warning rather than a clamp: the author may
    // genuinely know the mapping is immutable, and the deployment ceiling
    // clamps the effective value regardless.
    if resolver.scope.is_some()
        && resolver
            .cache_ttl
            .is_some_and(|ttl| ttl > SCOPE_TTL_WARN_SECS)
    {
        issues.warn(
            "resolver_cache_ttl_wide",
            format!(
                "resolver declares `scope` (which decides the permission key) with a \
                 cache_ttl over {SCOPE_TTL_WARN_SECS}s; a grant can then match a mapping \
                 that stale while the call still targets the raw argument"
            ),
            format!("{base}.resolve.cache_ttl"),
        );
    }

    if resolver.display.is_some() && resolver.pick.is_some() {
        issues.err(
            "invalid_resolver_projection",
            "resolver declares both `pick` and `display`; `pick` is the single-path \
             shorthand for `display`, so declare one",
            format!("{base}.resolve"),
        );
    }
    // `{param}` placeholders in `get` and `args` name params of the action
    // being called. Placeholders in `display` name dot-paths in the resolver
    // *response*, which the template can't know here — those are checked at
    // runtime by falling back to the raw value.
    let mut check_placeholders = |text: &str, field: &str| {
        if has_unclosed_brace(text) {
            issues.err(
                "invalid_path_syntax",
                format!("resolver.{field} has an unclosed '{{' placeholder"),
                format!("{base}.resolve.{field}"),
            );
        }
        for (_, ident) in iter_placeholders(text) {
            // Dotted idents are legal here: `substitute_placeholders`
            // descends nested objects, so `{query.database}` resolves against
            // an object-valued `query` param. Only the head is checkable.
            if !param_ident_resolvable(all_params, ident) {
                issues.err(
                    "unknown_resolver_param",
                    format!(
                        "resolver placeholder {{{ident}}} does not reference a defined param on this action"
                    ),
                    format!("{base}.resolve.{field}"),
                );
            }
        }
    };
    if let Some(ref get) = resolver.get {
        check_placeholders(get, "get");
    }
    for (name, value) in &resolver.args {
        check_placeholders(value, &format!("args.{name}"));
    }

    // An array-valued param fans out one permission key per element
    // (`scope_param: [to, cc, bcc]` on an email send). A single canonical
    // string cannot stand in for that list without collapsing the fan-out
    // into one key covering addresses the reviewer never saw, so refuse the
    // combination outright rather than silently widening a grant.
    if resolver.scope.is_some()
        && all_params
            .get(param_name)
            .is_some_and(|p| p.param_type == "array")
    {
        issues.err(
            "invalid_resolver_scope",
            "resolver.scope is not supported on an array param: each element mints its own \
             permission key, and one canonical value cannot replace the list",
            format!("{base}.resolve.scope"),
        );
    }

    // Projection checks last, so a resolver that is missing its projection
    // *and* references a `{ghost}` param reports both in one pass instead of
    // making the author fix one to discover the other.
    let Some(display) = resolver.display_template() else {
        issues.err(
            "missing_field",
            "resolver must declare `pick` or `display`",
            format!("{base}.resolve"),
        );
        return;
    };

    // The display template shares the description grammar, so a stray bracket
    // silently swallows the rest of the field rather than erroring at runtime,
    // and an unclosed `{` renders as a literal `{name` in the approval.
    if resolver.display.is_some() {
        if validate_flat_brackets(&display).is_err() {
            issues.err(
                "unbalanced_brackets",
                "resolver.display has unbalanced or nested '[...]' segments",
                format!("{base}.resolve.display"),
            );
        }
        if has_unclosed_brace(&display) {
            issues.err(
                "invalid_path_syntax",
                "resolver.display has an unclosed '{' placeholder",
                format!("{base}.resolve.display"),
            );
        }
    }

    // Measured on the declared paths, not the assembled template: `pick: ""`
    // renders as `{}`, which is non-empty as a string but names nothing, and
    // `iter_placeholders` skips empty idents — so it would reach an approval
    // as a literal `{}` where the contact's name should be.
    let projection_is_blank = match (&resolver.display, &resolver.pick) {
        (Some(display), _) => display.trim().is_empty(),
        (None, Some(pick)) => pick.trim().is_empty(),
        (None, None) => true,
    };
    if projection_is_blank {
        issues.err(
            "missing_field",
            "resolver projection is empty",
            format!("{base}.resolve"),
        );
    }
}

/// Service-level resolver checks.
///
/// Two things only the whole definition can decide:
///
/// 1. The declared target matches the service runtime. The dispatchers select
///    on exactly that field (`resolver.get.as_ref()?` / `resolver.tool
///    .as_ref()?`), so `get:` on an MCP action — or `tool:` on an HTTP one —
///    would compile clean and then never run. That silent no-op is the whole
///    reason `parse_resolver` stopped dropping half-declared resolvers.
/// 2. An MCP `tool:` names a sibling `risk: read` tool. A resolver runs on the
///    approval path, before the human has seen anything, so letting one point
///    at a write would make the act of *reviewing* a call perform a mutation.
pub(super) fn check_resolver_targets(def: &ServiceDefinition, issues: &mut Issues) {
    let mut action_keys: Vec<&String> = def.actions.keys().collect();
    action_keys.sort();
    for key in action_keys {
        let action = &def.actions[key];
        let mut param_names: Vec<&String> = action.params.keys().collect();
        param_names.sort();
        for name in param_names {
            let Some(resolver) = action.params[name].resolve.as_ref() else {
                continue;
            };
            let base = format!("actions.{key}.params.{name}.resolve");

            match (def.runtime, resolver.get.is_some(), resolver.tool.is_some()) {
                (Runtime::Mcp, true, _) => issues.err(
                    "invalid_resolver_target",
                    "resolver.get is an HTTP-runtime target; an MCP action resolves through \
                     `tool:` + `args:`",
                    format!("{base}.get"),
                ),
                (Runtime::Http, _, true) => issues.err(
                    "invalid_resolver_target",
                    "resolver.tool is an MCP-runtime target; an HTTP action resolves through \
                     `get:`",
                    format!("{base}.tool"),
                ),
                _ => {}
            }

            let Some(tool) = resolver.tool.as_deref() else {
                continue;
            };
            // Match on the *wire* name, the one the resolver dispatches
            // verbatim — `mcp_tool` when the tool name isn't a valid action
            // key (`some-list-tool` lowering to key `some_list_tool`),
            // otherwise the key itself. Accepting the action key for a
            // renamed tool would validate clean and then call a name the
            // server does not have.
            let target = def
                .actions
                .iter()
                .find(|(k, a)| a.mcp_tool.as_deref().unwrap_or(k.as_str()) == tool);
            match target {
                None => issues.err(
                    "unknown_resolver_tool",
                    format!("resolver tool {tool:?} is not a tool on this service"),
                    format!("{base}.tool"),
                ),
                Some((_, target)) if target.risk.display_risk().is_mutating() => issues.err(
                    "invalid_resolver_tool",
                    format!(
                        "resolver tool {tool:?} is risk {}; resolvers run before approval and must be read-only",
                        target.risk.display_risk()
                    ),
                    format!("{base}.tool"),
                ),
                Some(_) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::template_validation::core::tests::{minimal_mcp, minimal_valid, param, run};
    use crate::types::{McpAuth, ParamResolver, Risk, ServiceAction, ServiceDefinition};
    use std::collections::HashMap;

    /// A wide `cache_ttl` on a `scope`-bearing resolver is warned about, not
    /// rejected: the author may know the mapping is immutable, but they should
    /// have to know they're widening an authorization window to do it.
    #[test]
    fn a_wide_cache_ttl_on_a_scope_resolver_warns() {
        let mut d = minimal_valid();
        let a = d.actions.get_mut("list").unwrap();
        let mut p = param("string", false);
        p.resolve = Some(ParamResolver {
            get: Some("/items/{x}".into()),
            pick: Some("name".into()),
            scope: Some("phone".into()),
            cache_ttl: Some(3600),
            ..Default::default()
        });
        a.params.insert("x".into(), p);
        let r = run(&d);
        assert!(
            r.warnings
                .iter()
                .any(|w| w.code == "resolver_cache_ttl_wide")
        );
        assert!(
            r.errors.is_empty(),
            "a warning, not an error: {:?}",
            r.errors
        );
    }

    /// The same wide TTL without `scope` is unremarkable — nothing about a
    /// display string decides which grant matches.
    #[test]
    fn a_wide_cache_ttl_without_scope_is_silent() {
        let mut d = minimal_valid();
        let a = d.actions.get_mut("list").unwrap();
        let mut p = param("string", false);
        p.resolve = Some(ParamResolver {
            get: Some("/items/{x}".into()),
            pick: Some("name".into()),
            cache_ttl: Some(86_400),
            ..Default::default()
        });
        a.params.insert("x".into(), p);
        let r = run(&d);
        assert!(
            !r.warnings
                .iter()
                .any(|w| w.code == "resolver_cache_ttl_wide")
        );
    }

    #[test]
    fn unknown_resolver_param() {
        let mut d = minimal_valid();
        let a = d.actions.get_mut("list").unwrap();
        let mut p = param("string", false);
        p.resolve = Some(ParamResolver {
            get: Some("/items/{ghost}".into()),
            pick: Some("name".into()),
            ..Default::default()
        });
        a.params.insert("x".into(), p);
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "unknown_resolver_param"));
    }

    /// An MCP resolver's `args` are just as much a placeholder surface as an
    /// HTTP resolver's path — a typo there is the same silent-no-op bug.
    #[test]
    fn unknown_resolver_param_in_mcp_args() {
        let mut d = mcp_with_resolver(ParamResolver {
            tool: Some("lookup".into()),
            args: [("jid".to_string(), "{ghost}".to_string())]
                .into_iter()
                .collect(),
            display: Some("{name}".into()),
            ..Default::default()
        });
        d.actions.get_mut("send").unwrap().risk = Risk::Write.into();
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "unknown_resolver_param"));
    }

    /// The export_query shape: the resolver reaches an id nested inside an
    /// object-valued body param, so only the head segment is a declared param.
    #[test]
    fn resolver_dotted_placeholder_checks_only_the_head_segment() {
        let mut d = minimal_valid();
        let a = d.actions.get_mut("list").unwrap();
        let mut p = param("object", false);
        p.resolve = Some(ParamResolver {
            get: Some("/api/database/{query.database}".into()),
            pick: Some("name".into()),
            ..Default::default()
        });
        a.params.insert("query".into(), p);
        let r = run(&d);
        assert!(!r.errors.iter().any(|e| e.code == "unknown_resolver_param"));
    }

    #[test]
    fn resolver_dotted_placeholder_with_unknown_head_is_still_reported() {
        let mut d = minimal_valid();
        let a = d.actions.get_mut("list").unwrap();
        let mut p = param("object", false);
        p.resolve = Some(ParamResolver {
            get: Some("/api/database/{ghost.database}".into()),
            pick: Some("name".into()),
            ..Default::default()
        });
        a.params.insert("query".into(), p);
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "unknown_resolver_param"));
    }

    #[test]
    fn resolver_needs_exactly_one_target() {
        for resolver in [
            ParamResolver {
                pick: Some("name".into()),
                ..Default::default()
            },
            ParamResolver {
                get: Some("/x".into()),
                tool: Some("lookup".into()),
                pick: Some("name".into()),
                ..Default::default()
            },
        ] {
            let r = run(&mcp_with_resolver(resolver));
            assert!(
                r.errors.iter().any(|e| e.code == "invalid_resolver_target"),
                "expected invalid_resolver_target, got {:?}",
                r.errors
            );
        }
    }

    #[test]
    fn resolver_needs_a_projection() {
        let r = run(&mcp_with_resolver(ParamResolver {
            tool: Some("lookup".into()),
            ..Default::default()
        }));
        assert!(r.errors.iter().any(|e| e.code == "missing_field"));
    }

    #[test]
    fn resolver_rejects_both_pick_and_display() {
        let r = run(&mcp_with_resolver(ParamResolver {
            tool: Some("lookup".into()),
            pick: Some("name".into()),
            display: Some("{name}".into()),
            ..Default::default()
        }));
        assert!(
            r.errors
                .iter()
                .any(|e| e.code == "invalid_resolver_projection")
        );
    }

    #[test]
    fn resolver_tool_must_exist_on_this_service() {
        let r = run(&mcp_with_resolver(ParamResolver {
            tool: Some("nope".into()),
            display: Some("{name}".into()),
            ..Default::default()
        }));
        assert!(r.errors.iter().any(|e| e.code == "unknown_resolver_tool"));
    }

    /// Resolvers run on the approval path, before a human has seen anything.
    /// A resolver pointed at a write would make *reviewing* a call mutate.
    #[test]
    fn resolver_tool_must_be_read_only() {
        let mut d = mcp_with_resolver(ParamResolver {
            tool: Some("lookup".into()),
            display: Some("{name}".into()),
            ..Default::default()
        });
        d.actions.get_mut("lookup").unwrap().risk = Risk::Write.into();
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "invalid_resolver_tool"));
    }

    /// An array param mints one key per element; a single canonical string
    /// would collapse that into one key covering addresses nobody reviewed.
    #[test]
    fn resolver_scope_is_rejected_on_an_array_param() {
        let mut d = mcp_with_resolver(ParamResolver {
            tool: Some("lookup".into()),
            display: Some("{name}".into()),
            scope: Some("phone".into()),
            ..Default::default()
        });
        d.actions
            .get_mut("send")
            .unwrap()
            .params
            .get_mut("recipient")
            .unwrap()
            .param_type = "array".into();
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "invalid_resolver_scope"));
    }

    /// The dispatchers select on the target field, so a target that does not
    /// match the runtime never runs. Compiling clean would reproduce exactly
    /// the silent no-op this validation exists to eliminate.
    #[test]
    fn resolver_target_must_match_the_service_runtime() {
        let mcp = mcp_with_resolver(ParamResolver {
            get: Some("/lookup/{recipient}".into()),
            pick: Some("name".into()),
            ..Default::default()
        });
        let r = run(&mcp);
        assert!(
            r.errors.iter().any(|e| e.code == "invalid_resolver_target"),
            "`get:` on an MCP action must be rejected: {:?}",
            r.errors
        );

        let mut http = minimal_valid();
        let mut p = param("string", false);
        p.resolve = Some(ParamResolver {
            tool: Some("lookup".into()),
            display: Some("{name}".into()),
            ..Default::default()
        });
        http.actions
            .get_mut("list")
            .unwrap()
            .params
            .insert("x".into(), p);
        let r = run(&http);
        assert!(
            r.errors.iter().any(|e| e.code == "invalid_resolver_target"),
            "`tool:` on an HTTP action must be rejected: {:?}",
            r.errors
        );
    }

    /// The resolver dispatches `tool` verbatim, so validation must match the
    /// wire name. Accepting the action key for a tool whose wire name was
    /// rewritten (`some-list-tool` → key `some_list_tool`) would validate
    /// clean and then call a name the server does not have.
    #[test]
    fn resolver_tool_matches_the_wire_name_not_the_action_key() {
        let mut d = mcp_with_resolver(ParamResolver {
            tool: Some("lookup".into()),
            display: Some("{name}".into()),
            ..Default::default()
        });
        d.actions.get_mut("lookup").unwrap().mcp_tool = Some("look-up".into());
        let r = run(&d);
        assert!(
            r.errors.iter().any(|e| e.code == "unknown_resolver_tool"),
            "action key must not stand in for a renamed wire name: {:?}",
            r.errors
        );

        // The wire name itself resolves.
        let mut d = mcp_with_resolver(ParamResolver {
            tool: Some("look-up".into()),
            display: Some("{name}".into()),
            ..Default::default()
        });
        d.actions.get_mut("lookup").unwrap().mcp_tool = Some("look-up".into());
        let r = run(&d);
        assert!(!r.errors.iter().any(|e| e.code == "unknown_resolver_tool"));
    }

    /// `pick: ""` renders as `{}` — non-empty as a string, but it names
    /// nothing and `iter_placeholders` skips empty idents, so it would reach
    /// an approval as a literal `{}`.
    #[test]
    fn resolver_rejects_a_blank_pick() {
        for pick in ["", "   "] {
            let r = run(&mcp_with_resolver(ParamResolver {
                tool: Some("lookup".into()),
                pick: Some(pick.into()),
                ..Default::default()
            }));
            assert!(
                r.errors.iter().any(|e| e.code == "missing_field"),
                "pick {pick:?} must be rejected: {:?}",
                r.errors
            );
        }
    }

    #[test]
    fn resolver_display_rejects_an_unclosed_brace() {
        let r = run(&mcp_with_resolver(ParamResolver {
            tool: Some("lookup".into()),
            display: Some("{name".into()),
            ..Default::default()
        }));
        assert!(r.errors.iter().any(|e| e.code == "invalid_path_syntax"));
    }

    /// A missing projection must not mask a bad `{param}` reference — both
    /// land in one pass so the author needs one round-trip, not two.
    #[test]
    fn missing_projection_still_reports_placeholder_errors() {
        let r = run(&mcp_with_resolver(ParamResolver {
            tool: Some("lookup".into()),
            args: [("jid".to_string(), "{ghost}".to_string())]
                .into_iter()
                .collect(),
            ..Default::default()
        }));
        assert!(r.errors.iter().any(|e| e.code == "missing_field"));
        assert!(r.errors.iter().any(|e| e.code == "unknown_resolver_param"));
    }

    #[test]
    fn well_formed_mcp_resolver_is_accepted() {
        let r = run(&mcp_with_resolver(ParamResolver {
            tool: Some("lookup".into()),
            args: [("jid".to_string(), "{recipient}".to_string())]
                .into_iter()
                .collect(),
            display: Some("{name}[ ({phone})]".into()),
            scope: Some("phone".into()),
            ..Default::default()
        }));
        assert!(
            !r.errors
                .iter()
                .any(|e| e.code.starts_with("invalid_resolver")
                    || e.code == "unknown_resolver_tool"
                    || e.code == "unknown_resolver_param"),
            "well-formed resolver rejected: {:?}",
            r.errors
        );
    }

    /// An MCP service with a `send` action whose `recipient` param carries
    /// `resolver`, plus a read `lookup` tool for it to point at.
    fn mcp_with_resolver(resolver: ParamResolver) -> ServiceDefinition {
        let mut d = minimal_mcp(McpAuth::None);
        let mut recipient = param("string", true);
        recipient.resolve = Some(resolver);
        d.actions.insert(
            "send".into(),
            mcp_action("send", Risk::Write, {
                let mut m = HashMap::new();
                m.insert("recipient".to_string(), recipient);
                m
            }),
        );
        d.actions.insert(
            "lookup".into(),
            mcp_action("lookup", Risk::Read, HashMap::new()),
        );
        d
    }

    fn mcp_action(
        tool: &str,
        risk: Risk,
        params: HashMap<String, crate::types::ActionParam>,
    ) -> ServiceAction {
        ServiceAction {
            wait_mode: None,
            handoff_after_ms: None,
            pagination: None,
            timeout_ms: None,
            method: String::new(),
            path: String::new(),
            description: format!("{tool} something"),
            summary: None,
            risk: risk.into(),
            response_type: None,
            params,
            scope_param: Default::default(),
            required_scopes: Vec::new(),
            permission: None,
            disclose: Vec::new(),
            redact: Vec::new(),
            mcp_tool: Some(tool.into()),
            output_schema: None,
            disabled: false,
            request_body: None,
            download: None,
        }
    }
}
