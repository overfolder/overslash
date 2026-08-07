use crate::description_grammar::{iter_placeholders, validate_flat_brackets};
use crate::template_validation::Issues;
use crate::types::{ActionParam, DeclaredRisk, ServiceAction};

use super::sql_policy::check_sql_policy;

fn is_valid_action_key(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

// --- per-action ------------------------------------------------------------

const VALID_HTTP_METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
// `""` is the "type unspecified" sentinel produced by the OpenAPI loader for
// params with no concrete `type` (anyOf/oneOf/untyped); it is valid and simply
// opts the param out of runtime type checks.
const VALID_PARAM_TYPES: &[&str] = &[
    "", "string", "number", "integer", "boolean", "array", "object",
];
const VALID_RESPONSE_TYPES: &[&str] = &["json", "binary"];

pub(super) fn check_action(key: &str, action: &ServiceAction, issues: &mut Issues) {
    let action_path = format!("actions.{key}");

    if !is_valid_action_key(key) {
        issues.err(
            "invalid_action_key",
            "action key must match ^[a-z][a-z0-9_]*$",
            action_path.clone(),
        );
    }

    // Platform-namespace actions (e.g. overslash.yaml) have no method/path
    // and are used only as permission anchors. Skip HTTP-specific checks
    // when method is absent.
    let has_http = !action.method.is_empty();

    if has_http {
        let method_upper = action.method.to_uppercase();
        if !VALID_HTTP_METHODS.contains(&method_upper.as_str()) {
            issues.err(
                "invalid_http_method",
                format!(
                    "method {:?} is not a valid HTTP method (expected one of {VALID_HTTP_METHODS:?})",
                    action.method
                ),
                format!("{action_path}.method"),
            );
        } else {
            // Rule 15: risk plausibility warning — only when risk is
            // EXPLICITLY mismatched. Since `Risk` defaults to `Read` at the
            // type level, we can't tell "omitted" from "explicit read" without
            // the raw JSON; the JSON entry point annotates this via a
            // secondary pass (see json.rs).
            check_risk_method_plausibility(&method_upper, action.risk, &action_path, issues);
        }
    }

    // Path validation: only required when HTTP.
    if has_http {
        check_action_path(&action.path, &action.params, &action_path, issues);
    }

    // Description required for HTTP + platform actions, optional for MCP
    // tools — the MCP spec declares the tool description as optional, and
    // tools/list responses frequently omit it for trivial utilities.
    // Placeholder / bracket syntax is still checked when a description is
    // present, regardless of runtime.
    let is_mcp_action = action.mcp_tool.is_some();
    check_description(
        &action.description,
        action.summary.as_deref(),
        &action.params,
        &action_path,
        is_mcp_action,
        issues,
    );

    // Params validation (type, enum, resolvers).
    for (name, param) in &action.params {
        check_param(name, param, &action.params, &action_path, issues);
    }

    // Every scope_param entry must reference an existing param. The *label*
    // half needs no check — it names a permission namespace the author invents
    // (`to:recipient`), not something the schema declares.
    for scope in action.scope_param.refs() {
        if !action.params.contains_key(&scope.param) {
            issues.err(
                "unknown_scope_param",
                format!(
                    "scope_param {:?} does not reference a defined param",
                    scope.param
                ),
                format!("{action_path}.scope_param"),
            );
        }
    }

    // response_type must be json or binary if set.
    if let Some(ref rt) = action.response_type
        && !VALID_RESPONSE_TYPES.contains(&rt.as_str())
    {
        issues.err(
            "invalid_response_type",
            format!("response_type {rt:?} must be \"json\" or \"binary\""),
            format!("{action_path}.response_type"),
        );
    }

    check_sql_policy(action, &action_path, issues);
}

pub(super) fn check_platform_action(key: &str, action: &ServiceAction, issues: &mut Issues) {
    let action_path = format!("actions.{key}");

    if !is_valid_action_key(key) {
        issues.err(
            "invalid_action_key",
            "action key must match ^[a-z][a-z0-9_]*$",
            action_path.clone(),
        );
    }

    if !action.method.is_empty() {
        issues.err(
            "platform_has_method",
            "platform actions must not declare a method",
            format!("{action_path}.method"),
        );
    }
    if !action.path.is_empty() {
        issues.err(
            "platform_has_path",
            "platform actions must not declare a path",
            format!("{action_path}.path"),
        );
    }

    if action.description.trim().is_empty() {
        issues.err(
            "missing_description",
            "description is required",
            format!("{action_path}.description"),
        );
    }

    if let Some(ref perm) = action.permission
        && !is_valid_action_key(perm)
    {
        issues.err(
            "invalid_permission_key",
            format!("permission {perm:?} must match ^[a-z][a-z0-9_]*$"),
            format!("{action_path}.permission"),
        );
    }

    for (name, param) in &action.params {
        check_param(name, param, &action.params, &action_path, issues);
    }
}

fn check_risk_method_plausibility(
    method_upper: &str,
    risk: DeclaredRisk,
    action_path: &str,
    issues: &mut Issues,
) {
    // `dynamic` is classified per call — a GET action carrying SQL in a
    // query param is a legitimate shape, so no method plausibility applies.
    if risk.is_dynamic() {
        return;
    }
    let risk = risk.display_risk();
    // We warn only on clear mismatches. Since `Risk::Read` is the serde
    // default, a POST action without an explicit `risk` field is
    // indistinguishable from POST + `risk: read` here — so we can't warn on
    // "omitted risk on a mutating method" at the struct level without losing
    // true positives. Instead we warn on:
    //   - read-only methods marked write/delete
    //   - (explicit) mutating methods left as `read` when that doesn't match
    //
    // The second case is checked at the JSON layer where we still have the
    // raw value and can distinguish omitted vs explicit. Here we only catch
    // the first case, which is always a real mismatch.
    let is_read_method = matches!(method_upper, "GET" | "HEAD" | "OPTIONS");
    if is_read_method && risk.is_mutating() {
        issues.warn(
            "risk_method_mismatch",
            format!("{method_upper} is a read-only method but risk is {risk}"),
            format!("{action_path}.risk"),
        );
    }
}

fn check_action_path(
    path: &str,
    params: &std::collections::HashMap<String, ActionParam>,
    action_path: &str,
    issues: &mut Issues,
) {
    if path.is_empty() {
        issues.err(
            "missing_field",
            "action path is required for HTTP actions",
            format!("{action_path}.path"),
        );
        return;
    }
    if !path.starts_with('/') {
        issues.err(
            "invalid_path_syntax",
            "action path must start with '/'",
            format!("{action_path}.path"),
        );
    }

    // Check for unclosed `{` — iter_placeholders skips them silently, so we
    // detect them explicitly.
    if has_unclosed_brace(path) {
        issues.err(
            "invalid_path_syntax",
            "action path has an unclosed '{' placeholder",
            format!("{action_path}.path"),
        );
    }

    // Every {param} placeholder must reference a defined param, and that
    // param must be required (otherwise the path can't be constructed).
    for (_, ident) in iter_placeholders(path) {
        if !params.contains_key(ident) {
            issues.err(
                "unknown_path_param",
                format!("path placeholder {{{ident}}} does not reference a defined param"),
                format!("{action_path}.path"),
            );
            continue;
        }
        let p = &params[ident];
        if !p.required {
            issues.err(
                "path_param_not_required",
                format!(
                    "path placeholder {{{ident}}} references a param that is not marked required: true"
                ),
                format!("{action_path}.params.{ident}"),
            );
        }
    }
}

/// Check the action's agent-facing `description` for presence, then check the
/// **label template** — `summary` when authored, else `description` — for
/// placeholder and bracket grammar.
///
/// The two are separated because only the label is ever interpolated
/// ([`ServiceAction::label_template`]). A `description` is prose the model
/// reads, and prose legitimately contains braces: LinkedIn's `create_post`
/// explains that an author URN looks like `urn:li:person:{sub}`, which is
/// documentation, not a placeholder referencing a param. Validating it as one
/// would force authors to mangle their own examples.
///
/// When an action authors only `description`, the label *is* that description
/// and the grammar checks apply to it exactly as before — which is the case
/// for nearly every shipped template.
///
/// Takes `summary` rather than a pre-resolved label so the reported field is a
/// structural fact, not an inference: comparing the two strings would call an
/// action that authors the same text in both fields a `description` error and
/// send the author editing the wrong line.
fn check_description(
    desc: &str,
    summary: Option<&str>,
    params: &std::collections::HashMap<String, ActionParam>,
    action_path: &str,
    optional: bool,
    issues: &mut Issues,
) {
    if desc.trim().is_empty() && !optional {
        issues.err(
            "missing_field",
            "description is required",
            format!("{action_path}.description"),
        );
    }

    // Mirrors `ServiceAction::label_template`, and names the field the author
    // actually wrote the offending text in.
    let (label, field) = match summary {
        Some(s) => (s, "summary"),
        None => (desc, "description"),
    };

    // Grammar is checked even when `description` is absent. Presence and
    // syntax are independent questions, and only the *label* is interpolated —
    // an action that omits its description but carries a malformed `summary`
    // must still be caught. Today that combination cannot be built (only the
    // HTTP path sets `summary`, and it is never `optional`), so this is
    // structural rather than a live fix — but the invariant lives in another
    // module, and returning early here would silently drop the check the day
    // an MCP tool gains a relabelled summary. An empty label makes every check
    // below a no-op, so the ordinary "no description, no summary" case is
    // unaffected.

    if let Err(off) = validate_flat_brackets(label) {
        issues.err(
            "unbalanced_brackets",
            format!("{field} has an unbalanced or nested '[' at byte offset {off}"),
            format!("{action_path}.{field}"),
        );
    }

    if has_unclosed_brace(label) {
        issues.err(
            "invalid_description_syntax",
            format!("{field} has an unclosed '{{' placeholder"),
            format!("{action_path}.{field}"),
        );
    }

    for (_, ident) in iter_placeholders(label) {
        if !params.contains_key(ident) {
            issues.err(
                "unknown_description_param",
                format!("{field} placeholder {{{ident}}} does not reference a defined param"),
                format!("{action_path}.{field}"),
            );
        }
    }
}

fn check_param(
    name: &str,
    param: &ActionParam,
    all_params: &std::collections::HashMap<String, ActionParam>,
    action_path: &str,
    issues: &mut Issues,
) {
    let base = format!("{action_path}.params.{name}");

    if !VALID_PARAM_TYPES.contains(&param.param_type.as_str()) {
        issues.err(
            "invalid_param_type",
            format!(
                "param type {:?} is not one of {VALID_PARAM_TYPES:?}",
                param.param_type
            ),
            format!("{base}.type"),
        );
    }

    if let Some(ref values) = param.enum_values {
        if values.is_empty() {
            issues.err(
                "invalid_enum_values",
                "enum must contain at least one value",
                format!("{base}.enum"),
            );
        }
        if let Some(ref default) = param.default
            && let Some(default_str) = default.as_str()
            && !values.iter().any(|v| v == default_str)
        {
            issues.err(
                "invalid_enum_values",
                format!("default value {default_str:?} is not a member of the enum"),
                format!("{base}.default"),
            );
        }
    }

    if let Some(ref resolver) = param.resolve {
        if has_unclosed_brace(&resolver.get) {
            issues.err(
                "invalid_path_syntax",
                "resolver.get has an unclosed '{' placeholder",
                format!("{base}.resolve.get"),
            );
        }
        for (_, ident) in iter_placeholders(&resolver.get) {
            if !all_params.contains_key(ident) {
                issues.err(
                    "unknown_resolver_param",
                    format!(
                        "resolver placeholder {{{ident}}} does not reference a defined param on this action"
                    ),
                    format!("{base}.resolve.get"),
                );
            }
        }
        if resolver.pick.trim().is_empty() {
            issues.err(
                "missing_field",
                "resolver.pick is required",
                format!("{base}.resolve.pick"),
            );
        }
    }
}

/// Detect an unclosed `{` — something that iter_placeholders silently skips
/// but is a syntax error in the linter's view.
fn has_unclosed_brace(s: &str) -> bool {
    let mut i = 0;
    let bytes = s.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'{' {
            match s[i + 1..].find('}') {
                Some(off) => i = i + 1 + off + 1,
                None => return true,
            }
        } else {
            i += 1;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::template_validation::core::tests::{minimal_mcp, minimal_valid, param, run};
    use crate::types::{McpAuth, ParamResolver, Risk, Runtime, ServiceAction, ServiceDefinition};
    use std::collections::HashMap;

    #[test]
    fn unknown_http_method() {
        let mut d = minimal_valid();
        d.actions.get_mut("list").unwrap().method = "SNOOZE".into();
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "invalid_http_method"));
    }

    #[test]
    fn unknown_path_param() {
        let mut d = minimal_valid();
        d.actions.get_mut("list").unwrap().path = "/items/{id}".into();
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "unknown_path_param"));
    }

    #[test]
    fn path_param_not_required() {
        let mut d = minimal_valid();
        let a = d.actions.get_mut("list").unwrap();
        a.path = "/items/{id}".into();
        a.params.insert("id".into(), param("string", false));
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "path_param_not_required"));
    }

    #[test]
    fn invalid_param_type() {
        let mut d = minimal_valid();
        d.actions
            .get_mut("list")
            .unwrap()
            .params
            .insert("x".into(), param("float", false));
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "invalid_param_type"));
    }

    #[test]
    fn invalid_enum_values_empty() {
        let mut d = minimal_valid();
        let mut p = param("string", false);
        p.enum_values = Some(vec![]);
        d.actions
            .get_mut("list")
            .unwrap()
            .params
            .insert("x".into(), p);
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "invalid_enum_values"));
    }

    #[test]
    fn invalid_enum_default_not_member() {
        let mut d = minimal_valid();
        let mut p = param("string", false);
        p.enum_values = Some(vec!["a".into(), "b".into()]);
        p.default = Some(serde_json::json!("c"));
        d.actions
            .get_mut("list")
            .unwrap()
            .params
            .insert("x".into(), p);
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "invalid_enum_values"));
    }

    #[test]
    fn description_unbalanced_brackets() {
        let mut d = minimal_valid();
        d.actions.get_mut("list").unwrap().description = "List [unclosed".into();
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "unbalanced_brackets"));
    }

    #[test]
    fn description_unknown_param() {
        let mut d = minimal_valid();
        d.actions.get_mut("list").unwrap().description = "List {ghost}".into();
        let r = run(&d);
        assert!(
            r.errors
                .iter()
                .any(|e| e.code == "unknown_description_param")
        );
    }

    #[test]
    fn description_placeholder_defined_ok() {
        let mut d = minimal_valid();
        let a = d.actions.get_mut("list").unwrap();
        a.description = "List[ filtered by {filter}]".into();
        a.params.insert("filter".into(), param("string", false));
        assert!(run(&d).valid);
    }

    /// Prose the agent reads is not a label template. LinkedIn's `create_post`
    /// documents that an author URN looks like `urn:li:person:{sub}` — real
    /// documentation, not a placeholder. Only the `summary` is interpolated,
    /// so only the `summary` is grammar-checked.
    #[test]
    fn braces_in_description_are_prose_when_a_summary_exists() {
        let mut d = minimal_valid();
        let a = d.actions.get_mut("list").unwrap();
        a.description = "The author URN is urn:li:person:{sub}.".into();
        a.summary = Some("List items".into());
        assert!(run(&d).valid);
    }

    /// ...but a bad placeholder in the `summary` still fails, and the issue
    /// points at `summary` rather than at `description`.
    #[test]
    fn summary_unknown_param_is_reported_against_summary() {
        let mut d = minimal_valid();
        let a = d.actions.get_mut("list").unwrap();
        a.description = "List items".into();
        a.summary = Some("List {ghost}".into());
        let r = run(&d);
        let issue = r
            .errors
            .iter()
            .find(|e| e.code == "unknown_description_param")
            .expect("summary placeholder must still be validated");
        assert!(
            issue.path.ends_with(".summary"),
            "issue should name the summary field, got {:?}",
            issue.path
        );
    }

    /// An action may author the same text in both fields. The reported field
    /// has to come from which field exists, not from comparing their contents
    /// — otherwise this case blames `description` and sends the author editing
    /// a line that is not the one being validated.
    #[test]
    fn identical_summary_and_description_still_blames_summary() {
        let mut d = minimal_valid();
        let a = d.actions.get_mut("list").unwrap();
        a.description = "List {ghost}".into();
        a.summary = Some("List {ghost}".into());
        let r = run(&d);
        let issue = r
            .errors
            .iter()
            .find(|e| e.code == "unknown_description_param")
            .expect("the placeholder must still be caught");
        assert!(
            issue.path.ends_with(".summary"),
            "identical text must still be attributed to the field that is \
             interpolated, got {:?}",
            issue.path
        );
    }

    /// Presence and syntax are independent: a missing `description` must not
    /// buy a malformed `summary` a free pass. Both issues are reported, each
    /// against its own field.
    #[test]
    fn absent_description_does_not_suppress_summary_grammar_checks() {
        let mut d = minimal_valid();
        let a = d.actions.get_mut("list").unwrap();
        a.description = String::new();
        a.summary = Some("List {ghost}".into());
        let r = run(&d);

        assert!(
            r.errors
                .iter()
                .any(|e| e.code == "missing_field" && e.path.ends_with(".description")),
            "the absent description must still be reported: {:?}",
            r.errors
        );
        let placeholder = r
            .errors
            .iter()
            .find(|e| e.code == "unknown_description_param")
            .expect("an empty description must not skip the summary's grammar");
        assert!(placeholder.path.ends_with(".summary"), "{placeholder:?}");
    }

    /// The ordinary shape of an MCP tool that declares neither — the MCP spec
    /// makes a tool description optional and `tools/list` often omits it. An
    /// empty label has no grammar to be wrong about, so dropping the early
    /// return must not start reporting anything here.
    #[test]
    fn absent_description_and_summary_report_nothing_extra() {
        let mut d = minimal_mcp(McpAuth::Bearer {
            secret_name: Some("tok".into()),
        });
        for a in d.actions.values_mut() {
            a.description = String::new();
            a.summary = None;
        }
        let r = run(&d);
        assert!(r.valid, "expected a clean report, got {:?}", r.errors);
    }

    #[test]
    fn description_required() {
        let mut d = minimal_valid();
        d.actions.get_mut("list").unwrap().description = "".into();
        let r = run(&d);
        assert!(
            r.errors
                .iter()
                .any(|e| e.code == "missing_field" && e.path.ends_with(".description"))
        );
    }

    #[test]
    fn unknown_scope_param() {
        let mut d = minimal_valid();
        d.actions.get_mut("list").unwrap().scope_param = "ghost".into();
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "unknown_scope_param"));
    }

    /// Each entry in a list is checked on its own, and the message names the
    /// offending param rather than the whole list.
    #[test]
    fn unknown_scope_param_inside_a_list() {
        let mut d = minimal_valid();
        let action = d.actions.get_mut("list").unwrap();
        action
            .params
            .insert("folder".into(), param("string", false));
        action.scope_param = crate::types::ScopeParams::parse_list(["folder", "ghost"]).unwrap();
        let r = run(&d);
        let issues: Vec<_> = r
            .errors
            .iter()
            .filter(|e| e.code == "unknown_scope_param")
            .collect();
        assert_eq!(issues.len(), 1, "only the unknown entry should report");
        assert!(issues[0].message.contains("ghost"), "{:?}", issues[0]);
    }

    /// The label half names a permission namespace the author invents, not a
    /// param — validating it against the schema would reject the shipped
    /// `to:recipient` form.
    #[test]
    fn scope_param_label_need_not_name_a_param() {
        let mut d = minimal_valid();
        let action = d.actions.get_mut("list").unwrap();
        action
            .params
            .insert("folder".into(), param("string", false));
        action.scope_param = crate::types::ScopeParams::parse_list(["folder:recipient"]).unwrap();
        let r = run(&d);
        assert!(!r.errors.iter().any(|e| e.code == "unknown_scope_param"));
    }

    #[test]
    fn invalid_response_type() {
        let mut d = minimal_valid();
        d.actions.get_mut("list").unwrap().response_type = Some("xml".into());
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "invalid_response_type"));
    }

    #[test]
    fn unknown_resolver_param() {
        let mut d = minimal_valid();
        let a = d.actions.get_mut("list").unwrap();
        let mut p = param("string", false);
        p.resolve = Some(ParamResolver {
            get: "/items/{ghost}".into(),
            pick: "name".into(),
        });
        a.params.insert("x".into(), p);
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "unknown_resolver_param"));
    }

    #[test]
    fn risk_method_mismatch_warning() {
        let mut d = minimal_valid();
        d.actions.get_mut("list").unwrap().risk = Risk::Delete.into();
        let r = run(&d);
        assert!(r.valid); // warning, not error
        assert!(r.warnings.iter().any(|w| w.code == "risk_method_mismatch"));
    }

    #[test]
    fn platform_namespace_action_allowed() {
        // An action with empty method/path (like overslash.yaml) must validate
        // clean as long as description is present.
        let mut d = ServiceDefinition {
            secrets: Vec::new(),
            config: Vec::new(),
            key: "overslash".into(),
            display_name: "Overslash".into(),
            description: None,
            hosts: vec![],
            category: Some("platform".into()),
            hidden: false,
            auth: vec![],
            actions: HashMap::new(),
            runtime: Runtime::Platform,
            mcp: None,
            instance_defaults: None,
        };
        d.actions.insert(
            "manage_secrets".into(),
            ServiceAction {
                method: String::new(),
                path: String::new(),
                description: "Manage secrets".into(),
                summary: None,
                risk: Risk::Write.into(),
                response_type: None,
                params: HashMap::new(),
                scope_param: Default::default(),
                required_scopes: Vec::new(),
                permission: None,
                disclose: Vec::new(),
                redact: Vec::new(),
                mcp_tool: None,
                output_schema: None,
                disabled: false,
                request_body: None,
                download: None,
            },
        );
        let r = run(&d);
        assert!(r.valid, "errors: {:?}", r.errors);
    }

    #[test]
    fn mcp_description_is_optional() {
        // MCP spec: tool description is optional. A tools/list response
        // that omits description should still validate — HTTP actions
        // require one, platform actions require one, but MCP tools do not.
        let mut d = minimal_mcp(McpAuth::None);
        d.actions.get_mut("search").unwrap().description = String::new();
        let r = run(&d);
        assert!(r.valid, "errors: {:?}", r.errors);
    }

    #[test]
    fn http_description_still_required() {
        // Regression guard: making description optional for MCP must not
        // relax the HTTP path. Platform + HTTP actions still reject empty
        // descriptions.
        let mut d = minimal_valid();
        let a = d.actions.get_mut("list").unwrap();
        a.description = String::new();
        let r = run(&d);
        assert!(
            r.errors
                .iter()
                .any(|e| e.code == "missing_field" && e.path.contains("description"))
        );
    }
}
