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

    check_pagination(action, &action_path, issues);

    check_sql_policy(action, &action_path, issues);
}

/// Cross-field checks for `x-overslash-pagination`. The structural shape was
/// already settled by `extract::parse_pagination`; what only this layer can see
/// is whether the parameters it names exist on the action, since the extension
/// and the parameter list are parsed from different parts of the document.
///
/// Every finding here is an **error**, unlike the extension lint's warnings.
/// The distinction is what the mistake costs: a key nothing reads is inert, but
/// a page size pointing at a parameter that does not exist is a bound the
/// gateway believes it applied and never did — the exact silent unboundedness
/// this extension was added to end.
fn check_pagination(action: &ServiceAction, action_path: &str, issues: &mut Issues) {
    let Some(pagination) = action.pagination.as_ref() else {
        return;
    };
    let base = format!("{action_path}.pagination");

    let named = |field: &str, param: &str, issues: &mut Issues| -> Option<&ActionParam> {
        match action.params.get(param) {
            Some(p) => Some(p),
            None => {
                issues.err(
                    "unknown_pagination_param",
                    format!(
                        "pagination {field} {param:?} does not reference a defined param — a page the request cannot express is not a page"
                    ),
                    format!("{base}.{field}"),
                );
                None
            }
        }
    };

    if let Some(page_size) = pagination.page_size.as_ref()
        && let Some(param) = named("page_size.param", &page_size.param, issues)
    {
        if param.param_type != "integer" && param.param_type != "number" {
            issues.err(
                "invalid_pagination_param_type",
                format!(
                    "pagination page_size.param {:?} is declared {:?}; a page size must be numeric",
                    page_size.param, param.param_type
                ),
                format!("{base}.page_size.param"),
            );
        }
        // The compiler seeds the param's `default:` from here only when it has
        // none, so two different numbers means the one written in the extension
        // is inert. Not an error — the action still pages, and the behaviour is
        // the parameter's, which is the more specific statement — but it reads
        // as a promise it does not keep.
        if let (Some(declared), Some(seeded)) = (
            param.default.as_ref().and_then(|d| d.as_i64()),
            page_size.default,
        ) && declared != seeded
        {
            issues.warn(
                "pagination_default_shadowed",
                format!(
                    "pagination page_size.default ({seeded}) is ignored: param {:?} declares its own default ({declared})",
                    page_size.param
                ),
                format!("{base}.page_size.default"),
            );
        }
        if let (Some(max), Some(declared)) = (
            page_size.max,
            param.default.as_ref().and_then(|d| d.as_i64()),
        ) && declared > max
        {
            issues.err(
                "pagination_default_exceeds_max",
                format!(
                    "param {:?} defaults to {declared}, above the page_size.max of {max}",
                    page_size.param
                ),
                format!("{action_path}.params.{}.default", page_size.param),
            );
        }
    }

    if let Some(param) = pagination.next.param.as_ref() {
        let numeric_needed = pagination.next.style.is_arithmetic();
        if let Some(p) = named("next.param", param, issues)
            && numeric_needed
            && p.param_type != "integer"
            && p.param_type != "number"
        {
            issues.err(
                "invalid_pagination_param_type",
                format!(
                    "pagination next.param {param:?} is declared {:?}; style {:?} advances a number",
                    p.param_type,
                    pagination.next.style.as_str()
                ),
                format!("{base}.next.param"),
            );
        }
    }

    // `items` is what an arithmetic style uses to tell a full page from the
    // last one. Without it — and without an explicit `has_more` — the gateway
    // has to offer the next page unconditionally, which costs the caller one
    // empty call at the end of every traversal.
    if pagination.next.style.is_arithmetic()
        && pagination.items.is_none()
        && pagination.has_more.is_none()
    {
        issues.warn(
            "pagination_unbounded_end",
            format!(
                "style {:?} has no `items` or `has_more`, so the last page cannot be recognised and `next` is offered after it",
                pagination.next.style.as_str()
            ),
            base.clone(),
        );
    }
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
        if !param_ident_resolvable(params, ident) {
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
        super::resolver::check_resolver(resolver, name, all_params, &base, issues);
    }
}

/// Does `ident` name something the runtime substituter can resolve?
///
/// Exact param name, or a dotted path whose head segment is a defined param —
/// `crate::description::substitute_placeholders` descends nested objects, so
/// `{query.database}` resolves against the object-valued `query` param. Only
/// the head is checkable here: the shape inside an object param is the
/// upstream's, not something the template declares.
///
/// Deliberately not used for action-path placeholders. Those are substituted
/// by a separate flat loop over the call params
/// (`routes::actions::resolve`), which never descends — a dotted path
/// placeholder would survive into the outbound URL verbatim.
pub(super) fn param_ident_resolvable(
    params: &std::collections::HashMap<String, ActionParam>,
    ident: &str,
) -> bool {
    params.contains_key(ident)
        || ident
            .split_once('.')
            .is_some_and(|(head, _)| params.contains_key(head))
}

/// Detect an unclosed `{` — something that iter_placeholders silently skips
/// but is a syntax error in the linter's view.
pub(super) fn has_unclosed_brace(s: &str) -> bool {
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
mod tests;
