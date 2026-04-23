//! WASM-safe struct-level validator. Pure function over a parsed
//! [`ServiceDefinition`]. No YAML, no `serde_json` deserialization, no I/O.
//!
//! The full rule set is documented inline and mirrored in SPEC.md §9.

use std::collections::HashSet;

use crate::description_grammar::{iter_placeholders, validate_flat_brackets};
use crate::types::{
    ActionParam, McpAuth, Risk, Runtime, ServiceAction, ServiceAuth, ServiceDefinition,
    TokenInjection,
};

use super::{Issues, ValidationReport};

/// Validate a parsed [`ServiceDefinition`].
///
/// `raw_action_keys` is the in-order list of action keys as they appeared in
/// the source document. The YAML entry point supplies this from a raw YAML
/// walk; callers with already-deduped input (JSON, a typed struct built
/// programmatically) can pass an empty slice to skip duplicate-key detection.
pub fn validate_service_definition(
    def: &ServiceDefinition,
    raw_action_keys: &[String],
) -> ValidationReport {
    let mut issues = Issues::default();

    check_service_shape(def, &mut issues);
    check_auth(&def.auth, &mut issues);
    check_mcp(def, &mut issues);
    check_duplicate_action_keys(raw_action_keys, &mut issues);

    // Iterate actions in a deterministic order so test assertions can match
    // on issue order when needed.
    let mut action_keys: Vec<&String> = def.actions.keys().collect();
    action_keys.sort();
    for key in action_keys {
        let action = &def.actions[key];
        check_action(key, action, &mut issues);
    }

    issues.finish()
}

// --- service-level ---------------------------------------------------------

fn check_service_shape(def: &ServiceDefinition, issues: &mut Issues) {
    if def.key.is_empty() {
        issues.err("missing_field", "key is required", "key");
    } else if !is_valid_service_key(&def.key) {
        issues.err("invalid_key", "key must match ^[a-z][a-z0-9_-]*$", "key");
    }

    if def.display_name.trim().is_empty() {
        issues.err("missing_field", "display_name is required", "display_name");
    }

    for (i, host) in def.hosts.iter().enumerate() {
        let path = format!("hosts[{i}]");
        if host.trim().is_empty() {
            issues.err("invalid_host", "host must be non-empty", path);
        } else if !is_valid_hostname(host) {
            issues.err(
                "invalid_host",
                "host must be a plain hostname (no scheme, no path, no whitespace)",
                path,
            );
        }
    }
}

fn is_valid_service_key(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

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

fn is_valid_hostname(s: &str) -> bool {
    !s.is_empty() && !s.contains("://") && !s.contains('/') && !s.chars().any(|c| c.is_whitespace())
}

// --- auth ------------------------------------------------------------------

fn check_auth(auth: &[ServiceAuth], issues: &mut Issues) {
    for (i, entry) in auth.iter().enumerate() {
        match entry {
            ServiceAuth::OAuth {
                provider,
                token_injection,
                ..
            } => {
                if provider.trim().is_empty() {
                    issues.err(
                        "missing_field",
                        "oauth provider is required",
                        format!("auth[{i}].provider"),
                    );
                }
                check_token_injection(
                    token_injection,
                    &format!("auth[{i}].token_injection"),
                    issues,
                );
            }
            ServiceAuth::ApiKey {
                default_secret_name,
                injection,
            } => {
                if default_secret_name.trim().is_empty() {
                    issues.err(
                        "missing_field",
                        "api_key default_secret_name is required",
                        format!("auth[{i}].default_secret_name"),
                    );
                }
                check_token_injection(injection, &format!("auth[{i}].injection"), issues);
            }
        }
    }
}

fn check_token_injection(inj: &TokenInjection, base_path: &str, issues: &mut Issues) {
    match inj.inject_as.as_str() {
        "header" => {
            if inj.header_name.as_deref().unwrap_or("").trim().is_empty() {
                issues.err(
                    "incomplete_token_injection",
                    "token_injection with as=\"header\" requires header_name",
                    base_path.to_string(),
                );
            }
        }
        "query" => {
            if inj.query_param.as_deref().unwrap_or("").trim().is_empty() {
                issues.err(
                    "incomplete_token_injection",
                    "token_injection with as=\"query\" requires query_param",
                    base_path.to_string(),
                );
            }
        }
        other => {
            issues.err(
                "invalid_token_injection",
                format!("token_injection `as` must be \"header\" or \"query\" (got {other:?})"),
                format!("{base_path}.as"),
            );
        }
    }
}

// --- duplicate action keys -------------------------------------------------

fn check_duplicate_action_keys(raw_keys: &[String], issues: &mut Issues) {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut reported: HashSet<&str> = HashSet::new();
    for k in raw_keys {
        if !seen.insert(k.as_str()) && reported.insert(k.as_str()) {
            issues.err(
                "duplicate_action_key",
                format!("action key {k:?} is defined more than once"),
                format!("actions.{k}"),
            );
        }
    }
}

// --- mcp-runtime congruence -------------------------------------------------

fn check_mcp(def: &ServiceDefinition, issues: &mut Issues) {
    match def.runtime {
        Runtime::Http => {
            if def.mcp.is_some() {
                issues.err(
                    "mcp_misplaced",
                    "`mcp` block is only valid when runtime=`mcp`",
                    "mcp",
                );
            }
            for (k, a) in &def.actions {
                if a.mcp_tool.is_some() {
                    issues.err(
                        "mcp_misplaced",
                        "mcp_tool set on an Http-runtime action",
                        format!("actions.{k}.mcp_tool"),
                    );
                }
            }
        }
        Runtime::Mcp => {
            let Some(mcp) = def.mcp.as_ref() else {
                issues.err(
                    "mcp_missing",
                    "runtime=`mcp` but `mcp` block is absent",
                    "mcp",
                );
                return;
            };
            if mcp.url.trim().is_empty() {
                issues.err("mcp_invalid", "mcp.url must be non-empty", "mcp.url");
            } else if !mcp.url.starts_with("https://") && !mcp.url.starts_with("http://") {
                issues.err(
                    "mcp_invalid",
                    "mcp.url must begin with http:// or https://",
                    "mcp.url",
                );
            }
            match &mcp.auth {
                McpAuth::None => {}
                McpAuth::Bearer { secret_name } if secret_name.trim().is_empty() => {
                    issues.err(
                        "mcp_invalid",
                        "mcp.auth.secret_name must be non-empty for kind=bearer",
                        "mcp.auth.secret_name",
                    );
                }
                McpAuth::Bearer { .. } => {}
            }
            if !def.hosts.is_empty() {
                issues.err(
                    "mcp_misplaced",
                    "`hosts` must be empty for mcp-runtime templates (MCP uses mcp.url)",
                    "hosts",
                );
            }
            if !def.auth.is_empty() {
                issues.err(
                    "mcp_misplaced",
                    "HTTP-style `auth` entries are not used for mcp-runtime templates — put auth under mcp.auth",
                    "auth",
                );
            }
            for (k, a) in &def.actions {
                if !a.method.is_empty() || !a.path.is_empty() {
                    issues.err(
                        "mcp_misplaced",
                        "mcp-runtime actions must not carry HTTP method/path",
                        format!("actions.{k}"),
                    );
                }
                if a.mcp_tool.is_none() {
                    issues.err(
                        "mcp_missing",
                        "mcp-runtime action must carry mcp_tool",
                        format!("actions.{k}.mcp_tool"),
                    );
                }
            }
        }
    }
}

// --- per-action ------------------------------------------------------------

const VALID_HTTP_METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
const VALID_PARAM_TYPES: &[&str] = &["string", "number", "integer", "boolean", "array", "object"];
const VALID_RESPONSE_TYPES: &[&str] = &["json", "binary"];

fn check_action(key: &str, action: &ServiceAction, issues: &mut Issues) {
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

    // Description required always (even for platform actions).
    check_description(&action.description, &action.params, &action_path, issues);

    // Params validation (type, enum, resolvers).
    for (name, param) in &action.params {
        check_param(name, param, &action.params, &action_path, issues);
    }

    // scope_param must reference an existing param.
    if let Some(ref scope) = action.scope_param {
        if !action.params.contains_key(scope) {
            issues.err(
                "unknown_scope_param",
                format!("scope_param {scope:?} does not reference a defined param"),
                format!("{action_path}.scope_param"),
            );
        }
    }

    // response_type must be json or binary if set.
    if let Some(ref rt) = action.response_type {
        if !VALID_RESPONSE_TYPES.contains(&rt.as_str()) {
            issues.err(
                "invalid_response_type",
                format!("response_type {rt:?} must be \"json\" or \"binary\""),
                format!("{action_path}.response_type"),
            );
        }
    }
}

fn check_risk_method_plausibility(
    method_upper: &str,
    risk: Risk,
    action_path: &str,
    issues: &mut Issues,
) {
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

fn check_description(
    desc: &str,
    params: &std::collections::HashMap<String, ActionParam>,
    action_path: &str,
    issues: &mut Issues,
) {
    if desc.trim().is_empty() {
        issues.err(
            "missing_field",
            "description is required",
            format!("{action_path}.description"),
        );
        return;
    }

    if let Err(off) = validate_flat_brackets(desc) {
        issues.err(
            "unbalanced_brackets",
            format!("description has an unbalanced or nested '[' at byte offset {off}"),
            format!("{action_path}.description"),
        );
    }

    if has_unclosed_brace(desc) {
        issues.err(
            "invalid_description_syntax",
            "description has an unclosed '{' placeholder",
            format!("{action_path}.description"),
        );
    }

    for (_, ident) in iter_placeholders(desc) {
        if !params.contains_key(ident) {
            issues.err(
                "unknown_description_param",
                format!("description placeholder {{{ident}}} does not reference a defined param"),
                format!("{action_path}.description"),
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
        if let Some(ref default) = param.default {
            if let Some(default_str) = default.as_str() {
                if !values.iter().any(|v| v == default_str) {
                    issues.err(
                        "invalid_enum_values",
                        format!("default value {default_str:?} is not a member of the enum"),
                        format!("{base}.default"),
                    );
                }
            }
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
    use super::*;
    use crate::types::{
        ActionParam, ParamResolver, Risk, ServiceAction, ServiceAuth, ServiceDefinition,
        TokenInjection,
    };
    use std::collections::HashMap;

    fn minimal_valid() -> ServiceDefinition {
        ServiceDefinition {
            key: "svc".into(),
            display_name: "Service".into(),
            description: None,
            hosts: vec!["api.example.com".into()],
            category: None,
            auth: vec![ServiceAuth::ApiKey {
                default_secret_name: "svc_token".into(),
                injection: TokenInjection {
                    inject_as: "header".into(),
                    header_name: Some("Authorization".into()),
                    query_param: None,
                    prefix: Some("Bearer ".into()),
                },
            }],
            actions: {
                let mut m = HashMap::new();
                m.insert(
                    "list".into(),
                    ServiceAction {
                        method: "GET".into(),
                        path: "/items".into(),
                        description: "List items".into(),
                        risk: Risk::Read,
                        response_type: None,
                        params: HashMap::new(),
                        scope_param: None,
                        required_scopes: Vec::new(),
                        disclose: Vec::new(),
                        redact: Vec::new(),
                        mcp_tool: None,
                        output_schema: None,
                        disabled: false,
                    },
                );
                m
            },
            runtime: Default::default(),
            mcp: None,
        }
    }

    fn param(ty: &str, required: bool) -> ActionParam {
        ActionParam {
            param_type: ty.into(),
            required,
            description: String::new(),
            enum_values: None,
            default: None,
            resolve: None,
        }
    }

    fn run(def: &ServiceDefinition) -> ValidationReport {
        validate_service_definition(def, &[])
    }

    #[test]
    fn happy_path_valid() {
        let report = run(&minimal_valid());
        assert!(report.valid, "errors: {:?}", report.errors);
        assert!(report.errors.is_empty());
    }

    #[test]
    fn invalid_key() {
        let mut d = minimal_valid();
        d.key = "Bad-Key".into();
        let r = run(&d);
        assert!(!r.valid);
        assert!(r.errors.iter().any(|e| e.code == "invalid_key"));
    }

    #[test]
    fn missing_display_name() {
        let mut d = minimal_valid();
        d.display_name = "".into();
        let r = run(&d);
        assert!(
            r.errors
                .iter()
                .any(|e| e.code == "missing_field" && e.path == "display_name")
        );
    }

    #[test]
    fn invalid_host() {
        let mut d = minimal_valid();
        d.hosts = vec!["https://api.example.com/foo".into()];
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "invalid_host"));
    }

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
        d.actions.get_mut("list").unwrap().scope_param = Some("ghost".into());
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "unknown_scope_param"));
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
    fn incomplete_token_injection_header() {
        let mut d = minimal_valid();
        d.auth = vec![ServiceAuth::ApiKey {
            default_secret_name: "x".into(),
            injection: TokenInjection {
                inject_as: "header".into(),
                header_name: None,
                query_param: None,
                prefix: None,
            },
        }];
        let r = run(&d);
        assert!(
            r.errors
                .iter()
                .any(|e| e.code == "incomplete_token_injection")
        );
    }

    #[test]
    fn incomplete_token_injection_query() {
        let mut d = minimal_valid();
        d.auth = vec![ServiceAuth::ApiKey {
            default_secret_name: "x".into(),
            injection: TokenInjection {
                inject_as: "query".into(),
                header_name: None,
                query_param: None,
                prefix: None,
            },
        }];
        let r = run(&d);
        assert!(
            r.errors
                .iter()
                .any(|e| e.code == "incomplete_token_injection")
        );
    }

    #[test]
    fn risk_method_mismatch_warning() {
        let mut d = minimal_valid();
        d.actions.get_mut("list").unwrap().risk = Risk::Delete;
        let r = run(&d);
        assert!(r.valid); // warning, not error
        assert!(r.warnings.iter().any(|w| w.code == "risk_method_mismatch"));
    }

    #[test]
    fn duplicate_action_key() {
        let d = minimal_valid();
        let report =
            validate_service_definition(&d, &["list".into(), "other".into(), "list".into()]);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.code == "duplicate_action_key")
        );
    }

    #[test]
    fn platform_namespace_action_allowed() {
        // An action with empty method/path (like overslash.yaml) must validate
        // clean as long as description is present.
        let mut d = ServiceDefinition {
            key: "overslash".into(),
            display_name: "Overslash".into(),
            description: None,
            hosts: vec![],
            category: Some("platform".into()),
            auth: vec![],
            actions: HashMap::new(),
            runtime: Default::default(),
            mcp: None,
        };
        d.actions.insert(
            "manage_secrets".into(),
            ServiceAction {
                method: String::new(),
                path: String::new(),
                description: "Manage secrets".into(),
                risk: Risk::Write,
                response_type: None,
                params: HashMap::new(),
                scope_param: None,
                required_scopes: Vec::new(),
                disclose: Vec::new(),
                redact: Vec::new(),
                mcp_tool: None,
                output_schema: None,
                disabled: false,
            },
        );
        let r = run(&d);
        assert!(r.valid, "errors: {:?}", r.errors);
    }

    // ── MCP runtime validation ────────────────────────────────────────

    fn minimal_mcp(auth: McpAuth) -> ServiceDefinition {
        use crate::types::McpSpec;
        let mut actions = HashMap::new();
        actions.insert(
            "search".into(),
            ServiceAction {
                method: String::new(),
                path: String::new(),
                description: "Search {team}".into(),
                risk: Risk::Read,
                response_type: None,
                params: {
                    let mut p = HashMap::new();
                    p.insert(
                        "team".into(),
                        ActionParam {
                            param_type: "string".into(),
                            required: true,
                            description: String::new(),
                            enum_values: None,
                            default: None,
                            resolve: None,
                        },
                    );
                    p
                },
                scope_param: Some("team".into()),
                required_scopes: vec![],
                mcp_tool: Some("search".into()),
                output_schema: None,
                disabled: false,
            },
        );
        ServiceDefinition {
            key: "linear_mcp".into(),
            display_name: "Linear".into(),
            description: None,
            hosts: vec![],
            category: None,
            auth: vec![],
            actions,
            runtime: Runtime::Mcp,
            mcp: Some(McpSpec {
                url: "https://mcp.linear.app/mcp".into(),
                auth,
                autodiscover: true,
            }),
        }
    }

    #[test]
    fn mcp_happy_path_valid() {
        let d = minimal_mcp(McpAuth::Bearer {
            secret_name: "tok".into(),
        });
        let r = run(&d);
        assert!(r.valid, "errors: {:?}", r.errors);
    }

    #[test]
    fn mcp_requires_spec() {
        let mut d = minimal_mcp(McpAuth::None);
        d.mcp = None;
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "mcp_missing"));
    }

    #[test]
    fn mcp_rejects_hosts() {
        let mut d = minimal_mcp(McpAuth::None);
        d.hosts = vec!["example.com".into()];
        let r = run(&d);
        assert!(
            r.errors
                .iter()
                .any(|e| e.code == "mcp_misplaced" && e.path == "hosts")
        );
    }

    #[test]
    fn mcp_rejects_http_auth() {
        let mut d = minimal_mcp(McpAuth::None);
        d.auth = vec![ServiceAuth::ApiKey {
            default_secret_name: "k".into(),
            injection: TokenInjection {
                inject_as: "header".into(),
                header_name: Some("Authorization".into()),
                query_param: None,
                prefix: None,
            },
        }];
        let r = run(&d);
        assert!(
            r.errors
                .iter()
                .any(|e| e.code == "mcp_misplaced" && e.path == "auth")
        );
    }

    #[test]
    fn mcp_rejects_http_action_shape() {
        let mut d = minimal_mcp(McpAuth::None);
        let a = d.actions.get_mut("search").unwrap();
        a.method = "GET".into();
        a.path = "/x".into();
        let r = run(&d);
        assert!(
            r.errors
                .iter()
                .any(|e| e.code == "mcp_misplaced" && e.path.starts_with("actions.search"))
        );
    }

    #[test]
    fn mcp_requires_mcp_tool_on_actions() {
        let mut d = minimal_mcp(McpAuth::None);
        d.actions.get_mut("search").unwrap().mcp_tool = None;
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "mcp_missing"));
    }

    #[test]
    fn mcp_invalid_url_scheme_rejected() {
        let mut d = minimal_mcp(McpAuth::None);
        d.mcp.as_mut().unwrap().url = "mcp.example.com".into();
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "mcp_invalid"));
    }

    #[test]
    fn mcp_bearer_empty_secret_rejected() {
        let d = minimal_mcp(McpAuth::Bearer {
            secret_name: "   ".into(),
        });
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "mcp_invalid"));
    }

    #[test]
    fn http_runtime_rejects_stray_mcp_block() {
        use crate::types::McpSpec;
        let mut d = minimal_valid();
        d.mcp = Some(McpSpec {
            url: "https://x".into(),
            auth: McpAuth::None,
            autodiscover: true,
        });
        let r = run(&d);
        assert!(
            r.errors
                .iter()
                .any(|e| e.code == "mcp_misplaced" && e.path == "mcp")
        );
    }
}
