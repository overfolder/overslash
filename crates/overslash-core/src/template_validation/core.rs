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
    if def.runtime != Runtime::Platform {
        check_auth(def, &mut issues);
    }
    check_mcp(def, &mut issues);
    check_duplicate_action_keys(raw_action_keys, &mut issues);

    // Iterate actions in a deterministic order so test assertions can match
    // on issue order when needed.
    let mut action_keys: Vec<&String> = def.actions.keys().collect();
    action_keys.sort();
    for key in action_keys {
        let action = &def.actions[key];
        if def.runtime == Runtime::Platform {
            check_platform_action(key, action, &mut issues);
        } else {
            check_action(key, action, &mut issues);
        }
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

    // Platform services have no hosts — they dispatch in-process.
    if def.runtime == Runtime::Platform {
        return;
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

fn check_auth(def: &ServiceDefinition, issues: &mut Issues) {
    let mut seen_schemes: Vec<&str> = Vec::new();
    for (i, entry) in def.auth.iter().enumerate() {
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
            ServiceAuth::Secret {
                scheme, injection, ..
            } => {
                // An org-source slot resolves ONLY through its default secret
                // name — with none, the credential can never be found. An
                // instance-source slot resolves from the instance's binding,
                // so it needs no default.
                for slot in def.slots_for(entry) {
                    if slot.source == crate::types::SecretSource::Org
                        && slot.default_secret_name.trim().is_empty()
                    {
                        issues.err(
                            "missing_field",
                            format!(
                                "secret `{}` is org-sourced and needs a default_secret_name \
                                 to resolve against the org vault",
                                slot.key
                            ),
                            format!("auth[{i}].default_secret_name"),
                        );
                    }
                }
                // Instances bind secrets per scheme key (`credentials[scheme]`),
                // so any number of secret schemes is fine — but the keys must be
                // unambiguous. Unique by construction when compiled from a
                // securitySchemes map; guard the programmatic construction paths.
                if !scheme.is_empty() {
                    if seen_schemes.contains(&scheme.as_str()) {
                        issues.err(
                            "duplicate_scheme_key",
                            format!(
                                "security scheme key {scheme:?} appears more than once; \
                                 per-instance credential bindings are keyed by scheme"
                            ),
                            format!("auth[{i}].scheme"),
                        );
                    }
                    seen_schemes.push(scheme.as_str());
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
            // url is optional — absent means the service instance must supply one.
            // When present, validate scheme (format already checked in extract.rs;
            // this guard catches templates loaded from DB that may have bypassed it).
            if let Some(url) = &mcp.url {
                if !url.starts_with("https://") && !url.starts_with("http://") {
                    issues.err(
                        "mcp_invalid",
                        "mcp.url must begin with http:// or https://",
                        "mcp.url",
                    );
                }
            }
            // secret_name is optional — absent means the service instance must supply one.
            match &mcp.auth {
                McpAuth::None => {}
                McpAuth::Bearer { .. } => {}
                McpAuth::OAuth { provider, .. } => {
                    if provider.trim().is_empty() {
                        issues.err(
                            "mcp_invalid",
                            "mcp.auth.provider must be non-empty when kind is `oauth`",
                            "mcp.auth.provider",
                        );
                    }
                }
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
        // Platform runtime has no mcp block — check_platform_action enforces
        // platform-specific invariants; nothing to do here.
        Runtime::Platform => {}
    }
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

    // Description required for HTTP + platform actions, optional for MCP
    // tools — the MCP spec declares the tool description as optional, and
    // tools/list responses frequently omit it for trivial utilities.
    // Placeholder / bracket syntax is still checked when a description is
    // present, regardless of runtime.
    let is_mcp_action = action.mcp_tool.is_some();
    check_description(
        &action.description,
        &action.params,
        &action_path,
        is_mcp_action,
        issues,
    );

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

fn check_platform_action(key: &str, action: &ServiceAction, issues: &mut Issues) {
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

    if let Some(ref perm) = action.permission {
        if !is_valid_action_key(perm) {
            issues.err(
                "invalid_permission_key",
                format!("permission {perm:?} must match ^[a-z][a-z0-9_]*$"),
                format!("{action_path}.permission"),
            );
        }
    }

    for (name, param) in &action.params {
        check_param(name, param, &action.params, &action_path, issues);
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
    optional: bool,
    issues: &mut Issues,
) {
    if desc.trim().is_empty() {
        if !optional {
            issues.err(
                "missing_field",
                "description is required",
                format!("{action_path}.description"),
            );
        }
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
        ActionParam, ParamResolver, Risk, Runtime, SecretSource, ServiceAction, ServiceAuth,
        ServiceDefinition, TokenInjection,
    };
    use std::collections::HashMap;

    fn minimal_valid() -> ServiceDefinition {
        ServiceDefinition {
            secrets: Vec::new(),
            key: "svc".into(),
            display_name: "Service".into(),
            description: None,
            hosts: vec!["api.example.com".into()],
            category: None,
            hidden: false,
            auth: vec![ServiceAuth::Secret {
                template: None,
                slots: Vec::new(),
                scheme: String::new(),
                label: String::new(),
                description: String::new(),
                default_secret_name: "svc_token".into(),
                injection: TokenInjection {
                    inject_as: "header".into(),
                    header_name: Some("Authorization".into()),
                    query_param: None,
                    prefix: Some("Bearer ".into()),
                },
                secret_source: SecretSource::Instance,
                optional: false,
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
                        permission: None,
                        disclose: Vec::new(),
                        redact: Vec::new(),
                        mcp_tool: None,
                        output_schema: None,
                        disabled: false,
                        request_body: None,
                    },
                );
                m
            },
            runtime: Runtime::Http,
            mcp: None,
            instance_defaults: None,
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
            aliases: Vec::new(),
            location: crate::types::ParamLocation::Body,
            instance_config: false,
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
        d.auth = vec![ServiceAuth::Secret {
            template: None,
            slots: Vec::new(),
            scheme: String::new(),
            label: String::new(),
            description: String::new(),
            default_secret_name: "x".into(),
            injection: TokenInjection {
                inject_as: "header".into(),
                header_name: None,
                query_param: None,
                prefix: None,
            },
            secret_source: SecretSource::Instance,
            optional: false,
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
        d.auth = vec![ServiceAuth::Secret {
            template: None,
            slots: Vec::new(),
            scheme: String::new(),
            label: String::new(),
            description: String::new(),
            default_secret_name: "x".into(),
            injection: TokenInjection {
                inject_as: "query".into(),
                header_name: None,
                query_param: None,
                prefix: None,
            },
            secret_source: SecretSource::Instance,
            optional: false,
        }];
        let r = run(&d);
        assert!(
            r.errors
                .iter()
                .any(|e| e.code == "incomplete_token_injection")
        );
    }

    fn secret(scheme: &str, source: SecretSource) -> ServiceAuth {
        ServiceAuth::Secret {
            template: None,
            slots: Vec::new(),
            scheme: scheme.into(),
            label: String::new(),
            description: String::new(),
            default_secret_name: "x".into(),
            injection: TokenInjection {
                inject_as: "header".into(),
                header_name: Some("Authorization".into()),
                query_param: None,
                prefix: None,
            },
            secret_source: source,
            optional: false,
        }
    }

    #[test]
    fn several_instance_source_schemes_are_valid() {
        // Instances bind secrets per scheme key (`credentials[scheme]`), so a
        // template may declare any number of instance-source secret schemes —
        // the old `multiple_instance_secrets` scalar-storage rule is gone.
        let mut d = minimal_valid();
        d.auth = vec![
            secret("first", SecretSource::Instance),
            secret("second", SecretSource::Instance),
        ];
        let r = run(&d);
        assert!(r.valid, "errors: {:?}", r.errors);
    }

    #[test]
    fn duplicate_scheme_keys_are_rejected() {
        let mut d = minimal_valid();
        d.auth = vec![
            secret("token", SecretSource::Instance),
            secret("token", SecretSource::Org),
        ];
        let r = run(&d);
        assert!(
            r.errors.iter().any(|e| e.code == "duplicate_scheme_key"),
            "errors: {:?}",
            r.errors
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
            secrets: Vec::new(),
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
                risk: Risk::Write,
                response_type: None,
                params: HashMap::new(),
                scope_param: None,
                required_scopes: Vec::new(),
                permission: None,
                disclose: Vec::new(),
                redact: Vec::new(),
                mcp_tool: None,
                output_schema: None,
                disabled: false,
                request_body: None,
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
                            aliases: Vec::new(),
                            location: crate::types::ParamLocation::Body,
                            instance_config: false,
                        },
                    );
                    p
                },
                scope_param: Some("team".into()),
                required_scopes: vec![],
                permission: None,
                disclose: vec![],
                redact: vec![],
                mcp_tool: Some("search".into()),
                output_schema: None,
                disabled: false,
                request_body: None,
            },
        );
        ServiceDefinition {
            secrets: Vec::new(),
            key: "linear_mcp".into(),
            display_name: "Linear".into(),
            description: None,
            hosts: vec![],
            category: None,
            hidden: false,
            auth: vec![],
            actions,
            runtime: Runtime::Mcp,
            mcp: Some(McpSpec {
                url: Some("https://mcp.linear.app/mcp".into()),
                auth,
                autodiscover: true,
            }),
            instance_defaults: None,
        }
    }

    #[test]
    fn mcp_happy_path_valid() {
        let d = minimal_mcp(McpAuth::Bearer {
            secret_name: Some("tok".into()),
        });
        let r = run(&d);
        assert!(r.valid, "errors: {:?}", r.errors);
    }

    #[test]
    fn mcp_bearer_without_secret_name_is_valid() {
        // secret_name absent means the service instance must supply one.
        let d = minimal_mcp(McpAuth::Bearer { secret_name: None });
        let r = run(&d);
        assert!(r.valid, "errors: {:?}", r.errors);
    }

    #[test]
    fn mcp_without_url_is_valid() {
        // url absent means the service instance must supply one.
        let mut d = minimal_mcp(McpAuth::None);
        d.mcp.as_mut().unwrap().url = None;
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
        d.auth = vec![ServiceAuth::Secret {
            template: None,
            slots: Vec::new(),
            scheme: String::new(),
            label: String::new(),
            description: String::new(),
            default_secret_name: "k".into(),
            injection: TokenInjection {
                inject_as: "header".into(),
                header_name: Some("Authorization".into()),
                query_param: None,
                prefix: None,
            },
            secret_source: SecretSource::Instance,
            optional: false,
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
        d.mcp.as_mut().unwrap().url = Some("mcp.example.com".into());
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "mcp_invalid"));
    }

    #[test]
    fn http_runtime_rejects_stray_mcp_block() {
        use crate::types::McpSpec;
        let mut d = minimal_valid();
        d.mcp = Some(McpSpec {
            url: Some("https://x".into()),
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
