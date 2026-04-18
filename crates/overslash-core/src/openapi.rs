//! OpenAPI 3.1 + `x-overslash-*` front door for service templates.
//!
//! Service templates are authored as OpenAPI 3.1 documents. Fields the gateway
//! needs that OpenAPI cannot express natively (risk class, permission-scope
//! binding, parameter resolution, symbolic OAuth provider, default secret
//! name) live under the `x-overslash-*` vendor-extension namespace.
//!
//! To keep authoring ergonomic, the same keys may also be written without the
//! prefix (`risk:` instead of `x-overslash-risk:`). The normalizer in this
//! module rewrites every known alias to its canonical form before the rest of
//! the pipeline sees the document, and rejects ambiguous documents (both
//! forms present on the same object) with a `ambiguous_alias` issue.
//!
//! Three public entry points:
//!
//! - [`parse_yaml`] — YAML text → `serde_json::Value` (YAML-feature-gated).
//! - [`normalize_aliases`] — rewrites alias keys to canonical form in place.
//! - [`compile_service`] — lowers a normalized OpenAPI document into a
//!   [`ServiceDefinition`] (the in-memory shape every downstream consumer
//!   reads from).

use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::template_validation::ValidationIssue;
use crate::types::{
    ActionParam, ParamResolver, Risk, ServiceAction, ServiceAuth, ServiceDefinition, TokenInjection,
};

// ── Alias table ──────────────────────────────────────────────────────────

/// Where an alias may appear and the canonical key it rewrites to.
#[derive(Debug, Clone, Copy)]
struct Alias {
    alias: &'static str,
    canonical: &'static str,
}

const ROOT_ALIASES: &[Alias] = &[Alias {
    alias: "platform_actions",
    canonical: "x-overslash-platform_actions",
}];

const INFO_ALIASES: &[Alias] = &[
    Alias {
        alias: "key",
        canonical: "x-overslash-key",
    },
    Alias {
        alias: "category",
        canonical: "x-overslash-category",
    },
];

const OPERATION_ALIASES: &[Alias] = &[
    Alias {
        alias: "risk",
        canonical: "x-overslash-risk",
    },
    Alias {
        alias: "scope_param",
        canonical: "x-overslash-scope_param",
    },
];

const PARAMETER_ALIASES: &[Alias] = &[Alias {
    alias: "resolve",
    canonical: "x-overslash-resolve",
}];

const OAUTH2_SEC_ALIASES: &[Alias] = &[Alias {
    alias: "provider",
    canonical: "x-overslash-provider",
}];

const APIKEY_HTTP_SEC_ALIASES: &[Alias] = &[Alias {
    alias: "default_secret_name",
    canonical: "x-overslash-default_secret_name",
}];

const HTTP_METHODS: &[&str] = &[
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

// ── Public API ───────────────────────────────────────────────────────────

/// Parse an OpenAPI YAML document into a `serde_json::Value`.
#[cfg(feature = "yaml")]
pub fn parse_yaml(src: &str) -> Result<Value, ValidationIssue> {
    let y: serde_yaml::Value = serde_yaml::from_str(src).map_err(|e| {
        ValidationIssue::new(
            "openapi_parse_error",
            format!("failed to parse YAML: {e}"),
            "",
        )
    })?;
    serde_json::to_value(y).map_err(|e| {
        ValidationIssue::new(
            "openapi_parse_error",
            format!("failed to convert YAML to JSON: {e}"),
            "",
        )
    })
}

/// Walk the document and rewrite every alias key under its supported context
/// to its canonical `x-overslash-*` form. Returns issues for any ambiguous
/// objects that carry both forms at once.
pub fn normalize_aliases(v: &mut Value) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    let Value::Object(root) = v else {
        return issues;
    };

    rewrite_aliases(root, ROOT_ALIASES, "", &mut issues);

    if let Some(info) = root.get_mut("info").and_then(Value::as_object_mut) {
        rewrite_aliases(info, INFO_ALIASES, "info", &mut issues);
    }

    if let Some(paths) = root.get_mut("paths").and_then(Value::as_object_mut) {
        for (path_key, path_item) in paths.iter_mut() {
            let Value::Object(path_obj) = path_item else {
                continue;
            };
            for method in HTTP_METHODS {
                let Some(op) = path_obj.get_mut(*method).and_then(Value::as_object_mut) else {
                    continue;
                };
                let op_base = format!("paths.{path_key}.{method}");
                rewrite_aliases(op, OPERATION_ALIASES, &op_base, &mut issues);
                normalize_operation_parameters(op, &op_base, &mut issues);
            }
        }
    }

    if let Some(comps) = root.get_mut("components").and_then(Value::as_object_mut) {
        if let Some(schemes) = comps
            .get_mut("securitySchemes")
            .and_then(Value::as_object_mut)
        {
            for (name, scheme) in schemes.iter_mut() {
                let Value::Object(obj) = scheme else {
                    continue;
                };
                let base = format!("components.securitySchemes.{name}");
                let ty = obj.get("type").and_then(Value::as_str).unwrap_or("");
                match ty {
                    "oauth2" => rewrite_aliases(obj, OAUTH2_SEC_ALIASES, &base, &mut issues),
                    "apiKey" | "http" => {
                        rewrite_aliases(obj, APIKEY_HTTP_SEC_ALIASES, &base, &mut issues)
                    }
                    _ => {}
                }
            }
        }
    }

    // Platform actions live under the x-overslash-platform_actions extension
    // (or its `platform_actions` alias, already rewritten above). Each entry
    // is an operation-shaped object, so operation-level aliases apply.
    if let Some(platform) = root
        .get_mut("x-overslash-platform_actions")
        .and_then(Value::as_object_mut)
    {
        for (action_key, action) in platform.iter_mut() {
            let Value::Object(obj) = action else {
                continue;
            };
            let base = format!("x-overslash-platform_actions.{action_key}");
            rewrite_aliases(obj, OPERATION_ALIASES, &base, &mut issues);
        }
    }

    issues
}

/// Lower a normalized OpenAPI document into a [`ServiceDefinition`].
///
/// Returns the compiled definition plus any non-fatal warnings. Fatal errors
/// return `Err`. This function does not enforce full OpenAPI 3.1 schema
/// compliance — it only extracts the bits the gateway cares about and rejects
/// inputs that violate gateway-specific constraints (e.g. `risk` not in
/// read/write/delete).
pub fn compile_service(
    doc: &Value,
) -> Result<(ServiceDefinition, Vec<ValidationIssue>), Vec<ValidationIssue>> {
    let mut errors: Vec<ValidationIssue> = Vec::new();
    let warnings: Vec<ValidationIssue> = Vec::new();

    let Some(root) = doc.as_object() else {
        errors.push(ValidationIssue::new(
            "openapi_parse_error",
            "document root must be an object",
            "",
        ));
        return Err(errors);
    };

    let info = root.get("info").and_then(Value::as_object);

    let key = info
        .and_then(|i| i.get("x-overslash-key"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let display_name = info
        .and_then(|i| i.get("title"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let description = info
        .and_then(|i| i.get("description"))
        .and_then(Value::as_str)
        .map(str::to_string);

    let category = info
        .and_then(|i| i.get("x-overslash-category"))
        .and_then(Value::as_str)
        .map(str::to_string);

    let hosts = extract_hosts(root.get("servers"));

    let auth = match extract_auth(root.get("components")) {
        Ok(a) => a,
        Err(mut es) => {
            errors.append(&mut es);
            Vec::new()
        }
    };

    let mut actions: HashMap<String, ServiceAction> = HashMap::new();
    if let Some(paths) = root.get("paths").and_then(Value::as_object) {
        for (path_key, path_item) in paths {
            let Some(path_obj) = path_item.as_object() else {
                continue;
            };
            let path_level_params = path_obj.get("parameters");
            for method in HTTP_METHODS {
                let Some(op) = path_obj.get(*method).and_then(Value::as_object) else {
                    continue;
                };
                match extract_http_action(path_key, method, op, path_level_params, &mut actions) {
                    Ok(()) => {}
                    Err(mut es) => errors.append(&mut es),
                }
            }
        }
    }

    if let Some(platform) = root
        .get("x-overslash-platform_actions")
        .and_then(Value::as_object)
    {
        for (action_key, action) in platform {
            let Some(obj) = action.as_object() else {
                errors.push(ValidationIssue::new(
                    "openapi_invalid",
                    "platform action must be an object",
                    format!("x-overslash-platform_actions.{action_key}"),
                ));
                continue;
            };
            match extract_platform_action(action_key, obj) {
                Ok(a) => {
                    actions.insert(action_key.clone(), a);
                }
                Err(mut es) => errors.append(&mut es),
            }
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    Ok((
        ServiceDefinition {
            key,
            display_name,
            description,
            hosts,
            category,
            auth,
            actions,
        },
        warnings,
    ))
}

// ── Alias rewriting ──────────────────────────────────────────────────────

fn rewrite_aliases(
    obj: &mut Map<String, Value>,
    table: &[Alias],
    base_path: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    for a in table {
        let has_alias = obj.contains_key(a.alias);
        let has_canonical = obj.contains_key(a.canonical);
        match (has_alias, has_canonical) {
            (true, true) => {
                let path = if base_path.is_empty() {
                    a.alias.to_string()
                } else {
                    format!("{base_path}.{}", a.alias)
                };
                issues.push(ValidationIssue::new(
                    "ambiguous_alias",
                    format!(
                        "both `{}` and `{}` are present on the same object; remove one",
                        a.alias, a.canonical
                    ),
                    path,
                ));
            }
            (true, false) => {
                if let Some(val) = obj.remove(a.alias) {
                    obj.insert(a.canonical.to_string(), val);
                }
            }
            _ => {}
        }
    }
}

fn normalize_operation_parameters(
    op: &mut Map<String, Value>,
    op_base: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    let Some(params) = op.get_mut("parameters").and_then(Value::as_array_mut) else {
        return;
    };
    for (i, p) in params.iter_mut().enumerate() {
        let Value::Object(pm) = p else { continue };
        let base = format!("{op_base}.parameters[{i}]");
        rewrite_aliases(pm, PARAMETER_ALIASES, &base, issues);
    }
}

// ── Extraction helpers ───────────────────────────────────────────────────

fn extract_hosts(servers: Option<&Value>) -> Vec<String> {
    let Some(arr) = servers.and_then(Value::as_array) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|s| s.as_object())
        .filter_map(|o| o.get("url").and_then(Value::as_str))
        .filter_map(url_to_host)
        .collect()
}

fn url_to_host(url: &str) -> Option<String> {
    let s = url.trim();
    let s = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    let host = s.split('/').next()?.split(':').next()?.trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn extract_auth(components: Option<&Value>) -> Result<Vec<ServiceAuth>, Vec<ValidationIssue>> {
    let mut out = Vec::new();
    let mut errors = Vec::new();
    let Some(schemes) = components
        .and_then(Value::as_object)
        .and_then(|c| c.get("securitySchemes"))
        .and_then(Value::as_object)
    else {
        return Ok(out);
    };

    // Deterministic order so tests/snapshots are stable.
    let mut keys: Vec<&String> = schemes.keys().collect();
    keys.sort();
    for name in keys {
        let scheme = &schemes[name];
        let Some(obj) = scheme.as_object() else {
            continue;
        };
        let base = format!("components.securitySchemes.{name}");
        let ty = obj.get("type").and_then(Value::as_str).unwrap_or("");
        match ty {
            "oauth2" => match extract_oauth2(obj, &base) {
                Ok(a) => out.push(a),
                Err(mut es) => errors.append(&mut es),
            },
            "apiKey" => match extract_api_key(obj, &base) {
                Ok(a) => out.push(a),
                Err(mut es) => errors.append(&mut es),
            },
            "http" => match extract_http_auth(obj, &base) {
                Ok(a) => out.push(a),
                Err(mut es) => errors.append(&mut es),
            },
            other => errors.push(ValidationIssue::new(
                "openapi_unsupported_construct",
                format!("security scheme type {other:?} is not supported"),
                format!("{base}.type"),
            )),
        }
    }

    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

fn extract_oauth2(
    obj: &Map<String, Value>,
    base: &str,
) -> Result<ServiceAuth, Vec<ValidationIssue>> {
    let provider = obj
        .get("x-overslash-provider")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    // Collect scopes from all declared OAuth flows (authorizationCode is the
    // common one). A scope declared in any flow counts as supported.
    let mut scopes: Vec<String> = Vec::new();
    if let Some(flows) = obj.get("flows").and_then(Value::as_object) {
        for flow in flows.values() {
            if let Some(f) = flow.as_object() {
                if let Some(s) = f.get("scopes").and_then(Value::as_object) {
                    for k in s.keys() {
                        if !scopes.contains(k) {
                            scopes.push(k.clone());
                        }
                    }
                }
            }
        }
    }

    // OAuth tokens are standardly injected as `Authorization: Bearer <token>`.
    // Allow an explicit override via x-overslash-token_injection; otherwise
    // use the bearer default.
    let token_injection = parse_token_injection(obj.get("x-overslash-token_injection"), base)
        .unwrap_or(TokenInjection {
            inject_as: "header".into(),
            header_name: Some("Authorization".into()),
            query_param: None,
            prefix: Some("Bearer ".into()),
        });

    let _ = base;
    Ok(ServiceAuth::OAuth {
        provider,
        scopes,
        token_injection,
    })
}

fn extract_api_key(
    obj: &Map<String, Value>,
    base: &str,
) -> Result<ServiceAuth, Vec<ValidationIssue>> {
    let default_secret_name = obj
        .get("x-overslash-default_secret_name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let inject_as = obj.get("in").and_then(Value::as_str).unwrap_or("header");
    let name = obj.get("name").and_then(Value::as_str).map(str::to_string);

    let injection = match inject_as {
        "header" => TokenInjection {
            inject_as: "header".into(),
            header_name: name,
            query_param: None,
            prefix: obj
                .get("x-overslash-prefix")
                .and_then(Value::as_str)
                .map(str::to_string),
        },
        "query" => TokenInjection {
            inject_as: "query".into(),
            header_name: None,
            query_param: name,
            prefix: None,
        },
        other => {
            return Err(vec![ValidationIssue::new(
                "openapi_unsupported_construct",
                format!("apiKey `in` must be `header` or `query` (got {other:?})"),
                format!("{base}.in"),
            )]);
        }
    };

    Ok(ServiceAuth::ApiKey {
        default_secret_name,
        injection,
    })
}

fn extract_http_auth(
    obj: &Map<String, Value>,
    base: &str,
) -> Result<ServiceAuth, Vec<ValidationIssue>> {
    let scheme = obj.get("scheme").and_then(Value::as_str).unwrap_or("");
    if scheme != "bearer" {
        return Err(vec![ValidationIssue::new(
            "openapi_unsupported_construct",
            format!("http auth scheme {scheme:?} is not supported (only `bearer`)"),
            format!("{base}.scheme"),
        )]);
    }
    let default_secret_name = obj
        .get("x-overslash-default_secret_name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    Ok(ServiceAuth::ApiKey {
        default_secret_name,
        injection: TokenInjection {
            inject_as: "header".into(),
            header_name: Some("Authorization".into()),
            query_param: None,
            prefix: Some("Bearer ".into()),
        },
    })
}

fn parse_token_injection(v: Option<&Value>, _base: &str) -> Option<TokenInjection> {
    let obj = v?.as_object()?;
    Some(TokenInjection {
        inject_as: obj
            .get("as")
            .and_then(Value::as_str)
            .unwrap_or("header")
            .to_string(),
        header_name: obj
            .get("header_name")
            .and_then(Value::as_str)
            .map(str::to_string),
        query_param: obj
            .get("query_param")
            .and_then(Value::as_str)
            .map(str::to_string),
        prefix: obj
            .get("prefix")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

fn extract_http_action(
    path_key: &str,
    method: &str,
    op: &Map<String, Value>,
    path_level_params: Option<&Value>,
    sink: &mut HashMap<String, ServiceAction>,
) -> Result<(), Vec<ValidationIssue>> {
    let base = format!("paths.{path_key}.{method}");

    let action_key = op
        .get("operationId")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            vec![ValidationIssue::new(
                "missing_field",
                "operationId is required (used as the action key)",
                format!("{base}.operationId"),
            )]
        })?
        .to_string();

    let description = op
        .get("summary")
        .and_then(Value::as_str)
        .or_else(|| op.get("description").and_then(Value::as_str))
        .unwrap_or("")
        .to_string();

    let risk = match op.get("x-overslash-risk").and_then(Value::as_str) {
        Some("read") => Risk::Read,
        Some("write") => Risk::Write,
        Some("delete") => Risk::Delete,
        Some(other) => {
            return Err(vec![ValidationIssue::new(
                "invalid_risk",
                format!("x-overslash-risk must be one of read/write/delete (got {other:?})"),
                format!("{base}.x-overslash-risk"),
            )]);
        }
        None => Risk::from_http_method(method),
    };

    let scope_param = op
        .get("x-overslash-scope_param")
        .and_then(Value::as_str)
        .map(str::to_string);

    let response_type = detect_response_type(op);

    // Merge path-level parameters with operation-level parameters. Operation-
    // level entries win on name collision (OpenAPI rule).
    let mut params: HashMap<String, ActionParam> = HashMap::new();
    if let Some(arr) = path_level_params.and_then(Value::as_array) {
        collect_parameters(arr, &mut params);
    }
    if let Some(arr) = op.get("parameters").and_then(Value::as_array) {
        collect_parameters(arr, &mut params);
    }
    collect_body_parameters(op.get("requestBody"), &mut params);

    sink.insert(
        action_key,
        ServiceAction {
            method: method.to_uppercase(),
            path: path_key.to_string(),
            description,
            risk,
            response_type,
            params,
            scope_param,
        },
    );

    Ok(())
}

fn extract_platform_action(
    action_key: &str,
    op: &Map<String, Value>,
) -> Result<ServiceAction, Vec<ValidationIssue>> {
    let base = format!("x-overslash-platform_actions.{action_key}");

    let description = op
        .get("description")
        .and_then(Value::as_str)
        .or_else(|| op.get("summary").and_then(Value::as_str))
        .unwrap_or("")
        .to_string();

    let risk = match op.get("x-overslash-risk").and_then(Value::as_str) {
        Some("read") | None => Risk::Read,
        Some("write") => Risk::Write,
        Some("delete") => Risk::Delete,
        Some(other) => {
            return Err(vec![ValidationIssue::new(
                "invalid_risk",
                format!("x-overslash-risk must be one of read/write/delete (got {other:?})"),
                format!("{base}.x-overslash-risk"),
            )]);
        }
    };

    Ok(ServiceAction {
        method: String::new(),
        path: String::new(),
        description,
        risk,
        response_type: None,
        params: HashMap::new(),
        scope_param: op
            .get("x-overslash-scope_param")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

fn detect_response_type(op: &Map<String, Value>) -> Option<String> {
    let responses = op.get("responses")?.as_object()?;
    // Prefer 200; fall back to any 2xx code. Binary wins if any content entry
    // is octet-stream or application/pdf etc.
    let ordered: Vec<&String> = responses.keys().collect();
    for code in ordered {
        if !code.starts_with('2') && code.as_str() != "default" {
            continue;
        }
        let Some(content) = responses[code]
            .as_object()
            .and_then(|r| r.get("content"))
            .and_then(Value::as_object)
        else {
            continue;
        };
        for media in content.keys() {
            let m = media.to_lowercase();
            if m.starts_with("application/json") || m.starts_with("application/problem+json") {
                return Some("json".into());
            }
            if m.starts_with("application/octet-stream")
                || m.starts_with("application/pdf")
                || m.starts_with("image/")
                || m.starts_with("video/")
                || m.starts_with("audio/")
            {
                return Some("binary".into());
            }
        }
    }
    None
}

fn collect_parameters(arr: &[Value], out: &mut HashMap<String, ActionParam>) {
    for p in arr {
        let Some(obj) = p.as_object() else { continue };
        let Some(name) = obj.get("name").and_then(Value::as_str) else {
            continue;
        };
        let required = obj
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let description = obj
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let schema = obj.get("schema").and_then(Value::as_object);
        let (param_type, enum_values, default) = schema_fields(schema);

        let resolve = obj.get("x-overslash-resolve").and_then(parse_resolver);

        out.insert(
            name.to_string(),
            ActionParam {
                param_type,
                required,
                description,
                enum_values,
                default,
                resolve,
            },
        );
    }
}

fn collect_body_parameters(body: Option<&Value>, out: &mut HashMap<String, ActionParam>) {
    let Some(b) = body.and_then(Value::as_object) else {
        return;
    };
    let body_required = b.get("required").and_then(Value::as_bool).unwrap_or(false);
    let Some(schema) = b
        .get("content")
        .and_then(Value::as_object)
        .and_then(|c| c.get("application/json"))
        .and_then(Value::as_object)
        .and_then(|j| j.get("schema"))
        .and_then(Value::as_object)
    else {
        return;
    };

    let required_names: Vec<String> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    let Some(props) = schema.get("properties").and_then(Value::as_object) else {
        return;
    };

    for (name, prop) in props {
        let pobj = prop.as_object();
        let (param_type, enum_values, default) = schema_fields(pobj);
        let description = pobj
            .and_then(|o| o.get("description"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let resolve = pobj
            .and_then(|o| o.get("x-overslash-resolve"))
            .and_then(parse_resolver);

        out.insert(
            name.clone(),
            ActionParam {
                param_type,
                required: body_required && required_names.iter().any(|r| r == name),
                description,
                enum_values,
                default,
                resolve,
            },
        );
    }
}

fn schema_fields(
    schema: Option<&Map<String, Value>>,
) -> (String, Option<Vec<String>>, Option<Value>) {
    let Some(s) = schema else {
        return ("string".into(), None, None);
    };
    let param_type = s
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("string")
        .to_string();
    let enum_values = s.get("enum").and_then(Value::as_array).map(|a| {
        a.iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect()
    });
    let default = s.get("default").cloned();
    (param_type, enum_values, default)
}

fn parse_resolver(v: &Value) -> Option<ParamResolver> {
    let obj = v.as_object()?;
    let get = obj.get("get").and_then(Value::as_str)?.to_string();
    let pick = obj.get("pick").and_then(Value::as_str)?.to_string();
    Some(ParamResolver { get, pick })
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc(v: Value) -> Value {
        v
    }

    // ── Normalizer tests ────────────────────────────────────────────

    #[test]
    fn normalize_alias_on_info() {
        let mut v = doc(json!({
            "info": {"key": "slack", "category": "chat", "title": "Slack"}
        }));
        let issues = normalize_aliases(&mut v);
        assert!(issues.is_empty(), "{issues:?}");
        let info = v["info"].as_object().unwrap();
        assert_eq!(info["x-overslash-key"], "slack");
        assert_eq!(info["x-overslash-category"], "chat");
        assert!(!info.contains_key("key"));
        assert!(!info.contains_key("category"));
    }

    #[test]
    fn normalize_idempotent_on_canonical_form() {
        let mut v = doc(json!({
            "info": {"x-overslash-key": "slack", "title": "Slack"}
        }));
        let issues = normalize_aliases(&mut v);
        assert!(issues.is_empty());
        assert_eq!(v["info"]["x-overslash-key"], "slack");
    }

    #[test]
    fn normalize_rejects_ambiguous_info_key() {
        let mut v = doc(json!({
            "info": {"key": "slack", "x-overslash-key": "slack", "title": "Slack"}
        }));
        let issues = normalize_aliases(&mut v);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, "ambiguous_alias");
        assert_eq!(issues[0].path, "info.key");
    }

    #[test]
    fn normalize_operation_risk_and_scope_param() {
        let mut v = doc(json!({
            "paths": {
                "/repos/{repo}/pulls": {
                    "post": {
                        "operationId": "createPull",
                        "risk": "write",
                        "scope_param": "repo"
                    }
                }
            }
        }));
        let issues = normalize_aliases(&mut v);
        assert!(issues.is_empty(), "{issues:?}");
        let op = v["paths"]["/repos/{repo}/pulls"]["post"]
            .as_object()
            .unwrap();
        assert_eq!(op["x-overslash-risk"], "write");
        assert_eq!(op["x-overslash-scope_param"], "repo");
        assert!(!op.contains_key("risk"));
    }

    #[test]
    fn normalize_parameter_resolve() {
        let mut v = doc(json!({
            "paths": {
                "/x/{id}": {
                    "get": {
                        "operationId": "getX",
                        "parameters": [
                            {"name": "id", "in": "path", "required": true,
                             "resolve": {"get": "/x/{id}", "pick": "name"}}
                        ]
                    }
                }
            }
        }));
        let issues = normalize_aliases(&mut v);
        assert!(issues.is_empty(), "{issues:?}");
        let p0 = &v["paths"]["/x/{id}"]["get"]["parameters"][0];
        assert!(p0.get("x-overslash-resolve").is_some());
        assert!(p0.get("resolve").is_none());
    }

    #[test]
    fn normalize_security_scheme_oauth2_provider() {
        let mut v = doc(json!({
            "components": {
                "securitySchemes": {
                    "slack_oauth": {"type": "oauth2", "provider": "slack", "flows": {}}
                }
            }
        }));
        let issues = normalize_aliases(&mut v);
        assert!(issues.is_empty());
        assert_eq!(
            v["components"]["securitySchemes"]["slack_oauth"]["x-overslash-provider"],
            "slack"
        );
    }

    #[test]
    fn normalize_security_scheme_api_key_default_secret() {
        let mut v = doc(json!({
            "components": {
                "securitySchemes": {
                    "slack_token": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "Authorization",
                        "default_secret_name": "slack_token"
                    }
                }
            }
        }));
        let issues = normalize_aliases(&mut v);
        assert!(issues.is_empty());
        assert_eq!(
            v["components"]["securitySchemes"]["slack_token"]["x-overslash-default_secret_name"],
            "slack_token"
        );
    }

    #[test]
    fn normalize_platform_actions_alias() {
        let mut v = doc(json!({
            "platform_actions": {
                "manage_members": {"description": "x", "risk": "delete"}
            }
        }));
        let issues = normalize_aliases(&mut v);
        assert!(issues.is_empty());
        assert!(v.get("x-overslash-platform_actions").is_some());
        assert_eq!(
            v["x-overslash-platform_actions"]["manage_members"]["x-overslash-risk"],
            "delete"
        );
    }

    // ── Compile tests ───────────────────────────────────────────────

    fn service_yaml_fixture() -> Value {
        json!({
            "openapi": "3.1.0",
            "info": {
                "title": "Slack",
                "x-overslash-key": "slack",
                "x-overslash-category": "chat"
            },
            "servers": [{"url": "https://slack.com"}, {"url": "https://api.slack.com"}],
            "components": {
                "securitySchemes": {
                    "oauth": {
                        "type": "oauth2",
                        "x-overslash-provider": "slack",
                        "flows": {
                            "authorizationCode": {
                                "authorizationUrl": "https://slack.com/oauth/v2/authorize",
                                "tokenUrl": "https://slack.com/api/oauth.v2.access",
                                "scopes": {"chat:write": "", "channels:read": ""}
                            }
                        }
                    },
                    "token": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "Authorization",
                        "x-overslash-prefix": "Bearer ",
                        "x-overslash-default_secret_name": "slack_token"
                    }
                }
            },
            "paths": {
                "/api/chat.postMessage": {
                    "post": {
                        "operationId": "send_message",
                        "summary": "Send a message to Slack channel {channel}",
                        "x-overslash-risk": "write",
                        "x-overslash-scope_param": "channel",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["channel", "text"],
                                        "properties": {
                                            "channel": {"type": "string", "description": "Channel ID"},
                                            "text": {"type": "string", "description": "Message text"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "/api/conversations.list": {
                    "get": {
                        "operationId": "list_channels",
                        "summary": "List Slack channels"
                    }
                }
            }
        })
    }

    #[test]
    fn compile_slack_fixture() {
        let mut v = service_yaml_fixture();
        let ns_issues = normalize_aliases(&mut v);
        assert!(ns_issues.is_empty(), "{ns_issues:?}");
        let (svc, warnings) = compile_service(&v).expect("compile ok");
        assert!(warnings.is_empty());

        assert_eq!(svc.key, "slack");
        assert_eq!(svc.display_name, "Slack");
        assert_eq!(svc.category.as_deref(), Some("chat"));
        assert_eq!(svc.hosts, vec!["slack.com", "api.slack.com"]);
        assert_eq!(svc.auth.len(), 2);

        let mut has_oauth = false;
        let mut has_apikey = false;
        for a in &svc.auth {
            match a {
                ServiceAuth::OAuth {
                    provider,
                    scopes,
                    token_injection,
                } => {
                    has_oauth = true;
                    assert_eq!(provider, "slack");
                    assert!(scopes.contains(&"chat:write".to_string()));
                    assert!(scopes.contains(&"channels:read".to_string()));
                    assert_eq!(token_injection.inject_as, "header");
                    assert_eq!(
                        token_injection.header_name.as_deref(),
                        Some("Authorization")
                    );
                    assert_eq!(token_injection.prefix.as_deref(), Some("Bearer "));
                }
                ServiceAuth::ApiKey {
                    default_secret_name,
                    injection,
                } => {
                    has_apikey = true;
                    assert_eq!(default_secret_name, "slack_token");
                    assert_eq!(injection.inject_as, "header");
                    assert_eq!(injection.header_name.as_deref(), Some("Authorization"));
                    assert_eq!(injection.prefix.as_deref(), Some("Bearer "));
                }
            }
        }
        assert!(has_oauth && has_apikey);

        let send = svc.actions.get("send_message").expect("send_message");
        assert_eq!(send.method, "POST");
        assert_eq!(send.path, "/api/chat.postMessage");
        assert_eq!(send.risk, Risk::Write);
        assert_eq!(send.scope_param.as_deref(), Some("channel"));
        assert_eq!(
            send.description,
            "Send a message to Slack channel {channel}"
        );
        assert!(send.params.contains_key("channel"));
        assert!(send.params["channel"].required);
        assert!(send.params.contains_key("text"));
        assert!(send.params["text"].required);

        let list = svc.actions.get("list_channels").expect("list_channels");
        assert_eq!(list.method, "GET");
        assert_eq!(list.risk, Risk::Read);
        assert!(list.scope_param.is_none());
    }

    #[test]
    fn compile_risk_defaults_from_method() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {
                "/a": {"get": {"operationId": "a"}},
                "/b": {"post": {"operationId": "b"}},
                "/c": {"delete": {"operationId": "c"}}
            }
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.actions["a"].risk, Risk::Read);
        assert_eq!(svc.actions["b"].risk, Risk::Write);
        assert_eq!(svc.actions["c"].risk, Risk::Delete);
    }

    #[test]
    fn compile_rejects_invalid_risk() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {
                "/a": {"get": {"operationId": "a", "x-overslash-risk": "catastrophic"}}
            }
        });
        let err = compile_service(&doc).unwrap_err();
        assert_eq!(err[0].code, "invalid_risk");
    }

    #[test]
    fn compile_path_parameters_required() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {
                "/cal/{id}/events": {
                    "get": {
                        "operationId": "list_events",
                        "parameters": [
                            {"name": "id", "in": "path", "required": true,
                             "schema": {"type": "string"}},
                            {"name": "q", "in": "query", "required": false,
                             "schema": {"type": "string"}}
                        ]
                    }
                }
            }
        });
        let (svc, _) = compile_service(&doc).unwrap();
        let a = &svc.actions["list_events"];
        assert!(a.params["id"].required);
        assert!(!a.params["q"].required);
        assert_eq!(a.params["id"].param_type, "string");
    }

    #[test]
    fn compile_param_enum_and_default() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {
                "/x": {
                    "get": {
                        "operationId": "x",
                        "parameters": [
                            {"name": "role", "in": "query",
                             "schema": {"type": "string", "enum": ["reader", "writer"], "default": "reader"}}
                        ]
                    }
                }
            }
        });
        let (svc, _) = compile_service(&doc).unwrap();
        let p = &svc.actions["x"].params["role"];
        assert_eq!(
            p.enum_values.as_deref().unwrap(),
            &["reader".to_string(), "writer".to_string()]
        );
        assert_eq!(p.default.as_ref().unwrap(), "reader");
    }

    #[test]
    fn compile_resolver_on_parameter() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {
                "/cal/{id}": {
                    "get": {
                        "operationId": "get_cal",
                        "parameters": [
                            {"name": "id", "in": "path", "required": true,
                             "schema": {"type": "string"},
                             "x-overslash-resolve": {"get": "/cal/{id}", "pick": "summary"}}
                        ]
                    }
                }
            }
        });
        let (svc, _) = compile_service(&doc).unwrap();
        let p = &svc.actions["get_cal"].params["id"];
        let r = p.resolve.as_ref().unwrap();
        assert_eq!(r.get, "/cal/{id}");
        assert_eq!(r.pick, "summary");
    }

    #[test]
    fn compile_platform_actions() {
        let doc = json!({
            "info": {"title": "Overslash Platform", "x-overslash-key": "overslash", "x-overslash-category": "platform"},
            "x-overslash-platform_actions": {
                "manage_members": {"description": "Manage org members", "x-overslash-risk": "delete"},
                "manage_secrets": {"description": "Manage secrets", "x-overslash-risk": "write"}
            }
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.key, "overslash");
        assert!(svc.hosts.is_empty());
        assert_eq!(svc.actions.len(), 2);
        let m = &svc.actions["manage_members"];
        assert!(m.method.is_empty());
        assert!(m.path.is_empty());
        assert_eq!(m.risk, Risk::Delete);
    }

    #[test]
    fn compile_detects_binary_response() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {
                "/file": {
                    "get": {
                        "operationId": "download",
                        "responses": {
                            "200": {
                                "content": {
                                    "application/octet-stream": {}
                                }
                            }
                        }
                    }
                }
            }
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(
            svc.actions["download"].response_type.as_deref(),
            Some("binary")
        );
    }

    #[test]
    fn compile_missing_operation_id_errors() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {
                "/x": {"get": {}}
            }
        });
        let err = compile_service(&doc).unwrap_err();
        assert_eq!(err[0].code, "missing_field");
        assert!(err[0].path.ends_with(".operationId"));
    }

    // ── End-to-end (YAML → normalize → compile) ───────────────────────

    #[cfg(feature = "yaml")]
    #[test]
    fn yaml_round_trip_with_aliases() {
        let src = r#"
openapi: 3.1.0
info:
  title: Slack
  key: slack
  category: chat
servers:
  - url: https://slack.com
components:
  securitySchemes:
    oauth:
      type: oauth2
      provider: slack
      flows:
        authorizationCode:
          authorizationUrl: https://slack.com/oauth
          tokenUrl: https://slack.com/token
          scopes:
            chat:write: ""
paths:
  /api/chat.postMessage:
    post:
      operationId: send_message
      summary: Send a message to {channel}
      risk: write
      scope_param: channel
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [channel, text]
              properties:
                channel:
                  type: string
                  description: Channel ID
                text:
                  type: string
                  description: Message text
"#;
        let mut v = parse_yaml(src).unwrap();
        let issues = normalize_aliases(&mut v);
        assert!(issues.is_empty(), "{issues:?}");
        let (svc, _) = compile_service(&v).unwrap();
        assert_eq!(svc.key, "slack");
        assert_eq!(svc.hosts, vec!["slack.com"]);
        let send = &svc.actions["send_message"];
        assert_eq!(send.risk, Risk::Write);
        assert_eq!(send.scope_param.as_deref(), Some("channel"));
        assert!(send.params["channel"].required);
    }
}
