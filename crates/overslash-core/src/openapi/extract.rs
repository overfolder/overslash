//! Extraction helpers: lower a normalized OpenAPI JSON document into the
//! fields of [`crate::types::ServiceDefinition`]. None of these helpers
//! mutate their inputs — normalization happens upstream in
//! [`super::alias`].
//!
//! The helpers are grouped by what they produce:
//!
//! - [`extract_hosts`] + [`url_to_host`] — `servers[].url` → `hosts`.
//! - [`extract_auth`] → [`extract_oauth2`] / [`extract_api_key`] /
//!   [`extract_http_auth`] — security schemes → `Vec<ServiceAuth>`.
//! - [`extract_http_action`] + [`extract_platform_action`] —
//!   `paths.*.*` and `x-overslash-platform_actions.*` → `ServiceAction`.
//! - [`collect_parameters`] + [`collect_body_parameters`] +
//!   [`schema_fields`] + [`parse_resolver`] — parameter-level helpers.
//! - [`detect_response_type`] — `responses.*.content.*` → `"json"` / `"binary"`.

use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::template_validation::ValidationIssue;
use crate::types::{
    ActionParam, DisclosureField, ParamResolver, Risk, ServiceAction, ServiceAuth, TokenInjection,
};

// ── servers → hosts ──────────────────────────────────────────────────

pub(super) fn extract_hosts(servers: Option<&Value>) -> Vec<String> {
    let Some(arr) = servers.and_then(Value::as_array) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|s| s.as_object())
        .filter_map(|o| o.get("url").and_then(Value::as_str))
        .filter_map(url_to_host)
        .collect()
}

pub(super) fn url_to_host(url: &str) -> Option<String> {
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

// ── securitySchemes → Vec<ServiceAuth> ───────────────────────────────

pub(super) fn extract_auth(
    components: Option<&Value>,
) -> Result<Vec<ServiceAuth>, Vec<ValidationIssue>> {
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
    _base: &str,
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
    let token_injection =
        parse_token_injection(obj.get("x-overslash-token_injection")).unwrap_or(TokenInjection {
            inject_as: "header".into(),
            header_name: Some("Authorization".into()),
            query_param: None,
            prefix: Some("Bearer ".into()),
        });

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

fn parse_token_injection(v: Option<&Value>) -> Option<TokenInjection> {
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

// ── paths.*.* → ServiceAction ────────────────────────────────────────

pub(super) fn extract_http_action(
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

    // Per-action OAuth scopes: look at the operation's `security` clause.
    // For each security requirement object pick the first non-empty scope
    // list — matches the OpenAPI 3.1 spec's "requirements are OR-ed" model
    // for the common case of a single `oauth2` security scheme.
    let required_scopes = op
        .get("security")
        .and_then(Value::as_array)
        .and_then(|reqs| {
            reqs.iter().find_map(|req| {
                req.as_object()?.values().find_map(|scopes| {
                    let arr = scopes.as_array()?;
                    if arr.is_empty() {
                        None
                    } else {
                        Some(
                            arr.iter()
                                .filter_map(Value::as_str)
                                .map(str::to_string)
                                .collect::<Vec<_>>(),
                        )
                    }
                })
            })
        })
        .unwrap_or_default();

    let mut disclose_errors = Vec::new();
    let disclose = parse_disclose(op.get("x-overslash-disclose"), &base, &mut disclose_errors);
    let redact = parse_redact(op.get("x-overslash-redact"), &base, &mut disclose_errors);
    if !disclose_errors.is_empty() {
        return Err(disclose_errors);
    }

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
            required_scopes,
            disclose,
            redact,
            mcp_tool: None,
            output_schema: None,
            disabled: false,
        },
    );

    Ok(())
}

pub(super) fn extract_platform_action(
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
        required_scopes: Vec::new(),
        // Platform actions don't have outbound HTTP payloads — disclosure
        // and redaction are no-ops for them.
        disclose: Vec::new(),
        redact: Vec::new(),
        mcp_tool: None,
        output_schema: None,
        disabled: false,
    })
}

// ── x-overslash-disclose / x-overslash-redact ─────────────────────────

fn parse_disclose(
    v: Option<&Value>,
    base: &str,
    issues: &mut Vec<ValidationIssue>,
) -> Vec<DisclosureField> {
    let Some(v) = v else { return Vec::new() };
    let Some(arr) = v.as_array() else {
        issues.push(ValidationIssue::new(
            "disclose_malformed",
            "x-overslash-disclose must be an array of {label, filter, max_chars?}",
            format!("{base}.x-overslash-disclose"),
        ));
        return Vec::new();
    };
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let p = format!("{base}.x-overslash-disclose[{i}]");
        let Some(obj) = item.as_object() else {
            issues.push(ValidationIssue::new(
                "disclose_malformed",
                "entry must be an object with `label` and `filter`",
                p,
            ));
            continue;
        };
        let label = match obj.get("label").and_then(Value::as_str) {
            Some(s) if !s.trim().is_empty() => s.to_string(),
            _ => {
                issues.push(ValidationIssue::new(
                    "disclose_invalid_label",
                    "`label` must be a non-empty string",
                    format!("{p}.label"),
                ));
                continue;
            }
        };
        let filter = match obj.get("filter").and_then(Value::as_str) {
            Some(s) if !s.trim().is_empty() => s.to_string(),
            _ => {
                issues.push(ValidationIssue::new(
                    "disclose_malformed",
                    "`filter` must be a non-empty jq expression string",
                    format!("{p}.filter"),
                ));
                continue;
            }
        };
        let max_chars = obj
            .get("max_chars")
            .and_then(Value::as_u64)
            .map(|n| n as usize);
        out.push(DisclosureField {
            label,
            filter,
            max_chars,
        });
    }
    out
}

fn parse_redact(v: Option<&Value>, base: &str, issues: &mut Vec<ValidationIssue>) -> Vec<String> {
    let Some(v) = v else { return Vec::new() };
    let Some(arr) = v.as_array() else {
        issues.push(ValidationIssue::new(
            "redact_invalid_path",
            "x-overslash-redact must be an array of dotted-path strings",
            format!("{base}.x-overslash-redact"),
        ));
        return Vec::new();
    };
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let p = format!("{base}.x-overslash-redact[{i}]");
        match item.as_str() {
            Some(s) if !s.trim().is_empty() && !s.split('.').any(str::is_empty) => {
                out.push(s.to_string());
            }
            _ => issues.push(ValidationIssue::new(
                "redact_invalid_path",
                "each entry must be a non-empty dotted path (e.g. `body.api_key`)",
                p,
            )),
        }
    }
    out
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

// ── parameters → HashMap<String, ActionParam> ────────────────────────

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

#[cfg(test)]
mod tests {
    use super::super::compile_service;
    use super::*;
    use crate::types::{Risk, ServiceAuth};
    use serde_json::json;

    // ── url_to_host / extract_hosts ──────────────────────────────────

    #[test]
    fn url_to_host_strips_https() {
        assert_eq!(
            url_to_host("https://api.example.com/v1"),
            Some("api.example.com".into())
        );
    }

    #[test]
    fn url_to_host_strips_http() {
        assert_eq!(
            url_to_host("http://internal.svc/api"),
            Some("internal.svc".into())
        );
    }

    #[test]
    fn url_to_host_strips_port() {
        assert_eq!(
            url_to_host("https://api.example.com:8443/v1"),
            Some("api.example.com".into())
        );
    }

    #[test]
    fn url_to_host_accepts_scheme_relative() {
        assert_eq!(
            url_to_host("api.example.com/v1"),
            Some("api.example.com".into())
        );
    }

    #[test]
    fn url_to_host_empty_returns_none() {
        assert!(url_to_host("").is_none());
        assert!(url_to_host("   ").is_none());
        assert!(url_to_host("https://").is_none());
    }

    #[test]
    fn extract_hosts_missing_servers_returns_empty() {
        let (svc, _) = compile_service(&json!({
            "info": {"title": "T", "x-overslash-key": "t"}
        }))
        .unwrap();
        assert!(svc.hosts.is_empty());
    }

    #[test]
    fn extract_hosts_skips_entries_without_url() {
        let (svc, _) = compile_service(&json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "servers": [
                {"description": "no url field"},
                {"url": "https://real.example.com"},
                "not-an-object"
            ]
        }))
        .unwrap();
        assert_eq!(svc.hosts, vec!["real.example.com"]);
    }

    // ── extract_auth / oauth2 / apiKey ───────────────────────────────

    #[test]
    fn auth_missing_components_yields_no_auth() {
        let doc = json!({"info": {"title": "T", "x-overslash-key": "t"}});
        let (svc, _) = compile_service(&doc).unwrap();
        assert!(svc.auth.is_empty());
    }

    #[test]
    fn auth_rejects_openid_connect() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "oidc": {"type": "openIdConnect", "openIdConnectUrl": "https://x/.well-known"}
            }}
        });
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter()
                .any(|i| i.code == "openapi_unsupported_construct" && i.path.ends_with(".type")),
            "got: {err:?}"
        );
    }

    #[test]
    fn auth_skips_non_object_scheme_value() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "junk": "string-value",
                "real": {
                    "type": "apiKey", "in": "header", "name": "Authorization",
                    "x-overslash-prefix": "Bearer ",
                    "x-overslash-default_secret_name": "svc_token"
                }
            }}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.auth.len(), 1);
        assert!(matches!(svc.auth[0], ServiceAuth::ApiKey { .. }));
    }

    #[test]
    fn api_key_in_query() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "token": {
                    "type": "apiKey",
                    "in": "query",
                    "name": "api_key",
                    "x-overslash-default_secret_name": "t_token"
                }
            }}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        match svc.auth.into_iter().next().unwrap() {
            ServiceAuth::ApiKey {
                default_secret_name,
                injection,
            } => {
                assert_eq!(default_secret_name, "t_token");
                assert_eq!(injection.inject_as, "query");
                assert_eq!(injection.query_param.as_deref(), Some("api_key"));
                assert!(injection.header_name.is_none());
                assert!(injection.prefix.is_none());
            }
            _ => panic!("expected ApiKey"),
        }
    }

    #[test]
    fn api_key_rejects_in_cookie() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "c": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": "session",
                    "x-overslash-default_secret_name": "t_token"
                }
            }}
        });
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter()
                .any(|i| i.code == "openapi_unsupported_construct" && i.path.ends_with(".in")),
            "got: {err:?}"
        );
    }

    #[test]
    fn api_key_defaults_in_to_header() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "token": {
                    "type": "apiKey",
                    "name": "Authorization",
                    "x-overslash-default_secret_name": "t_token"
                }
            }}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        match &svc.auth[0] {
            ServiceAuth::ApiKey { injection, .. } => {
                assert_eq!(injection.inject_as, "header");
                assert_eq!(injection.header_name.as_deref(), Some("Authorization"));
            }
            _ => panic!("expected ApiKey"),
        }
    }

    // ── extract_http_auth: full coverage ──────────────────────────────

    #[test]
    fn http_bearer_success() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "bearer": {
                    "type": "http",
                    "scheme": "bearer",
                    "x-overslash-default_secret_name": "t_token"
                }
            }}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        match &svc.auth[0] {
            ServiceAuth::ApiKey {
                default_secret_name,
                injection,
            } => {
                assert_eq!(default_secret_name, "t_token");
                assert_eq!(injection.inject_as, "header");
                assert_eq!(injection.header_name.as_deref(), Some("Authorization"));
                assert_eq!(injection.prefix.as_deref(), Some("Bearer "));
                assert!(injection.query_param.is_none());
            }
            _ => panic!("expected ApiKey for http/bearer"),
        }
    }

    #[test]
    fn http_bearer_allows_missing_default_secret_name() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "bearer": {"type": "http", "scheme": "bearer"}
            }}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        match &svc.auth[0] {
            ServiceAuth::ApiKey {
                default_secret_name,
                ..
            } => assert!(default_secret_name.is_empty()),
            _ => panic!("expected ApiKey for http/bearer"),
        }
    }

    #[test]
    fn http_rejects_basic_scheme() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "basic": {"type": "http", "scheme": "basic"}
            }}
        });
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter().any(|i| i.code == "openapi_unsupported_construct"
                && i.message.contains("basic")
                && i.path.ends_with(".scheme")),
            "got: {err:?}"
        );
    }

    #[test]
    fn http_rejects_digest_scheme() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "digest": {"type": "http", "scheme": "digest"}
            }}
        });
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter()
                .any(|i| i.code == "openapi_unsupported_construct" && i.message.contains("digest")),
            "got: {err:?}"
        );
    }

    #[test]
    fn http_rejects_missing_scheme() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "nope": {"type": "http"}
            }}
        });
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter()
                .any(|i| i.code == "openapi_unsupported_construct" && i.path.ends_with(".scheme")),
            "got: {err:?}"
        );
    }

    // ── extract_oauth2 ────────────────────────────────────────────────

    #[test]
    fn oauth2_with_explicit_token_injection_override() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "oauth": {
                    "type": "oauth2",
                    "x-overslash-provider": "custom",
                    "flows": {},
                    "x-overslash-token_injection": {
                        "as": "query",
                        "query_param": "access_token"
                    }
                }
            }}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        match &svc.auth[0] {
            ServiceAuth::OAuth {
                token_injection, ..
            } => {
                assert_eq!(token_injection.inject_as, "query");
                assert_eq!(token_injection.query_param.as_deref(), Some("access_token"));
                assert!(token_injection.header_name.is_none());
            }
            _ => panic!("expected OAuth"),
        }
    }

    #[test]
    fn oauth2_empty_provider_allowed() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "oauth": {"type": "oauth2", "flows": {}}
            }}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        match &svc.auth[0] {
            ServiceAuth::OAuth { provider, .. } => assert!(provider.is_empty()),
            _ => panic!("expected OAuth"),
        }
    }

    #[test]
    fn oauth2_dedups_scopes_across_flows() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "oauth": {
                    "type": "oauth2",
                    "x-overslash-provider": "p",
                    "flows": {
                        "authorizationCode": {
                            "authorizationUrl": "https://x", "tokenUrl": "https://y",
                            "scopes": {"read": "", "write": ""}
                        },
                        "clientCredentials": {
                            "tokenUrl": "https://y",
                            "scopes": {"read": "", "admin": ""}
                        }
                    }
                }
            }}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        match &svc.auth[0] {
            ServiceAuth::OAuth { scopes, .. } => {
                assert!(scopes.contains(&"read".to_string()));
                assert!(scopes.contains(&"write".to_string()));
                assert!(scopes.contains(&"admin".to_string()));
                let reads = scopes.iter().filter(|s| *s == "read").count();
                assert_eq!(reads, 1);
            }
            _ => panic!("expected OAuth"),
        }
    }

    // ── extract_http_action: risk / description fallbacks ────────────

    #[test]
    fn risk_defaults_from_method() {
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
    fn rejects_invalid_risk_on_operation() {
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
    fn description_falls_back_to_description_field() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"get": {
                "operationId": "x",
                "description": "Long-form description"
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.actions["x"].description, "Long-form description");
    }

    #[test]
    fn missing_operation_id_errors() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"get": {}}}
        });
        let err = compile_service(&doc).unwrap_err();
        assert_eq!(err[0].code, "missing_field");
        assert!(err[0].path.ends_with(".operationId"));
    }

    // ── extract_platform_action ──────────────────────────────────────

    #[test]
    fn platform_action_not_object_errors() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "x-overslash-platform_actions": {
                "bad": "not-an-object"
            }
        });
        let err = compile_service(&doc).unwrap_err();
        assert_eq!(err[0].code, "openapi_invalid");
        assert!(err[0].path.ends_with(".bad"));
    }

    #[test]
    fn platform_action_rejects_invalid_risk() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "x-overslash-platform_actions": {
                "act": {"description": "x", "x-overslash-risk": "yolo"}
            }
        });
        let err = compile_service(&doc).unwrap_err();
        assert_eq!(err[0].code, "invalid_risk");
    }

    #[test]
    fn platform_action_falls_back_to_summary_when_description_missing() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "x-overslash-platform_actions": {
                "act": {"summary": "Summary fallback", "x-overslash-risk": "write"}
            }
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.actions["act"].description, "Summary fallback");
    }

    #[test]
    fn platform_action_default_risk_is_read() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "x-overslash-platform_actions": {
                "act": {"description": "x"}
            }
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.actions["act"].risk, Risk::Read);
    }

    // ── detect_response_type ─────────────────────────────────────────

    #[test]
    fn response_type_none_when_no_responses() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"get": {"operationId": "x"}}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert!(svc.actions["x"].response_type.is_none());
    }

    #[test]
    fn response_type_ignores_non_success_codes() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"get": {
                "operationId": "x",
                "responses": {
                    "400": {"content": {"application/octet-stream": {}}},
                    "500": {"content": {"application/octet-stream": {}}}
                }
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert!(svc.actions["x"].response_type.is_none());
    }

    #[test]
    fn response_type_picks_up_default_code() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"get": {
                "operationId": "x",
                "responses": {
                    "default": {"content": {"application/json": {}}}
                }
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.actions["x"].response_type.as_deref(), Some("json"));
    }

    #[test]
    fn response_type_detects_binary_for_pdf_image_video_audio() {
        for media in ["application/pdf", "image/png", "video/mp4", "audio/mpeg"] {
            let doc = json!({
                "info": {"title": "T", "x-overslash-key": "t"},
                "paths": {"/x": {"get": {
                    "operationId": "x",
                    "responses": {"200": {"content": {media: {}}}}
                }}}
            });
            let (svc, _) = compile_service(&doc).unwrap();
            assert_eq!(
                svc.actions["x"].response_type.as_deref(),
                Some("binary"),
                "expected binary for media type {media}"
            );
        }
    }

    #[test]
    fn response_type_detects_octet_stream() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/file": {"get": {
                "operationId": "download",
                "responses": {"200": {"content": {"application/octet-stream": {}}}}
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(
            svc.actions["download"].response_type.as_deref(),
            Some("binary")
        );
    }

    // ── collect_parameters / body / schema_fields ────────────────────

    #[test]
    fn parameter_without_name_is_skipped() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"get": {
                "operationId": "x",
                "parameters": [
                    {"in": "query", "schema": {"type": "string"}},
                    {"name": "q", "in": "query", "schema": {"type": "string"}}
                ]
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.actions["x"].params.len(), 1);
        assert!(svc.actions["x"].params.contains_key("q"));
    }

    #[test]
    fn parameter_without_schema_defaults_to_string() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"get": {
                "operationId": "x",
                "parameters": [{"name": "q", "in": "query"}]
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.actions["x"].params["q"].param_type, "string");
    }

    #[test]
    fn path_parameters_required_and_typed() {
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
    fn parameter_enum_and_default() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"get": {
                "operationId": "x",
                "parameters": [{
                    "name": "role", "in": "query",
                    "schema": {
                        "type": "string",
                        "enum": ["reader", "writer"],
                        "default": "reader"
                    }
                }]
            }}}
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
    fn resolver_on_parameter() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/cal/{id}": {"get": {
                "operationId": "get_cal",
                "parameters": [{
                    "name": "id", "in": "path", "required": true,
                    "schema": {"type": "string"},
                    "x-overslash-resolve": {"get": "/cal/{id}", "pick": "summary"}
                }]
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        let r = svc.actions["get_cal"].params["id"]
            .resolve
            .as_ref()
            .unwrap();
        assert_eq!(r.get, "/cal/{id}");
        assert_eq!(r.pick, "summary");
    }

    #[test]
    fn body_without_required_array_marks_props_optional() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"post": {
                "operationId": "x",
                "requestBody": {
                    "required": true,
                    "content": {"application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {"foo": {"type": "string"}}
                        }
                    }}
                }
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert!(!svc.actions["x"].params["foo"].required);
    }

    #[test]
    fn body_required_false_makes_all_props_optional() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"post": {
                "operationId": "x",
                "requestBody": {
                    "content": {"application/json": {
                        "schema": {
                            "type": "object",
                            "required": ["foo"],
                            "properties": {"foo": {"type": "string"}}
                        }
                    }}
                }
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert!(!svc.actions["x"].params["foo"].required);
    }

    #[test]
    fn body_wrong_content_type_ignored() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"post": {
                "operationId": "x",
                "requestBody": {
                    "required": true,
                    "content": {"application/xml": {
                        "schema": {
                            "type": "object",
                            "required": ["foo"],
                            "properties": {"foo": {"type": "string"}}
                        }
                    }}
                }
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert!(svc.actions["x"].params.is_empty());
    }

    #[test]
    fn body_without_properties_is_noop() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"post": {
                "operationId": "x",
                "requestBody": {
                    "required": true,
                    "content": {"application/json": {
                        "schema": {"type": "object"}
                    }}
                }
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert!(svc.actions["x"].params.is_empty());
    }

    #[test]
    fn operation_params_shadow_path_params() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x/{id}": {
                "parameters": [{
                    "name": "id", "in": "path", "required": true,
                    "description": "path-level", "schema": {"type": "string"}
                }],
                "get": {
                    "operationId": "x",
                    "parameters": [{
                        "name": "id", "in": "path", "required": true,
                        "description": "op-level", "schema": {"type": "string"}
                    }]
                }
            }}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.actions["x"].params["id"].description, "op-level");
    }

    // ── parse_resolver structural edge cases ──────────────────────────

    #[test]
    fn resolver_drops_entry_missing_get() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x/{id}": {"get": {
                "operationId": "x",
                "parameters": [{
                    "name": "id", "in": "path", "required": true,
                    "schema": {"type": "string"},
                    "x-overslash-resolve": {"pick": "name"}
                }]
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert!(svc.actions["x"].params["id"].resolve.is_none());
    }

    #[test]
    fn resolver_drops_entry_missing_pick() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x/{id}": {"get": {
                "operationId": "x",
                "parameters": [{
                    "name": "id", "in": "path", "required": true,
                    "schema": {"type": "string"},
                    "x-overslash-resolve": {"get": "/x/{id}"}
                }]
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert!(svc.actions["x"].params["id"].resolve.is_none());
    }
}
