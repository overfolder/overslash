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
    ActionParam, CredentialTemplate, DisclosureField, McpAuth, McpSpec, ParamLocation,
    ParamResolver, Risk, SecretSlot, ServiceAction, ServiceAuth, ServiceDefinition, TokenInjection,
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

pub fn url_to_host(url: &str) -> Option<String> {
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

/// Compile `components.x-overslash-secrets` + `components.securitySchemes`
/// into the credential model: the slots an operator binds, and the injections
/// that read them.
pub(super) fn extract_auth(
    components: Option<&Value>,
) -> Result<(Vec<ServiceAuth>, Vec<SecretSlot>), Vec<ValidationIssue>> {
    let mut out = Vec::new();
    let mut errors = Vec::new();

    let mut slots = match extract_secret_slots(components) {
        Ok(s) => s,
        Err(mut es) => {
            errors.append(&mut es);
            Vec::new()
        }
    };
    let declared: Vec<String> = slots.iter().map(|s| s.key.clone()).collect();

    let Some(schemes) = components
        .and_then(Value::as_object)
        .and_then(|c| c.get("securitySchemes"))
        .and_then(Value::as_object)
    else {
        if !errors.is_empty() {
            return Err(errors);
        }
        return Ok((out, slots));
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
            "apiKey" => match extract_api_key(obj, &base, name, &declared) {
                Ok(a) => out.push(a),
                Err(mut es) => errors.append(&mut es),
            },
            "http" => match extract_http_auth(obj, &base, name) {
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

    // Every scheme implicitly declares a slot named after itself, carrying the
    // scheme's own label/source/optional. That is the shape of a credential
    // that needs just one secret, so those templates declare no secrets block.
    for auth in &out {
        if let ServiceAuth::Secret {
            scheme,
            label,
            description,
            default_secret_name,
            slots: read,
            secret_source,
            optional,
            ..
        } = auth
        {
            if read.iter().any(|s| s == scheme) && !slots.iter().any(|s| &s.key == scheme) {
                slots.push(SecretSlot {
                    key: scheme.clone(),
                    label: label.clone(),
                    description: description.clone(),
                    default_secret_name: default_secret_name.clone(),
                    source: *secret_source,
                    optional: *optional,
                });
            }
        }
    }

    // A slot nothing reads is dead config: the dashboard would ask for a
    // secret that can never reach a request.
    let read: Vec<&str> = out
        .iter()
        .filter_map(|a| match a {
            ServiceAuth::Secret { slots, .. } => Some(slots.iter().map(String::as_str)),
            _ => None,
        })
        .flatten()
        .collect();
    for slot in &slots {
        if !read.contains(&slot.key.as_str()) {
            errors.push(ValidationIssue::new(
                "openapi_unsupported_construct",
                format!(
                    "secret `{}` is declared but no security scheme reads it",
                    slot.key
                ),
                format!("components.x-overslash-secrets.{}", slot.key),
            ));
        }
    }

    slots.sort_by(|a, b| a.key.cmp(&b.key));

    if errors.is_empty() {
        Ok((out, slots))
    } else {
        Err(errors)
    }
}

/// Parse `components.x-overslash-secrets` — the credential slots this template
/// needs, declared once and referenced by name from the schemes' templates.
fn extract_secret_slots(
    components: Option<&Value>,
) -> Result<Vec<SecretSlot>, Vec<ValidationIssue>> {
    let Some(map) = components
        .and_then(Value::as_object)
        .and_then(|c| c.get("x-overslash-secrets"))
    else {
        return Ok(Vec::new());
    };
    let Some(map) = map.as_object() else {
        return Err(vec![ValidationIssue::new(
            "openapi_unsupported_construct",
            "x-overslash-secrets must be a map of slot key to declaration",
            "components.x-overslash-secrets",
        )]);
    };

    let mut out = Vec::new();
    let mut errors = Vec::new();
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    for key in keys {
        let base = format!("components.x-overslash-secrets.{key}");
        let Some(obj) = map[key].as_object() else {
            errors.push(ValidationIssue::new(
                "openapi_unsupported_construct",
                format!("secret `{key}` must be an object"),
                base,
            ));
            continue;
        };
        let source = match obj.get("source").and_then(Value::as_str) {
            Some("org") => crate::types::SecretSource::Org,
            Some("instance") | None => crate::types::SecretSource::Instance,
            Some(other) => {
                errors.push(ValidationIssue::new(
                    "openapi_unsupported_construct",
                    format!("secret source must be `instance` or `org` (got {other:?})"),
                    format!("{base}.source"),
                ));
                continue;
            }
        };
        out.push(SecretSlot {
            key: key.clone(),
            label: str_field(obj, "label"),
            description: str_field(obj, "description"),
            default_secret_name: str_field(obj, "default_secret_name"),
            source,
            optional: obj
                .get("optional")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        });
    }

    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

fn str_field(obj: &Map<String, Value>, key: &str) -> String {
    obj.get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string()
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
    // The securitySchemes map key (`gateway`, `mailbox`, …) — NOT the scheme
    // object's `name` field, which is the HTTP header/query-param name.
    scheme_key: &str,
    // Slot keys declared under `components.x-overslash-secrets`.
    declared_slots: &[String],
) -> Result<ServiceAuth, Vec<ValidationIssue>> {
    let default_secret_name = obj
        .get("x-overslash-default_secret_name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let inject_as = obj.get("in").and_then(Value::as_str).unwrap_or("header");
    let name = obj.get("name").and_then(Value::as_str).map(str::to_string);

    // Predecessors of `x-overslash-template`. A live template in the wild
    // still carrying them would silently lose its transform, so name the
    // replacement rather than ignoring the key.
    for (legacy, replacement) in [
        ("x-overslash-prefix", r#""Bearer " + .SLOT"#),
        ("x-overslash-encode", r#"(.SLOT | @base64)"#),
    ] {
        if obj.contains_key(legacy) {
            return Err(vec![ValidationIssue::new(
                "openapi_unsupported_construct",
                format!(
                    "{legacy} was replaced by x-overslash-template; express it as \
                     `{{lang: jq, expr: '{replacement}'}}`"
                ),
                format!("{base}.{legacy}"),
            )]);
        }
    }

    let (template, slots) = extract_template(obj, base, scheme_key, declared_slots)?;

    let secret_source = match obj.get("x-overslash-secret_source").and_then(Value::as_str) {
        Some("org") => crate::types::SecretSource::Org,
        Some("instance") | None => crate::types::SecretSource::Instance,
        Some(other) => {
            return Err(vec![ValidationIssue::new(
                "openapi_unsupported_construct",
                format!("x-overslash-secret_source must be `instance` or `org` (got {other:?})"),
                format!("{base}.x-overslash-secret_source"),
            )]);
        }
    };

    let optional = match obj.get("x-overslash-optional") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(other) => {
            return Err(vec![ValidationIssue::new(
                "openapi_unsupported_construct",
                format!("x-overslash-optional must be a boolean (got {other})"),
                format!("{base}.x-overslash-optional"),
            )]);
        }
    };

    let injection = match inject_as {
        "header" => TokenInjection {
            inject_as: "header".into(),
            header_name: name,
            query_param: None,
            prefix: None,
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

    let label = match obj.get("x-overslash-label") {
        None => String::new(),
        Some(Value::String(s)) => s.trim().to_string(),
        Some(other) => {
            return Err(vec![ValidationIssue::new(
                "openapi_unsupported_construct",
                format!("x-overslash-label must be a string (got {other})"),
                format!("{base}.x-overslash-label"),
            )]);
        }
    };

    Ok(ServiceAuth::Secret {
        scheme: scheme_key.to_string(),
        label,
        description: scheme_description(obj),
        default_secret_name,
        injection,
        template,
        slots,
        secret_source,
        optional,
    })
}

/// Parse `x-overslash-template` and resolve the slots it reads.
///
/// Returns `(None, [scheme_key])` when absent: the credential is one secret
/// injected verbatim, from the slot named after the scheme.
fn extract_template(
    obj: &Map<String, Value>,
    base: &str,
    scheme_key: &str,
    declared_slots: &[String],
) -> Result<(Option<CredentialTemplate>, Vec<String>), Vec<ValidationIssue>> {
    let issue = |msg: String, path: String| {
        vec![ValidationIssue::new(
            "openapi_unsupported_construct",
            msg,
            path,
        )]
    };
    let path = format!("{base}.x-overslash-template");

    let Some(raw) = obj.get("x-overslash-template") else {
        return Ok((None, vec![scheme_key.to_string()]));
    };
    let Some(raw) = raw.as_object() else {
        return Err(issue(
            "x-overslash-template must be an object with `lang` and `expr`".into(),
            path,
        ));
    };

    match raw.get("lang").and_then(Value::as_str) {
        Some("jq") => {}
        Some(other) => {
            return Err(issue(
                format!("credential template lang must be `jq` (got {other:?})"),
                format!("{path}.lang"),
            ));
        }
        None => {
            return Err(issue(
                "credential template needs a `lang` (only `jq` today)".into(),
                format!("{path}.lang"),
            ));
        }
    }
    let Some(expr) = raw.get("expr").and_then(Value::as_str) else {
        return Err(issue(
            "credential template needs an `expr` string".into(),
            format!("{path}.expr"),
        ));
    };

    let template = CredentialTemplate::Jq {
        expr: expr.to_string(),
    };
    // Resolved once here so nothing on the request path parses jq to decide
    // which secrets to decrypt.
    let slots = crate::credential_template::referenced_slots(&template)
        .map_err(|e| issue(e.to_string(), format!("{path}.expr")))?;

    if slots.is_empty() {
        return Err(issue(
            "credential template reads no secret; a credential that needs no \
             secret should not be a security scheme"
                .into(),
            format!("{path}.expr"),
        ));
    }
    for slot in &slots {
        // A scheme always implicitly declares a slot named after itself, so a
        // single-secret credential needs no x-overslash-secrets entry at all.
        if slot != scheme_key && !declared_slots.iter().any(|d| d == slot) {
            return Err(issue(
                format!(
                    "credential template reads undeclared secret `{slot}`; \
                     components.x-overslash-secrets declares: {}",
                    if declared_slots.is_empty() {
                        "none".to_string()
                    } else {
                        declared_slots.join(", ")
                    }
                ),
                format!("{path}.expr"),
            ));
        }
    }

    Ok((Some(template), slots))
}

fn extract_http_auth(
    obj: &Map<String, Value>,
    base: &str,
    // The securitySchemes map key — NOT the `scheme` field below, which is
    // the HTTP auth scheme (`bearer`).
    scheme_key: &str,
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
    Ok(ServiceAuth::Secret {
        scheme: scheme_key.to_string(),
        label: obj
            .get("x-overslash-label")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string(),
        description: scheme_description(obj),
        default_secret_name,
        injection: TokenInjection {
            inject_as: "header".into(),
            header_name: Some("Authorization".into()),
            query_param: None,
            prefix: None,
        },
        // `http`+`bearer` is exactly "prepend `Bearer ` to the one secret",
        // so it compiles to the template that says so rather than to a
        // special case the injector has to know about.
        template: Some(CredentialTemplate::Jq {
            expr: format!(r#""Bearer " + .{scheme_key}"#),
        }),
        slots: vec![scheme_key.to_string()],
        secret_source: crate::types::SecretSource::Instance,
        optional: false,
    })
}

/// The standard OpenAPI securityScheme `description`, verbatim (empty when
/// absent). Surfaces as help text for the credential's dashboard row.
fn scheme_description(obj: &Map<String, Value>) -> String {
    obj.get("description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string()
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

/// Pick the required OAuth scopes out of a `security` array Value.
///
/// For each security requirement object we pick the first non-empty scope
/// list — matches the OpenAPI 3.1 "requirements are OR-ed" model for the
/// common case of a single `oauth2` scheme. A non-array Value, an empty array,
/// or requirements with only empty scope lists yield no scopes.
fn scopes_from_security(security: &Value) -> Vec<String> {
    security
        .as_array()
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
        .unwrap_or_default()
}

pub(super) fn extract_http_action(
    path_key: &str,
    method: &str,
    op: &Map<String, Value>,
    path_level_params: Option<&Value>,
    root_security: Option<&Value>,
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

    // Per-action OAuth scopes. The operation's own `security` key, when present
    // (even as an empty array `[]`, which OpenAPI 3.1 treats as an explicit
    // opt-out / "no security"), takes precedence. When the operation omits
    // `security` entirely it inherits the document root-level default.
    let required_scopes = op
        .get("security")
        .or(root_security)
        .map(scopes_from_security)
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
            permission: None,
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

    let params = op
        .get("params")
        .and_then(Value::as_object)
        .map(|m| parse_platform_params(m, &base))
        .unwrap_or_default();

    let permission = op
        .get("permission")
        .and_then(Value::as_str)
        .map(str::to_string);

    Ok(ServiceAction {
        method: String::new(),
        path: String::new(),
        description,
        risk,
        response_type: None,
        params,
        scope_param: op
            .get("x-overslash-scope_param")
            .and_then(Value::as_str)
            .map(str::to_string),
        required_scopes: Vec::new(),
        permission,
        // Platform actions don't have outbound HTTP payloads — disclosure
        // and redaction are no-ops for them.
        disclose: Vec::new(),
        redact: Vec::new(),
        mcp_tool: None,
        output_schema: None,
        disabled: false,
    })
}

/// Parse a flat `{name: {type, required, description}}` map (the platform_actions
/// params format) into the same `HashMap<String, ActionParam>` used by HTTP actions.
fn parse_platform_params(raw: &Map<String, Value>, _base: &str) -> HashMap<String, ActionParam> {
    raw.iter()
        .filter_map(|(name, spec)| {
            let obj = spec.as_object()?;
            // Empty = type unspecified (see `schema_fields`) — runtime type
            // checks skip it rather than guess "string".
            let param_type = obj
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let required = obj
                .get("required")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let description = obj
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let aliases = parse_aliases(Some(obj), name);
            let instance_config = parse_instance_config(Some(obj));
            Some((
                name.clone(),
                ActionParam {
                    param_type,
                    required,
                    description,
                    enum_values: None,
                    default: None,
                    resolve: None,
                    aliases,
                    location: ParamLocation::Body,
                    instance_config,
                },
            ))
        })
        .collect()
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
        let primary = obj.get("primary").and_then(Value::as_bool).unwrap_or(false);
        out.push(DisclosureField {
            label,
            filter,
            max_chars,
            primary,
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

// ── x-overslash-mcp → McpSpec + ServiceActions ───────────────────────

/// Lower the `x-overslash-mcp` block into a typed `McpSpec`.
pub(super) fn extract_mcp_spec(root: &Map<String, Value>) -> Result<McpSpec, Vec<ValidationIssue>> {
    let mut errors = Vec::new();
    let Some(mcp_obj) = root.get("x-overslash-mcp").and_then(Value::as_object) else {
        errors.push(ValidationIssue::new(
            "mcp_missing",
            "runtime is `mcp` but x-overslash-mcp block is absent",
            "x-overslash-mcp",
        ));
        return Err(errors);
    };

    // url is optional — absent means the service instance must supply one.
    // When present, validate it has an http/https scheme.
    let url = match mcp_obj.get("url").and_then(Value::as_str) {
        Some(u) if !u.is_empty() => {
            if !u.starts_with("http://") && !u.starts_with("https://") {
                errors.push(ValidationIssue::new(
                    "mcp_invalid",
                    "x-overslash-mcp.url must start with http:// or https://",
                    "x-overslash-mcp.url",
                ));
                return Err(errors);
            }
            Some(u.to_string())
        }
        _ => None,
    };

    // auth: object with a `kind` discriminator. Defaults to {kind: none} when absent.
    // secret_name is optional — absent means the service instance must supply one.
    let auth = match mcp_obj.get("auth") {
        None => McpAuth::None,
        Some(Value::Object(a)) => match a.get("kind").and_then(Value::as_str) {
            Some("none") | None => McpAuth::None,
            Some("bearer") => {
                let secret_name = a
                    .get("secret_name")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                McpAuth::Bearer { secret_name }
            }
            Some("oauth") => {
                let provider = a
                    .get("provider")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                let Some(provider) = provider else {
                    errors.push(ValidationIssue::new(
                        "mcp_invalid",
                        "x-overslash-mcp.auth.provider is required when kind is `oauth`",
                        "x-overslash-mcp.auth.provider",
                    ));
                    return Err(errors);
                };
                // Parse, don't validate: a non-string scope is a config error,
                // surfaced rather than silently dropped (which would grant fewer
                // permissions than the operator intended).
                let scopes = match a.get("scopes") {
                    None => Vec::new(),
                    Some(Value::Array(arr)) => {
                        let mut out = Vec::with_capacity(arr.len());
                        for (i, v) in arr.iter().enumerate() {
                            let Some(s) = v.as_str() else {
                                errors.push(ValidationIssue::new(
                                    "mcp_invalid",
                                    format!("x-overslash-mcp.auth.scopes[{i}] must be a string"),
                                    format!("x-overslash-mcp.auth.scopes[{i}]"),
                                ));
                                return Err(errors);
                            };
                            out.push(s.to_string());
                        }
                        out
                    }
                    Some(_) => {
                        errors.push(ValidationIssue::new(
                            "mcp_invalid",
                            "x-overslash-mcp.auth.scopes must be an array of strings",
                            "x-overslash-mcp.auth.scopes",
                        ));
                        return Err(errors);
                    }
                };
                McpAuth::OAuth { provider, scopes }
            }
            Some(other) => {
                errors.push(ValidationIssue::new(
                    "mcp_invalid",
                    format!(
                        "x-overslash-mcp.auth.kind must be one of `none`, `bearer`, `oauth` (got {other:?})"
                    ),
                    "x-overslash-mcp.auth.kind",
                ));
                return Err(errors);
            }
        },
        Some(_) => {
            errors.push(ValidationIssue::new(
                "mcp_invalid",
                "x-overslash-mcp.auth must be an object",
                "x-overslash-mcp.auth",
            ));
            return Err(errors);
        }
    };

    let autodiscover = mcp_obj
        .get("autodiscover")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    Ok(McpSpec {
        url,
        auth,
        autodiscover,
    })
}

/// Merge `discovered_tools[]` + `tools[]` from an `x-overslash-mcp` block into
/// a map of `ServiceAction` (keyed by tool name). YAML-authored `tools[]` wins
/// field-by-field over discovered entries with the same name. Tools present in
/// YAML but not in `discovered_tools` are emitted as warnings (admin may be
/// pre-annotating). When `autodiscover=false`, YAML `tools[]` is the source of
/// truth and `input_schema` is required on every entry.
pub(super) fn extract_mcp_actions(
    root: &Map<String, Value>,
    autodiscover: bool,
    sink: &mut HashMap<String, ServiceAction>,
    warnings: &mut Vec<ValidationIssue>,
) -> Result<(), Vec<ValidationIssue>> {
    let mut errors = Vec::new();
    let mcp_obj = match root.get("x-overslash-mcp").and_then(Value::as_object) {
        Some(o) => o,
        None => return Ok(()),
    };

    // Build the discovered map first (lower priority).
    let discovered_arr = mcp_obj
        .get("discovered_tools")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut merged: HashMap<String, Map<String, Value>> = HashMap::new();
    for (i, entry) in discovered_arr.iter().enumerate() {
        let Some(obj) = entry.as_object() else {
            errors.push(ValidationIssue::new(
                "mcp_invalid",
                "discovered tool must be an object",
                format!("x-overslash-mcp.discovered_tools[{i}]"),
            ));
            continue;
        };
        let Some(name) = obj.get("name").and_then(Value::as_str) else {
            errors.push(ValidationIssue::new(
                "mcp_invalid",
                "discovered tool missing `name`",
                format!("x-overslash-mcp.discovered_tools[{i}]"),
            ));
            continue;
        };
        merged.insert(name.to_string(), obj.clone());
    }

    // Apply YAML overrides (higher priority). Missing discovered entry when
    // autodiscover=true is a warning; when autodiscover=false it's the source.
    if let Some(tools_arr) = mcp_obj.get("tools").and_then(Value::as_array) {
        for (i, entry) in tools_arr.iter().enumerate() {
            let Some(obj) = entry.as_object() else {
                errors.push(ValidationIssue::new(
                    "mcp_invalid",
                    "authored tool must be an object",
                    format!("x-overslash-mcp.tools[{i}]"),
                ));
                continue;
            };
            let Some(name) = obj.get("name").and_then(Value::as_str) else {
                errors.push(ValidationIssue::new(
                    "mcp_invalid",
                    "authored tool missing `name`",
                    format!("x-overslash-mcp.tools[{i}]"),
                ));
                continue;
            };
            let name = name.to_string();
            let entry_path = format!("x-overslash-mcp.tools[{i}]");

            match merged.get_mut(&name) {
                Some(existing) => {
                    // Overlay: YAML fields overwrite discovered fields.
                    for (k, v) in obj {
                        existing.insert(k.clone(), v.clone());
                    }
                }
                None => {
                    if autodiscover {
                        warnings.push(ValidationIssue::new(
                            "mcp_tool_not_discovered",
                            format!(
                                "authored tool `{name}` is not present in discovered_tools — \
                                 run resync or remove the entry"
                            ),
                            entry_path.clone(),
                        ));
                    }
                    merged.insert(name, obj.clone());
                }
            }
        }
    }

    if !autodiscover && merged.is_empty() {
        errors.push(ValidationIssue::new(
            "mcp_invalid",
            "autodiscover=false but no tools declared under x-overslash-mcp.tools",
            "x-overslash-mcp.tools",
        ));
        return Err(errors);
    }

    // Lower merged entries to ServiceAction.
    for (name, obj) in merged {
        if let Some(action) = lower_mcp_tool(&name, &obj, autodiscover, &mut errors) {
            sink.insert(name, action);
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Lower a single merged MCP tool object into a [`ServiceAction`]. Returns
/// `None` (pushing to `errors`) when the object is malformed — an invalid
/// risk, or a missing `input_schema` while `autodiscover=false`. Shared by the
/// compile-time [`extract_mcp_actions`] and the per-instance
/// [`overlay_discovered_tools`].
fn lower_mcp_tool(
    name: &str,
    obj: &Map<String, Value>,
    autodiscover: bool,
    errors: &mut Vec<ValidationIssue>,
) -> Option<ServiceAction> {
    let base = format!("x-overslash-mcp.tools[{name}]");

    let risk = match obj.get("x-overslash-risk").and_then(Value::as_str) {
        Some("read") | None => Risk::Read,
        Some("write") => Risk::Write,
        Some("delete") => Risk::Delete,
        Some(other) => {
            errors.push(ValidationIssue::new(
                "invalid_risk",
                format!("x-overslash-risk must be one of read/write/delete (got {other:?})"),
                format!("{base}.x-overslash-risk"),
            ));
            return None;
        }
    };

    let description = obj
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let scope_param = obj
        .get("x-overslash-scope_param")
        .and_then(Value::as_str)
        .map(str::to_string);
    let disabled = obj
        .get("disabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let output_schema = obj.get("output_schema").cloned();

    // input_schema required when autodiscover=false; otherwise optional.
    let input_schema = obj.get("input_schema");
    if !autodiscover && input_schema.is_none() {
        errors.push(ValidationIssue::new(
            "mcp_invalid",
            format!("tool `{name}` missing `input_schema` (required when autodiscover=false)"),
            format!("{base}.input_schema"),
        ));
        return None;
    }
    let params = input_schema.map(lower_input_schema).unwrap_or_default();

    let disclose = parse_disclose(obj.get("x-overslash-disclose"), &base, errors);
    let redact = parse_redact(obj.get("x-overslash-redact"), &base, errors);

    // The upstream MCP tool name defaults to the action key, but may be
    // overridden with `mcp_tool` when the server's tool name isn't a valid
    // Overslash action key — e.g. a server naming its tools with dashes
    // (`some-list-tool`), which the action-key grammar `^[a-z][a-z0-9_]*$`
    // rejects: the key becomes `some_list_tool` and
    // `mcp_tool: some-list-tool` carries the real name upstream.
    let mcp_tool = obj
        .get("mcp_tool")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| name.to_string());

    Some(ServiceAction {
        method: String::new(),
        path: String::new(),
        description,
        risk,
        response_type: None,
        params,
        scope_param,
        required_scopes: Vec::new(),
        permission: None,
        disclose,
        redact,
        mcp_tool: Some(mcp_tool),
        output_schema,
        disabled,
    })
}

/// Overlay a service instance's `discovered_tools` onto an already-compiled
/// [`ServiceDefinition`], in place.
///
/// Applied only where an instance is in scope (actions listing, the call/
/// validate resolver, and visibility-scoped search), so `ServiceDefinition`
/// stays a pure function of the template key everywhere else.
///
/// Precedence: **existing actions win** — a tool the template already declares
/// (authored `tools:` or template-level `discovered_tools`) is left untouched,
/// so authored `input_schema`/aliases/disclose remain authoritative. Instance-
/// discovered tools that the template does not declare are added. Malformed
/// discovered entries are skipped silently (they came from a live server, not
/// authored config, so there is no author to warn).
pub fn overlay_discovered_tools(def: &mut ServiceDefinition, discovered: &[Value]) {
    for entry in discovered {
        let Some(obj) = entry.as_object() else {
            continue;
        };
        let Some(name) = obj.get("name").and_then(Value::as_str) else {
            continue;
        };
        if def.actions.contains_key(name) {
            // Authored / existing tool wins — don't overwrite.
            continue;
        }
        // Discovered tools come from a live tools/list, so autodiscover=true
        // semantics apply (input_schema optional). Errors are non-fatal here.
        let mut errors = Vec::new();
        if let Some(action) = lower_mcp_tool(name, obj, true, &mut errors) {
            def.actions.insert(name.to_string(), action);
        }
    }
}

/// Lower a JSON-Schema `{type: object, properties: {...}, required: [...]}`
/// into the subset of `ActionParam` shape Overslash understands. Unsupported
/// constructs (oneOf, nested object properties) are silently ignored — they
/// remain in the raw `output_schema` / `input_schema` for agent consumption.
pub(super) fn lower_input_schema(schema: &Value) -> HashMap<String, ActionParam> {
    let mut out = HashMap::new();
    let Some(obj) = schema.as_object() else {
        return out;
    };
    let required: Vec<&str> = obj
        .get("required")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let Some(props) = obj.get("properties").and_then(Value::as_object) else {
        return out;
    };
    for (name, pv) in props {
        let Some(po) = pv.as_object() else { continue };
        // Empty when no concrete `type` is declared (e.g. anyOf/oneOf/untyped)
        // — a sentinel that keeps runtime type checks from guessing "string"
        // and false-rejecting a param that legitimately accepts other types.
        let param_type = po
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let description = po
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let enum_values = po.get("enum").and_then(Value::as_array).map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        });
        let default = po.get("default").cloned();
        let aliases = parse_aliases(Some(po), name);
        let instance_config = parse_instance_config(Some(po));
        out.insert(
            name.clone(),
            ActionParam {
                param_type,
                required: required.contains(&name.as_str()),
                description,
                enum_values,
                default,
                resolve: None,
                aliases,
                location: ParamLocation::Body,
                instance_config,
            },
        );
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
        let aliases = parse_aliases(Some(obj), name);

        let location = match obj.get("in").and_then(Value::as_str) {
            Some("query") => ParamLocation::Query,
            Some("path") => ParamLocation::Path,
            Some("header") => ParamLocation::Header,
            _ => ParamLocation::Body,
        };

        let instance_config = parse_instance_config(Some(obj));

        out.insert(
            name.to_string(),
            ActionParam {
                param_type,
                required,
                description,
                enum_values,
                default,
                resolve,
                aliases,
                location,
                instance_config,
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
        let aliases = parse_aliases(pobj, name);
        let instance_config = parse_instance_config(pobj);

        out.insert(
            name.clone(),
            ActionParam {
                param_type,
                required: body_required && required_names.iter().any(|r| r == name),
                description,
                enum_values,
                default,
                resolve,
                aliases,
                location: ParamLocation::Body,
                instance_config,
            },
        );
    }
}

fn schema_fields(
    schema: Option<&Map<String, Value>>,
) -> (String, Option<Vec<String>>, Option<Value>) {
    // Empty `param_type` is the "type unspecified" sentinel (no schema, or a
    // schema with no concrete `type` such as anyOf/oneOf) — runtime type
    // checks skip these rather than guess "string".
    let Some(s) = schema else {
        return (String::new(), None, None);
    };
    let param_type = s
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("")
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

/// Read a parameter's `x-overslash-aliases` — a list of alternate caller-facing
/// names — off its object (a `parameters[]` entry, a schema property, or a
/// platform-action param spec). Non-string entries and blanks are dropped, and
/// an alias equal to the canonical `name` is skipped (it would be a no-op
/// rewrite). Returns an empty `Vec` when the extension is absent or malformed —
/// aliases are a convenience, never a load-time error.
/// `x-overslash-instance-config` — whether an org may pin this param per
/// service instance. Read from the same four param shapes `parse_aliases`
/// covers (operation params, body properties, platform params, lowered input
/// schemas), so the vocabulary means the same thing wherever it is authored.
fn parse_instance_config(obj: Option<&Map<String, Value>>) -> bool {
    obj.and_then(|o| o.get("x-overslash-instance-config"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn parse_aliases(obj: Option<&Map<String, Value>>, name: &str) -> Vec<String> {
    obj.and_then(|o| o.get("x-overslash-aliases"))
        .and_then(Value::as_array)
        .map(|a| {
            // Dedup within one param's list (order-preserving): `[to, to]` is
            // a single alias, not an ambiguity.
            let mut seen = std::collections::HashSet::new();
            a.iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty() && *s != name)
                .filter(|s| seen.insert(*s))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::super::compile_service;
    use super::*;
    use crate::types::{Risk, ServiceAuth};
    use serde_json::json;

    // ── parse_aliases / lower_input_schema ───────────────────────────

    #[test]
    fn lower_input_schema_reads_param_aliases() {
        let schema = json!({
            "type": "object",
            "properties": {
                "recipient": { "type": "string", "x-overslash-aliases": ["to", "dest"] },
                "text": { "type": "string" }
            },
            "required": ["recipient"]
        });
        let params = lower_input_schema(&schema);
        let mut aliases = params["recipient"].aliases.clone();
        aliases.sort();
        assert_eq!(aliases, vec!["dest".to_string(), "to".to_string()]);
        assert!(params["text"].aliases.is_empty());
    }

    #[test]
    fn parse_aliases_dedups_within_one_param() {
        let obj = json!({ "x-overslash-aliases": ["to", "to", "dest", "to"] });
        let aliases = parse_aliases(obj.as_object(), "recipient");
        assert_eq!(aliases, vec!["to".to_string(), "dest".to_string()]);
    }

    #[test]
    fn parse_aliases_drops_blanks_self_and_non_strings() {
        let obj = json!({
            "x-overslash-aliases": ["to", "", "  ", "recipient", 7, "dest"]
        });
        let aliases = parse_aliases(obj.as_object(), "recipient");
        // Blank, whitespace-only, the canonical name itself, and non-strings
        // are dropped.
        assert_eq!(aliases, vec!["to".to_string(), "dest".to_string()]);
    }

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
    fn auth_carries_scheme_keys_and_descriptions_in_sorted_order() {
        // Two apiKey schemes à la services/email.yaml: the securitySchemes map
        // KEY (`gateway`/`mailbox`) — not the header `name` — must ride into
        // `ServiceAuth::Secret.scheme`, in the deterministic sorted order the
        // dashboard's per-scheme credential rows key off.
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "mailbox": {
                    "type": "apiKey", "in": "header", "name": "X-Mailbox-Auth",
                    "description": "Per-mailbox IMAP/SMTP login.",
                    "x-overslash-default_secret_name": "mailbox_credential"
                },
                "gateway": {
                    "type": "apiKey", "in": "header", "name": "Authorization",
                    "x-overslash-label": "Overfwd API Token",
                    "x-overslash-template": {"lang": "jq", "expr": "\"Bearer \" + .gateway"},
                    "x-overslash-secret_source": "org",
                    "x-overslash-optional": true,
                    "x-overslash-default_secret_name": "overfwd_gateway_key"
                }
            }}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.auth.len(), 2);
        match &svc.auth[0] {
            ServiceAuth::Secret {
                scheme,
                label,
                description,
                secret_source,
                optional,
                ..
            } => {
                assert_eq!(scheme, "gateway");
                assert_eq!(label, "Overfwd API Token");
                assert!(description.is_empty());
                assert_eq!(*secret_source, crate::types::SecretSource::Org);
                assert!(optional);
            }
            other => panic!("expected Secret, got {other:?}"),
        }
        match &svc.auth[1] {
            ServiceAuth::Secret {
                scheme,
                label,
                description,
                secret_source,
                injection,
                ..
            } => {
                assert_eq!(scheme, "mailbox");
                assert!(label.is_empty());
                assert_eq!(description, "Per-mailbox IMAP/SMTP login.");
                assert_eq!(*secret_source, crate::types::SecretSource::Instance);
                // The header name stays injection config — proves the scheme
                // key wasn't confused with the scheme object's `name` field.
                assert_eq!(injection.header_name.as_deref(), Some("X-Mailbox-Auth"));
            }
            other => panic!("expected Secret, got {other:?}"),
        }
    }

    #[test]
    fn auth_skips_non_object_scheme_value() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {
                "junk": "string-value",
                "real": {
                    "type": "apiKey", "in": "header", "name": "Authorization",
                    "x-overslash-template": {"lang": "jq", "expr": "\"Bearer \" + .real"},
                    "x-overslash-default_secret_name": "svc_token"
                }
            }}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.auth.len(), 1);
        assert!(matches!(svc.auth[0], ServiceAuth::Secret { .. }));
    }

    // ── credential slots + templates ─────────────────────────────────

    /// The services/email.yaml shape: two declared secrets joined into one
    /// header by a jq template.
    fn composed_mailbox_doc() -> serde_json::Value {
        json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {
                "x-overslash-secrets": {
                    "mailbox_user": {"label": "Mailbox username", "source": "instance"},
                    "mailbox_pass": {"label": "Mailbox password", "source": "instance"}
                },
                "securitySchemes": {"mailbox": {
                    "type": "apiKey", "in": "header", "name": "X-Mailbox-Auth",
                    "x-overslash-template": {
                        "lang": "jq",
                        "expr": "\"Basic \" + (.mailbox_user + \":\" + .mailbox_pass | @base64)"
                    }
                }}
            }
        })
    }

    #[test]
    fn composed_scheme_declares_its_slots() {
        let (svc, _) = compile_service(&composed_mailbox_doc()).unwrap();
        let ServiceAuth::Secret {
            slots,
            template,
            injection,
            ..
        } = &svc.auth[0]
        else {
            panic!("expected Secret");
        };
        // Slot order follows the expression, so the send path decrypts in the
        // order the header reads.
        assert_eq!(slots, &["mailbox_user", "mailbox_pass"]);
        assert!(template.is_some());
        assert_eq!(injection.header_name.as_deref(), Some("X-Mailbox-Auth"));

        // Declared slots keep their own labels; the scheme key is NOT a slot
        // here, because nothing reads it.
        let all = svc.all_slots();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].key, "mailbox_user");
        assert_eq!(all[0].label, "Mailbox username");
        assert!(!all.iter().any(|s| s.key == "mailbox"));
    }

    #[test]
    fn slots_are_sorted_for_determinism() {
        let (svc, _) = compile_service(&composed_mailbox_doc()).unwrap();
        let keys: Vec<&str> = svc.secrets.iter().map(|s| s.key.as_str()).collect();
        assert_eq!(keys, ["mailbox_pass", "mailbox_user"]);
    }

    /// The property that makes static analysis worth having: a template with
    /// four declared secrets whose header names two reads exactly two.
    #[test]
    fn scheme_reads_only_the_slots_its_template_names() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {
                "x-overslash-secrets": {
                    "a": {}, "b": {}, "c": {}, "d": {}
                },
                "securitySchemes": {
                    "one": {
                        "type": "apiKey", "in": "header", "name": "X-One",
                        "x-overslash-template": {"lang": "jq", "expr": ".a + \":\" + .b"}
                    },
                    "two": {
                        "type": "apiKey", "in": "header", "name": "X-Two",
                        "x-overslash-template": {"lang": "jq", "expr": ".c + .d"}
                    }
                }
            }
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.slots_for(&svc.auth[0]).len(), 2);
        assert_eq!(
            svc.slots_for(&svc.auth[0])
                .iter()
                .map(|s| s.key.clone())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert_eq!(svc.all_slots().len(), 4);
    }

    #[test]
    fn template_reading_undeclared_slot_is_rejected() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {
                "x-overslash-secrets": {"user": {}},
                "securitySchemes": {"cred": {
                    "type": "apiKey", "in": "header", "name": "X-Cred",
                    "x-overslash-template": {"lang": "jq", "expr": ".user + \":\" + .pass"}
                }}
            }
        });
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter()
                .any(|i| i.message.contains("undeclared secret `pass`")),
            "got: {err:?}"
        );
    }

    #[test]
    fn declared_but_unread_slot_is_rejected() {
        // Dead config: the dashboard would ask for a secret that can never
        // reach a request.
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {
                "x-overslash-secrets": {"user": {}, "unused": {}},
                "securitySchemes": {"cred": {
                    "type": "apiKey", "in": "header", "name": "X-Cred",
                    "x-overslash-template": {"lang": "jq", "expr": ".user"}
                }}
            }
        });
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter()
                .any(|i| i.message.contains("`unused` is declared")),
            "got: {err:?}"
        );
    }

    #[test]
    fn template_with_dynamic_key_is_rejected() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {
                "x-overslash-secrets": {"user": {}},
                "securitySchemes": {"cred": {
                    "type": "apiKey", "in": "header", "name": "X-Cred",
                    "x-overslash-template": {"lang": "jq", "expr": "to_entries"}
                }}
            }
        });
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter().any(|i| i.message.contains("computed key")),
            "got: {err:?}"
        );
    }

    #[test]
    fn template_syntax_error_is_rejected() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {"cred": {
                "type": "apiKey", "in": "header", "name": "X-Cred",
                "x-overslash-template": {"lang": "jq", "expr": "\"unterminated"}
            }}}
        });
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter().any(|i| i.message.contains("invalid jq")),
            "got: {err:?}"
        );
    }

    #[test]
    fn unknown_template_lang_is_rejected() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {"cred": {
                "type": "apiKey", "in": "header", "name": "X-Cred",
                "x-overslash-template": {"lang": "handlebars", "expr": "{{user}}"}
            }}}
        });
        let err = compile_service(&doc).unwrap_err();
        assert!(
            err.iter().any(|i| i.message.contains("must be `jq`")),
            "got: {err:?}"
        );
    }

    #[test]
    fn removed_extensions_name_their_replacement() {
        // A template in the wild still carrying these would silently lose its
        // transform, so the error is the migration guide.
        for legacy in ["x-overslash-prefix", "x-overslash-encode"] {
            let doc = json!({
                "info": {"title": "T", "x-overslash-key": "t"},
                "components": {"securitySchemes": {"cred": {
                    "type": "apiKey", "in": "header", "name": "X-Cred",
                    legacy: "Bearer ",
                    "x-overslash-default_secret_name": "k"
                }}}
            });
            let err = compile_service(&doc).unwrap_err();
            assert!(
                err.iter()
                    .any(|i| i.message.contains("x-overslash-template")),
                "{legacy} -> got: {err:?}"
            );
        }
    }

    #[test]
    fn template_less_scheme_keeps_its_implicit_slot() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "components": {"securitySchemes": {"token": {
                "type": "apiKey", "in": "header", "name": "X-Key",
                "x-overslash-label": "API key",
                "x-overslash-default_secret_name": "svc_key"
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        let ServiceAuth::Secret {
            template, slots, ..
        } = &svc.auth[0]
        else {
            panic!("expected Secret");
        };
        assert!(template.is_none(), "no template means inject verbatim");
        assert_eq!(slots, &["token"]);
        let all = svc.all_slots();
        assert_eq!(all[0].key, "token");
        assert_eq!(all[0].label, "API key");
        assert_eq!(all[0].default_secret_name, "svc_key");
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
            ServiceAuth::Secret {
                default_secret_name,
                injection,
                ..
            } => {
                assert_eq!(default_secret_name, "t_token");
                assert_eq!(injection.inject_as, "query");
                assert_eq!(injection.query_param.as_deref(), Some("api_key"));
                assert!(injection.header_name.is_none());
                assert!(injection.prefix.is_none());
            }
            _ => panic!("expected Secret"),
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
            ServiceAuth::Secret { injection, .. } => {
                assert_eq!(injection.inject_as, "header");
                assert_eq!(injection.header_name.as_deref(), Some("Authorization"));
            }
            _ => panic!("expected Secret"),
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
            ServiceAuth::Secret {
                default_secret_name,
                injection,
                template,
                slots,
                ..
            } => {
                assert_eq!(default_secret_name, "t_token");
                assert_eq!(injection.inject_as, "header");
                assert_eq!(injection.header_name.as_deref(), Some("Authorization"));
                assert!(injection.query_param.is_none());
                // `http`+`bearer` is "prepend Bearer to the one secret", which
                // compiles to the template that says so rather than to a
                // special case the injector would have to know about.
                assert_eq!(
                    template.as_ref().map(CredentialTemplate::expr),
                    Some(r#""Bearer " + .bearer"#)
                );
                assert_eq!(slots, &["bearer"]);
            }
            _ => panic!("expected Secret for http/bearer"),
        }
        // The implicit self-named slot carries the scheme's own metadata, so a
        // single-secret template declares no x-overslash-secrets block.
        let all = svc.all_slots();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].key, "bearer");
        assert_eq!(all[0].default_secret_name, "t_token");
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
            ServiceAuth::Secret {
                default_secret_name,
                ..
            } => assert!(default_secret_name.is_empty()),
            _ => panic!("expected Secret for http/bearer"),
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
    fn parameter_without_schema_has_unspecified_type() {
        // No `schema` → no concrete `type`, so `param_type` is the empty
        // "unspecified" sentinel (opts the param out of runtime type checks)
        // rather than a fabricated "string".
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"get": {
                "operationId": "x",
                "parameters": [{"name": "q", "in": "query"}]
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(svc.actions["x"].params["q"].param_type, "");
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
    fn parameter_location_from_in() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {
                "/cal/{id}/events": {
                    "post": {
                        "operationId": "create_event",
                        "parameters": [
                            {"name": "id", "in": "path", "required": true,
                             "schema": {"type": "string"}},
                            {"name": "sendUpdates", "in": "query",
                             "schema": {"type": "string"}},
                            {"name": "Notion-Version", "in": "header",
                             "schema": {"type": "string", "default": "2022-06-28"}}
                        ],
                        "requestBody": {
                            "content": {"application/json": {"schema": {
                                "type": "object",
                                "properties": {"summary": {"type": "string"}}
                            }}}
                        }
                    }
                }
            }
        });
        let (svc, _) = compile_service(&doc).unwrap();
        let a = &svc.actions["create_event"];
        assert_eq!(a.params["id"].location, ParamLocation::Path);
        assert_eq!(a.params["sendUpdates"].location, ParamLocation::Query);
        assert_eq!(a.params["summary"].location, ParamLocation::Body);
        // `in: header` params land on `Header`, carrying their default so
        // `apply_defaults` can pin a constant version header at call time.
        assert_eq!(a.params["Notion-Version"].location, ParamLocation::Header);
        assert_eq!(
            a.params["Notion-Version"].default,
            Some(serde_json::json!("2022-06-28"))
        );
        // Path template is unaffected by location tracking.
        assert_eq!(a.path, "/cal/{id}/events");
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

    // ── per-op security → required_scopes ─────────────────────────────

    #[test]
    fn per_op_security_populates_required_scopes() {
        let doc = json!({
            "info": {"title": "Gmail", "x-overslash-key": "gmail"},
            "paths": {
                "/gmail/v1/users/{userId}/drafts": {"post": {
                    "operationId": "create_draft",
                    "security": [{"oauth": ["https://www.googleapis.com/auth/gmail.compose"]}]
                }},
                "/gmail/v1/users/{userId}/messages/send": {"post": {
                    "operationId": "send_message",
                    "security": [{"oauth": ["https://www.googleapis.com/auth/gmail.send"]}]
                }}
            }
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(
            svc.actions["create_draft"].required_scopes,
            vec!["https://www.googleapis.com/auth/gmail.compose"]
        );
        assert_eq!(
            svc.actions["send_message"].required_scopes,
            vec!["https://www.googleapis.com/auth/gmail.send"]
        );
    }

    #[test]
    fn missing_op_security_yields_empty_required_scopes() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "paths": {"/x": {"get": {"operationId": "x"}}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert!(svc.actions["x"].required_scopes.is_empty());
    }

    // ── root-level security → default required_scopes ─────────────────

    #[test]
    fn root_security_inherited_when_op_omits_security() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "security": [{"oauth": ["https://example.com/auth/default"]}],
            "paths": {"/x": {"get": {"operationId": "x"}}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(
            svc.actions["x"].required_scopes,
            vec!["https://example.com/auth/default"]
        );
    }

    #[test]
    fn op_security_overrides_root_security() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "security": [{"oauth": ["https://example.com/auth/default"]}],
            "paths": {"/x": {"get": {
                "operationId": "x",
                "security": [{"oauth": ["https://example.com/auth/override"]}]
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert_eq!(
            svc.actions["x"].required_scopes,
            vec!["https://example.com/auth/override"]
        );
    }

    #[test]
    fn op_empty_security_array_opts_out_of_root_default() {
        let doc = json!({
            "info": {"title": "T", "x-overslash-key": "t"},
            "security": [{"oauth": ["https://example.com/auth/default"]}],
            "paths": {"/x": {"get": {
                "operationId": "x",
                "security": []
            }}}
        });
        let (svc, _) = compile_service(&doc).unwrap();
        assert!(svc.actions["x"].required_scopes.is_empty());
    }
}
