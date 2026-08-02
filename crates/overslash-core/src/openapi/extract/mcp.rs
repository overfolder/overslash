//! `x-overslash-mcp` → `McpSpec` + the `ServiceAction`s its tools compile to.

use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::template_validation::ValidationIssue;
use crate::types::{
    ActionParam, DeclaredRisk, McpAuth, McpSpec, ParamLocation, ServiceAction, ServiceDefinition,
};

use super::{
    parse_aliases, parse_disclose, parse_instance_config, parse_redact, parse_scope_params,
    parse_sql_policy,
};

// ── x-overslash-mcp → McpSpec + ServiceActions ───────────────────────

/// Lower the `x-overslash-mcp` block into a typed `McpSpec`.
pub(crate) fn extract_mcp_spec(root: &Map<String, Value>) -> Result<McpSpec, Vec<ValidationIssue>> {
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
pub(crate) fn extract_mcp_actions(
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
        Some("read") | None => DeclaredRisk::Read,
        Some("write") => DeclaredRisk::Write,
        Some("delete") => DeclaredRisk::Delete,
        // An MCP tool taking raw SQL (e.g. HubSpot `query_crm_data`) can be
        // classified per call exactly like an HTTP action (D42).
        Some("dynamic") => DeclaredRisk::Dynamic,
        Some(other) => {
            errors.push(ValidationIssue::new(
                "invalid_risk",
                format!(
                    "x-overslash-risk must be one of read/write/delete/dynamic (got {other:?})"
                ),
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
    let scope_param = match parse_scope_params(obj.get("x-overslash-scope_param"), &base) {
        Ok(sp) => sp,
        Err(issue) => {
            errors.push(issue);
            return None;
        }
    };
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
        summary: None,
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
        // MCP tool calls are framed by the MCP client (which sets its own
        // JSON-RPC content type), never routed through `resolve`.
        request_body: None,
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
pub(crate) fn lower_input_schema(schema: &Value) -> HashMap<String, ActionParam> {
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
        let (sql_field, sql_database) = parse_sql_policy(Some(po));
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
                sql_field,
                sql_database,
            },
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
}
