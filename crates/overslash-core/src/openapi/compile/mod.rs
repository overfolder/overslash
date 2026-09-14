//! Compile step: lower a normalized OpenAPI JSON document into a
//! [`ServiceDefinition`]. The per-group extraction helpers live in
//! [`super::extract`]; this module wires them together, collects the issues
//! they raise, and applies the cross-cutting checks that need the whole
//! document (runtime selection, config/instance-config namespace collisions).

use std::collections::HashMap;

use serde_json::Value;

use crate::service_icon::ServiceIcon;
use crate::template_validation::ValidationIssue;
use crate::types::{Runtime, ServiceAction, ServiceDefinition};

use super::alias::HTTP_METHODS;
use super::ext::{self, Ext, Pos};
use super::extract;
use super::extract::{
    extract_auth, extract_hosts, extract_http_action, extract_mcp_actions, extract_mcp_spec,
    extract_platform_action, parse_timeout_ms,
};

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
    let mut warnings: Vec<ValidationIssue> = Vec::new();

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
        .and_then(|i| ext::get(i, Pos::Info, Ext::Key))
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
        .and_then(|i| ext::get(i, Pos::Info, Ext::Category))
        .and_then(Value::as_str)
        .map(str::to_string);

    let hidden = match info.and_then(|i| ext::get(i, Pos::Info, Ext::Hidden)) {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(other) => {
            // A typo like `hidden: "true"` must not silently unhide — warn
            // and fall back to visible so the mistake is observable.
            warnings.push(ValidationIssue::new(
                "openapi_invalid",
                format!("{} must be a boolean (got {other})", Ext::Hidden.key()),
                format!("info.{}", Ext::Hidden.key()),
            ));
            false
        }
    };

    // Catalog icon. Warnings, not errors, for the same reason as `hidden`
    // above: `ServiceRegistry::load_from_dir` skips a whole file when compile
    // fails, and refusing to load a service over a malformed logo is strictly
    // the worse failure.
    //
    // An absent or unusable value falls through to the implicit rule: a
    // template whose key matches a shipped asset gets `builtin:<key>` for
    // free. Resolving it here rather than at response time is what lets a
    // derived layer inherit it — `apply_delta` keys off the *layer's* name, so
    // a later lookup would find no asset and silently drop the base's icon.
    let authored_icon = match info.and_then(|i| ext::get(i, Pos::Info, Ext::Icon)) {
        None => None,
        Some(Value::String(raw)) => match ServiceIcon::try_from(raw.clone()) {
            Ok(icon) => Some(icon),
            Err(e) => {
                warnings.push(ValidationIssue::new(
                    "openapi_invalid",
                    format!("{}: {e}", Ext::Icon.key()),
                    format!("info.{}", Ext::Icon.key()),
                ));
                None
            }
        },
        Some(other) => {
            warnings.push(ValidationIssue::new(
                "openapi_invalid",
                format!("{} must be a string (got {other})", Ext::Icon.key()),
                format!("info.{}", Ext::Icon.key()),
            ));
            None
        }
    };
    let icon = authored_icon.or_else(|| ServiceIcon::implicit_for_key(&key));

    // Service-wide upstream timeout default. Warnings, not errors: an
    // unparseable value here would otherwise refuse to load a whole template
    // over one slow-upstream hint.
    let default_timeout_ms = parse_timeout_ms(
        info.and_then(|i| ext::get(i, Pos::Info, Ext::DefaultTimeoutMs)),
        Ext::DefaultTimeoutMs.key(),
        "info",
        &mut warnings,
    );

    let hosts = extract_hosts(root.get("servers"));

    let creds = match extract_auth(root.get("components")) {
        Ok(c) => c,
        Err(mut es) => {
            errors.append(&mut es);
            extract::CompiledCredentials {
                auth: Vec::new(),
                secrets: Vec::new(),
                config: Vec::new(),
            }
        }
    };
    let extract::CompiledCredentials {
        auth,
        secrets,
        config,
    } = creds;

    // Document root-level `security`, applied as the default required-scopes
    // for every operation that doesn't declare its own (OpenAPI 3.1 semantics).
    let root_security = root.get("security");

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
                match extract_http_action(
                    path_key,
                    method,
                    op,
                    path_level_params,
                    root_security,
                    &mut actions,
                ) {
                    Ok(()) => {}
                    Err(mut es) => errors.append(&mut es),
                }
            }
        }
    }

    if let Some(platform) =
        ext::get(root, Pos::Root, Ext::PlatformActions).and_then(Value::as_object)
    {
        for (action_key, action) in platform {
            let Some(obj) = action.as_object() else {
                errors.push(ValidationIssue::new(
                    "openapi_invalid",
                    "platform action must be an object",
                    format!("{}.{action_key}", Ext::PlatformActions.key()),
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

    // MCP runtime branch: populate McpSpec + per-tool actions from the
    // x-overslash-mcp block (merging discovered_tools[] + tools[]).
    let runtime = match ext::get(root, Pos::Root, Ext::Runtime).and_then(Value::as_str) {
        Some("mcp") => Runtime::Mcp,
        Some("platform") => Runtime::Platform,
        Some("http") | None => Runtime::Http,
        Some(other) => {
            errors.push(ValidationIssue::new(
                "openapi_invalid",
                format!(
                    "{} must be `http`, `mcp`, or `platform` (got {other:?})",
                    Ext::Runtime.key()
                ),
                Ext::Runtime.key(),
            ));
            Runtime::Http
        }
    };
    let mcp = if runtime == Runtime::Mcp {
        match extract_mcp_spec(root) {
            Ok(spec) => {
                if let Err(mut es) =
                    extract_mcp_actions(root, spec.autodiscover, &mut actions, &mut warnings)
                {
                    errors.append(&mut es);
                }
                Some(spec)
            }
            Err(mut es) => {
                errors.append(&mut es);
                None
            }
        }
    } else {
        None
    };

    // A declared page size only bounds anything if it reaches the request, and
    // the mechanism that puts it there is `validate_input::apply_defaults`,
    // which reads the parameter's own `default:`. So the extension does not
    // grow a second injection path — it seeds the first one.
    //
    // Seeding, not overwriting: a parameter that already declares `default:`
    // keeps it, because that is the more specific statement and the one an org
    // layer can patch. The two disagreeing is a warning at validation time, not
    // here — compile is past the point where anyone can act on it.
    for (action_key, action) in actions.iter_mut() {
        let Some(page_size) = action
            .pagination
            .as_ref()
            .and_then(|p| p.page_size.as_ref())
        else {
            continue;
        };
        let (Some(default), Some(param)) =
            (page_size.default, action.params.get_mut(&page_size.param))
        else {
            // A `page_size.param` naming a parameter the action does not
            // declare is reported by `validate_service_definition`, which sees
            // the whole action; silently doing nothing here is correct.
            let _ = action_key;
            continue;
        };
        if param.default.is_none() {
            param.default = Some(Value::from(default));
        }
    }

    // Credential config vars and `x-overslash-instance-config` params share one
    // namespace: both are keys of the instance's single `config` map, and both
    // render as one field on the instance form. A collision would make one
    // field feed two unrelated consumers, so it is a template error rather than
    // a precedence rule nobody could guess.
    for var in &config {
        if let Some(action_key) = actions
            .iter()
            .find(|(_, a)| a.params.get(&var.key).is_some_and(|p| p.instance_config))
            .map(|(k, _)| k)
        {
            errors.push(ValidationIssue::new(
                "openapi_unsupported_construct",
                format!(
                    "config `{}` collides with the instance-config param of the \
                     same name on action `{action_key}`; instance config is one \
                     namespace",
                    var.key
                ),
                format!("components.x-overslash-config.{}", var.key),
            ));
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
            hidden,
            icon,
            auth,
            secrets,
            config,
            actions,
            default_timeout_ms,
            runtime,
            mcp,
            // Only the fold sets these; a shipped template expresses its
            // defaults through `servers:` and param `default:`.
            instance_defaults: None,
        },
        warnings,
    ))
}

// ── End-to-end tests (public API, YAML ↔ compile round-trips) ──────────

#[cfg(test)]
mod tests;
