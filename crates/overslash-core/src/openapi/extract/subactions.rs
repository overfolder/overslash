//! `x-overslash-subactions` → [`SubactionSpec`], and the actions its callable
//! variants compile to.

use std::collections::{BTreeMap, HashMap};

use serde_json::{Map, Value};

use crate::template_validation::ValidationIssue;
use crate::types::{DeclaredRisk, Risk, ServiceAction, Subaction, SubactionRef, SubactionSpec};

use super::super::ext::Ext;
use super::mcp::lower_input_schema;
use super::{parse_disclose, parse_redact, parse_scope_params, parse_timeout_ms};

/// Keys a `subactions` block may carry. Strict, unlike an operation: the block
/// is extension-internal, so an unknown key is a typo rather than OpenAPI.
const SPEC_KEYS: &[&str] = &["each", "summary", "verb", "phrase", "variants"];
const VARIANT_KEYS: &[&str] = &[
    "name",
    "match",
    "description",
    "verb",
    "phrase",
    "summary",
    "vars",
    "risk",
    "scope_param",
    "disclose",
    "redact",
    "timeout_ms",
    "required_scopes",
    "input_schema",
    "transform",
];

fn is_action_key(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some('a'..='z'))
        && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_'))
}

fn issue(code: &str, msg: impl Into<String>, path: impl Into<String>) -> ValidationIssue {
    ValidationIssue::new(code, msg, path)
}

fn opt_str(
    obj: &Map<String, Value>,
    key: &str,
    path: &str,
    errors: &mut Vec<ValidationIssue>,
) -> Option<String> {
    match obj.get(key) {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if !s.trim().is_empty() => Some(s.clone()),
        Some(_) => {
            errors.push(issue(
                "subactions_malformed",
                format!("`{key}` must be a non-empty string"),
                format!("{path}.{key}"),
            ));
            None
        }
    }
}

fn unknown_keys(
    obj: &Map<String, Value>,
    allowed: &[&str],
    path: &str,
    errors: &mut Vec<ValidationIssue>,
) {
    for k in obj.keys() {
        if !allowed.contains(&k.as_str()) {
            errors.push(issue(
                "subactions_malformed",
                format!(
                    "unknown key `{k}` (expected one of: {})",
                    allowed.join(", ")
                ),
                format!("{path}.{k}"),
            ));
        }
    }
}

/// Parse an action's `x-overslash-subactions` block. `None` when absent, and
/// also when malformed (with the reason pushed to `errors`).
pub(in crate::openapi) fn parse_subactions(
    raw: Option<&Value>,
    parent_risk: DeclaredRisk,
    base: &str,
    errors: &mut Vec<ValidationIssue>,
) -> Option<SubactionSpec> {
    let raw = raw?;
    let path = format!("{base}.{}", Ext::Subactions.key());
    let Some(obj) = raw.as_object() else {
        errors.push(issue(
            "subactions_malformed",
            "x-overslash-subactions must be a mapping with a `variants` list",
            path,
        ));
        return None;
    };
    // A dynamic parent is already classified per call, by the SQL policy.
    // Stacking a second classifier on top would leave two answers to "what
    // risk is this call", and no principled way to pick between them.
    if parent_risk.is_dynamic() {
        errors.push(issue(
            "subactions_on_dynamic_risk",
            "x-overslash-subactions cannot be declared on a `risk: dynamic` action",
            path,
        ));
        return None;
    }
    let before = errors.len();
    unknown_keys(obj, SPEC_KEYS, &path, errors);
    let each = opt_str(obj, "each", &path, errors);
    let summary = opt_str(obj, "summary", &path, errors);
    let verb = opt_str(obj, "verb", &path, errors);
    let phrase = opt_str(obj, "phrase", &path, errors);

    let Some(entries) = obj.get("variants").and_then(Value::as_array) else {
        errors.push(issue(
            "subactions_malformed",
            "`variants` must be a non-empty list",
            format!("{path}.variants"),
        ));
        return None;
    };
    if entries.is_empty() {
        errors.push(issue(
            "subactions_malformed",
            "`variants` must be a non-empty list",
            format!("{path}.variants"),
        ));
    }
    let mut variants = Vec::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        let vpath = format!("{path}.variants[{i}]");
        if let Some(v) = parse_variant(entry, parent_risk.display_risk(), &vpath, errors) {
            if variants.iter().any(|o: &Subaction| o.key == v.key) {
                errors.push(issue(
                    "subactions_duplicate_variant",
                    format!("variant `{}` is declared twice", v.key),
                    format!("{vpath}.name"),
                ));
                continue;
            }
            variants.push(v);
        }
    }
    if errors.len() > before {
        return None;
    }
    Some(SubactionSpec {
        each,
        summary,
        verb,
        phrase,
        variants,
    })
}

fn parse_variant(
    entry: &Value,
    parent_risk: Risk,
    path: &str,
    errors: &mut Vec<ValidationIssue>,
) -> Option<Subaction> {
    let Some(obj) = entry.as_object() else {
        errors.push(issue(
            "subactions_malformed",
            "a variant must be a mapping",
            path,
        ));
        return None;
    };
    let before = errors.len();
    unknown_keys(obj, VARIANT_KEYS, path, errors);

    let key = opt_str(obj, "name", path, errors);
    match key.as_deref() {
        None => errors.push(issue(
            "subactions_malformed",
            "a variant needs a `name`",
            format!("{path}.name"),
        )),
        Some(k) if !is_action_key(k) => errors.push(issue(
            "subactions_malformed",
            format!("variant name {k:?} must match ^[a-z][a-z0-9_]*$"),
            format!("{path}.name"),
        )),
        Some(_) => {}
    }
    let matches = opt_str(obj, "match", path, errors);
    // `opt_str` already reports a non-string `match`; an absent or explicit
    // `null` one (YAML `match:` with no value) is reported here, or the
    // variant would be dropped without a word.
    if matches.is_none() && obj.get("match").is_none_or(Value::is_null) {
        errors.push(issue(
            "subactions_malformed",
            "a variant needs a `match` jq predicate",
            format!("{path}.match"),
        ));
    }
    let description = opt_str(obj, "description", path, errors).unwrap_or_default();
    let verb = opt_str(obj, "verb", path, errors);
    let phrase = opt_str(obj, "phrase", path, errors);
    let summary = opt_str(obj, "summary", path, errors);

    let mut vars = BTreeMap::new();
    match obj.get("vars") {
        None => {}
        Some(Value::Object(m)) => {
            for (name, expr) in m {
                if !crate::types::is_scope_ident(name) {
                    errors.push(issue(
                        "subactions_malformed",
                        format!("var name {name:?} must be an identifier"),
                        format!("{path}.vars.{name}"),
                    ));
                }
                match expr.as_str() {
                    Some(e) if !e.trim().is_empty() => {
                        vars.insert(name.clone(), e.to_string());
                    }
                    _ => errors.push(issue(
                        "subactions_malformed",
                        "a var must be a jq expression string",
                        format!("{path}.vars.{name}"),
                    )),
                }
            }
        }
        Some(_) => errors.push(issue(
            "subactions_malformed",
            "`vars` must be a mapping of name → jq expression",
            format!("{path}.vars"),
        )),
    }

    let risk = match obj.get("risk").map(|v| v.as_str()) {
        None => parent_risk,
        Some(Some("read")) => Risk::Read,
        Some(Some("write")) => Risk::Write,
        Some(Some("delete")) => Risk::Delete,
        Some(other) => {
            errors.push(issue(
                "invalid_risk",
                format!("a variant's risk must be read/write/delete (got {other:?})"),
                format!("{path}.risk"),
            ));
            parent_risk
        }
    };
    let scope_param = match parse_scope_params(obj.get("scope_param"), path) {
        Ok(sp) => sp,
        Err(e) => {
            errors.push(e);
            Default::default()
        }
    };
    let disclose = parse_disclose(obj.get("disclose"), path, errors);
    let redact = parse_redact(obj.get("redact"), path, errors);
    let timeout_ms = parse_timeout_ms(obj.get("timeout_ms"), "timeout_ms", path, errors);
    let required_scopes = match obj.get("required_scopes") {
        None => Vec::new(),
        Some(Value::Array(a)) if a.iter().all(Value::is_string) => a
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        Some(_) => {
            errors.push(issue(
                "subactions_malformed",
                "`required_scopes` must be a list of strings",
                format!("{path}.required_scopes"),
            ));
            Vec::new()
        }
    };

    let transform = opt_str(obj, "transform", path, errors);
    let params = match (obj.get("input_schema"), &transform) {
        (Some(schema), Some(_)) => lower_input_schema(schema, path, errors),
        (None, None) => HashMap::new(),
        _ => {
            errors.push(issue(
                "subactions_malformed",
                "a callable variant needs both `input_schema` and `transform`",
                path,
            ));
            HashMap::new()
        }
    };

    if errors.len() > before {
        return None;
    }
    Some(Subaction {
        key: key?,
        matches: matches?,
        description,
        verb,
        phrase,
        summary,
        vars,
        risk,
        scope_param,
        disclose,
        redact,
        timeout_ms,
        required_scopes,
        transform,
        params,
    })
}

/// Emit an action for every callable variant, beside the parents already in
/// `actions`. Routing fields come from the parent — a callable variant is the
/// parent called with rewritten params — and its gating comes from
/// classification at call time, which is why `scope_param` and `disclose` are
/// left empty here.
///
/// A variant name colliding with any other action is an error rather than an
/// overwrite: the map insert would otherwise silently decide which one wins.
pub(in crate::openapi) fn emit_callable_subactions(
    actions: &mut HashMap<String, ServiceAction>,
    errors: &mut Vec<ValidationIssue>,
) {
    let mut emitted: Vec<(String, ServiceAction)> = Vec::new();
    let mut parents: Vec<&String> = actions.keys().collect();
    parents.sort();
    for parent_key in parents {
        let parent = &actions[parent_key];
        let Some(spec) = &parent.subactions else {
            continue;
        };
        for v in spec.variants.iter().filter(|v| v.is_callable()) {
            if actions.contains_key(&v.key) || emitted.iter().any(|(k, _)| k == &v.key) {
                errors.push(issue(
                    "subactions_key_collision",
                    format!(
                        "callable variant `{}` of `{parent_key}` collides with another action",
                        v.key
                    ),
                    format!("{parent_key}.{}", Ext::Subactions.key()),
                ));
                continue;
            }
            let mut required_scopes = parent.required_scopes.clone();
            for s in &v.required_scopes {
                if !required_scopes.contains(s) {
                    required_scopes.push(s.clone());
                }
            }
            emitted.push((
                v.key.clone(),
                ServiceAction {
                    method: parent.method.clone(),
                    path: parent.path.clone(),
                    description: v.description.clone(),
                    // The variant's summary is a *group* template (it may
                    // `enumerate`), rendered by classification — not by the
                    // flat label grammar this field feeds.
                    summary: None,
                    risk: v.risk.into(),
                    response_type: parent.response_type.clone(),
                    timeout_ms: v.timeout_ms.or(parent.timeout_ms),
                    wait_mode: parent.wait_mode,
                    handoff_after_ms: parent.handoff_after_ms,
                    params: v.params.clone(),
                    required_scopes,
                    mcp_tool: parent.mcp_tool.clone(),
                    output_schema: parent.output_schema.clone(),
                    disabled: parent.disabled,
                    request_body: parent.request_body.clone(),
                    success: parent.success.clone(),
                    subaction_of: Some(SubactionRef {
                        parent: parent_key.clone(),
                        variant: v.key.clone(),
                    }),
                    ..Default::default()
                },
            ));
        }
    }
    actions.extend(emitted);
}
