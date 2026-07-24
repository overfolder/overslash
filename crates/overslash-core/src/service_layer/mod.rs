//! Layered service templates — the **fold**.
//!
//! A *layer* is one stored `service_templates` row. Its `extends` field decides
//! its nature: `NULL` → **standalone** (holds a full OpenAPI doc), set → **derived**
//! (holds a [`Delta`] over the base named by `extends`). The public/API concept of
//! a "template" is the *effective, resolved* blueprint an agent instantiates:
//!
//! ```text
//! resolve(layer) = apply(layer.delta, resolve(layer.extends))
//! base case:       resolve(standalone) = compile(openapi)
//! ```
//!
//! This module owns the **pure** half — [`apply_delta`] and [`validate_delta`]
//! — operating on already-compiled [`ServiceDefinition`]s with no I/O, so the
//! resolution algebra is testable in isolation. The recursive walker that
//! fetches base rows / the registry and threads cycle detection lives in the
//! API crate (it needs the DB and the in-memory registry).
//!
//! ## Invariants
//!
//! - **Containment.** For the restrictive (mask) half of any delta,
//!   `resolve(child).actions ⊆ resolve(base).actions`. A derived layer can never
//!   widen past its base. The visibility ops (`allowlist` ∩, `denylist` \) are
//!   monotonic and order-independent, so a chain of layers can only ever shrink
//!   the surface — a user layer over an org layer inherits the org's curation as
//!   a hard ceiling for free.
//! - **Extensions are bounded.** A delta may add new action keys and hosts, but
//!   **never** auth (no field exists) and **never** rebind an existing base
//!   action (a colliding key is rejected at write time; at runtime the base
//!   wins and the extension is shadowed).
//! - **Instance defaults are presets, not rebinding.** [`InstanceDefaults`] is
//!   the one half of a delta that is neither restrictive nor capability-adding:
//!   it *replaces* a fallback rather than intersecting or appending. It does not
//!   rebind actions — method, path and auth are untouched — it only presets what
//!   a service instance would otherwise have to fill in by hand (its endpoint
//!   URL and its `x-overslash-instance-config` pins), and an instance that sets
//!   the field still wins. Because it can redirect where an org's traffic lands,
//!   it is **org-tier only** (`validate_delta`'s `user_tier` flag rejects it on a
//!   user layer), and it can never carry a credential — those live in the vault
//!   and bind through `credentials`.
//!
//! See `docs/design/layered-service-templates.md`.

use std::collections::HashMap;

use serde_json::Value;

use crate::template_validation::ValidationIssue;
use crate::types::{ServiceAction, ServiceDefinition};

mod apply;
mod types;
mod validate;

pub use apply::apply_delta;
pub use types::{ActionPatch, Delta, ExtensionAction, Extensions, InstanceDefaults};
pub use validate::validate_delta;

/// Compile a delta's extension actions into typed [`ServiceAction`]s by
/// assembling a synthetic OpenAPI doc and running it through the normal
/// compile pipeline. Reuses all shipped-template extraction so an extension
/// lowers exactly like a first-class action.
fn compile_extension_actions(
    base: &ServiceDefinition,
    ext: &Extensions,
) -> Result<HashMap<String, ServiceAction>, Vec<ValidationIssue>> {
    // servers = base hosts ∪ extension hosts, so extension operations resolve
    // a host the compiler accepts.
    let mut host_urls: Vec<Value> = Vec::new();
    for h in base.hosts.iter().chain(ext.hosts.iter()) {
        host_urls.push(serde_json::json!({ "url": format!("https://{h}") }));
    }

    let mut paths = serde_json::Map::new();
    for (key, action) in &ext.actions {
        let mut operation = action.operation.as_object().cloned().unwrap_or_default();
        // The action key is the operationId (used as the action key by the compiler).
        operation.insert("operationId".to_string(), Value::String(key.clone()));
        let method = action.method.to_lowercase();
        let path_item = paths
            .entry(action.path.clone())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Some(obj) = path_item.as_object_mut() {
            obj.insert(method, Value::Object(operation));
        }
    }

    let mut doc = serde_json::json!({
        "openapi": "3.1.0",
        "info": { "title": base.display_name, "x-overslash-key": base.key },
        "servers": host_urls,
        "paths": Value::Object(paths),
    });
    // Extension operations may use unprefixed aliases (`risk:` etc.).
    let ns_issues = crate::openapi::normalize_aliases(&mut doc);
    if !ns_issues.is_empty() {
        return Err(ns_issues);
    }
    let (def, _warnings) = crate::openapi::compile_service(&doc)?;
    Ok(def.actions)
}

/// Normalize a layer's default endpoint at fold time: trailing `/` trimmed, so
/// the executor's `format!("{base}{path}")` never produces a double slash.
/// Mirrors the per-instance `url` handling in the action resolver. Applied on
/// read rather than on write, so a row stored before this existed still folds
/// correctly.
fn normalize_default_url(url: &str) -> String {
    url.trim_end_matches('/').to_string()
}

/// Fixtures shared by the `apply` and `validate` test modules.
#[cfg(test)]
pub(crate) mod fixtures {
    use std::collections::{HashMap, HashSet};

    use crate::types::{Risk, Runtime, ServiceAction, ServiceDefinition};

    use super::InstanceDefaults;

    pub(crate) fn action(risk: Risk) -> ServiceAction {
        ServiceAction {
            method: "GET".into(),
            path: "/x".into(),
            description: "x".into(),
            summary: None,
            risk: risk.into(),
            response_type: None,
            params: HashMap::new(),
            scope_param: Default::default(),
            required_scopes: vec![],
            permission: None,
            disclose: vec![],
            redact: vec![],
            mcp_tool: None,
            output_schema: None,
            disabled: false,
            request_body: None,
        }
    }

    pub(crate) fn base_with(keys: &[(&str, Risk)]) -> ServiceDefinition {
        let mut actions = HashMap::new();
        for (k, r) in keys {
            actions.insert((*k).to_string(), action(*r));
        }
        ServiceDefinition {
            secrets: Vec::new(),
            config: Vec::new(),
            key: "github".into(),
            display_name: "GitHub".into(),
            description: Some("d".into()),
            hosts: vec!["api.github.com".into()],
            category: Some("Dev".into()),
            hidden: false,
            auth: vec![],
            actions,
            runtime: Runtime::Http,
            mcp: None,
            instance_defaults: None,
        }
    }

    pub(crate) fn keyset(def: &ServiceDefinition) -> HashSet<String> {
        def.actions.keys().cloned().collect()
    }

    pub(crate) fn defaults(url: Option<&str>, config: &[(&str, &str)]) -> InstanceDefaults {
        InstanceDefaults {
            url: url.map(str::to_string),
            config: config
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }
    }

    /// A base declaring one `x-overslash-instance-config` param, mirroring
    /// `email`'s mailbox-endpoint headers.
    pub(crate) fn base_with_pinnable_param(name: &str) -> ServiceDefinition {
        let mut base = base_with(&[("a", Risk::Read)]);
        base.actions.get_mut("a").unwrap().params.insert(
            name.to_string(),
            crate::types::ActionParam {
                param_type: "string".into(),
                required: false,
                description: String::new(),
                enum_values: None,
                default: None,
                resolve: None,
                aliases: vec![],
                location: crate::types::ParamLocation::Header,
                instance_config: true,
                sql_field: None,
                sql_database: None,
            },
        );
        base
    }
}
