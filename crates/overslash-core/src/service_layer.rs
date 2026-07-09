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
//!
//! See `docs/design/layered-service-templates.md`.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::template_validation::{Issues, ValidationIssue, ValidationReport};
use crate::types::{DisclosureField, Risk, Runtime, ServiceAction, ServiceDefinition};

/// A derived layer's stored content: a **mask** half (restrictive) and an
/// **extension** half (expansive). A single delta may carry both.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Delta {
    // ---- template-level masks ----
    /// Drop the whole (derived) template from the catalog. `None` → inherit the
    /// base's `hidden`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden: Option<bool>,
    /// Relabel the template. `None` → inherit the base's display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Relabel the description. `None` → inherit the base's description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    // ---- action masks (restrictive; monotonic; order-independent) ----
    /// Keep only these action keys (∩). `None` → keep all of the base's actions;
    /// `Some([])` → expose nothing. Excludes any un-listed action, *including new
    /// tools an upstream autodiscovered base later adds* (the autodiscover-safety
    /// story).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowlist: Option<Vec<String>>,
    /// Drop these action keys (\).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denylist: Vec<String>,
    /// Per-action metadata masks over the base's own actions.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub action_patch: HashMap<String, ActionPatch>,

    // ---- extensions (expansive; capability-adding) ----
    #[serde(default, skip_serializing_if = "Extensions::is_empty")]
    pub extensions: Extensions,
}

/// A restrictive metadata mask over one base action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActionPatch {
    /// Clamp risk **upward only** (adds approvals; never removes them). A patch
    /// that would *lower* risk is a write-time error and is ignored at apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<Risk>,
    /// Additional disclose specs appended to the action's existing ones.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disclose: Vec<DisclosureField>,
    /// Relabel the action's description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// The expansive half of a delta: new actions + hosts. No auth, no rebinding.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Extensions {
    /// New actions, keyed by action key. Each value is an OpenAPI operation
    /// fragment (`method` + `path` + `operation` object); compiled through the
    /// normal pipeline at write/apply time so it lowers to the same typed
    /// [`ServiceAction`] as a shipped template.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub actions: HashMap<String, ExtensionAction>,
    /// Additional hosts, unioned onto the base's.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
}

impl Extensions {
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty() && self.hosts.is_empty()
    }
}

/// One extension action: an OpenAPI operation fragment. `method`/`path` are the
/// structural binding; `operation` is the OpenAPI operation object (parameters,
/// requestBody, `x-overslash-*`). The action key is the map key.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtensionAction {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub operation: Value,
}

/// The `apply()` half of the fold: overlay `delta` onto an already-resolved
/// base, producing the effective [`ServiceDefinition`] plus non-blocking
/// **resolution warnings** (`shadowed_extension`, `dead_*`, `unreviewed_new_actions`).
///
/// The effective def keeps `base.key`; the async walker overrides it with the
/// deriving layer's own key (so a distinct-key layer surfaces under its own key,
/// a same-key layer keeps shadowing the base).
pub fn apply_delta(
    delta: &Delta,
    base: &ServiceDefinition,
) -> (ServiceDefinition, Vec<ValidationIssue>) {
    let mut issues = Issues::default();
    let mut actions = base.actions.clone();

    // ── Visibility = base.actions ∩ allowlist \ denylist ──────────────────
    if let Some(allow) = &delta.allowlist {
        let allow_set: HashSet<&str> = allow.iter().map(String::as_str).collect();
        for a in allow {
            if !base.actions.contains_key(a) {
                issues.warn(
                    "dead_allowlist_entry",
                    format!("allowlist entry '{a}' is not an action of the base template"),
                    format!("allowlist.{a}"),
                );
            }
        }
        actions.retain(|k, _| allow_set.contains(k.as_str()));

        // Autodiscover-safety: an allowlist over an autodiscovered MCP base
        // silently excludes any tool the upstream server adds later. Surface
        // the count so an admin can review + allowlist deliberately.
        if base.runtime == Runtime::Mcp && base.mcp.as_ref().is_some_and(|m| m.autodiscover) {
            let n = base
                .actions
                .keys()
                .filter(|k| !allow_set.contains(k.as_str()))
                .count();
            if n > 0 {
                issues.warn(
                    "unreviewed_new_actions",
                    format!("{n} action(s) on the autodiscovered base are not in the allowlist"),
                    "allowlist",
                );
            }
        }
    }
    for d in &delta.denylist {
        if !base.actions.contains_key(d) {
            issues.warn(
                "dead_denylist_entry",
                format!("denylist entry '{d}' is not an action of the base template"),
                format!("denylist.{d}"),
            );
        }
        actions.remove(d);
    }

    // ── action_patch: risk clamp-up / additive disclose / relabel ─────────
    for (key, patch) in &delta.action_patch {
        match actions.get_mut(key) {
            Some(action) => apply_action_patch(action, patch),
            None => {
                let reason = if base.actions.contains_key(key) {
                    "is masked out by allowlist/denylist"
                } else {
                    "is not an action of the base template"
                };
                issues.warn(
                    "dead_action_patch_target",
                    format!("action_patch target '{key}' {reason}"),
                    format!("action_patch.{key}"),
                );
            }
        }
    }

    // ── extensions: add new actions (base wins on collision) + hosts ──────
    let mut hosts = base.hosts.clone();
    for h in &delta.extensions.hosts {
        if !hosts.contains(h) {
            hosts.push(h.clone());
        }
    }
    if !delta.extensions.actions.is_empty() {
        match compile_extension_actions(base, &delta.extensions) {
            Ok(compiled) => {
                for (key, action) in compiled {
                    if base.actions.contains_key(&key) {
                        // Runtime collision: the base action wins; the extension
                        // is shadowed but not deleted, and we flag it.
                        issues.warn(
                            "shadowed_extension",
                            format!(
                                "extension action '{key}' collides with a base action; base wins"
                            ),
                            format!("extensions.actions.{key}"),
                        );
                        continue;
                    }
                    actions.insert(key, action);
                }
            }
            Err(errs) => {
                for e in errs {
                    issues.warn(
                        "extension_compile_failed",
                        format!("extension actions failed to compile: {}", e.message),
                        "extensions.actions",
                    );
                }
            }
        }
    }

    let def = ServiceDefinition {
        key: base.key.clone(),
        display_name: delta
            .display_name
            .clone()
            .unwrap_or_else(|| base.display_name.clone()),
        description: delta
            .description
            .clone()
            .or_else(|| base.description.clone()),
        hosts,
        category: base.category.clone(),
        hidden: delta.hidden.unwrap_or(base.hidden),
        auth: base.auth.clone(),
        actions,
        runtime: base.runtime,
        mcp: base.mcp.clone(),
    };

    let report = issues.finish();
    (def, report.warnings)
}

fn apply_action_patch(action: &mut ServiceAction, patch: &ActionPatch) {
    if let Some(risk) = patch.risk {
        // Clamp UP only: raise to `risk` if it's more severe; never lower.
        if risk.severity() >= action.risk.severity() {
            action.risk = risk;
        }
    }
    if !patch.disclose.is_empty() {
        action.disclose.extend(patch.disclose.iter().cloned());
    }
    if let Some(desc) = &patch.description {
        action.description = desc.clone();
    }
}

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

/// Write-time **blocking** validation of a delta against its resolved base.
/// Returns a [`ValidationReport`] in the same shape as template validation.
pub fn validate_delta(delta: &Delta, base: &ServiceDefinition) -> ValidationReport {
    let mut issues = Issues::default();

    // The base's FULL keyset (there is no hidden-vs-visible split once compiled;
    // every base action key is off-limits for an extension).
    let base_keys: HashSet<&str> = base.actions.keys().map(String::as_str).collect();

    // allowlist / denylist entries should reference real base actions (a dead
    // entry is a warning at resolve time, but at write time we surface it too so
    // a typo is caught immediately — non-blocking).
    if let Some(allow) = &delta.allowlist {
        for a in allow {
            if !base_keys.contains(a.as_str()) {
                issues.warn(
                    "dead_allowlist_entry",
                    format!("allowlist entry '{a}' is not an action of the base template"),
                    format!("allowlist.{a}"),
                );
            }
        }
    }
    for d in &delta.denylist {
        if !base_keys.contains(d.as_str()) {
            issues.warn(
                "dead_denylist_entry",
                format!("denylist entry '{d}' is not an action of the base template"),
                format!("denylist.{d}"),
            );
        }
    }

    // action_patch: target must exist; risk may only clamp UP.
    for (key, patch) in &delta.action_patch {
        match base.actions.get(key) {
            None => issues.err(
                "unknown_action",
                format!("action_patch target '{key}' is not an action of the base template"),
                format!("action_patch.{key}"),
            ),
            Some(action) => {
                if let Some(risk) = patch.risk
                    && risk.severity() < action.risk.severity()
                {
                    issues.err(
                        "risk_clamp_down",
                        format!(
                            "action_patch may only raise risk (base '{}' is '{}', patch '{}')",
                            key, action.risk, risk
                        ),
                        format!("action_patch.{key}.risk"),
                    );
                }
            }
        }
    }

    // extensions: keys must not collide with ANY base key (closes the
    // hide-then-re-add hijack); fragments must compile; no rebinding.
    for key in delta.extensions.actions.keys() {
        if base_keys.contains(key.as_str()) {
            issues.err(
                "extension_key_collision",
                format!(
                    "extension action '{key}' collides with a base action key \
                     (extensions may only add new keys, never rebind)"
                ),
                format!("extensions.actions.{key}"),
            );
        }
    }
    if !delta.extensions.actions.is_empty() {
        if let Err(errs) = compile_extension_actions(base, &delta.extensions) {
            for e in errs {
                issues.err(
                    "extension_invalid",
                    format!("extension actions failed to compile: {}", e.message),
                    "extensions.actions",
                );
            }
        }
    }

    issues.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Risk;
    use std::collections::HashMap;

    fn action(risk: Risk) -> ServiceAction {
        ServiceAction {
            method: "GET".into(),
            path: "/x".into(),
            description: "x".into(),
            risk,
            response_type: None,
            params: HashMap::new(),
            scope_param: None,
            required_scopes: vec![],
            permission: None,
            disclose: vec![],
            redact: vec![],
            mcp_tool: None,
            output_schema: None,
            disabled: false,
        }
    }

    fn base_with(keys: &[(&str, Risk)]) -> ServiceDefinition {
        let mut actions = HashMap::new();
        for (k, r) in keys {
            actions.insert((*k).to_string(), action(*r));
        }
        ServiceDefinition {
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
        }
    }

    fn keyset(def: &ServiceDefinition) -> HashSet<String> {
        def.actions.keys().cloned().collect()
    }

    #[test]
    fn allowlist_intersects() {
        let base = base_with(&[("a", Risk::Read), ("b", Risk::Read), ("c", Risk::Write)]);
        let delta = Delta {
            allowlist: Some(vec!["a".into(), "b".into()]),
            ..Default::default()
        };
        let (def, _) = apply_delta(&delta, &base);
        assert_eq!(keyset(&def), HashSet::from(["a".into(), "b".into()]));
    }

    #[test]
    fn empty_allowlist_exposes_nothing() {
        let base = base_with(&[("a", Risk::Read)]);
        let delta = Delta {
            allowlist: Some(vec![]),
            ..Default::default()
        };
        let (def, _) = apply_delta(&delta, &base);
        assert!(def.actions.is_empty());
    }

    #[test]
    fn denylist_removes() {
        let base = base_with(&[("a", Risk::Read), ("delete_repo", Risk::Delete)]);
        let delta = Delta {
            denylist: vec!["delete_repo".into()],
            ..Default::default()
        };
        let (def, _) = apply_delta(&delta, &base);
        assert_eq!(keyset(&def), HashSet::from(["a".into()]));
    }

    #[test]
    fn containment_child_subset_of_base() {
        // A chain: base → org (allow a,b,c) → user (allow a,b). The user layer
        // can never re-expose an action the org hid.
        let base = base_with(&[
            ("a", Risk::Read),
            ("b", Risk::Read),
            ("c", Risk::Read),
            ("d", Risk::Read),
        ]);
        let org_delta = Delta {
            allowlist: Some(vec!["a".into(), "b".into(), "c".into()]),
            ..Default::default()
        };
        let (org, _) = apply_delta(&org_delta, &base);
        // user tries to allow 'd' too — but folds over ORG, not base.
        let user_delta = Delta {
            allowlist: Some(vec!["a".into(), "b".into(), "d".into()]),
            ..Default::default()
        };
        let (user, _) = apply_delta(&user_delta, &org);
        assert!(keyset(&user).is_subset(&keyset(&org)));
        assert!(
            !user.actions.contains_key("d"),
            "user cannot re-expose 'd' hidden by org"
        );
        assert_eq!(keyset(&user), HashSet::from(["a".into(), "b".into()]));
    }

    #[test]
    fn masks_are_order_independent() {
        // S ∩ A₁\D₁ ∩ A₂\D₂ == S ∩ (A₁∩A₂) \ (D₁∪D₂)
        let base = base_with(&[
            ("a", Risk::Read),
            ("b", Risk::Read),
            ("c", Risk::Read),
            ("d", Risk::Read),
        ]);
        let d1 = Delta {
            allowlist: Some(vec!["a".into(), "b".into(), "c".into()]),
            denylist: vec!["c".into()],
            ..Default::default()
        };
        let d2 = Delta {
            allowlist: Some(vec!["a".into(), "b".into(), "d".into()]),
            denylist: vec!["b".into()],
            ..Default::default()
        };
        let (s1, _) = apply_delta(&d1, &base);
        let (s12, _) = apply_delta(&d2, &s1);
        let (s2, _) = apply_delta(&d2, &base);
        let (s21, _) = apply_delta(&d1, &s2);
        assert_eq!(keyset(&s12), keyset(&s21));
        assert_eq!(keyset(&s12), HashSet::from(["a".into()]));
    }

    #[test]
    fn risk_clamps_up_only() {
        let base = base_with(&[("merge", Risk::Write)]);
        // clamp up write→delete: applies
        let up = Delta {
            action_patch: HashMap::from([(
                "merge".to_string(),
                ActionPatch {
                    risk: Some(Risk::Delete),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        let (def, _) = apply_delta(&up, &base);
        assert_eq!(def.actions["merge"].risk, Risk::Delete);

        // clamp down delete→write: ignored at apply
        let base2 = base_with(&[("merge", Risk::Delete)]);
        let down = Delta {
            action_patch: HashMap::from([(
                "merge".to_string(),
                ActionPatch {
                    risk: Some(Risk::Write),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        let (def2, _) = apply_delta(&down, &base2);
        assert_eq!(
            def2.actions["merge"].risk,
            Risk::Delete,
            "clamp-down ignored"
        );
    }

    #[test]
    fn validate_rejects_risk_clamp_down() {
        let base = base_with(&[("merge", Risk::Delete)]);
        let down = Delta {
            action_patch: HashMap::from([(
                "merge".to_string(),
                ActionPatch {
                    risk: Some(Risk::Write),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        let report = validate_delta(&down, &base);
        assert!(!report.valid);
        assert!(report.errors.iter().any(|e| e.code == "risk_clamp_down"));
    }

    #[test]
    fn validate_rejects_extension_collision_including_hidden() {
        // denylist hides delete_repo, then extensions re-adds it → rejected,
        // because collision is checked against the base's FULL keyset.
        let base = base_with(&[("delete_repo", Risk::Delete)]);
        let delta = Delta {
            denylist: vec!["delete_repo".into()],
            extensions: Extensions {
                actions: HashMap::from([(
                    "delete_repo".to_string(),
                    ExtensionAction {
                        method: "DELETE".into(),
                        path: "/x".into(),
                        operation: serde_json::json!({}),
                    },
                )]),
                hosts: vec![],
            },
            ..Default::default()
        };
        let report = validate_delta(&delta, &base);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.code == "extension_key_collision")
        );
    }

    #[test]
    fn extension_adds_action_and_host() {
        let base = base_with(&[("a", Risk::Read)]);
        let delta = Delta {
            extensions: Extensions {
                actions: HashMap::from([(
                    "archive_repo".to_string(),
                    ExtensionAction {
                        method: "POST".into(),
                        path: "/repos/archive".into(),
                        operation: serde_json::json!({ "description": "Archive", "x-overslash-risk": "write" }),
                    },
                )]),
                hosts: vec!["ghe.acme.internal".into()],
            },
            ..Default::default()
        };
        let report = validate_delta(&delta, &base);
        assert!(
            report.valid,
            "extension should validate: {:?}",
            report.errors
        );
        let (def, warnings) = apply_delta(&delta, &base);
        assert!(def.actions.contains_key("archive_repo"));
        assert!(def.hosts.contains(&"ghe.acme.internal".to_string()));
        assert_eq!(def.actions["archive_repo"].risk, Risk::Write);
        assert!(warnings.is_empty(), "no warnings expected: {warnings:?}");
    }

    #[test]
    fn shadowed_extension_warns_base_wins() {
        // An extension whose key collides with a base key: apply keeps the base
        // (write-time validation would have rejected this, but at resolve time
        // an upstream base can grow a colliding key later).
        let base = base_with(&[("a", Risk::Read)]);
        let delta = Delta {
            extensions: Extensions {
                actions: HashMap::from([(
                    "a".to_string(),
                    ExtensionAction {
                        method: "POST".into(),
                        path: "/a".into(),
                        operation: serde_json::json!({ "description": "shadow" }),
                    },
                )]),
                hosts: vec![],
            },
            ..Default::default()
        };
        let (def, warnings) = apply_delta(&delta, &base);
        assert_eq!(def.actions["a"].method, "GET", "base action wins");
        assert!(warnings.iter().any(|w| w.code == "shadowed_extension"));
    }

    #[test]
    fn template_relabel_and_hide() {
        let base = base_with(&[("a", Risk::Read)]);
        let delta = Delta {
            display_name: Some("GitHub (Acme)".into()),
            hidden: Some(true),
            ..Default::default()
        };
        let (def, _) = apply_delta(&delta, &base);
        assert_eq!(def.display_name, "GitHub (Acme)");
        assert!(def.hidden);
        assert_eq!(
            def.key, "github",
            "effective key stays the base key (walker overrides for distinct-key layers)"
        );
    }

    #[test]
    fn dead_entries_warn() {
        let base = base_with(&[("a", Risk::Read)]);
        let delta = Delta {
            allowlist: Some(vec!["a".into(), "nope".into()]),
            ..Default::default()
        };
        let (_, warnings) = apply_delta(&delta, &base);
        assert!(warnings.iter().any(|w| w.code == "dead_allowlist_entry"));
    }
}
