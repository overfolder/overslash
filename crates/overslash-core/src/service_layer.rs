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

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::instance_config::{self, ConfigMap};
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

    // ---- instance defaults (presets; org-tier only) ----
    /// Defaults every instance of this layer inherits unless it sets the field
    /// itself. `None` → inherit the base's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_defaults: Option<InstanceDefaults>,
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

/// Defaults a layer supplies for the surface a service instance would otherwise
/// fill in by hand. Exactly the **non-secret** half of that surface:
///
/// | `service_instances` column | here | why |
/// |---|---|---|
/// | `url` | ✅ | the endpoint — an org's own deployment |
/// | `config` | ✅ | declared `x-overslash-instance-config` pins |
/// | `secret_name` / `credentials` / `connection_id` | ❌ | credentials — a delta never touches auth |
/// | `discovered_tools` | ❌ | runtime-derived, not authored |
///
/// Precedence at execution is `instance > layer > template`: an instance that
/// sets `url` (or a `config` key) keeps its own value, so a developer can still
/// point one instance at a local deployment while the rest of the org inherits
/// the shared one.
///
/// `deny_unknown_fields` is deliberate: a misspelled key (`"URL"`, `"configs"`)
/// would otherwise deserialize to an empty struct, validate clean, and silently
/// leave the org's traffic on the shipped default. A field this
/// consequential fails loudly instead.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceDefaults {
    /// Endpoint every instance dials unless it sets its own `url`. Absolute,
    /// scheme included; a path prefix is allowed (a gateway mounted under
    /// `/api/v3`) but no query or fragment. Takes precedence over the
    /// template's first `servers[]` entry (HTTP) and over `mcp.url` (MCP
    /// runtime). Normalized at fold time — see [`normalize_default_url`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Default values for params the template declares
    /// `x-overslash-instance-config`. Merged *under* an instance's own `config`
    /// (per key), which is itself merged under the caller's args.
    #[serde(default, skip_serializing_if = "ConfigMap::is_empty")]
    pub config: ConfigMap,
}

impl InstanceDefaults {
    pub fn is_empty(&self) -> bool {
        self.url.is_none() && self.config.is_empty()
    }

    /// Overlay `self` (the deriving layer) onto `base`'s defaults. A set `url`
    /// replaces; `config` merges per key.
    ///
    /// Both halves are normalized here rather than at write time, so a row
    /// stored before the normalization existed still folds correctly, and a
    /// value written through the layer path is injected byte-identically to the
    /// same value pinned on an instance (which `instance_config::validate_config`
    /// trims on write).
    ///
    /// Only org layers may *set* defaults, but every tier **inherits** them: a
    /// user layer over an org layer carries the org's gateway forward untouched.
    /// Chained org layers (org layer over org layer) are the case where the
    /// override arm matters.
    fn merge_over(&self, base: Option<&InstanceDefaults>) -> InstanceDefaults {
        let mut out = base.cloned().unwrap_or_default();
        if let Some(url) = &self.url {
            out.url = Some(normalize_default_url(url));
        }
        for (k, v) in &self.config {
            out.config.insert(k.clone(), v.trim().to_string());
        }
        out
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

    // ── instance defaults: merge over the base's ──────────────────────────
    let instance_defaults = match &delta.instance_defaults {
        Some(d) => Some(d.merge_over(base.instance_defaults.as_ref())),
        None => base.instance_defaults.clone(),
    };
    // A default URL is also an egress target: the service+HTTP-verb shape
    // validates a caller-supplied `url:` against `hosts`, so without this union
    // an org could route its actions through its own gateway yet be unable to
    // name that gateway in a raw verb call. Appended (not prepended) — `hosts`
    // ordering still belongs to the template; the endpoint is read from
    // `instance_defaults.url` directly, not from `hosts.first()`.
    //
    // The **origin** (`scheme://host[:port]`) is unioned, not the bare hostname
    // `url_to_host` would give: the verb shape matches host AND port, so a bare
    // entry would both reject the admin's own `:8443` gateway and quietly
    // allow-list `:443` on that host, which they never named.
    if let Some(origin) = instance_defaults
        .as_ref()
        .and_then(|d| d.url.as_deref())
        .and_then(url_to_origin)
        && !hosts.contains(&origin)
    {
        hosts.push(origin);
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
        // Credential slots ride with `auth`: a mask may add actions and hosts,
        // never rebind credentials.
        secrets: base.secrets.clone(),
        actions,
        runtime: base.runtime,
        mcp: base.mcp.clone(),
        instance_defaults,
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
///
/// `user_tier` is `true` when the layer being written is owned by an individual
/// (`service_templates.owner_identity_id IS NOT NULL`). It gates
/// [`InstanceDefaults`], which can redirect where an org's traffic lands and so
/// stays with org admins.
pub fn validate_delta(
    delta: &Delta,
    base: &ServiceDefinition,
    user_tier: bool,
) -> ValidationReport {
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

    // instance_defaults: org-tier only; a valid absolute endpoint; config keys
    // the template actually declares.
    //
    // The tier gate keys off *presence*, not content: accepting a
    // `"instance_defaults": {}` from a user layer would persist a field the
    // error text says is rejected outright.
    if let Some(defaults) = &delta.instance_defaults {
        if user_tier {
            issues.err(
                "instance_defaults_user_tier",
                "a user layer may not set `instance_defaults` — an endpoint or config default \
                 that every instance inherits is an org-admin decision"
                    .to_string(),
                "instance_defaults",
            );
        }
        if let Some(url) = &defaults.url
            && let Err(reason) = check_default_url(url)
        {
            issues.err(
                "instance_defaults_invalid_url",
                format!("`instance_defaults.url` {reason}"),
                "instance_defaults.url",
            );
        }
        // Validate config keys against the *folded* surface, not the base's:
        // this delta's own extension actions may declare instance-config params,
        // and defaulting one of those is legitimate.
        if !defaults.config.is_empty() {
            let (folded, _) = apply_delta(delta, base);
            if let Err(e) = instance_config::validate_config(&folded, &defaults.config) {
                issues.err(
                    e.code(),
                    e.message(&folded.key),
                    format!("instance_defaults.config.{}", e.key()),
                );
            }
        }
    }

    issues.finish()
}

/// The `scheme://host[:port]` prefix of a default endpoint, dropping any path.
/// Used to union the endpoint into `hosts` in a form the verb shape's
/// host-and-port matcher reads exactly — `url_to_host` would drop the port.
/// Returns `None` for anything `check_default_url` would reject.
fn url_to_origin(url: &str) -> Option<String> {
    let (scheme, rest) = url
        .strip_prefix("https://")
        .map(|r| ("https", r))
        .or_else(|| url.strip_prefix("http://").map(|r| ("http", r)))?;
    let authority = rest.split('/').next()?.trim();
    if authority.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{authority}"))
}

/// Shape check for a layer's default endpoint. Deliberately string-level (core
/// carries no URL parser): an absolute `http`/`https` URL with a host and no
/// query or fragment. A path prefix is allowed — a gateway mounted under
/// `/api/v3` is a legitimate base — but a request is not.
fn check_default_url(url: &str) -> Result<(), &'static str> {
    let trimmed = url.trim();
    if trimmed != url {
        return Err("must not have leading or trailing whitespace");
    }
    let Some(rest) = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
    else {
        return Err("must be an absolute URL starting with http:// or https://");
    };
    if rest.split('/').next().unwrap_or("").is_empty() {
        return Err("has no host");
    }
    if trimmed.contains('?') || trimmed.contains('#') {
        return Err("must not carry a query string or fragment");
    }
    Ok(())
}

/// Normalize a layer's default endpoint at fold time: trailing `/` trimmed, so
/// the executor's `format!("{base}{path}")` never produces a double slash.
/// Mirrors the per-instance `url` handling in the action resolver. Applied on
/// read rather than on write, so a row stored before this existed still folds
/// correctly.
fn normalize_default_url(url: &str) -> String {
    url.trim_end_matches('/').to_string()
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
            request_body: None,
        }
    }

    fn base_with(keys: &[(&str, Risk)]) -> ServiceDefinition {
        let mut actions = HashMap::new();
        for (k, r) in keys {
            actions.insert((*k).to_string(), action(*r));
        }
        ServiceDefinition {
            secrets: Vec::new(),
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
        let report = validate_delta(&down, &base, false);
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
        let report = validate_delta(&delta, &base, false);
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
        let report = validate_delta(&delta, &base, false);
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

    // ── instance_defaults ────────────────────────────────────────────────

    fn defaults(url: Option<&str>, config: &[(&str, &str)]) -> InstanceDefaults {
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
    fn base_with_pinnable_param(name: &str) -> ServiceDefinition {
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
            },
        );
        base
    }

    #[test]
    fn instance_defaults_url_sets_effective_endpoint() {
        let base = base_with(&[("a", Risk::Read)]);
        let delta = Delta {
            instance_defaults: Some(defaults(Some("https://ghe.acme.internal"), &[])),
            ..Default::default()
        };
        let (def, _) = apply_delta(&delta, &base);
        assert_eq!(
            def.instance_defaults.unwrap().url.unwrap(),
            "https://ghe.acme.internal"
        );
        assert_eq!(
            def.hosts[0], "api.github.com",
            "the template still owns `hosts` ordering; the endpoint is read from instance_defaults"
        );
    }

    #[test]
    fn defaults_url_trailing_slash_is_normalized() {
        let base = base_with(&[("a", Risk::Read)]);
        let delta = Delta {
            instance_defaults: Some(defaults(Some("https://ghe.acme.internal/"), &[])),
            ..Default::default()
        };
        let (def, _) = apply_delta(&delta, &base);
        assert_eq!(
            def.instance_defaults.unwrap().url.unwrap(),
            "https://ghe.acme.internal",
            "otherwise `format!(\"{{base}}{{path}}\")` yields a double slash"
        );
    }

    #[test]
    fn defaults_origin_unioned_into_hosts_with_port() {
        let base = base_with(&[("a", Risk::Read)]);
        let delta = Delta {
            instance_defaults: Some(defaults(Some("https://ghe.acme.internal:8443/api"), &[])),
            ..Default::default()
        };
        let (def, _) = apply_delta(&delta, &base);
        assert!(
            def.hosts
                .contains(&"https://ghe.acme.internal:8443".to_string()),
            "the default endpoint must be a legal egress target for the service \
             + HTTP-verb shape, which matches host AND port — a bare hostname \
             would reject :8443 and silently allow :443. got {:?}",
            def.hosts
        );
        assert!(
            !def.hosts.contains(&"ghe.acme.internal".to_string()),
            "the bare-hostname form must not leak in: it implies :443"
        );
    }

    #[test]
    fn defaults_override_through_an_org_layer_chain() {
        // Only org layers may *set* defaults, so the override case is an org
        // layer over an org layer: gateway + pin, then a re-point of the pin.
        let base = base_with_pinnable_param("X-Imap");
        let outer = Delta {
            instance_defaults: Some(defaults(
                Some("https://mail.overfolder-dev.com"),
                &[("X-Imap", "imap.acme.com")],
            )),
            ..Default::default()
        };
        let (outer_def, _) = apply_delta(&outer, &base);

        let inner = Delta {
            instance_defaults: Some(defaults(None, &[("X-Imap", "imap.eu.acme.com")])),
            ..Default::default()
        };
        let (inner_def, _) = apply_delta(&inner, &outer_def);

        let d = inner_def.instance_defaults.unwrap();
        assert_eq!(
            d.url.unwrap(),
            "https://mail.overfolder-dev.com",
            "a layer that does not re-point inherits the gateway"
        );
        assert_eq!(d.config["X-Imap"], "imap.eu.acme.com");
    }

    #[test]
    fn user_layer_inherits_org_defaults_untouched() {
        // A user layer may not *set* defaults, but it must still *inherit* them
        // — otherwise a user's own curation of an org template would silently
        // drop the org's gateway.
        let base = base_with_pinnable_param("X-Imap");
        let org = Delta {
            instance_defaults: Some(defaults(
                Some("https://mail.overfolder-dev.com"),
                &[("X-Imap", "imap.acme.com")],
            )),
            ..Default::default()
        };
        let (org_def, _) = apply_delta(&org, &base);

        let user = Delta {
            denylist: vec!["a".into()],
            ..Default::default()
        };
        assert!(
            validate_delta(&user, &org_def, true).valid,
            "a user layer with no instance_defaults of its own is legal"
        );
        let (user_def, _) = apply_delta(&user, &org_def);
        assert_eq!(
            user_def.instance_defaults.unwrap(),
            org_def.instance_defaults.unwrap()
        );
    }

    #[test]
    fn empty_defaults_still_rejected_on_a_user_layer() {
        let base = base_with(&[("a", Risk::Read)]);
        let delta = Delta {
            instance_defaults: Some(InstanceDefaults::default()),
            ..Default::default()
        };
        assert!(
            !validate_delta(&delta, &base, true).valid,
            "presence, not content, gates the tier — otherwise the API persists \
             a field it claims to reject"
        );
    }

    #[test]
    fn misspelled_defaults_key_is_a_hard_error() {
        // Without `deny_unknown_fields` this deserializes to an empty struct and
        // the org's traffic silently stays on the shipped default.
        let err = serde_json::from_value::<Delta>(serde_json::json!({
            "instance_defaults": { "URL": "https://gw.acme.com" }
        }))
        .unwrap_err();
        assert!(err.to_string().contains("URL"), "got: {err}");
    }

    #[test]
    fn config_defaults_are_trimmed_at_fold_time() {
        // Symmetric with the instance write path, which trims on write — the
        // same value must inject byte-identically from either source.
        let base = base_with_pinnable_param("X-Imap");
        let delta = Delta {
            instance_defaults: Some(defaults(None, &[("X-Imap", "  imap.acme.com  ")])),
            ..Default::default()
        };
        let (def, _) = apply_delta(&delta, &base);
        assert_eq!(
            def.instance_defaults.unwrap().config["X-Imap"],
            "imap.acme.com"
        );
    }

    #[test]
    fn defaults_inherit_when_child_delta_has_none() {
        let base = base_with(&[("a", Risk::Read)]);
        let org = Delta {
            instance_defaults: Some(defaults(Some("https://gw.acme.com"), &[])),
            ..Default::default()
        };
        let (org_def, _) = apply_delta(&org, &base);
        let (child_def, _) = apply_delta(&Delta::default(), &org_def);
        assert_eq!(
            child_def.instance_defaults.unwrap().url.unwrap(),
            "https://gw.acme.com"
        );
    }

    #[test]
    fn defaults_rejected_for_user_tier() {
        let base = base_with(&[("a", Risk::Read)]);
        let delta = Delta {
            instance_defaults: Some(defaults(Some("https://evil.example.com"), &[])),
            ..Default::default()
        };
        let report = validate_delta(&delta, &base, true);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.code == "instance_defaults_user_tier")
        );
        assert!(
            validate_delta(&delta, &base, false).valid,
            "the same delta is legal on an org layer"
        );
    }

    #[test]
    fn defaults_url_must_be_an_absolute_origin() {
        let base = base_with(&[("a", Risk::Read)]);
        for bad in [
            "ghe.acme.internal",
            "ftp://ghe.acme.internal",
            "https://",
            "https://gw.acme.com/x?a=1",
            "https://gw.acme.com#f",
        ] {
            let delta = Delta {
                instance_defaults: Some(defaults(Some(bad), &[])),
                ..Default::default()
            };
            let report = validate_delta(&delta, &base, false);
            assert!(
                report
                    .errors
                    .iter()
                    .any(|e| e.code == "instance_defaults_invalid_url"),
                "'{bad}' should be rejected"
            );
        }
    }

    #[test]
    fn undeclared_config_default_is_rejected() {
        let base = base_with_pinnable_param("X-Imap");
        let delta = Delta {
            instance_defaults: Some(defaults(None, &[("X-Nope", "v")])),
            ..Default::default()
        };
        let report = validate_delta(&delta, &base, false);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.code == "unknown_instance_config")
        );

        let ok = Delta {
            instance_defaults: Some(defaults(None, &[("X-Imap", "imap.acme.com")])),
            ..Default::default()
        };
        assert!(validate_delta(&ok, &base, false).valid);
    }

    #[test]
    fn config_default_may_target_this_deltas_own_extension_action() {
        // Regression guard on fold order: config keys validate against the
        // *folded* surface, so a param declared by an action this same delta
        // adds is defaultable. Validating against the bare base would 400.
        let base = base_with(&[("a", Risk::Read)]);
        let delta = Delta {
            extensions: Extensions {
                actions: HashMap::from([(
                    "regional".to_string(),
                    ExtensionAction {
                        method: "GET".into(),
                        path: "/regional".into(),
                        operation: serde_json::json!({
                            "description": "Regional lookup",
                            "x-overslash-risk": "read",
                            "parameters": [{
                                "name": "X-Region",
                                "in": "header",
                                "schema": { "type": "string" },
                                "x-overslash-instance-config": true
                            }]
                        }),
                    },
                )]),
                hosts: vec![],
            },
            instance_defaults: Some(defaults(None, &[("X-Region", "eu-west-1")])),
            ..Default::default()
        };
        let report = validate_delta(&delta, &base, false);
        assert!(
            report.valid,
            "expected valid, got errors: {:?}",
            report.errors
        );
    }
}
