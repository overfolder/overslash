//! The stored shape of a derived layer: [`Delta`] and its parts.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::instance_config::ConfigMap;
use crate::types::{DisclosureField, Risk};

use super::normalize_default_url;

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
    /// Relabel the action's agent-facing description.
    ///
    /// Deliberately does not touch `ServiceAction::summary`: an org rewording
    /// what the agent reads should not silently rewrite the approval title a
    /// human has learned to recognise. A layer that wants both re-authors the
    /// action through `Extensions.actions` instead.
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
    pub(super) fn merge_over(&self, base: Option<&InstanceDefaults>) -> InstanceDefaults {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
