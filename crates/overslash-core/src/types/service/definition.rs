use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::service_icon::ServiceIcon;

use super::action::ServiceAction;
use super::auth::{ConfigVar, SecretSlot, ServiceAuth};

/// Execution runtime for a service definition.
///
/// - `Http` (default): actions are OpenAPI operations invoked by the HTTP executor.
/// - `Mcp`: actions are tools on an external MCP server (Streamable HTTP, JSON-RPC 2.0).
/// - `Platform`: actions are dispatched in-process to registered Rust handlers.
///   Used by the `overslash` meta-service so agents can manage templates, secrets,
///   etc. through the same Mode-C permission/approval graph as external services.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Runtime {
    #[default]
    Http,
    Mcp,
    Platform,
}

impl Runtime {
    pub fn is_default(&self) -> bool {
        matches!(self, Runtime::Http)
    }
}

fn default_true() -> bool {
    true
}

/// A service definition — describes an external API, its auth methods, and available actions.
/// Also referred to as a "service template" (the blueprint from which service instances are created).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDefinition {
    pub key: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Catalog visibility (`x-overslash-hidden`). Hidden templates are
    /// omitted from agent-facing list/search surfaces (MCP discovery,
    /// `/v1/search`, embeddings) but stay reachable by key and instantiable;
    /// dashboard surfaces show them flagged.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hidden: bool,
    /// Catalog icon (`info.x-overslash-icon`). Usually implicit: a template
    /// whose key matches a shipped asset gets `builtin:<key>` without
    /// declaring anything. Resolved to an absolute URL at the API boundary —
    /// never rendered from this value directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<ServiceIcon>,
    #[serde(default)]
    pub auth: Vec<ServiceAuth>,
    /// Credential slots this template needs, declared once
    /// (`components.x-overslash-secrets`) and referenced by the auth entries'
    /// templates. One slot is one vault secret the operator binds; a slot may
    /// feed several injections.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<SecretSlot>,
    /// Non-secret per-instance inputs a credential template may read alongside
    /// its secrets (`components.x-overslash-config`). Declared here, stored in
    /// the instance's `config` jsonb next to the instance-config *param* pins,
    /// and never vaulted — see [`ConfigVar`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub config: Vec<ConfigVar>,
    #[serde(default)]
    pub actions: HashMap<String, ServiceAction>,
    /// `info.x-overslash-default_timeout_ms`: the timeout every action of this
    /// service inherits unless it declares its own. The one-line answer to
    /// "this whole upstream is slow" — a per-action value
    /// ([`ServiceAction::timeout_ms`]) still wins, and the org and deployment
    /// maxima still clamp the result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_timeout_ms: Option<u64>,
    /// Execution runtime. Defaults to `Http` for backwards compat with every
    /// existing template. MCP templates set this to `Mcp` and populate `mcp`.
    #[serde(default, skip_serializing_if = "Runtime::is_default")]
    pub runtime: Runtime,
    /// MCP-specific config. Present iff `runtime == Mcp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpSpec>,
    /// Defaults an org layer supplies for the per-instance override surface
    /// (endpoint URL + `instance_config` pins). Only ever set by the fold —
    /// a shipped template expresses its defaults through `servers:` and param
    /// `default:` instead, so the compile path always leaves this `None`.
    ///
    /// An instance that sets the corresponding field still wins; see
    /// [`crate::service_layer::InstanceDefaults`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_defaults: Option<crate::service_layer::InstanceDefaults>,
}

/// MCP external-server configuration. Lives inside a `ServiceDefinition` when
/// `runtime == Mcp`. All per-tool shape lives on `ServiceAction` (one action
/// per tool) — this struct only carries transport + auth + discovery config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpSpec {
    /// Streamable HTTP endpoint (MCP 2025-06-18). JSON-RPC 2.0 POST target.
    /// `None` means the template has no default URL; the service instance must
    /// supply one via its `url` field at creation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// How to authenticate to the MCP server.
    pub auth: McpAuth,
    /// When `true` (default), saving the template triggers `tools/list` and
    /// caches the result; the compile step merges discovered tools with any
    /// authored `tools:` overrides. When `false`, the tool set is pinned to
    /// what the YAML declares and every tool must carry `input_schema`.
    #[serde(default = "default_true")]
    pub autodiscover: bool,
}

/// How Overslash authenticates outbound to an MCP server.
///
/// The tagged-enum shape is forward-compatible: adding future variants
/// (`header`, `headers`, `oauth`) is a pure addition that does not break
/// existing serialized templates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum McpAuth {
    /// No auth — public or internal MCP servers.
    None,
    /// `Authorization: Bearer <secret>`. The secret is resolved at call time
    /// from the Overslash vault by name (org or user scope, versioned).
    /// `secret_name: None` means the template has no default; the service
    /// instance must supply one via its `secret_name` field at creation time.
    Bearer {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secret_name: Option<String>,
    },
    /// `Authorization: Bearer <token>`, where the token is a live OAuth access
    /// token resolved at call time from the caller's connection for `provider`
    /// (refreshed via the standard grant, using the org/BYOC OAuth client).
    /// Mirrors HTTP-runtime `ServiceAuth::OAuth` but for MCP servers that sit
    /// behind OAuth (e.g. HubSpot's remote MCP). `scopes` is the superset the
    /// service may request at connect time.
    #[serde(rename = "oauth")]
    OAuth {
        provider: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        scopes: Vec<String>,
    },
}

impl ServiceDefinition {
    /// The config key whose per-instance value names the account this instance
    /// speaks for, if the template declares one (`identity: true` on a
    /// `components.x-overslash-config` entry).
    ///
    /// Discovery reads the instance's `config` at this key and surfaces it as
    /// `account_email`, which is what lets several secret-based instances of
    /// one template be told apart. Deterministic when a template mistakenly
    /// marks more than one: keys are sorted at parse time, so the first wins.
    pub fn identity_config_key(&self) -> Option<&str> {
        self.config
            .iter()
            .find(|c| c.identity)
            .map(|c| c.key.as_str())
    }

    /// The credential slots one secret-backed auth entry reads, paired with
    /// their declarations — the single place the implicit-slot rule lives.
    ///
    /// A slot declared under `components.x-overslash-secrets` uses that
    /// declaration. A slot with no declaration is the scheme's implicit
    /// self-named slot and inherits the scheme's own label, description,
    /// default secret name, source and optionality. That is how a
    /// single-secret template declares no secrets block at all — and why a
    /// definition rebuilt without one (parts-based CRUD) still resolves.
    ///
    /// Returns empty for OAuth entries, which carry no vault secret.
    pub fn slots_for(&self, auth: &ServiceAuth) -> Vec<SecretSlot> {
        let ServiceAuth::Secret {
            scheme,
            label,
            description,
            default_secret_name,
            slots,
            secret_source,
            optional,
            ..
        } = auth
        else {
            return Vec::new();
        };

        // A definition from before credential slots existed carries no
        // `slots`; its one secret is the scheme's own.
        let keys: Vec<&String> = if slots.is_empty() {
            vec![scheme]
        } else {
            slots.iter().collect()
        };

        keys.into_iter()
            .map(|key| match self.secrets.iter().find(|s| &s.key == key) {
                Some(declared) => declared.clone(),
                None => SecretSlot {
                    key: key.clone(),
                    label: label.clone(),
                    description: description.clone(),
                    default_secret_name: default_secret_name.clone(),
                    source: *secret_source,
                    optional: *optional,
                },
            })
            .collect()
    }

    /// The non-secret config vars one auth entry's template reads, paired with
    /// their declarations.
    ///
    /// Unlike [`Self::slots_for`] there is no implicit-var rule: a config key
    /// only exists because `components.x-overslash-config` declares it, which
    /// is what extraction checks. A key with no declaration here can only come
    /// from stored data that has drifted from its template, and is dropped
    /// rather than invented — resolution then treats the scheme as unresolved
    /// instead of rendering a credential from a value nobody declared.
    pub fn config_for(&self, auth: &ServiceAuth) -> Vec<ConfigVar> {
        let ServiceAuth::Secret { config_keys, .. } = auth else {
            return Vec::new();
        };
        config_keys
            .iter()
            .filter_map(|key| self.config.iter().find(|c| &c.key == key).cloned())
            .collect()
    }

    /// Every credential slot the template needs, deduped, in `auth` order.
    /// The set the dashboard renders and an instance binds.
    pub fn all_slots(&self) -> Vec<SecretSlot> {
        let mut out: Vec<SecretSlot> = Vec::new();
        for auth in &self.auth {
            for slot in self.slots_for(auth) {
                if !out.iter().any(|s| s.key == slot.key) {
                    out.push(slot);
                }
            }
        }
        out
    }
}

/// Alias: a service template is the same as a service definition.
pub type ServiceTemplate = ServiceDefinition;

/// Which tier a template belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TemplateTier {
    Global,
    Org,
    User,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Risk;

    // ── Runtime types ─────────────────────────────────────────────────

    #[test]
    fn runtime_default_is_http() {
        assert_eq!(Runtime::default(), Runtime::Http);
        assert!(Runtime::Http.is_default());
        assert!(!Runtime::Mcp.is_default());
        assert!(!Runtime::Platform.is_default());
    }

    #[test]
    fn runtime_serde_roundtrip() {
        assert_eq!(serde_json::to_string(&Runtime::Http).unwrap(), r#""http""#);
        assert_eq!(serde_json::to_string(&Runtime::Mcp).unwrap(), r#""mcp""#);
        assert_eq!(
            serde_json::to_string(&Runtime::Platform).unwrap(),
            r#""platform""#
        );
        assert_eq!(
            serde_json::from_str::<Runtime>(r#""http""#).unwrap(),
            Runtime::Http
        );
        assert_eq!(
            serde_json::from_str::<Runtime>(r#""mcp""#).unwrap(),
            Runtime::Mcp
        );
        assert_eq!(
            serde_json::from_str::<Runtime>(r#""platform""#).unwrap(),
            Runtime::Platform
        );
    }

    // ── MCP types ────────────────────────────────────────────────────

    #[test]
    fn mcp_auth_none_serde() {
        let j = serde_json::to_value(McpAuth::None).unwrap();
        assert_eq!(j, serde_json::json!({ "kind": "none" }));
        let back: McpAuth = serde_json::from_value(j).unwrap();
        assert_eq!(back, McpAuth::None);
    }

    #[test]
    fn mcp_auth_bearer_serde() {
        let a = McpAuth::Bearer {
            secret_name: Some("linear_token".into()),
        };
        let j = serde_json::to_value(&a).unwrap();
        assert_eq!(
            j,
            serde_json::json!({ "kind": "bearer", "secret_name": "linear_token" })
        );
        let back: McpAuth = serde_json::from_value(j).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn mcp_auth_bearer_without_secret_name_serde() {
        let a = McpAuth::Bearer { secret_name: None };
        let j = serde_json::to_value(&a).unwrap();
        assert_eq!(j, serde_json::json!({ "kind": "bearer" }));
        let back: McpAuth = serde_json::from_value(j).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn mcp_auth_oauth_serde() {
        let a = McpAuth::OAuth {
            provider: "hubspot".into(),
            scopes: vec!["crm.objects.contacts.read".into()],
        };
        let j = serde_json::to_value(&a).unwrap();
        assert_eq!(
            j,
            serde_json::json!({
                "kind": "oauth",
                "provider": "hubspot",
                "scopes": ["crm.objects.contacts.read"]
            })
        );
        let back: McpAuth = serde_json::from_value(j).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn mcp_auth_oauth_without_scopes_serde() {
        let a = McpAuth::OAuth {
            provider: "hubspot".into(),
            scopes: vec![],
        };
        let j = serde_json::to_value(&a).unwrap();
        // Empty scopes are elided; still round-trips.
        assert_eq!(
            j,
            serde_json::json!({ "kind": "oauth", "provider": "hubspot" })
        );
        let back: McpAuth = serde_json::from_value(j).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn mcp_auth_unknown_kind_rejected() {
        // Forward-compat spec: new variants in the enum are additions; *unknown*
        // variants must fail deserialization cleanly so callers know to upgrade.
        let v = serde_json::json!({ "kind": "quantum", "secret_name": "x" });
        assert!(serde_json::from_value::<McpAuth>(v).is_err());
    }

    #[test]
    fn mcp_spec_autodiscover_defaults_true() {
        // Omitting autodiscover should default to true.
        let v = serde_json::json!({
            "url": "https://mcp.example.com/mcp",
            "auth": { "kind": "none" }
        });
        let spec: McpSpec = serde_json::from_value(v).unwrap();
        assert!(spec.autodiscover);
        assert_eq!(spec.url.as_deref(), Some("https://mcp.example.com/mcp"));
        assert_eq!(spec.auth, McpAuth::None);
    }

    #[test]
    fn service_definition_http_defaults_keep_mcp_absent() {
        // Existing Http templates must serialize without runtime/mcp keys.
        let svc = ServiceDefinition {
            default_timeout_ms: None,
            secrets: Vec::new(),
            config: Vec::new(),
            key: "slack".into(),
            display_name: "Slack".into(),
            description: None,
            hosts: vec!["slack.com".into()],
            category: None,
            hidden: false,
            icon: None,
            auth: vec![],
            actions: HashMap::new(),
            runtime: Runtime::Http,
            mcp: None,
            instance_defaults: None,
        };
        let j = serde_json::to_value(&svc).unwrap();
        assert!(
            j.get("runtime").is_none(),
            "runtime must be elided when Http"
        );
        assert!(j.get("mcp").is_none(), "mcp must be elided when absent");
    }

    #[test]
    fn service_definition_mcp_roundtrip() {
        let mut actions = HashMap::new();
        actions.insert(
            "search_issues".into(),
            ServiceAction {
                wait_mode: None,
                handoff_after_ms: None,
                timeout_ms: None,
                method: "".into(),
                path: "".into(),
                description: "Search issues".into(),
                summary: None,
                risk: Risk::Read.into(),
                response_type: None,
                params: HashMap::new(),
                scope_param: "team".into(),
                required_scopes: vec![],
                permission: None,
                disclose: vec![],
                redact: vec![],
                mcp_tool: Some("search_issues".into()),
                output_schema: Some(serde_json::json!({ "type": "object" })),
                disabled: false,
                request_body: None,
                download: None,
            },
        );
        let svc = ServiceDefinition {
            default_timeout_ms: None,
            secrets: Vec::new(),
            config: Vec::new(),
            key: "linear_mcp".into(),
            display_name: "Linear".into(),
            description: None,
            hosts: vec![],
            category: Some("Development".into()),
            hidden: false,
            icon: None,
            auth: vec![],
            actions,
            runtime: Runtime::Mcp,
            mcp: Some(McpSpec {
                url: Some("https://mcp.linear.app/mcp".into()),
                auth: McpAuth::Bearer {
                    secret_name: Some("linear_api_token".into()),
                },
                autodiscover: true,
            }),
            instance_defaults: None,
        };
        let j = serde_json::to_value(&svc).unwrap();
        assert_eq!(j["runtime"], "mcp");
        assert_eq!(j["mcp"]["url"], "https://mcp.linear.app/mcp");
        assert_eq!(j["mcp"]["auth"]["kind"], "bearer");
        let back: ServiceDefinition = serde_json::from_value(j).unwrap();
        assert_eq!(back.runtime, Runtime::Mcp);
        let mcp = back.mcp.expect("mcp present");
        assert!(mcp.autodiscover);
        assert_eq!(
            mcp.auth,
            McpAuth::Bearer {
                secret_name: Some("linear_api_token".into())
            }
        );
        let a = &back.actions["search_issues"];
        assert_eq!(a.mcp_tool.as_deref(), Some("search_issues"));
        assert!(!a.disabled);
        assert!(a.output_schema.is_some());
    }

    #[test]
    fn service_action_disabled_elided_when_false() {
        let a = ServiceAction {
            wait_mode: None,
            handoff_after_ms: None,
            timeout_ms: None,
            method: "GET".into(),
            path: "/foo".into(),
            description: "x".into(),
            summary: None,
            risk: Risk::Read.into(),
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
            download: None,
        };
        let j = serde_json::to_value(&a).unwrap();
        assert!(j.get("disabled").is_none());
        assert!(j.get("mcp_tool").is_none());
        assert!(j.get("output_schema").is_none());
    }
}
