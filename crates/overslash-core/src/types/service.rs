use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Risk level of a service action: read, write, or delete.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    #[default]
    Read,
    Write,
    Delete,
}

impl Risk {
    /// Returns `true` for write and delete operations.
    pub fn is_mutating(self) -> bool {
        !matches!(self, Risk::Read)
    }

    /// Monotonic severity ordering: `read < write < delete`. Used by the
    /// layered-template fold to clamp risk **upward only** (a mask may add
    /// approvals, never remove them).
    pub fn severity(self) -> u8 {
        match self {
            Risk::Read => 0,
            Risk::Write => 1,
            Risk::Delete => 2,
        }
    }

    /// Infer risk from an HTTP method.
    pub fn from_http_method(method: &str) -> Risk {
        match method.to_uppercase().as_str() {
            "GET" | "HEAD" | "OPTIONS" => Risk::Read,
            "DELETE" => Risk::Delete,
            _ => Risk::Write,
        }
    }
}

impl fmt::Display for Risk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Risk::Read => write!(f, "read"),
            Risk::Write => write!(f, "write"),
            Risk::Delete => write!(f, "delete"),
        }
    }
}

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
    #[serde(default)]
    pub auth: Vec<ServiceAuth>,
    #[serde(default)]
    pub actions: HashMap<String, ServiceAction>,
    /// Execution runtime. Defaults to `Http` for backwards compat with every
    /// existing template. MCP templates set this to `Mcp` and populate `mcp`.
    #[serde(default, skip_serializing_if = "Runtime::is_default")]
    pub runtime: Runtime,
    /// MCP-specific config. Present iff `runtime == Mcp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpSpec>,
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

/// Auth method supported by a service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServiceAuth {
    #[serde(rename = "oauth")]
    OAuth {
        provider: String,
        /// Superset of OAuth scopes this service may request. The caller
        /// (dashboard/API) picks which subset to actually request at connect
        /// time; the provider's granted scopes land on `connections.scopes`.
        #[serde(default)]
        scopes: Vec<String>,
        token_injection: TokenInjection,
    },
    #[serde(rename = "api_key")]
    ApiKey {
        /// The securitySchemes key this was compiled from (`gateway`,
        /// `mailbox`, …). Identifies the credential slot: it keys the
        /// instance's per-scheme `credentials` bindings and labels the
        /// credential in the dashboard, so a template with several apiKey
        /// schemes doesn't present them as one anonymous field.
        #[serde(default)]
        scheme: String,
        /// Short human-readable display name for the credential slot, from
        /// `x-overslash-label` (alias `label`) — e.g. "Overfwd API Token".
        /// The dashboard uses it as the row label; absent falls back to the
        /// scheme key.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        label: String,
        /// The standard OpenAPI securityScheme `description`, verbatim.
        /// Help text for the credential's row in the dashboard.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        description: String,
        default_secret_name: String,
        injection: TokenInjection,
        /// Fallback policy when the instance has no explicit per-scheme
        /// binding in `credentials[scheme]`. `Instance` (default): fall back
        /// to the instance's legacy scalar `secret_name`; unbound means the
        /// credential is missing. `Org`: fall back to the fixed
        /// `default_secret_name` in the org vault — a sensible org-wide
        /// default for a shared credential (e.g. an overfwd gateway key)
        /// that any instance may still override per deployment.
        #[serde(default)]
        secret_source: SecretSource,
        /// When true, this credential is injected only if its secret is
        /// configured; a missing secret is skipped rather than failing the
        /// request. Meaningful for an `Org`-source static credential the
        /// deployment may not need — e.g. an overfwd gateway key when the
        /// gateway runs with `OVERFWD_REQUIRE_API_KEY=false`. Default `false`:
        /// a missing required secret still surfaces as an error at send time.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        optional: bool,
    },
}

/// Which secret a compiled apiKey injection falls back to at execution time
/// when the instance has no explicit `credentials[scheme]` binding.
/// See [`ServiceAuth::ApiKey::secret_source`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretSource {
    /// The instance's legacy scalar `secret_name` (per-instance credential,
    /// no org-wide default name).
    #[default]
    Instance,
    /// The scheme's fixed `default_secret_name`, from the org vault.
    Org,
}

/// How to inject a token/key into the HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInjection {
    #[serde(rename = "as")]
    pub inject_as: String, // "header" or "query"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_param: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Transform applied to the secret value before the `prefix` (mirrors
    /// [`crate::types::SecretRef::encode`]). Carried from the security
    /// scheme's `x-overslash-encode` into the runtime `SecretRef`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encode: Option<crate::types::SecretEncoding>,
}

/// An action within a service (maps to an HTTP request template).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAction {
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub path: String,
    pub description: String,
    #[serde(default)]
    pub risk: Risk,
    /// Response type hint: "json" (default) or "binary" (for file downloads).
    /// When "binary", callers should use `prefer_stream: true` to avoid buffering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_type: Option<String>,
    #[serde(default)]
    pub params: HashMap<String, ActionParam>,
    /// Which parameter provides the `{arg}` segment in permission keys.
    /// Without `scope_param`, the arg defaults to `*`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_param: Option<String>,
    /// OAuth scopes this specific action needs. Checked against the
    /// connection's granted scopes at execution time (SPEC §9 "Per-action
    /// scopes"). Empty means no gating — fall back to the service-level
    /// scope set granted at connect time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_scopes: Vec<String>,
    /// Platform-runtime only. When set, overrides the action key used for
    /// permission key derivation, letting multiple actions share a single
    /// permission anchor. E.g. `list_templates` and `get_template` both
    /// set `permission: manage_templates_own` so one `overslash:manage_templates_own:*`
    /// grant covers both without granting the broad action-key wildcard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission: Option<String>,
    /// Labeled jq filters to extract human-readable fields from the resolved
    /// request (method / url / params / body / resolved) at approval-create
    /// and audit write time. See SPEC §N "Detail disclosure".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disclose: Vec<DisclosureField>,
    /// Dotted paths into the resolved request to replace with `"[REDACTED]"`
    /// in the persisted raw payload (`approvals.action_detail` + audit
    /// `detail.request`). Does not affect the disclose jq input.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redact: Vec<String>,
    /// MCP tool name (present iff the owning service's `runtime == Mcp`).
    /// The map key in `ServiceDefinition.actions` equals this tool name for
    /// MCP actions, but we store it explicitly so renames are cheap later.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_tool: Option<String>,
    /// MCP 2025-06-18 `outputSchema` — carried so agents can consume typed
    /// structured results without a second round-trip to describe the tool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,
    /// Admin-controlled visibility toggle. When `true`, the action is hidden
    /// from the agent-visible action list and `/v1/actions/execute` rejects
    /// invocation. Applies equally to Http and Mcp actions, though v1 only
    /// surfaces it in the MCP discovery-override flow.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
}

/// One entry in `ServiceAction::disclose`. The `filter` is a jq expression
/// applied to a `{method, url, params, body, resolved}` projection of the
/// resolved request (`resolved` carries the display names produced by
/// `resolve` declarations, so filters can prefer
/// `.resolved.fileId // .params.fileId`). `max_chars` optionally clamps long
/// string outputs (e.g. email bodies); results longer than the clamp are
/// still carried but marked `truncated` for the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosureField {
    pub label: String,
    pub filter: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_chars: Option<usize>,
    /// When true, this field is rendered as a prominent "hero" value on the
    /// approval detail screen rather than collapsed into the parameter table.
    /// Multiple fields may be primary — they render in declaration order.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub primary: bool,
}

/// Describes how to resolve an opaque ID into a human-readable display name.
///
/// The resolver makes a GET request to the same service host (reusing existing auth)
/// and extracts a value from the JSON response using a dot-path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamResolver {
    /// GET endpoint path with `{param}` placeholders, e.g. `/calendar/v3/calendars/{calendarId}`.
    pub get: String,
    /// Dot-separated path into the JSON response, e.g. `summary` or `owner.login`.
    pub pick: String,
}

/// Where a parameter is sent on the wire, mirroring the OpenAPI `in:` field.
///
/// Routing consults `Query` and `Header`: on non-GET methods, query-located
/// params go to the URL query string, header-located params become request
/// headers, and everything else becomes the JSON body. A `Header` param with a
/// `default` (e.g. `Notion-Version: 2022-06-28`) is how a template pins a
/// constant version/accept header on every call — `apply_defaults` fills it in
/// when the caller omits it. `Path` is informational — path interpolation
/// matches `{name}` placeholders in the path template and never reads this field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParamLocation {
    #[default]
    Body,
    Query,
    Path,
    Header,
}

impl ParamLocation {
    pub fn is_default(&self) -> bool {
        matches!(self, ParamLocation::Body)
    }
}

/// A parameter for a service action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionParam {
    #[serde(rename = "type")]
    pub param_type: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "enum", skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
    /// Optional resolver to convert an opaque ID into a human-readable name for descriptions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolve: Option<ParamResolver>,
    /// Alternate caller-facing names for this parameter. A call that supplies
    /// one of these keys instead of the canonical name has it rewritten to the
    /// canonical name before validation (see
    /// `crate::openapi::validate_input::apply_aliases`), so a well-known
    /// synonym (`to` for `recipient`, `body` for `text`) is accepted rather
    /// than rejected as an unknown argument. Authored via the
    /// `x-overslash-aliases` (or unprefixed `aliases`) parameter extension.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    /// Where this parameter is sent (body/query/path). Omitted when `body` (the default).
    #[serde(default, skip_serializing_if = "ParamLocation::is_default")]
    pub location: ParamLocation,
    /// Whether an org can pin this parameter per service instance.
    ///
    /// Some parameters are properties of a *deployment*, not of a call: which
    /// IMAP host a mailbox gateway should dial, which region an API lives in.
    /// The caller has no business supplying them on every request and an agent
    /// has no way to know them. Marking the param `x-overslash-instance-config`
    /// (or unprefixed `instance-config`) lets the dashboard render a field on
    /// the service-instance form and store the value in
    /// `service_instances.config`, which is then merged *under* the caller's
    /// args at execution time — an explicit arg still wins.
    ///
    /// Only non-secret values belong here; it is stored as plain jsonb. A
    /// secret goes in the vault and is bound via `credentials`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub instance_config: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_serde_roundtrip() {
        assert_eq!(serde_json::to_string(&Risk::Read).unwrap(), r#""read""#);
        assert_eq!(serde_json::to_string(&Risk::Write).unwrap(), r#""write""#);
        assert_eq!(serde_json::to_string(&Risk::Delete).unwrap(), r#""delete""#);

        assert_eq!(
            serde_json::from_str::<Risk>(r#""read""#).unwrap(),
            Risk::Read
        );
        assert_eq!(
            serde_json::from_str::<Risk>(r#""write""#).unwrap(),
            Risk::Write
        );
        assert_eq!(
            serde_json::from_str::<Risk>(r#""delete""#).unwrap(),
            Risk::Delete
        );
    }

    #[test]
    fn risk_default_is_read() {
        assert_eq!(Risk::default(), Risk::Read);
    }

    #[test]
    fn risk_is_mutating() {
        assert!(!Risk::Read.is_mutating());
        assert!(Risk::Write.is_mutating());
        assert!(Risk::Delete.is_mutating());
    }

    #[test]
    fn risk_from_http_method() {
        assert_eq!(Risk::from_http_method("GET"), Risk::Read);
        assert_eq!(Risk::from_http_method("HEAD"), Risk::Read);
        assert_eq!(Risk::from_http_method("OPTIONS"), Risk::Read);
        assert_eq!(Risk::from_http_method("POST"), Risk::Write);
        assert_eq!(Risk::from_http_method("PUT"), Risk::Write);
        assert_eq!(Risk::from_http_method("PATCH"), Risk::Write);
        assert_eq!(Risk::from_http_method("DELETE"), Risk::Delete);
        // case-insensitive
        assert_eq!(Risk::from_http_method("get"), Risk::Read);
        assert_eq!(Risk::from_http_method("delete"), Risk::Delete);
    }

    #[test]
    fn risk_display() {
        assert_eq!(Risk::Read.to_string(), "read");
        assert_eq!(Risk::Write.to_string(), "write");
        assert_eq!(Risk::Delete.to_string(), "delete");
    }

    // ── ParamLocation ─────────────────────────────────────────────────

    #[test]
    fn param_location_serde_roundtrip() {
        assert_eq!(
            serde_json::to_string(&ParamLocation::Body).unwrap(),
            r#""body""#
        );
        assert_eq!(
            serde_json::to_string(&ParamLocation::Query).unwrap(),
            r#""query""#
        );
        assert_eq!(
            serde_json::to_string(&ParamLocation::Path).unwrap(),
            r#""path""#
        );
        assert_eq!(
            serde_json::to_string(&ParamLocation::Header).unwrap(),
            r#""header""#
        );

        assert_eq!(
            serde_json::from_str::<ParamLocation>(r#""body""#).unwrap(),
            ParamLocation::Body
        );
        assert_eq!(
            serde_json::from_str::<ParamLocation>(r#""query""#).unwrap(),
            ParamLocation::Query
        );
        assert_eq!(
            serde_json::from_str::<ParamLocation>(r#""path""#).unwrap(),
            ParamLocation::Path
        );
        assert_eq!(
            serde_json::from_str::<ParamLocation>(r#""header""#).unwrap(),
            ParamLocation::Header
        );
    }

    #[test]
    fn param_location_default_is_body() {
        assert_eq!(ParamLocation::default(), ParamLocation::Body);
        assert!(ParamLocation::Body.is_default());
        assert!(!ParamLocation::Query.is_default());
        assert!(!ParamLocation::Path.is_default());
        assert!(!ParamLocation::Header.is_default());
    }

    #[test]
    fn action_param_omits_default_location() {
        let p = ActionParam {
            param_type: "string".into(),
            required: false,
            description: String::new(),
            enum_values: None,
            default: None,
            resolve: None,
            aliases: Vec::new(),
            location: ParamLocation::Body,
            instance_config: false,
        };
        let json = serde_json::to_value(&p).unwrap();
        assert!(json.get("location").is_none());
        // Same omit-when-default contract as `location`: a param nobody pinned
        // must not grow an `instance_config: false` key in every serialized
        // template.
        assert!(json.get("instance_config").is_none());

        let q = ActionParam {
            location: ParamLocation::Query,
            ..p
        };
        let json = serde_json::to_value(&q).unwrap();
        assert_eq!(json["location"], "query");

        // Older serialized params without a `location` key deserialize as body.
        let legacy: ActionParam = serde_json::from_str(r#"{"type": "string"}"#).unwrap();
        assert_eq!(legacy.location, ParamLocation::Body);
    }

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
            key: "slack".into(),
            display_name: "Slack".into(),
            description: None,
            hosts: vec!["slack.com".into()],
            category: None,
            hidden: false,
            auth: vec![],
            actions: HashMap::new(),
            runtime: Runtime::Http,
            mcp: None,
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
                method: "".into(),
                path: "".into(),
                description: "Search issues".into(),
                risk: Risk::Read,
                response_type: None,
                params: HashMap::new(),
                scope_param: Some("team".into()),
                required_scopes: vec![],
                permission: None,
                disclose: vec![],
                redact: vec![],
                mcp_tool: Some("search_issues".into()),
                output_schema: Some(serde_json::json!({ "type": "object" })),
                disabled: false,
            },
        );
        let svc = ServiceDefinition {
            key: "linear_mcp".into(),
            display_name: "Linear".into(),
            description: None,
            hosts: vec![],
            category: Some("Development".into()),
            hidden: false,
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
            method: "GET".into(),
            path: "/foo".into(),
            description: "x".into(),
            risk: Risk::Read,
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
        };
        let j = serde_json::to_value(&a).unwrap();
        assert!(j.get("disabled").is_none());
        assert!(j.get("mcp_tool").is_none());
        assert!(j.get("output_schema").is_none());
    }
}
