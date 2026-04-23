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
    #[serde(default)]
    pub auth: Vec<ServiceAuth>,
    #[serde(default)]
    pub actions: HashMap<String, ServiceAction>,
    #[serde(default, skip_serializing_if = "Runtime::is_default")]
    pub runtime: Runtime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpSpec>,
}

/// Which runtime backs this service template.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Runtime {
    /// Tools are served over HTTP (`paths:` in the OpenAPI doc).
    #[default]
    Http,
    /// Tools are served by an MCP server process; see [`McpSpec`].
    Mcp,
}

impl Runtime {
    pub fn is_default(&self) -> bool {
        matches!(self, Runtime::Http)
    }
}

/// Describes how to launch and authenticate an MCP server backing a service template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpSpec {
    /// npm package name, e.g. `@modelcontextprotocol/server-github`.
    /// Ignored when `command` is set.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub package: String,
    /// npm semver range, e.g. `^1.0.0`. Ignored when `command` is set.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// Optional argv override for non-npm MCPs. When set, replaces the
    /// default `npx -y <package>@<version>` launch line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    /// Env vars the MCP subprocess expects, keyed by env var name. Each
    /// binding declares where the value comes from (secret, OAuth token, or
    /// literal). Resolved at execute time by the api and sent to the
    /// runtime, never baked into the template.
    #[serde(default)]
    pub env: HashMap<String, McpEnvBinding>,
    /// Per-subprocess resource quotas. When set, the runtime wraps the
    /// spawn in `prlimit` so the kernel enforces the caps. Unset fields
    /// fall back to the runtime's global defaults.
    #[serde(default, skip_serializing_if = "McpLimits::is_empty")]
    pub limits: McpLimits,
}

/// Resource quotas applied to a single MCP subprocess. All fields are
/// optional; the runtime fills in defaults for missing ones.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct McpLimits {
    /// Max resident+virtual memory, in megabytes (maps to `prlimit --as`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<u32>,
    /// Max CPU seconds consumed by the subprocess (maps to `prlimit --cpu`).
    /// Cumulative, not real-time. Useful against runaway loops.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_seconds: Option<u32>,
    /// Max open file descriptors (maps to `prlimit --nofile`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_files: Option<u32>,
    /// Max processes/threads the subprocess can spawn (maps to `prlimit --nproc`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processes: Option<u32>,
}

impl McpLimits {
    pub fn is_empty(&self) -> bool {
        self.memory_mb.is_none()
            && self.cpu_seconds.is_none()
            && self.open_files.is_none()
            && self.processes.is_none()
    }
}

/// Where an MCP env var's value comes from.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "from", rename_all = "snake_case")]
pub enum McpEnvBinding {
    /// Resolve to the current value of a named org secret. If
    /// `default_secret_name` is set and the service instance has no explicit
    /// override, that name is used; otherwise the key in the `env` map
    /// doubles as the secret name.
    Secret {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        default_secret_name: Option<String>,
    },
    /// Resolve to an OAuth access token for the given provider, refreshed
    /// automatically by the existing oauth engine.
    OauthToken { provider: String },
    /// A literal value baked into the template. Used for non-sensitive
    /// config (feature flags, locale, etc.) — never for secrets.
    Literal { value: String },
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
        default_secret_name: String,
        injection: TokenInjection,
    },
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
    /// MCP tool name to invoke (only set when the parent service's
    /// [`Runtime`] is [`Runtime::Mcp`]). For HTTP runtimes this is `None`
    /// and `method`/`path` carry the request template instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_tool: Option<String>,
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
}
