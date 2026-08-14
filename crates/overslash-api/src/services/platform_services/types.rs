//! Request and response types for the service-instance kernels.

use super::*;

// ── Request types ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
pub struct CreateServiceInput {
    pub template_key: String,
    pub name: Option<String>,
    pub connection_id: Option<Uuid>,
    /// Legacy scalar alias for the template's sole instance-source secret
    /// scheme (or the MCP bearer secret). Rejected when the template declares
    /// several instance-source schemes — bind those via `credentials`.
    pub secret_name: Option<String>,
    /// Per-scheme secret bindings: securityScheme key → secret NAME in the
    /// org vault. Keys must match the template's secret scheme keys.
    #[serde(default)]
    pub credentials: Option<CredentialsMap>,
    /// Per-instance non-secret param values: param name → value. Keys must
    /// name a template param marked `x-overslash-instance-config`.
    #[serde(default)]
    pub config: Option<ConfigMap>,
    pub url: Option<String>,
    #[serde(default = "default_status")]
    pub status: String,
    pub user_level: Option<bool>,
    /// Group grants to attach at creation time. Required (non-empty) when the
    /// instance is org-level (`user_level: false`): an org-level instance with
    /// no grant is unreachable by anyone, since the group ceiling is the only
    /// path to a service nobody owns. On the user-level path these are
    /// optional extras — the Myself auto-grant already covers the owner.
    #[serde(default)]
    pub groups: Vec<CreateServiceGroupGrant>,
    #[serde(default)]
    pub on_behalf_of: Option<Uuid>,
    /// Suppress the default auto-connect behavior for OAuth-backed
    /// templates. With this `true` the kernel creates the instance with
    /// `connection_id = NULL` and never initiates an OAuth flow — the
    /// caller is expected to pin a connection later via `PUT
    /// /v1/services/{id}/manage`. Ignored when `connection_id` is already
    /// pinned or when the template is not OAuth-backed.
    #[serde(default)]
    pub skip_connect: Option<bool>,
    /// When `false`, this instance must never fall back to the identity's
    /// default connection for the provider at execution time — it requires an
    /// explicit `connection_id`. Defaults to `true` (legacy fallback). White-
    /// label callers that mint a dedicated connection per service set this
    /// `false` and pin the connection via `pin_service_ids` on connection
    /// creation. See `service_instances.use_default_connection` (migration 090).
    #[serde(default)]
    pub use_default_connection: Option<bool>,
    /// Tenant-supplied URL the OAuth callback redirects back to once the
    /// dance finishes. Only consulted when the kernel auto-initiates a
    /// flow (OAuth template + no pinned connection + not opted out). See
    /// [`crate::services::platform_connections::CreateConnectionInput::return_url`]
    /// for the validation contract.
    #[serde(default)]
    pub connect_return_url: Option<String>,
}

/// One `groups[]` entry on [`CreateServiceInput`] — the create-time twin of
/// `AddGrantRequest` on `POST /v1/groups/{id}/grants`.
#[derive(Debug, Deserialize, Clone)]
pub struct CreateServiceGroupGrant {
    pub group_id: Uuid,
    /// `read` | `write` | `admin`. Defaults to `write`: `admin` is what the
    /// Myself auto-grant hands a single owner, and is too broad to hand a
    /// shared group silently.
    #[serde(default = "default_grant_access_level")]
    pub access_level: String,
    /// `none` | `read` | `write` | `admin`, bounded by `access_level` (D53).
    /// Defaults to `none`: a shared group gets no unattended calls unless the
    /// creator asks for them by name.
    #[serde(default)]
    pub auto_approve_level: Option<String>,
    /// DEPRECATED alias for `auto_approve_level`: `true` => `"read"`.
    /// Ignored when `auto_approve_level` is present.
    #[serde(default)]
    pub auto_approve_reads: Option<bool>,
}

fn default_status() -> String {
    "active".into()
}

fn default_grant_access_level() -> String {
    "write".into()
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdateServiceInput {
    pub name: Option<String>,
    pub connection_id: Option<Option<Uuid>>,
    /// Legacy scalar alias for the template's sole instance-source secret
    /// scheme (or the MCP bearer secret). Rejected when the template declares
    /// several instance-source schemes — bind those via `credentials`.
    pub secret_name: Option<Option<String>>,
    /// Per-scheme secret bindings: securityScheme key → secret NAME in the
    /// org vault. `Some` = whole-map replace (an empty map clears every
    /// binding); absent = leave unchanged. Keys must match the template's
    /// secret scheme keys.
    #[serde(default)]
    pub credentials: Option<CredentialsMap>,
    /// Per-instance non-secret param values. `Some` = whole-map replace (an
    /// empty map clears every value); absent = leave unchanged. Keys must name
    /// a template param marked `x-overslash-instance-config`.
    #[serde(default)]
    pub config: Option<ConfigMap>,
    pub url: Option<Option<String>>,
    /// `Some` = update the flag; `None` = leave unchanged.
    pub use_default_connection: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
pub struct GetServiceInput {
    pub name: String,
    #[serde(default)]
    pub include_inactive: bool,
}

// ── Response types ────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ServiceInstanceSummary {
    pub id: Uuid,
    pub name: String,
    pub template_source: String,
    pub template_key: String,
    pub status: String,
    pub is_system: bool,
    /// Absolute URL of the template's catalog icon. Instances deliberately
    /// have no icon of their own — an instance is a binding of a template to a
    /// credential, and two Gmail instances are both Gmail. Omitted when the
    /// template resolves to nothing renderable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_identity_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,
    /// Per-scheme secret bindings: securityScheme key → secret NAME in the
    /// org vault. Names only — secret values never leave the vault.
    #[serde(skip_serializing_if = "CredentialsMap::is_empty")]
    pub credentials: CredentialsMap,
    /// Per-instance non-secret param values. Plain values, not vault
    /// references — see `service_instances.config`.
    #[serde(skip_serializing_if = "ConfigMap::is_empty")]
    pub config: ConfigMap,
    /// Per-instance MCP server URL override. Overrides the template's `mcp.url`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// When `false`, an unbound instance won't fall back to the default
    /// connection. See `service_instances.use_default_connection`.
    pub use_default_connection: bool,
    #[serde(default)]
    pub groups: Vec<ServiceGroupRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials_status: Option<CredentialsStatus>,
}

#[derive(Serialize, Clone)]
pub struct ServiceGroupRef {
    pub grant_id: Uuid,
    pub group_id: Uuid,
    pub group_name: String,
    /// `'everyone'`, `'admins'`, `'self'` for system groups; absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_kind: Option<String>,
    pub access_level: String,
    /// `"none" | "read" | "write" | "admin"` — how far up the ladder actions
    /// on this service skip Layer 2 for members of this group.
    pub auto_approve_level: String,
    /// DEPRECATED — `auto_approve_level != "none"`.
    pub auto_approve_reads: bool,
}

impl From<ServiceGroupRow> for ServiceGroupRef {
    fn from(r: ServiceGroupRow) -> Self {
        Self {
            grant_id: r.grant_id,
            group_id: r.group_id,
            group_name: r.group_name,
            system_kind: r.system_kind,
            access_level: r.access_level,
            auto_approve_level: r.auto_approve_level,
            auto_approve_reads: r.auto_approve_reads,
        }
    }
}

#[derive(Serialize)]
pub struct ServiceInstanceDetail {
    pub id: Uuid,
    pub org_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_identity_id: Option<Uuid>,
    pub name: String,
    pub template_source: String,
    pub template_key: String,
    /// Absolute URL of the template's catalog icon. Instances deliberately
    /// have no icon of their own — an instance is a binding of a template to a
    /// credential, and two Gmail instances are both Gmail. Omitted when the
    /// template resolves to nothing renderable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,
    /// Per-scheme secret bindings: securityScheme key → secret NAME in the
    /// org vault. Names only — secret values never leave the vault.
    #[serde(skip_serializing_if = "CredentialsMap::is_empty")]
    pub credentials: CredentialsMap,
    /// Per-instance non-secret param values. Plain values, not vault
    /// references — see `service_instances.config`.
    #[serde(skip_serializing_if = "ConfigMap::is_empty")]
    pub config: ConfigMap,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// When `false`, an unbound instance won't fall back to the default
    /// connection. See `service_instances.use_default_connection`.
    pub use_default_connection: bool,
    pub status: String,
    pub is_system: bool,
    pub created_at: String,
    pub updated_at: String,
    /// When this instance's MCP tools were last resynced (RFC3339). Absent
    /// until the first `POST /v1/services/{id}/mcp/resync`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovered_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials_status: Option<CredentialsStatus>,
    /// Present on the response to `POST /v1/services` when the kernel
    /// auto-initiated an OAuth flow as part of setting up the instance.
    /// The caller hands `auth_url` to the user and the OAuth callback
    /// will write `connection_id` back onto this row when the dance
    /// finishes. Omitted on every other code path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect: Option<ConnectBundle>,
}

/// OAuth bootstrap bundle returned alongside a freshly-created service
/// instance. Callers hand the gated `auth_url` to the user; the raw upstream
/// provider URL is never surfaced.
#[derive(Serialize, Debug)]
pub struct ConnectBundle {
    pub auth_url: String,
    pub state: String,
    pub flow_id: String,
    pub expires_at: time::OffsetDateTime,
}

/// Derived credential-health state for a service instance.
///
/// - `NeedsAuthentication` — service has no connection (and the template
///   declares an OAuth auth scheme). The agent must run the OAuth dance
///   before any call will succeed. This is the freshly-instantiated state
///   when an agent creates a service from a template via `create_service`.
/// - `Ok` — at least one action is fully covered by the connection's scopes.
/// - `PartiallyDegraded` — some actions covered, some not. Calls outside the
///   covered set 403 with `missing_scopes`.
/// - `NeedsReconnect` — every scope-bearing action is uncovered. The
///   connection is bound but useless for this service.
#[derive(Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialsStatus {
    NeedsAuthentication,
    Ok,
    PartiallyDegraded,
    NeedsReconnect,
}
