//! Serialized response shapes and deserialized request bodies for the
//! `/v1/templates` endpoints.

use super::*;

// -- Response types --

#[derive(Serialize)]
pub(super) struct TemplateSummary {
    pub(super) key: String,
    pub(super) display_name: String,
    pub(super) description: Option<String>,
    pub(super) category: Option<String>,
    pub(super) hosts: Vec<String>,
    pub(super) action_count: usize,
    pub(super) tier: String,
    /// Absolute URL of the catalog icon, resolved from the template's
    /// `icon` (usually implicit from its key). Omitted when there is
    /// nothing safe to render — the dashboard falls back to a letter tile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) icon_url: Option<String>,

    /// `x-overslash-hidden` — dashboard surfaces show hidden templates
    /// flagged; agent-facing surfaces (`/v1/search`, MCP) omit them.
    pub(super) hidden: bool,
    /// Base template key when this row is a derived layer (lets the catalog
    /// route its editor to the layer editor). Omitted for standalone/global.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) extends: Option<String>,
    /// Count of fold-time resolution warnings, if any — the catalog badges it.
    #[serde(skip_serializing_if = "is_zero")]
    pub(super) warnings: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

#[derive(Serialize)]
pub(super) struct TemplateDetail {
    pub(super) key: String,
    pub(super) display_name: String,
    pub(super) description: Option<String>,
    pub(super) category: Option<String>,
    pub(super) hosts: Vec<String>,
    /// Absolute URL of the catalog icon, resolved from the template's
    /// `icon` (usually implicit from its key). Omitted when there is
    /// nothing safe to render — the dashboard falls back to a letter tile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) icon_url: Option<String>,
    /// Compiled auth view for the dashboard's connect flows.
    pub(super) auth: Vec<serde_json::Value>,
    /// The credential slots an instance binds — one vault secret each, with
    /// the label and help text the dashboard's credentials form renders. A
    /// slot may feed several injections and an injection may join several
    /// slots, so this is NOT derivable from `auth` on the client.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) secrets: Vec<overslash_core::types::SecretSlot>,
    /// Canonical OpenAPI 3.1 YAML source — the editable document. For DB
    /// templates this is the stored, alias-normalized text. For global
    /// templates it's the shipped YAML verbatim.
    pub(super) openapi: String,
    /// Compiled actions view for rendering the service detail page without
    /// re-parsing on the client.
    pub(super) actions: Vec<ActionSummary>,
    /// Union of every action's `required_scopes` — the OAuth scopes a caller
    /// must request so the connection covers this service. White-label
    /// partners read this to build their own authorize URL (token-vault
    /// model); the dashboard renders them as the service-specific scope chips.
    pub(super) scopes: Vec<String>,
    pub(super) tier: String,
    /// DB id for org/user templates; None for global.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) id: Option<Uuid>,
    /// "http" (default) or "mcp". Dashboard uses this to switch the actions
    /// tab column layout and to reveal the MCP-only "Resync tools" button.
    pub(super) runtime: String,
    /// Summary of the MCP block when `runtime == "mcp"`. Omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) mcp: Option<McpDetail>,
    /// `x-overslash-hidden` — see [`TemplateSummary::hidden`].
    pub(super) hidden: bool,
    /// True when the endpoint URL is set per service instance rather than baked
    /// into the template. The dashboard reveals a URL field on the
    /// instance-create/edit form when this is set. See [`configurable_url`].
    pub(super) configurable_url: bool,
    /// Params an org may pin per service instance (`x-overslash-instance-config`),
    /// deduped across actions. The dashboard renders one field per entry on the
    /// instance-create/edit form and submits them as `config`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) instance_config_params: Vec<InstanceConfigParam>,
    /// Effective defaults an org layer supplies for the per-instance surface
    /// (endpoint `url` + `config` pins), folded through the whole chain. The
    /// instance form renders these as placeholders — leaving a field blank
    /// inherits the layer's value. `None` when no layer in the chain sets any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) instance_defaults: Option<overslash_core::service_layer::InstanceDefaults>,
    /// Base template key this layer derives from (a **derived** layer). `None`
    /// for a standalone layer or a global template.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) extends: Option<String>,
    /// The stored delta for a derived layer (masks + extensions). `None` for a
    /// standalone layer. The dashboard layer editor reads this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) delta: Option<serde_json::Value>,
    /// Non-blocking resolution warnings computed during the fold
    /// (`shadowed_extension`, `dead_*`, `unreviewed_new_actions`). Recomputed on
    /// every read, so drift surfaces the moment an upstream base changes.
    #[serde(skip_serializing_if = "ResolutionReport::is_empty")]
    pub(super) resolution_report: ResolutionReport,
}

/// The resolution-warning report attached to a resolved template. Mirrors the
/// `{warnings}` half of the template `ValidationReport` shape.
#[derive(Serialize, Default)]
pub(super) struct ResolutionReport {
    pub(super) warnings: Vec<overslash_core::template_validation::ValidationIssue>,
}

impl ResolutionReport {
    fn is_empty(&self) -> bool {
        self.warnings.is_empty()
    }
}

#[derive(Serialize)]
pub(super) struct McpDetail {
    /// The template's default MCP server URL. `null` means the service instance
    /// must supply a URL at creation time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) url: Option<String>,
    /// `none`, `bearer`, or `oauth`. The dashboard uses this to gate the
    /// credential UI (secret-name field for bearer, connect prompt for oauth).
    pub(super) auth_kind: String,
    /// `true` when the template has a hard-coded `secret_name`; `false` when
    /// the operator must supply one at instance creation time.
    pub(super) has_default_secret_name: bool,
    /// The OAuth provider key when `auth_kind == "oauth"`; the dashboard
    /// renders a "connect <provider>" affordance. `None` otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) provider: Option<String>,
    /// Superset OAuth scopes requested at connect time when `auth_kind ==
    /// "oauth"`. The dashboard passes these to `initiateOAuth` — without them
    /// the connect flow would request no scopes and mint a useless token.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) scopes: Vec<String>,
    pub(super) autodiscover: bool,
    /// ISO-8601 timestamp of the most recent tools/list sync. `None` if never.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) discovered_at: Option<String>,
}

#[derive(Serialize)]
pub(super) struct AdminTemplateSummary {
    pub(super) key: String,
    pub(super) display_name: String,
    pub(super) description: Option<String>,
    pub(super) category: Option<String>,
    pub(super) hosts: Vec<String>,
    pub(super) action_count: usize,
    pub(super) tier: String,
    /// See [`TemplateSummary::icon_url`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) icon_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) owner_identity_id: Option<Uuid>,
    /// For global templates: whether the template is explicitly enabled
    /// when `global_templates_enabled` is off. Always `true` for org/user tiers.
    pub(super) enabled: bool,
    /// `x-overslash-hidden` — see [`TemplateSummary::hidden`].
    pub(super) hidden: bool,
    /// Base template key when this row is a derived layer. Omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) extends: Option<String>,
    /// The raw stored delta for a derived layer, so the admin catalog can
    /// toggle `hidden` (and other masks) without a second fetch. Omitted for
    /// standalone/global rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) delta: Option<serde_json::Value>,
    /// Count of fold-time resolution warnings, if any.
    #[serde(skip_serializing_if = "is_zero")]
    pub(super) warnings: usize,
}

#[derive(Serialize, Clone)]
pub(crate) struct ActionSummary {
    pub(super) key: String,
    pub(super) method: String,
    pub(super) path: String,
    /// Agent-facing text — the full contract, examples included. Can run to a
    /// paragraph, so a table cell should prefer `summary` and keep this for a
    /// tooltip or an expanded row.
    pub(super) description: String,
    /// The short one-line label (`summary`), when the action authors one
    /// distinctly from its `description`. Absent when the two are the same
    /// string, which is the common case.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) summary: Option<String>,
    pub(super) risk: DeclaredRisk,
    /// MCP tool name when the owning service has `runtime: mcp`; None for HTTP.
    /// The dashboard switches its column layout on this field's presence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) mcp_tool: Option<String>,
    /// MCP outputSchema (JSON Schema). Present for MCP tools declaring one;
    /// callers may render it as a typed shape hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) output_schema: Option<serde_json::Value>,
    /// Admin-hidden tool. Dashboard shows these with a "hidden" pill and
    /// `/v1/actions/call` rejects invocation at resolve time.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) disabled: bool,
    /// Per-action OAuth scope coverage against the bound connection's granted
    /// scopes. Only populated when listing actions *for a configured instance*
    /// (`list_service_actions`) and the action declares scopes; absent on the
    /// bare template-key listing. `needs_reconnect` means calling it will 403.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) scope_coverage: Option<ScopeCoverage>,
    /// Missing-scope delta when `scope_coverage == needs_reconnect`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) missing_scopes: Vec<String>,
    /// `x-overslash-wait-mode` — the execution mode a call to this action
    /// defaults to when the caller names none.
    ///
    /// Absent for the overwhelming majority, which is the point: it is here so
    /// the handful of actions that answer `accepted` to a request that never
    /// asked for it are legible *before* someone calls one and wonders why.
    /// The response-shape consequence is invisible in every other listing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) wait_mode: Option<overslash_core::types::service::ExecutionMode>,
}

/// Full action details including the parameter schema — used by the API
/// Explorer to auto-generate a parameter form.
#[derive(Serialize)]
pub(super) struct ActionDetail {
    pub(super) key: String,
    pub(super) method: String,
    pub(super) path: String,
    pub(super) description: String,
    /// The short interpolatable label (`summary`) when the action authors one
    /// distinctly from its agent-facing `description`. Absent when the two are
    /// the same string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) summary: Option<String>,
    pub(super) risk: DeclaredRisk,
    pub(super) params: std::collections::HashMap<String, ActionParam>,
    /// The action's scoped params, resolved to `{param, label}` pairs. The
    /// authored `param:label` shorthand is a template-document detail; clients
    /// (the API Explorer marks scoped inputs with their label) get the pair so
    /// none of them re-implements the grammar. Absent when the action is
    /// unscoped.
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub(super) scope_param: Vec<ScopeParamRef>,
}

// -- Request types --

#[derive(Deserialize)]
pub(super) struct SearchQuery {
    pub(super) q: String,
}

#[derive(Deserialize)]
pub(super) struct CreateTemplateRequest {
    /// Raw OpenAPI 3.1 YAML source for a **standalone** layer. Must include
    /// `info.key` (or `info.x-overslash-key`) as the template key. Mutually
    /// exclusive with `extends`/`delta`.
    #[serde(default)]
    pub(super) openapi: Option<String>,
    /// If true, create as a user-level template (requires identity-bound key).
    #[serde(default)]
    pub(super) user_level: bool,
    /// Base template key for a **derived** layer. When set, `delta` is required
    /// and `openapi` must be absent.
    #[serde(default)]
    pub(super) extends: Option<String>,
    /// The derived-layer delta (masks + extensions). Required iff `extends` is set.
    #[serde(default)]
    pub(super) delta: Option<serde_json::Value>,
    /// Layer key for a derived layer. Defaults to `extends` (shadow-with-delta);
    /// set a distinct key for a separate catalog entry. Ignored for standalone
    /// layers (their key comes from the OpenAPI doc).
    #[serde(default)]
    pub(super) key: Option<String>,
    /// Display name for a derived layer. Optional (falls back to the delta's
    /// relabel or the base's name). Ignored for standalone layers.
    #[serde(default)]
    pub(super) display_name: Option<String>,
    /// Category for a derived layer. Optional. Ignored for standalone layers.
    #[serde(default)]
    pub(super) category: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct UpdateTemplateRequest {
    /// Replacement OpenAPI 3.1 YAML source for a standalone layer. The template
    /// `key` must match the existing key — it cannot be changed via update.
    #[serde(default)]
    pub(super) openapi: Option<String>,
    /// Replacement delta for a derived layer.
    #[serde(default)]
    pub(super) delta: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub(super) struct EnableGlobalRequest {
    pub(super) template_key: String,
}

/// One deployment-supplied service-template variable (D44), for the template
/// editor's reference panel.
///
/// The value is returned in the clear, and to any authenticated caller.
/// Withholding it would be theatre: anyone who can author a template can
/// recover it by writing `${NAME}` into a `servers[].url` and reading the
/// resolved definition back. That is why `OVERSLASH_TEMPLATE_VAR_*` is a
/// non-secret-by-declaration namespace — see the module docs on
/// `overslash_core::template_vars`.
#[derive(Serialize)]
pub(super) struct TemplateVar {
    /// The name a template references, i.e. the env var minus its prefix.
    pub(super) name: String,
    pub(super) value: String,
}

/// One instance-settable value, flattened for the dashboard form. Covers both
/// sources — an `x-overslash-instance-config` param and a credential template's
/// `x-overslash-config` var — because they share the instance's one `config`
/// map and render as one list of fields.
#[derive(Serialize)]
pub(super) struct InstanceConfigParam {
    pub(super) name: String,
    #[serde(rename = "type")]
    pub(super) param_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(super) description: String,
    /// Whether every action declaring this param marks it required. A param
    /// that is optional on any action stays optional on the form.
    pub(super) required: bool,
    /// Display name, when the declaration gives one. Config vars carry a
    /// human label ("Mailbox username") because their key is not a header name
    /// an operator would recognise; params have none and fall back to `name`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(super) label: String,
}
