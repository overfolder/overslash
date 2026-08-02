use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::risk::DeclaredRisk;
use super::scope::ScopeParams;

/// An action within a service (maps to an HTTP request template).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAction {
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub path: String,
    /// What the *agent* reads when choosing this action, and the text the
    /// keyword/embedding index scores against. For an HTTP operation this is
    /// the OpenAPI `description`, falling back to `summary` when only the
    /// short form is authored.
    ///
    /// This is the only string about an action that ever reaches the model —
    /// parameter descriptions, defaults, and response schemas do not — so it
    /// carries the whole contract, examples included, and is free to be long.
    pub description: String,
    /// The short, interpolatable human label: the OpenAPI `summary`, e.g.
    /// `"Search folder '{folder}' for {criteria}"`. `{param}` placeholders are
    /// substituted with the caller's actual arguments to title the approval
    /// screen and the audit row.
    ///
    /// Separate from [`description`](Self::description) because the two jobs
    /// pull in opposite directions: the agent needs the long form, while an
    /// approval prompt a human must read in one glance needs a single line.
    /// `None` falls back to `description`, which is how every action that
    /// authors only one of the two behaves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default)]
    pub risk: DeclaredRisk,
    /// Response type hint: "json" (default) or "binary" (for file downloads).
    /// When "binary", callers should use `prefer_stream: true` to avoid buffering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_type: Option<String>,
    #[serde(default)]
    pub params: HashMap<String, ActionParam>,
    /// Which params provide the `{arg}` segment in permission keys, and under
    /// which label. Empty (`scope_param` absent) means the arg defaults to `*`.
    #[serde(default, skip_serializing_if = "ScopeParams::is_empty")]
    pub scope_param: ScopeParams,
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
    /// The operation's declared `requestBody`, parsed at template-load time.
    /// `None` means the operation takes no body at all (e.g. a POST whose only
    /// inputs are path params) — routing then sends neither a body nor a
    /// `Content-Type`.
    ///
    /// Presence here is a static fact about the contract, *not* a function of
    /// which arguments a caller happened to supply: an operation whose body
    /// fields are all optional (`POST /email/search`) must still send `{}` with
    /// the declared media type, or a strict upstream extractor rejects the call
    /// before it ever looks at the body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body: Option<RequestBodySpec>,
}

impl ServiceAction {
    /// The template to interpolate for human-facing surfaces (approval title,
    /// audit description). Prefers the short [`summary`](Self::summary) and
    /// falls back to [`description`](Self::description) when the action
    /// authors only the long form.
    pub fn label_template(&self) -> &str {
        self.summary.as_deref().unwrap_or(&self.description)
    }
}

/// An operation's declared `requestBody`, reduced to what routing needs: which
/// media type to send it as, and whether the upstream demands it.
///
/// `Content-Type` is deliberately modelled here rather than as a header param:
/// it is derived from the payload, not chosen by the caller. Caller/template
/// -chosen headers keep their own channel (`ParamLocation::Header` and
/// `securitySchemes` injection), so the two mechanisms never contend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestBodySpec {
    /// The media type key declared under `requestBody.content`, sent verbatim
    /// as the `Content-Type` header (e.g. `application/json`).
    pub content_type: String,
    /// The `requestBody.required` flag. Informational for routing — a body is
    /// sent whenever one is declared — but retained so validation can tell an
    /// omitted-but-required body from an omitted-and-optional one.
    #[serde(default)]
    pub required: bool,
}

impl RequestBodySpec {
    /// Whether this body is carried as JSON — `application/json` or a
    /// structured suffix like `application/vnd.api+json`. Parameters are only
    /// extracted (and bodies only serialised) for JSON media types today.
    pub fn is_json(&self) -> bool {
        let base = self
            .content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        base == "application/json" || (base.starts_with("application/") && base.ends_with("+json"))
    }
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
    /// `x-overslash-sql-field` (D42/D43): presence marks this string param
    /// as the one carrying a raw SQL query — the call handler parses and
    /// classifies it (read/write becomes a risk floor, referenced tables
    /// become per-table permission keys, referenced column identifiers are
    /// screened against deny rules). The *value* is the dotted path the
    /// param is nested under when the outgoing JSON body is assembled:
    /// `native.query` sends the value as `{"native": {"query": …}}`, while a
    /// path equal to the param name means flat placement. This keeps the
    /// caller surface flat and agent-friendly while matching an upstream
    /// API's nested payload — and keeps the annotation on the real string
    /// param rather than inside an opaque object. Template validation
    /// enforces at most one per action, on a string param.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sql_field: Option<String>,
    /// `x-overslash-sql-database` (D42): a jq expression over the call
    /// params (e.g. `.database | tostring`) whose result keys into the
    /// instance's `sql_databases` config map to resolve the parse dialect
    /// and the human DB label used in audit and permission keys. Only
    /// meaningful on an action that has an
    /// [`sql_field`](Self::sql_field) param.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sql_database: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

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
            sql_field: None,
            sql_database: None,
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
}
