use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use super::execution::ExecutionMode;
use super::risk::DeclaredRisk;
use super::scope::ScopeParams;

/// An action within a service (maps to an HTTP request template).
///
/// `Default` is derived so construction sites can spread `..Default::default()`
/// rather than restating every field. Without it, adding one optional field
/// means touching every fixture in the workspace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    /// `x-overslash-timeout_ms`: how long this specific action is expected to
    /// need upstream, in milliseconds. A *default*, not a cap — it says
    /// "Metabase aggregations are slow", and the org and deployment maxima
    /// still clamp it. `None` falls through to the service default, then the
    /// org default, then the deployment default.
    ///
    /// Always the most specific default that survives the layer fold: an org
    /// `ActionPatch` overwrites this value in place, so by the time a caller
    /// reads it there is no separate "org per-action" layer left to consult.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// `x-overslash-wait-mode`: the execution mode a call to this action falls
    /// back to when the caller names no `execution` of its own.
    ///
    /// A *default*, not a cap, and the same shape as
    /// [`timeout_ms`](Self::timeout_ms) one field up: the template author is
    /// the one party who knows this upstream takes four minutes, and before
    /// this there was no way to say so — the caller who did not know either
    /// simply rode into a 504 at the synchronous ceiling.
    ///
    /// Weaker than `timeout_ms` in one direction on purpose. A conflicting
    /// request flag (`prefer_stream`, `deliver: "url"`, `return_url`) or a
    /// template that cannot defer at all (`runtime: platform`, a binary
    /// response) **demotes this to sync silently** rather than refusing the
    /// call. The caller who names `execution` explicitly still gets the 400:
    /// that caller is present and can act on it, while a mistyped template
    /// value that 400s every call in the org is strictly worse than one that
    /// quietly runs synchronously — D56's asymmetry, applied to a mode
    /// instead of a number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_mode: Option<ExecutionMode>,
    /// `x-overslash-handoff_after_ms`: how long a *hybrid* call to this action
    /// holds the connection before answering 202.
    ///
    /// Clamped to the deployment maximum and to the call's own budget, never
    /// refused — this is a template default, and the same reasoning as
    /// [`wait_mode`](Self::wait_mode) applies. Only a caller-supplied
    /// `handoff_after_ms` out of range is a 400.
    ///
    /// Meaningful only when the resolved mode is hybrid. Under any other mode
    /// it is inert rather than an error, because the resolved mode depends on
    /// the request and a template cannot know it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handoff_after_ms: Option<u64>,
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
    /// `x-overslash-download`: this action's *result* points at a downloadable
    /// object rather than carrying it. Only meaningful for MCP actions — an
    /// HTTP action that returns bytes already *is* its own download, so
    /// `deliver: "url"` mints a token straight from the resolved request and
    /// needs no declaration.
    ///
    /// MCP has no such request to replay: the tool returns a descriptor
    /// (`{media_path, mime, size, …}`) and the bytes live behind a second,
    /// undeclared endpoint. These jq filters are how a template says *which*
    /// field of that descriptor is the object and what it looks like.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download: Option<DownloadSpec>,
}

/// How to turn an MCP tool result into a downloadable object.
///
/// Every field is a jq expression over the same `{runtime, tool, structured,
/// content, is_error}` envelope `mcp_caller` builds, so filters address
/// `.structured.*` the way `disclose` filters address `.arguments.*`.
///
/// Only [`url`](Self::url) is required; the rest are metadata the caller sees
/// on the minted descriptor and never affect what bytes come back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadSpec {
    /// jq expression yielding the object's location. A relative result (`/media/abc`)
    /// resolves against the resolved MCP instance URL's origin — the bytes live on
    /// the same host that served the tool call. An absolute `http(s)://` result is
    /// used verbatim.
    pub url: String,
    /// jq expression yielding the MIME type, surfaced on the descriptor and sent
    /// as a fallback `Content-Type` when the upstream omits one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    /// jq expression yielding the byte length. Advisory only — it tells the
    /// caller how big the fetch will be before committing to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    /// jq expression yielding a suggested filename.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    /// Which credential the deferred fetch presents. See [`DownloadAuth`].
    #[serde(default)]
    pub auth: DownloadAuth,
}

/// Which credential a deferred download presents to the upstream host.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DownloadAuth {
    /// Re-resolve the service instance's credential at fetch time and send it.
    /// The default, and the only correct choice when the byte route sits behind
    /// the same auth as the MCP endpoint.
    #[default]
    Inherit,
    /// Send nothing — the URL is already self-authorizing (a pre-signed CDN
    /// link). Declaring this on a route that *does* need credentials produces a
    /// 401 at fetch time, not a leak.
    None,
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
/// Two runtimes, one shape. An HTTP action names a `get` path, fetched with a
/// GET against the same service host reusing existing auth; an MCP action
/// names a `tool` on the same service plus the `args` to call it with. Either
/// way the JSON response is projected through `pick` (a single dot-path) or
/// `display` (a `{dot.path}` template with `[optional]` segments).
///
/// `scope` additionally names the dot-path whose value canonicalizes the
/// permission key. Without it a WhatsApp grant is minted against whichever
/// opaque address the agent happened to use — `recipient=2391...@lid` one
/// call, `recipient=34600...@s.whatsapp.net` the next, for the same human.
/// With it both collapse to `recipient=+34600123456`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParamResolver {
    /// HTTP runtime: GET endpoint path with `{param}` placeholders, e.g.
    /// `/calendar/v3/calendars/{calendarId}`. Mutually exclusive with `tool`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub get: Option<String>,
    /// MCP runtime: the name of a `risk: read` tool on the same service.
    /// Mutually exclusive with `get`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// MCP runtime: arguments for `tool`. Values may contain `{param}`
    /// placeholders naming params of the action being called.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub args: BTreeMap<String, String>,
    /// Dot-separated path into the JSON response, e.g. `summary` or
    /// `owner.login`. Shorthand for a single-placeholder `display`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pick: Option<String>,
    /// Display template over response dot-paths, e.g. `{name}[ ({phone})]`.
    /// Mutually exclusive with `pick`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    /// Dot-path whose value replaces the raw argument when deriving the
    /// permission key. The value sent upstream is never rewritten — this
    /// renames the permission, it does not retarget the call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// How long this resolver's answer may be reused, in seconds. Overrides
    /// the deployment default; `Some(0)` opts out of caching entirely.
    ///
    /// A default, not a cap — the deployment's ceiling still clamps it, and
    /// tighter still when `scope` is set, because a cached `scope` value
    /// decides which *grant* matches while the request keeps the caller's raw
    /// argument. The template author is the one who knows whether the mapping
    /// is immutable (`me` → your own address) or something the provider can
    /// re-point under you (a JID → a phone number).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_ttl: Option<u64>,
}

impl ParamResolver {
    /// The display projection, with the `pick` shorthand normalized into the
    /// `display` template form so callers only handle one shape. `None` when
    /// the template declares neither — a malformed resolver that
    /// `template_validation` reports rather than silently half-running.
    pub fn display_template(&self) -> Option<String> {
        match (&self.display, &self.pick) {
            (Some(display), _) => Some(display.clone()),
            (None, Some(pick)) => Some(format!("{{{pick}}}")),
            (None, None) => None,
        }
    }

    /// Whether exactly one runtime target is declared.
    pub fn has_one_target(&self) -> bool {
        self.get.is_some() != self.tool.is_some()
    }
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
