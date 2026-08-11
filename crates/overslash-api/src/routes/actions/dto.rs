//! Shared request/response and resolution types for the action execution
//! endpoints.
//!
//! Split out of `mod.rs`; `mod.rs` glob-re-exports these so every sibling's
//! `use super::*;` keeps reaching them.

use super::*;

/// Query options for `POST /v1/actions/call`.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct CallQuery {
    /// Opt-in (dashboard "try it" surface): return the gateway's own auth
    /// errors (`needs_authentication` / `reauth_required`) as a `200` envelope
    /// with the status inside the body, instead of a real `401`. Browser
    /// clients otherwise can't distinguish a target-service auth prompt from an
    /// expired-session `401` and bounce the user to `/login`. The default
    /// (unset) keeps the typed-`401` contract MCP/REST/white-label callers rely
    /// on. Only the gateway's auth `401`s are wrapped — upstream statuses
    /// already ride inside the `status: "called"` envelope, and other gateway
    /// errors (400/403/5xx) pass through unchanged.
    #[serde(default)]
    pub(super) wrap: Option<bool>,
}

/// Unified call request — `service` is required and selects between the
/// two SPEC §8 shapes: Service + defined action (when `action` is set) and
/// Service + HTTP verb (when only `method` + `url`/`path` is set). Mode A
/// raw HTTP rides on the verb shape against the synthetic `http`
/// pseudo-service. See module docs for the field-presence selection rules.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CallRequest {
    // Raw HTTP fields (also reused by service + HTTP verb)
    pub(super) method: Option<String>,
    pub(super) url: Option<String>,
    #[serde(default)]
    pub(super) headers: HashMap<String, String>,
    pub(super) body: Option<String>,
    #[serde(default)]
    pub(super) secrets: Vec<SecretRef>,

    // Service + action / Service + HTTP verb fields
    pub(super) service: Option<String>,
    /// Optional instance UUID. When present, the resolver looks the instance
    /// up by id (org-scoped) instead of by caller-shadowed name — required for
    /// an org admin to invoke an instance owned by another user, since
    /// name-based lookup is intentionally caller-scoped.
    pub(super) service_id: Option<Uuid>,
    pub(super) action: Option<String>,
    /// Service + HTTP verb (SPEC §8): path-only form (host comes from
    /// `svc.hosts`). Mutually exclusive with `action`.
    pub(super) path: Option<String>,
    #[serde(default)]
    pub(super) params: HashMap<String, serde_json::Value>,

    // Large file handling
    #[serde(default)]
    pub(super) prefer_stream: Option<bool>,

    /// Where the response body should go. See [`Delivery`].
    #[serde(default)]
    pub(super) deliver: Option<Delivery>,
    /// Whether this call runs on the caller's connection. See [`ExecutionMode`].
    ///
    /// Load-bearing that this exists at all: `CallRequest` is
    /// `deny_unknown_fields`, so without it the flag would be a 400 at
    /// deserialization rather than a feature.
    #[serde(default)]
    pub(super) execution: Option<ExecutionMode>,

    /// How long this call may wait on the upstream, in milliseconds.
    ///
    /// The most specific rung of the D56 cascade: it beats the action
    /// template, the service template, the org default, and the deployment
    /// default. It does *not* beat the ceilings — asking for more than the
    /// org (or deployment) maximum is a 400 rather than a silent clamp,
    /// because unlike a template default there is a caller present who asked
    /// explicitly and can act on the error.
    ///
    /// For `prefer_stream: true` this bounds time-to-first-byte only; the
    /// transfer itself is bounded by a per-chunk idle timeout.
    #[serde(default)]
    pub(super) timeout_ms: Option<u64>,

    // Optional server-side filter applied to the upstream response body
    // (e.g., jq). Output is attached to `result.filtered_body`; the
    // original `body` is always preserved.
    #[serde(default)]
    pub(super) filter: Option<ResponseFilter>,

    // Caller-asserted risk class. Today only `read` is meaningful: when set
    // to `read`, the resolved action's risk must be `Read` or the call is
    // rejected with 400. `write` / `delete` are accepted by the parser but
    // do not gate anything (no caller currently asks for them). Set by the
    // MCP `overslash_read` tool to enforce its readOnlyHint.
    #[serde(default)]
    pub(super) require_risk: Option<Risk>,

    // Response shape selector. `Some(true)` → current full ActionResult
    // (headers, raw stringified body, no crop). `Some(false)` → compact
    // shape (headers dropped, body parsed as JSON when possible, output
    // capped at ~8 KB). `None` defaults to `true` on the HTTP API to keep
    // direct callers wire-compatible. The MCP layer forwards `false` by
    // default and only flips to `true` when the caller passes `verbose: true`
    // on the tool args.
    #[serde(default)]
    pub(super) verbose: Option<bool>,

    // Optional URL the OAuth callback redirects the user back to if this
    // call triggers a reactive auth flow (reauth_required / missing_scopes /
    // needs_authentication). Mirrors `return_url` on the connect endpoint
    // (`routes/connections.rs::InitiateConnectionRequest`); validated by
    // `parse_return_url` at the request boundary and gated at callback time
    // by `OVERSLASH_CONNECTION_RETURN_URL_HOSTS` — when the host isn't on the
    // allow-list the callback falls back to the historical JSON response.
    #[serde(default)]
    pub(super) return_url: Option<String>,
}

/// Where a call's response body should be delivered.
///
/// Defaults to [`Inline`](Self::Inline) — minting a URL creates a live
/// capability plus a row, and changes the response shape, so it has to be
/// asked for. `response_type: "binary"` on an action does *not* silently flip
/// this; it only sharpens the hint the caller sees when the buffered path
/// refuses an oversized body.
///
/// Unlike `prefer_stream`, this is reachable from every surface — including
/// MCP, where a URL is the only representation of a file that fits in a tool
/// result at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Delivery {
    /// Body rides back in the `Called` envelope. The historical behavior.
    Inline,
    /// Mint a short-lived capability URL and return a descriptor instead. The
    /// bytes are fetched later, out of band, by `GET /v1/downloads/{token}`.
    Url,
}

impl Delivery {
    pub(super) fn is_url(self) -> bool {
        matches!(self, Delivery::Url)
    }
}

/// Whether the caller waits on this connection for the upstream.
///
/// Named `execution` rather than `async` because `async` is a Rust keyword and
/// a reserved word in JS/TS, so the field would be unnameable in generated
/// clients and awkward in every mirror type.
///
/// `Sync` is the historical behaviour: the response carries the upstream body,
/// bounded by the deployment's request cap. `Async` accepts the call, persists
/// it, and hands back an execution id to poll — the only way a call can outlive
/// the caller's connection. See DECISIONS D57.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum ExecutionMode {
    Sync,
    Async,
}

impl ExecutionMode {
    pub(super) fn is_async(self) -> bool {
        matches!(self, ExecutionMode::Async)
    }
}

#[derive(Serialize)]
#[serde(tag = "status")]
pub(super) enum CallResponse {
    #[serde(rename = "called")]
    Called {
        /// Pre-rendered `ActionResult` view. Verbose mode encodes the full
        /// struct (status_code, headers, raw body string, duration_ms,
        /// optional filtered_body). Compact mode returns the shape from
        /// `services::compact_response::compact` (headers dropped, body
        /// parsed as JSON, ≤8 KB). The selector lives on `CallRequest.verbose`.
        result: serde_json::Value,
        action_description: Option<String>,
        /// True when the upstream itself reported failure — an MCP envelope
        /// with `is_error: true`, or an upstream HTTP status >= 400 — even
        /// though the call executed. Mirrors `detail.is_error` on the
        /// `action.executed` audit entry so callers (dashboard Try It, MCP
        /// clients) can flag the result without parsing the body.
        is_error: bool,
    },
    #[serde(rename = "pending_approval")]
    PendingApproval {
        approval_id: Uuid,
        approval_url: String,
        action_description: String,
        expires_at: String,
        /// Caller↔requester relationship as classified server-side. The agent
        /// uses this to pick `overslash_approve_self` vs
        /// `overslash_approve` on the first try instead of
        /// trial-and-error against the typed-error envelope. Always `"self"`
        /// when this payload comes from the same agent that triggered the
        /// action; `"downstream"` when listed by an ancestor.
        relationship: String,
        /// Same broadening ladder GET /v1/approvals/{id} returns — included
        /// here so callers can offer "remember at a broader scope" prompts
        /// without a second round-trip. Deterministic on the approval's
        /// `permission_keys`.
        suggested_tiers: Vec<SuggestedTier>,
        /// Mirrors the *requesting* agent's `identities.auto_call_on_approve`.
        /// When `true` (default), an `allow` / `allow_remember` resolution
        /// auto-replays the call in the background and the execution result
        /// lands via webhook/audit — the MCP client does **not** need to
        /// follow up with `POST /v1/approvals/{id}/call`. When `false`, the
        /// agent is in deferred-execution mode and the caller must replay
        /// explicitly (e.g. `overslash_call` with `approval_id`) after the
        /// approval is granted. Surfaced so MCP clients can choose whether
        /// to wait or to issue an explicit follow-up.
        auto_call_on_approve: bool,
        // ── Render-form fields ───────────────────────────────────────────
        // White-label integrations (Telegram/WhatsApp/web bots) render an
        // approval prompt straight off this envelope. The four fields below
        // mirror the matching `ApprovalResponse` fields the dashboard's
        // `ApprovalRow` / `ApprovalDetail` render from, so a caller can draw
        // the same card without a second `GET /v1/approvals/{id}` round-trip.
        /// Labeled, human-readable slice of the resolved request extracted via
        /// the template's `x-overslash-disclose` filters. Omitted when the
        /// template declared none. Same shape as
        /// `ApprovalResponse.disclosed_fields`.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        disclosed_fields: Vec<disclosure::DisclosedField>,
        /// Risk class for the gated action: `"low" | "med" | "high"`. Drives
        /// the approval card's severity styling. Mirrors `ApprovalResponse.risk`
        /// (defaults to `"med"` for verb/http shapes with no declared risk).
        risk: String,
        /// Permission key(s) being requested — what the approver grants.
        /// Mirrors `ApprovalResponse.permission_keys`.
        permission_keys: Vec<String>,
        /// Redacted, pretty-printed request payload (`x-overslash-redact`
        /// applied), truncated at the same 100 KB UTF-8 boundary as the read
        /// path. Omitted when no detail was stored. Mirrors
        /// `ApprovalResponse.action_detail` + its truncation companions.
        #[serde(skip_serializing_if = "Option::is_none")]
        action_detail: Option<String>,
        action_detail_truncated: bool,
        action_detail_size_bytes: usize,
    },
    #[serde(rename = "denied")]
    Denied { reason: String },
    /// Async call accepted. The upstream has not been dialled yet — poll
    /// `GET /v1/executions/{execution_id}` for the outcome, or subscribe to
    /// the `executions` event topic.
    ///
    /// Note this shares its HTTP status (202) with `PendingApproval`. That is
    /// deliberate — 202 is exact for both ("accepted, not completed") and
    /// `status` is the documented discriminator everywhere else in this API —
    /// but it means a client must branch on `status`, never on the code alone.
    #[serde(rename = "accepted")]
    Accepted {
        execution_id: Uuid,
        /// Absolute poll URL, built the same way `approval_url` is.
        execution_url: String,
        action_description: Option<String>,
        /// RFC 3339. After this the row is swept to `expired` and the call
        /// will never run.
        expires_at: String,
        /// The D56-resolved budget the worker will run under. Echoed so a
        /// caller knows how long to keep polling rather than guessing from a
        /// deployment default it cannot see.
        timeout_ms: u64,
        /// Server-suggested delay before the first poll, in milliseconds.
        poll_after_ms: u64,
    },
}

/// Metadata from request resolution, used to derive the correct permission key type.
pub(super) struct ResolvedMeta {
    pub(super) description: Option<String>,
    /// Present for service shapes (action / verb); carries info to derive
    /// service permission keys.
    pub(super) service_scope: Option<ServiceScope>,
    /// Declared risk of the action (action shape only, from the action
    /// definition). `Dynamic` resolves per call via the SQL classifier.
    pub(super) risk: Option<DeclaredRisk>,
    /// Disclosure declarations from the action template (action shape only;
    /// empty for verb / `http`). Runs at approval-create and audit-write time.
    pub(super) disclose: Vec<DisclosureField>,
    /// Redact paths from the action template (action shape only; empty for
    /// verb / `http`). Applied to the request projection before it's
    /// persisted as `approvals.action_detail`.
    pub(super) redact: Vec<String>,
    /// `x-overslash-timeout_ms` on the resolved action, post-fold — an org
    /// `ActionPatch` has already overwritten the shipped template's value, so
    /// this single field carries both the template and org-per-action rungs.
    /// `None` for verb / `http` shapes, which have no action to read.
    pub(super) action_timeout_ms: Option<u64>,
    /// `info.x-overslash-default_timeout_ms` on the resolved service, post-fold.
    pub(super) service_timeout_ms: Option<u64>,
    /// `x-overslash-download` from the action template. MCP actions only —
    /// it's how a tool result says "the bytes are over there". HTTP actions
    /// are their own download and leave this `None`.
    pub(super) download: Option<overslash_core::types::DownloadSpec>,
    /// Whether this call authenticates via OAuth, mirroring
    /// `ResolvedAuth::oauth_injected`.
    ///
    /// Deliberately *not* `auth_header.is_some()`: a template declaring a
    /// query-param token injection resolves OAuth successfully but builds no
    /// header, so the header check reads as "no credential" and would let a
    /// deferred download mint a token the fetch cannot authenticate — a URL
    /// that 401s later instead of an error now.
    pub(super) oauth_injected: bool,
    /// Original resolved params (before url/body assembly), retained for the
    /// disclosure `.params.*` projection. Empty for verb / `http` shapes.
    pub(super) params: HashMap<String, serde_json::Value>,
    /// Display names from the template's `resolve` declarations (param name →
    /// human-readable string), feeding both description interpolation and the
    /// disclosure `.resolved.*` projection. Populated for the HTTP and MCP
    /// action shapes; verb / platform shapes carry an empty map. Resolution
    /// happens once, at resolve time, and rides here across execution:
    /// audit-write disclosure for a delete action still names the object even
    /// though it's gone upstream.
    pub(super) resolved: HashMap<String, String>,
    /// Canonical scope values from `resolve.scope` (param name → canonical
    /// string), used *only* to derive the permission key.
    ///
    /// Separate from `resolved` because the two decide different things: a
    /// display string is cosmetic, while this one selects which grants match.
    /// The value sent upstream is never rewritten from here — canonicalization
    /// renames the permission, it does not retarget the call.
    pub(super) canonical: HashMap<String, String>,
    /// When the resolved service has `runtime: Mcp`, dispatch skips the HTTP
    /// executor and goes through `mcp_caller::invoke` with this payload.
    pub(super) mcp_target: Option<McpTarget>,
    /// When the resolved service has `runtime: Platform`, dispatch calls the
    /// in-process handler registry instead of making any outgoing call.
    pub(super) platform_target: Option<PlatformTarget>,
    /// Resolved service-instance id (HTTP shapes only). Stored on approval
    /// replay payloads so the replay path can re-resolve OAuth against the
    /// same binding instead of persisting a live token.
    pub(super) instance_id: Option<uuid::Uuid>,
    /// Which template, instance and account this call resolved to. Captured
    /// during resolution because the instance row is consumed there, and read
    /// back out by the metadata tagger.
    pub(super) binding: BindingFacts,
}

/// The resolved service binding, reduced to the three names worth tagging.
///
/// Exists because resolution *consumes* the `ServiceInstanceRow` — by the time
/// the handler wants to tag the call, the row is gone and re-fetching it would
/// add a query per call to name something already in hand a moment earlier.
#[derive(Default, Clone)]
pub(super) struct BindingFacts {
    pub(super) template_key: Option<String>,
    pub(super) instance_name: Option<String>,
    /// The account the call authenticates as — see
    /// [`crate::services::principals`] for the precedence.
    pub(super) principal: Option<String>,
}

impl BindingFacts {
    pub(super) fn new(
        instance: Option<&overslash_db::repos::service_instance::ServiceInstanceRow>,
        svc: &overslash_core::types::ServiceDefinition,
        principal: Option<String>,
    ) -> Self {
        Self {
            // An instance names its own template; a template-only call (no
            // instance bound) is still a call against that template.
            template_key: Some(
                instance
                    .map(|i| i.template_key.clone())
                    .unwrap_or_else(|| svc.key.clone()),
            ),
            instance_name: instance.map(|i| i.name.clone()),
            // The OAuth resolvers name the account they authenticated as. A
            // secret-based instance has no connection to ask, so fall back to
            // the template's identity config var — the same last step
            // `resolve_service_principals` takes.
            principal: principal.or_else(|| {
                instance
                    .and_then(|i| crate::services::principals::instance_config_principal(svc, i))
            }),
        }
    }
}

pub(super) struct McpTarget {
    /// Resolved MCP server URL (instance.url ?? template mcp.url).
    pub(super) url: String,
    /// Resolved auth — for Bearer, secret_name is always Some at this point.
    pub(super) auth: McpAuth,
    /// Live OAuth bearer for `McpAuth::OAuth`, resolved out-of-band from the
    /// caller's connection (never persisted in the request). `None` for
    /// `None`/`Bearer` auth. Merged into the outbound MCP headers at send time.
    pub(super) auth_header: Option<overslash_core::types::AuthHeader>,
    pub(super) tool: String,
    pub(super) arguments: serde_json::Value,
}

pub(super) struct PlatformTarget {
    pub(super) action_key: String,
    pub(super) params: serde_json::Map<String, serde_json::Value>,
}

pub(super) struct ServiceScope {
    pub(super) service_key: String,
    /// Empty string for the Service + HTTP verb shape (then `http_verb` is `Some`).
    pub(super) action_key: String,
    pub(super) scope_param: ScopeParams,
    /// Service + HTTP verb (SPEC §8) — when `Some`, permission keys derive as
    /// `{service_key}:{METHOD}:{path}` instead of `{service_key}:{action_key}:{arg}`.
    pub(super) http_verb: Option<HttpVerb>,
}

#[derive(Clone)]
pub(super) struct HttpVerb {
    pub(super) method: String,
    pub(super) path: String,
}

/// Cheap, side-effect-free pre-resolution of a `CallRequest`.
///
/// Returns enough information for the top-level handler to:
///   1. Validate caller-supplied args against the action's schema
///      (action shape only; verb / `http` carry an empty schema).
///   2. Derive permission keys.
///   3. Run the caller-asserted risk gate.
///
/// Raw HTTP doesn't touch the DB. Service shapes load the template and
/// (for the action shape) look up the action — no OAuth refresh, no
/// `param_resolver` HTTP, no scope checks, no audit. Used by both
/// `/v1/actions/call` (so `validate_args` can sit at the top of the
/// handler, structurally before any approval-creation work) and
/// `/v1/actions/validate` (which only runs the cheap path and never
/// builds a real request).
///
/// For service shapes, the resolved template + instance ride along in
/// the returned tuple so `resolve_request` can reuse them and avoid the
/// duplicate DB lookup that a separate metadata pre-resolve would
/// otherwise force on the call hot path.
pub(super) struct ActionMetadata {
    /// Schema for `validate_args`. Empty for verb / `http` shapes.
    pub(super) validation_params: HashMap<String, overslash_core::types::ActionParam>,
    /// Service info for permission-key derivation (service shapes only).
    pub(super) service_scope: Option<ServiceScope>,
    /// Declared risk class — action shape reads it from the template; verb /
    /// `http` shapes leave it `None` and the caller infers from method.
    /// `Dynamic` resolves per call via the SQL classifier.
    pub(super) risk: Option<DeclaredRisk>,
    /// Caller-supplied raw HTTP fields used for `http`-pseudo-service
    /// permission-key derivation. Service shapes use `service_scope`.
    pub(super) raw_method: String,
    pub(super) raw_url: String,
    /// Whether this request needs Layer 2 (permission-chain) gating.
    /// Service shapes are always gated (templates ship with auth or are
    /// platform/MCP); raw HTTP is gated only when secrets are injected.
    pub(super) needs_gate: bool,
}

/// Pre-resolved service template + instance, threaded
/// from `resolve_action_metadata` into `resolve_request` so the call
/// path doesn't re-fetch them.
pub(super) struct ResolvedModeC {
    pub(super) svc: overslash_core::types::ServiceDefinition,
    pub(super) instance: Option<overslash_db::repos::service_instance::ServiceInstanceRow>,
}

/// D42 SQL policy outcome for one call. `None` (from [`evaluate_sql_policy`])
/// when the action nominates no SQL param, the shape is not a service action,
/// or the caller didn't supply the SQL param.
pub(super) struct SqlPolicyOutcome {
    /// Risk floor from classification — callers merge it with
    /// `Risk::max_severity`, never downward.
    pub(super) floor: Risk,
    /// `table=…` keys, appended to (or replacing the `:*` fallback of) the
    /// scope_param-derived keys. May be empty for a table-less `SELECT 1`.
    pub(super) table_keys: Vec<overslash_core::permissions::PermissionKey>,
    /// `column=…` / `column_star=…` keys — deny-screen only.
    pub(super) column_keys: Vec<overslash_core::permissions::PermissionKey>,
    /// Audit label as configured ("reveni-prod", the raw db-key, or
    /// "unknown"). Sanitized at the point of use — `PermissionKey` and
    /// `overslash_core::tags` both run it through the same sanitizer.
    pub(super) db_label: String,
    /// The full classifier verdict. Kept whole rather than reduced to the
    /// risk floor: the tables, columns and write reason are what get minted
    /// into metadata tags and written to the audit `detail.sql` block, and
    /// reducing here is how they used to get thrown away.
    pub(super) analysis: overslash_core::sql_policy::SqlAnalysis,
}

/// Classify an OAuth resolver error so the action handler can respond
/// with the right HTTP status. The split mirrors RFC 7231 semantics:
///   * `Reauth(reason)` → 401, the user can fix it by clicking a link.
///   * `Internal` → 500, server-side problem the user can't fix
///     (crypto, DB, parse, provider config missing from the DB).
///   * `Upstream` → 502, the *provider* is the broken party (transport
///     error, provider rejected the credentials with a non-refresh body).
#[derive(Debug)]
pub(super) enum OAuthOutcome {
    Reauth(&'static str),
    Internal,
    Upstream,
}
