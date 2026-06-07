// Mirrors backend Rust types from overslash-core and overslash-api

import type { DisclosedField, SuggestedTier } from './session';

export interface OrgInfo {
  id: string;
  name: string;
  slug: string;
  subagent_idle_timeout_secs: number;
  subagent_archive_retention_days: number;
  /** Populated on post-multi-org backends; undefined on older APIs. Personal
   *  orgs hide the IdP + OAuth credential surfaces entirely. */
  is_personal?: boolean;
  /** When true, this org accepts Overslash-managed sign-in (env-var OAuth
   *  apps). Admission is gated by `org_invites` — see migration 066 and
   *  `docs/design/multi_org_auth.md`. Undefined on older APIs. */
  allow_overslash_managed_signin?: boolean;
}

/**
 * Shape of GET/PATCH /v1/orgs/{id}/managed-signin.
 */
export interface ManagedSigninSettings {
  allow_overslash_managed_signin: boolean;
}

/**
 * One `org_invites` row. Pending invites are the membership gate for orgs
 * with `allow_overslash_managed_signin = true`.
 */
export interface OrgInvite {
  id: string;
  org_id: string;
  email: string;
  role: 'admin' | 'member';
  invited_by: string | null;
  created_at: string;
  accepted_at: string | null;
  accepted_by_user_id: string | null;
  status: 'pending' | 'accepted';
}

/**
 * Shape of GET/PATCH /v1/orgs/{id}/secret-request-settings. Lives in its
 * own type (not on `OrgInfo`) because the endpoint is distinct, mirrors
 * the backend's `SecretRequestSettingsResponse`, and keeps the base org
 * fetch stable.
 */
export interface SecretRequestSettings {
  allow_unsigned_secret_provide: boolean;
}

/**
 * Shape of GET/PATCH /v1/orgs/{id}/execution-settings. When
 * `default_deferred_execution` is `true`, agents created in this org
 * after the flip are seeded with `auto_call_on_approve = false` —
 * existing agents are not touched.
 */
export interface ExecutionSettings {
  default_deferred_execution: boolean;
}

export interface IdpConfig {
  id?: string;
  org_id?: string;
  provider_key: string;
  display_name: string;
  source: 'env' | 'db';
  /** True when this entry is the Overslash-managed env-var IdP surfaced
   * because the org has `allow_overslash_managed_signin = true`. Sign-in
   * is allowed but admission requires a pending `org_invites` row. */
  managed?: boolean;
  enabled?: boolean;
  allowed_email_domains?: string[];
  uses_org_credentials?: boolean;
  /** Designated default IdP for the org's OAuth authorize flow. The login
   * page on a corp subdomain auto-redirects to the default; only one row
   * per org may be true. */
  is_default?: boolean;
  created_at?: string;
  updated_at?: string;
}

/** One row in the Org Settings → OAuth App Credentials table. */
export interface OAuthCredential {
  provider_key: string;
  display_name: string;
  source: 'env' | 'db';
  client_id_preview: string;
}

export interface McpClient {
  client_id: string;
  client_name: string | null;
  software_id: string | null;
  software_version: string | null;
  redirect_uris: string[];
  created_at: string;
  last_seen_at: string | null;
  is_revoked: boolean;
}

/**
 * Per-agent MCP binding + the connecting client's last-recorded `initialize`
 * state. Used by the Agents detail page to render the "MCP Connection"
 * section. `null` when no MCP client is bound to this agent.
 *
 * `elicitation_supported` is derived from the recorded `capabilities` —
 * `true` when the client declared `capabilities.elicitation` at handshake.
 * The Elicitation Approvals toggle is disabled in the UI when this is
 * `false`, since enabling it would have no effect.
 */
export interface McpConnection {
  client_id: string;
  client_name: string | null;
  software_id: string | null;
  software_version: string | null;
  capabilities: Record<string, unknown> | null;
  client_info: { name?: string; version?: string } | null;
  protocol_version: string | null;
  session_id: string | null;
  connected_at: string;
  last_seen_at: string | null;
  elicitation_enabled: boolean;
  elicitation_supported: boolean;
  /**
   * When true, the agent on this binding may resolve approvals it itself
   * requested via the `overslash_approve_self` MCP tool, and that tool
   * becomes visible in `tools/list`. Default `false` — flipping it on is
   * the human-at-the-keyboard escape hatch for sessions where the operator
   * is comfortable letting the agent rubber-stamp its own actions. See
   * docs/design/agent-self-management.md §2.
   */
  self_approve_enabled: boolean;
}

/**
 * Long-lived `osk_…` API key minted from Org Settings → Service keys.
 * Always carries the `service` pseudo-scope; carries `impersonate` when
 * minted with the danger toggle on. All service keys bind to the org's
 * shared `org-service` Agent identity (auto-created on first mint).
 */
export interface ServiceKeySummary {
  id: string;
  identity_id: string;
  name: string;
  key_prefix: string;
  scopes: string[];
  created_at: string;
  last_used_at: string | null;
}

/**
 * Returned exactly once when a service key is minted. Mirrors the backend's
 * `CreateResponse` — note: `created_at` / `last_used_at` are NOT in this
 * payload (the create endpoint returns only the fields needed for the
 * one-time reveal banner). Use `ServiceKeySummary` from the list endpoint
 * for those.
 */
export interface ServiceKeyCreated {
  id: string;
  identity_id: string;
  /** Plaintext `osk_…`. Must not be persisted by the dashboard. */
  key: string;
  key_prefix: string;
  name: string;
  scopes: string[];
}

export interface Webhook {
  id: string;
  url: string;
  events: string[];
  active: boolean;
}

export interface WebhookCreated extends Webhook {
  secret?: string;
}

export interface WebhookDelivery {
  id: string;
  event: string;
  status_code: number | null;
  attempts: number;
  delivered_at: string | null;
  created_at: string;
  next_retry_at: string | null;
}

// -- Service templates (catalog) --

export type TemplateTier = 'global' | 'org' | 'user';

export interface TemplateSummary {
  key: string;
  display_name: string;
  description?: string | null;
  category?: string | null;
  hosts: string[];
  action_count: number;
  tier: TemplateTier;
  /** `x-overslash-hidden` — shown flagged in the dashboard, omitted from agent-facing surfaces. */
  hidden?: boolean;
}

export interface TemplateDetail {
  key: string;
  display_name: string;
  description?: string | null;
  category?: string | null;
  hosts: string[];
  /** Compiled auth view for rendering the detail/connect UIs without re-parsing. */
  auth: ServiceAuth[];
  /** Raw OpenAPI 3.1 YAML source. This is the editable document. */
  openapi: string;
  /** Compiled actions view for rendering the detail page without re-parsing. */
  actions: ActionSummary[];
  tier: TemplateTier;
  id?: string;
  /** "http" (default) or "mcp". Dashboard switches column layout on this. */
  runtime?: ServiceRuntime;
  /** Present when `runtime === "mcp"`. */
  mcp?: McpDetail;
  /** `x-overslash-hidden` — shown flagged in the dashboard, omitted from agent-facing surfaces. */
  hidden?: boolean;
}

export interface CreateTemplateRequest {
  /** Raw OpenAPI 3.1 YAML. Must include `info.key` (or alias) as the template key. */
  openapi: string;
  user_level?: boolean;
}

export interface UpdateTemplateRequest {
  /** Full replacement OpenAPI YAML. Template key cannot change via update. */
  openapi: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationMessage[];
  warnings: ValidationMessage[];
}

export interface ValidationMessage {
  /** Stable machine-readable identifier, e.g. `"unknown_path_param"`. */
  code?: string;
  path?: string;
  message: string;
}

// -- OpenAPI import / drafts --

/** Request body for `POST /v1/templates/import`. */
export interface ImportTemplateRequest {
  source: ImportSource;
  /** Keep only the listed operationIds (real or synthesized) as actions. */
  include_operations?: string[];
  /** Override `info.x-overslash-key` (or seed it if the source has none). */
  key?: string;
  /** Override `info.title` (used as `display_name`). */
  display_name?: string;
  user_level?: boolean;
  /** Update an existing draft instead of creating a new one. */
  draft_id?: string;
}

export type ImportSource =
  | { type: 'url'; url: string }
  | { type: 'body'; content_type?: string; body: string };

export interface ImportWarning {
  code: string;
  message: string;
  path: string;
}

export interface OperationInfo {
  operation_id: string;
  method: string;
  path: string;
  summary?: string | null;
  included: boolean;
  synthesized_id: boolean;
}

export interface TemplatePreview {
  key: string;
  display_name: string;
  description?: string | null;
  category?: string | null;
  hosts: string[];
  auth: ServiceAuth[];
  actions: ActionSummary[];
}

export interface DraftTemplateDetail {
  id: string;
  tier: TemplateTier;
  /** Canonical OpenAPI 3.1 YAML, editable in the dashboard. */
  openapi: string;
  /** May be null when the draft doesn't yet compile cleanly; `validation.errors` explains why. */
  preview: TemplatePreview | null;
  validation: ValidationResult;
  import_warnings: ImportWarning[];
  operations: OperationInfo[];
}

export interface UpdateDraftRequest {
  openapi: string;
}

export interface ActionSummary {
  key: string;
  method: string;
  path: string;
  description: string;
  risk: string;
  /** MCP tool name when the owning service has `runtime: mcp`. Absent for HTTP. */
  mcp_tool?: string;
  /** MCP outputSchema (JSON Schema), when the tool declares one. */
  output_schema?: unknown;
  /** Admin-hidden tool; the dashboard renders a "hidden" pill. */
  disabled?: boolean;
}

export type ServiceRuntime = 'http' | 'mcp';

export interface McpDetail {
  /** Absent when the template has no default URL (operator must supply one at instance creation). */
  url?: string;
  /** v1: `none` | `bearer`. */
  auth_kind: 'none' | 'bearer';
  /** `true` when the template has a hard-coded `secret_name`; `false` means the operator must supply one at instance creation. */
  has_default_secret_name: boolean;
  autodiscover: boolean;
  /** ISO-8601 of the most recent `tools/list` sync; absent until first resync. */
  discovered_at?: string;
}

/** Full action details including the parameter schema — returned by
 *  `GET /v1/templates/{key}/actions/{action_key}`. Used by the API Explorer
 *  to auto-generate a parameter form. */
export interface ActionDetail {
  key: string;
  method: string;
  path: string;
  description: string;
  risk: string;
  params: Record<string, ActionParam>;
  scope_param?: string;
}

// -- Service instances --

export type ServiceStatus = 'draft' | 'active' | 'archived';

export interface ServiceGroupRef {
  grant_id: string;
  group_id: string;
  group_name: string;
  /** "everyone" | "admins" | "self" for system groups; absent otherwise. The
   *  dashboard renders self grants as a clean "Myself" label off this field
   *  rather than parsing the storage-form `group_name`. */
  system_kind?: 'everyone' | 'admins' | 'self';
  access_level: string;
  auto_approve_reads: boolean;
}

/** Derived from the bound connection's scopes vs. the template's per-action
 *  required_scopes. `needs_authentication` is the freshly-created state for an
 *  auth-bearing template with no connection bound; `needs_reconnect` is the
 *  "connection is bound but no action will work" state. */
export type CredentialsStatus =
  | 'needs_authentication'
  | 'ok'
  | 'partially_degraded'
  | 'needs_reconnect';

export interface ServiceInstanceSummary {
  id: string;
  name: string;
  template_source: string;
  template_key: string;
  status: ServiceStatus;
  is_system: boolean;
  owner_identity_id?: string;
  connection_id?: string;
  secret_name?: string;
  /** Per-instance MCP server URL override. Present only for MCP runtime services. */
  url?: string;
  groups?: ServiceGroupRef[];
  credentials_status?: CredentialsStatus;
}

export interface ServiceInstanceDetail extends ServiceInstanceSummary {
  org_id: string;
  template_id?: string;
  created_at: string;
  updated_at: string;
}

export interface CreateServiceRequest {
  template_key: string;
  name?: string;
  connection_id?: string;
  secret_name?: string;
  url?: string;
  status?: ServiceStatus;
  user_level?: boolean;
}

export interface UpdateServiceRequest {
  name?: string;
  connection_id?: string | null;
  secret_name?: string | null;
  url?: string | null;
}

// -- OAuth --

export interface InitiateConnectionRequest {
  provider: string;
  scopes?: string[];
  byoc_credential_id?: string;
}

/**
 * Entry returned by GET /v1/oauth-providers. The `has_*` flags drive the
 * Create Service BYOC UX: when neither org nor system credentials exist,
 * the user must supply their own OAuth app. Reflects SPEC §7 tiers 2/3.
 */
export interface OAuthProviderInfo {
  key: string;
  display_name: string;
  supports_pkce: boolean;
  has_org_credential: boolean;
  has_system_credential: boolean;
  has_user_byoc_credential: boolean;
  /** Authorized redirect URI the user must register in their own OAuth app. */
  oauth_redirect_uri: string;
  /** Authorized JavaScript origin to register alongside the redirect URI. */
  oauth_js_origin: string;
  /**
   * Scopes the backend always merges into any initiate/upgrade flow for this
   * provider so the OAuth callback can resolve `account_email` via the
   * provider's userinfo endpoint. Rendered alongside service-specific scopes
   * as fixed (non-removable) chips.
   */
  default_identity_scopes: string[];
}

export interface CreateByocCredentialRequest {
  provider: string;
  client_id: string;
  client_secret: string;
  identity_id: string;
}

export interface ByocCredentialSummary {
  id: string;
  org_id: string;
  identity_id: string;
  provider_key: string;
  created_at: string;
  updated_at: string;
}

export interface InitiateConnectionResponse {
  /// The Overslash-gated URL (`/connect-authorize?id=…`); fail-fasts on
  /// session mismatch before redirecting to the provider. Open this in
  /// the popup. Field name is unchanged from the pre-PR shape — the
  /// *value* upgrades to the gated URL so existing callers transparently
  /// inherit the chat-delivery hardening.
  auth_url: string;
  /// Optional shortened form (only present if the shortener is configured).
  short?: string;
  /// Raw provider authorize URL. Only included when the request set
  /// `include_raw: true`.
  raw?: string;
  state: string;
  provider: string;
  expires_at: string;
  flow_id: string;
}

export interface ServiceSummary {
  key: string;
  display_name: string;
  hosts: string[];
  action_count: number;
}

export interface ServiceDetail {
  key: string;
  display_name: string;
  hosts: string[];
  auth: ServiceAuth[];
  actions: Record<string, ServiceAction>;
}

export type ServiceAuth =
  | { type: 'oauth'; provider: string; scopes?: string[]; token_injection: TokenInjection }
  | { type: 'api_key'; default_secret_name: string; injection: TokenInjection };

export interface TokenInjection {
  as: string;
  header_name?: string;
  query_param?: string;
  prefix?: string;
}

export interface ServiceAction {
  method: string;
  path: string;
  description: string;
  risk: string;
  response_type?: string;
  params: Record<string, ActionParam>;
}

export interface ActionParam {
  type: string;
  required: boolean;
  description: string;
  enum?: string[];
  default?: unknown;
}

export interface ConnectionSummary {
  id: string;
  provider_key: string;
  account_email: string | null;
  scopes: string[];
  used_by_service_templates: string[];
  is_default: boolean;
  created_at: string;
}

/** A service instance bound to a connection, for the detail "Used by" list. */
export interface UsedByService {
  id: string;
  name: string;
  template_key: string;
}

/**
 * What OAuth client credentials a connection will use on its next refresh.
 * Mirrors the `client_credentials::resolve()` cascade against current state.
 */
export type CredentialSource =
  | { kind: 'byoc' }
  | { kind: 'org_secret' }
  | { kind: 'system' }
  | { kind: 'missing' };

/** Full connection detail from `GET /v1/connections/{id}`. */
export interface ConnectionDetail {
  id: string;
  provider_key: string;
  account_email: string | null;
  scopes: string[];
  is_default: boolean;
  created_at: string;
  /** Advances on an in-place reconnect — the detail page polls it. */
  updated_at: string;
  used_by: UsedByService[];
  credential_source: CredentialSource;
}

export interface SecretRef {
  name: string;
  inject_as: 'header' | 'query';
  header_name?: string;
  query_param?: string;
  prefix?: string;
}

export interface CallRequest {
  // `service` is required (use 'http' for raw HTTP via the synthetic
  // pseudo-service — the legacy no-service shape is rejected with 400).
  service: string;
  // Optional instance UUID. When set, the backend resolves the service by id
  // (org-scoped) and bypasses the caller-scoped name lookup. Required when an
  // org admin invokes another user's service; ignored otherwise.
  service_id?: string;
  // Service + defined action shape: set `action` + `params`.
  action?: string;
  params?: Record<string, unknown>;
  // Service + HTTP verb shape: set `method` + (`path` or `url`).
  // For `service: "http"`, `url` is required (no host base to prefix).
  method?: string;
  path?: string;
  url?: string;
  headers?: Record<string, string>;
  body?: string;
  secrets?: SecretRef[];
  // Optional server-side filter applied to the upstream JSON response.
  prefer_stream?: boolean;
  filter?: ResponseFilter;
}

export type ResponseFilter = { lang: 'jq'; expr: string };

export type FilterErrorKind =
  | 'body_not_json'
  | 'runtime_error'
  | 'timeout'
  | 'output_overflow';

export type FilteredBody =
  | {
      status: 'ok';
      lang: string;
      values: unknown[];
      original_bytes: number;
      filtered_bytes: number;
    }
  | {
      status: 'error';
      lang: string;
      kind: FilterErrorKind;
      message: string;
      original_bytes: number;
    };

export type CallResponse =
  | {
      status: 'called';
      result: ActionResult;
      action_description: string | null;
      /** True when the upstream itself reported failure (MCP `is_error`
       * envelope, or upstream HTTP >= 400) even though the call executed.
       * Optional for wire-compat with older API builds. */
      is_error?: boolean;
    }
  | {
      status: 'pending_approval';
      approval_id: string;
      approval_url: string;
      action_description: string;
      expires_at: string;
      /**
       * Caller↔requester relationship classified server-side. Always
       * `"self"` here (the caller of `overslash_call` is the requester);
       * the field is present so the same envelope shape works when an
       * ancestor inspects the row via `list_pending` and sees
       * `"downstream"`. MCP clients use it to pick
       * `overslash_approve_self` vs `overslash_approve`.
       */
      relationship: 'self' | 'downstream' | 'not_in_your_chain';
      /** Same broadening ladder GET /v1/approvals/{id} returns — exposed
       *  here so callers can render "remember at a broader scope" prompts
       *  without a second round-trip. Mirrors
       *  ApprovalResponse.suggested_tiers. */
      suggested_tiers: SuggestedTier[];
      /** Mirrors the requesting agent's identities.auto_call_on_approve.
       *  When true (default), allow/allow_remember auto-replays the call and
       *  the result lands via webhook/audit; when false the caller must replay
       *  explicitly. Backend may omit on older builds — treat undefined as
       *  true. */
      auto_call_on_approve?: boolean;
      /** Render-form fields mirroring ApprovalResponse so a white-label caller
       *  can draw the same approval card the dashboard does without a second
       *  GET /v1/approvals/{id}. */
      /** Labeled, human-readable slice of the resolved request (the
       *  x-overslash-disclose summary). Omitted when the template declared
       *  none. Same shape as ApprovalResponse.disclosed_fields. */
      disclosed_fields?: DisclosedField[];
      /** Risk class for the gated action; drives card severity styling.
       *  Mirrors ApprovalResponse.risk. */
      risk: 'low' | 'med' | 'high';
      /** Permission key(s) being requested. Mirrors
       *  ApprovalResponse.permission_keys. */
      permission_keys: string[];
      /** Redacted, pretty-printed request payload, truncated at 100 KB.
       *  Omitted when no detail was stored. Mirrors
       *  ApprovalResponse.action_detail + its truncation companions. */
      action_detail?: string;
      action_detail_truncated: boolean;
      action_detail_size_bytes: number;
    }
  | { status: 'denied'; reason: string };

/** Mirrors crates/overslash-api/src/routes/identities.rs IdentityResponse. */
export interface Identity {
  id: string;
  org_id: string;
  name: string;
  kind: 'user' | 'agent' | 'sub_agent';
  external_id: string | null;
  email?: string | null;
  provider?: string | null;
  picture?: string | null;
  parent_id: string | null;
  depth: number;
  owner_id: string | null;
  inherit_permissions: boolean;
  /**
   * When `true` (default), resolving an approval for this identity as
   * `allow`/`allow_remember` automatically replays the underlying call.
   * Flipping to `false` puts the agent in "deferred execution" mode —
   * the resolver/agent must call `POST /v1/approvals/{id}/call` explicitly.
   * Meaningless for `user`-kind rows. Backend may omit on older API
   * builds; treat `undefined` as `true` for display fallback.
   */
  auto_call_on_approve?: boolean;
  created_at?: string;
  last_active_at?: string;
  archived_at?: string | null;
  archived_reason?: string | null;
}

export interface PermissionRule {
  id: string;
  identity_id: string;
  action_pattern: string;
  effect: string;
}

export interface ActionResult {
  status_code: number;
  headers: Record<string, string>;
  body: string;
  duration_ms: number;
  filtered_body?: FilteredBody;
}

// -- Secrets dashboard --

/** GET /v1/secrets item — flattened metadata for the list view. */
export interface SecretSummary {
  name: string;
  current_version: number;
  /** Slot-owner identity (`secrets.owner_identity_id` column). Set on
   * first insert and preserved across subsequent versions; NULL for
   * legacy/org-wide rows that are admin-only (SPEC §6). */
  owner_identity_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface SecretVersionView {
  version: number;
  created_at: string;
  /** Identity that wrote this version. May differ from `owner_identity_id`
   *  on slots where another agent under the same user rotated the value. */
  created_by: string | null;
  /** Human who pasted the value on the standalone provide page (User
   *  Signed Mode); usually null. */
  provisioned_by_user_id: string | null;
}

export interface SecretUsedByView {
  id: string;
  name: string;
  status: 'active' | 'draft' | 'archived' | string;
}

/** GET /v1/secrets/{name} — detail with versions and used-by. */
export interface SecretDetail extends SecretSummary {
  versions: SecretVersionView[];
  used_by: SecretUsedByView[];
}

/** POST /v1/secrets/{name}/versions/{v}/reveal */
export interface SecretReveal {
  version: number;
  value: string;
}
