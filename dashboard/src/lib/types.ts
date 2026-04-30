// Mirrors backend Rust types from overslash-core and overslash-api

export interface OrgInfo {
  id: string;
  name: string;
  slug: string;
  subagent_idle_timeout_secs: number;
  subagent_archive_retention_days: number;
  /** Populated on post-multi-org backends; undefined on older APIs. Personal
   *  orgs hide the IdP + OAuth credential surfaces entirely. */
  is_personal?: boolean;
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

export interface IdpConfig {
  id?: string;
  org_id?: string;
  provider_key: string;
  display_name: string;
  source: 'env' | 'db';
  enabled?: boolean;
  allowed_email_domains?: string[];
  uses_org_credentials?: boolean;
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
}

export interface UpstreamConnection {
  id: string;
  upstream_resource: string;
  status: 'pending_auth' | 'ready' | 'revoked' | 'error';
  has_token: boolean;
  access_token_expires_at: string | null;
  created_at: string;
  last_refreshed_at: string | null;
}

export interface InitiateUpstreamResponse {
  status: 'ready' | 'pending_auth';
  flow_id?: string;
  expires_at?: string;
  authorize_urls?: {
    proxied: string;
    short?: string | null;
    raw?: string | null;
  };
  connection_id?: string;
  upstream_resource?: string;
  access_token_expires_at?: string | null;
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
 *  required_scopes. `needs_reconnect` is the "no action at all will work" state. */
export type CredentialsStatus = 'ok' | 'partially_degraded' | 'needs_reconnect';

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
  auth_url: string;
  state: string;
  provider: string;
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

export interface SecretRef {
  name: string;
  inject_as: 'header' | 'query';
  header_name?: string;
  query_param?: string;
  prefix?: string;
}

export interface CallRequest {
  // Mode A: Raw HTTP
  method?: string;
  url?: string;
  headers?: Record<string, string>;
  body?: string;
  secrets?: SecretRef[];
  // Mode B: Connection
  connection?: string;
  // Mode C: Service + Action
  service?: string;
  action?: string;
  params?: Record<string, unknown>;
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
  | { status: 'called'; result: ActionResult; action_description: string | null }
  | {
      status: 'pending_approval';
      approval_id: string;
      approval_url: string;
      action_description: string;
      expires_at: string;
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
  /** Identity that wrote v1 — the slot owner (SPEC §6). */
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
