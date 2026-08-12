// Mirrors backend Rust types from overslash-core and overslash-api

import type { DisclosedField, SuggestedTier } from './session';

/** GET /v1/version — build identity of the API this dashboard is talking to.
 *  `commit` is a full 40-char SHA, or the literal `"unknown"` when the build
 *  had neither a git checkout nor an injected SHA. */
export interface BuildInfo {
  version: string;
  commit: string;
  commit_short: string;
  /** Whether the build carries the D42 SQL parser (`sql_policy` Cargo
   *  feature). `false` means SQL-annotated actions never get parsed — they
   *  fail closed to write-on-unknown-tables and always route to approval. */
  sql_policy: boolean;
  /** Whether this deployment runs the Live Map — `OVERSLASH_LIVE_MAP` on the
   *  API. Gates the `/map` nav item and the page itself: without it no
   *  `action.*` events are emitted and the graph would never move. */
  live_map: boolean;
}

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
  /** When true (default), a managed-signin org admits invite-only. When
   * false, admission falls back to the `managed_signin_allowed_domains`
   * allowlist below. Independent of `allow_overslash_managed_signin`. */
  require_invite_admission: boolean;
  /** Org-wide email-domain allowlist consulted on the managed path when
   * `require_invite_admission` is false. Empty ⇒ domain admission is
   * unconfigured (managed sign-ins rejected as misconfigured, NOT open). */
  managed_signin_allowed_domains: string[];
}

/**
 * A pre-created member, projected onto the invite wire shape. Backed by a
 * `kind='user'` identity (the `org_invites` table was dropped in migration
 * 103): `status: 'pending'` while the person has never signed in
 * (`external_id IS NULL`), `'accepted'` once an SSO callback adopted the
 * identity. Pending members are the admission gate for orgs with
 * `allow_overslash_managed_signin = true`.
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
  /** Default upstream timeout for action calls, in ms. `null` inherits the
   * deployment default. A template action or an individual call overrides it. */
  call_timeout_ms: number | null;
  /** Ceiling on any resolved call timeout, in ms. `null` inherits the
   * deployment maximum. A caller asking for more is rejected. */
  max_call_timeout_ms: number | null;
}

/** Org-level capture mode for upstream response bodies on
 * `action.executed` audit rows: `off` stores nothing (default),
 * `errors_only` stores bodies of failed executions (`detail.is_error`),
 * `all` stores every captured body. Bodies are truncated server-side
 * (64 KB default). */
export type AuditResponseBodyMode = 'off' | 'errors_only' | 'all';

export interface AuditSettings {
  response_body_mode: AuditResponseBodyMode;
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
  /** Base template key when this row is a derived layer; absent for standalone/global. */
  extends?: string;
  /** Count of fold-time resolution warnings (drift, shadowed extensions, dead entries). */
  warnings?: number;
}

/**
 * Admin compliance view (`GET /v1/templates/admin`): every template across all
 * tiers. Global rows carry an `enabled` flag reflecting the org's curated-catalog
 * allow-list; org/user rows are always enabled.
 */
export interface AdminTemplateSummary extends TemplateSummary {
  id?: string | null;
  owner_identity_id?: string | null;
  /** For global rows: whether the template is in the org's curated catalog. */
  enabled: boolean;
  /** Raw stored delta for a derived layer, so the catalog can toggle `hidden`
   * without a second fetch. Absent for standalone/global rows. */
  delta?: Delta;
}

/** Whether org members may create user-namespace layers. `restrictive` is
 * reserved (mask-only) and not yet enforced. */
export type UserTemplatePolicy = 'none' | 'restrictive' | 'full';

/**
 * Org-level template/catalog settings (`/v1/orgs/{id}/template-settings`).
 */
export interface TemplateSettings {
  /** Whether members may create user-namespace layers (`none` | `restrictive` | `full`). */
  user_template_policy: UserTemplatePolicy;
  /** When true, every global template is available; when false, only curated ones. */
  global_templates_enabled: boolean;
  /** When false (default), non-admins cannot instantiate globals outside the curated catalog. */
  allow_services_outside_catalog: boolean;
}

/**
 * The `read < write < delete` risk ladder, ascending.
 *
 * Mirrors `Risk::severity` in crates/overslash-core/src/types/service/risk.rs.
 * The *order* is the contract, not just the membership: it is what gives the
 * audit log's `risk >=` its meaning, so the two must not drift.
 */
export const RISK_LADDER = ['read', 'write', 'delete'] as const;

export type RiskLevel = (typeof RISK_LADDER)[number];

export function isRiskLevel(v: string): v is RiskLevel {
  return (RISK_LADDER as readonly string[]).includes(v);
}

/** One entry in a derived layer's per-action metadata mask. */
export interface ActionPatch {
  /** Clamp risk upward only (adds approvals): `read` | `write` | `delete`. */
  risk?: 'read' | 'write' | 'delete';
  /** Relabel the action description. */
  description?: string;
  /** Additive disclose specs. */
  disclose?: unknown[];
}

/** The expansive half of a delta: new actions + hosts. No auth, no rebinding. */
export interface Extensions {
  /** New actions keyed by action key. Each value is an OpenAPI operation fragment. */
  actions?: Record<string, { method: string; path: string; operation?: unknown }>;
  /** Additional hosts unioned onto the base. */
  hosts?: string[];
}

/**
 * Defaults an org layer supplies for the surface a service instance would
 * otherwise fill in by hand. Non-secret only — credentials and connections are
 * never expressible in a delta. Org-tier layers only; the API rejects these on
 * a user layer.
 *
 * Precedence at execution is `instance > layer > template`.
 */
export interface InstanceDefaults {
  /** Endpoint every instance dials unless it sets its own `url`. */
  url?: string;
  /** Defaults for params declared `x-overslash-instance-config`, by param name. */
  config?: Record<string, string>;
}

/**
 * A derived layer's stored content — a mask half (restrictive) and an extension
 * half (expansive). Resolved by the fold as `apply(delta, resolve(extends))`.
 */
export interface Delta {
  /** Drop the derived template from the catalog. */
  hidden?: boolean;
  /** Relabel the template / description. */
  display_name?: string;
  description?: string;
  /** Keep only these action keys (∩). `[]` = expose nothing; omit = keep all. */
  allowlist?: string[];
  /** Drop these action keys (\). */
  denylist?: string[];
  /** Per-action metadata masks over the base's actions. */
  action_patch?: Record<string, ActionPatch>;
  /** New actions + hosts. */
  extensions?: Extensions;
  /** Defaults every instance of this layer inherits. Org-tier layers only. */
  instance_defaults?: InstanceDefaults;
}

/** Non-blocking resolution warnings computed during the fold. */
export interface ResolutionReport {
  warnings: ValidationMessage[];
}

export interface TemplateDetail {
  key: string;
  display_name: string;
  description?: string | null;
  category?: string | null;
  hosts: string[];
  /** Compiled auth view for rendering the detail/connect UIs without re-parsing. */
  auth: ServiceAuth[];
  /**
   * Credential slots an instance binds — one vault secret each. A slot may
   * feed several injections and an injection may join several slots, so this
   * is not derivable from `auth`; it is what the credentials form renders.
   */
  secrets?: SecretSlot[];
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
  /** True when the endpoint URL is set per instance (MCP servers, or HTTP
   * gateways like the `email` Mailbox Gateway). The instance form reveals a
   * URL field when this is set. */
  configurable_url?: boolean;
  /** Params an org may pin per instance (`x-overslash-instance-config`), deduped
   * across actions. The instance form renders one field each and submits them
   * as `config`. */
  instance_config_params?: InstanceConfigParam[];
  /** Effective defaults an org layer in this chain supplies for the per-instance
   * surface. The instance form renders these as placeholders — leaving a field
   * blank inherits the layer's value. */
  instance_defaults?: InstanceDefaults;
  /** Base template key when this is a derived layer; absent for standalone/global. */
  extends?: string;
  /** The stored delta for a derived layer; absent for standalone/global. */
  delta?: Delta;
  /** Fold-time resolution warnings (drift, shadowed extensions, dead entries). */
  resolution_report?: ResolutionReport;
}

/** A value an org can set on a service instance — either a pinnable action
 * param (`x-overslash-instance-config`) or a credential template's non-secret
 * input (`components.x-overslash-config`). Both live in the instance's one
 * `config` map, so the form renders them as one list. */
export interface InstanceConfigParam {
  name: string;
  type: string;
  description?: string;
  required?: boolean;
  /** Human label, when the declaration gives one. Config vars carry one
   * ("Mailbox username") because their key is not a header name an operator
   * would recognise; params have none and fall back to `name`. */
  label?: string;
}

export interface CreateTemplateRequest {
  /** Raw OpenAPI 3.1 YAML for a standalone layer. Mutually exclusive with `extends`. */
  openapi?: string;
  user_level?: boolean;
  /** Base template key for a derived layer. Requires `delta`. */
  extends?: string;
  /** The derived-layer delta. Required iff `extends` is set. */
  delta?: Delta;
  /** Layer key for a derived layer. Defaults to `extends` (shadow-with-delta). */
  key?: string;
  /** Display name for a derived layer. */
  display_name?: string;
  /** Category for a derived layer. */
  category?: string;
}

export interface UpdateTemplateRequest {
  /** Full replacement OpenAPI YAML for a standalone layer. Key cannot change. */
  openapi?: string;
  /** Replacement delta for a derived layer. */
  delta?: Delta;
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

/**
 * A deployment-supplied template variable (D44): what `${NAME}` resolves to in
 * a service template on this deployment.
 *
 * The value is not a secret and is not treated as one — only non-secret
 * deployment facts (hostnames, base URLs) may be configured under
 * `OVERSLASH_TEMPLATE_VAR_*`, precisely because any template author can read
 * them back through a resolved definition.
 */
export interface TemplateVar {
  /** The name a template references — the env var minus its prefix. */
  name: string;
  value: string;
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
  /** Agent-facing text: the full contract, examples included. May be a
   *  paragraph — prefer `summary` for a table cell. */
  description: string;
  /** Short one-line label. Absent when the action authors a single string for
   *  both jobs, in which case `description` is already short. */
  summary?: string;
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
  /** `none` | `bearer` | `oauth`. */
  auth_kind: 'none' | 'bearer' | 'oauth';
  /** `true` when the template has a hard-coded `secret_name`; `false` means the operator must supply one at instance creation. */
  has_default_secret_name: boolean;
  /** OAuth provider key when `auth_kind === 'oauth'` (D24); drives the connect affordance. */
  provider?: string;
  /** Superset OAuth scopes requested at connect time when `auth_kind === 'oauth'`. */
  scopes?: string[];
  autodiscover: boolean;
  /** ISO-8601 of the most recent `tools/list` sync; absent until first resync. */
  discovered_at?: string;
}

/** Mirrors overslash_core::types::ScopeParamRef */
export interface ScopeParamRef {
  param: string;
  label: string;
}

/** Full action details including the parameter schema — returned by
 *  `GET /v1/templates/{key}/actions/{action_key}`. Used by the API Explorer
 *  to auto-generate a parameter form. */
export interface ActionDetail {
  key: string;
  method: string;
  path: string;
  /** Agent-facing text: what the model reads when choosing this action. */
  description: string;
  /** Short interpolatable label used for the approval title. Absent when the
   *  action authors only one string for both jobs. */
  summary?: string;
  risk: string;
  params: Record<string, ActionParam>;
  /** Which params supply the `{arg}` segment of the action's permission keys,
   *  each resolved to the label its values are filed under (`to` → `recipient`).
   *  Params sharing a label share one key namespace. Absent when the action is
   *  unscoped. The template document's compact `param:label` shorthand is
   *  parsed server-side — never here. */
  scope_param?: ScopeParamRef[];
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
  /** "none" | "read" | "write" | "admin" — how far up the ladder actions on
   *  this service skip approval for members of this group. Never above
   *  `access_level`. */
  auto_approve_level: string;
  /** @deprecated derived from `auto_approve_level !== 'none'`. */
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
  /** Per-scheme secret bindings: securityScheme key → secret NAME in the org vault. */
  credentials?: Record<string, string>;
  /** Per-instance non-secret param values (plain values, not vault references).
   * Keys are template params marked `x-overslash-instance-config`. */
  config?: Record<string, string>;
  /** Per-instance MCP server URL override. Present only for MCP runtime services. */
  url?: string;
  /** When `false`, an unbound instance won't fall back to the identity's default connection for the provider. Defaults to `true`. */
  use_default_connection: boolean;
  groups?: ServiceGroupRef[];
  credentials_status?: CredentialsStatus;
}

export interface ServiceInstanceDetail extends ServiceInstanceSummary {
  org_id: string;
  template_id?: string;
  created_at: string;
  updated_at: string;
  /** When this instance's MCP tools were last resynced (RFC3339). Absent until the first resync. */
  discovered_at?: string;
}

export interface CreateServiceRequest {
  template_key: string;
  name?: string;
  connection_id?: string;
  secret_name?: string;
  /** Per-scheme secret bindings: securityScheme key → secret NAME in the org vault. */
  credentials?: Record<string, string>;
  /** Per-instance non-secret param values. Keys must be template params marked
   * `x-overslash-instance-config`. */
  config?: Record<string, string>;
  url?: string;
  status?: ServiceStatus;
  user_level?: boolean;
  /**
   * Group grants to attach at creation. Required (non-empty) when
   * `user_level` is `false`: an org-level instance has no Myself group, so
   * without a grant nothing can reach it. At least one must be a group the
   * caller belongs to.
   */
  groups?: ServiceGroupGrantInput[];
  /** When `false`, this instance won't fall back to the default connection for its provider. Defaults to `true` server-side. */
  use_default_connection?: boolean;
}

export interface ServiceGroupGrantInput {
  group_id: string;
  /** read | write | admin. Defaults to `write` server-side. */
  access_level?: 'read' | 'write' | 'admin';
  auto_approve_reads?: boolean;
}

export interface UpdateServiceRequest {
  name?: string;
  connection_id?: string | null;
  secret_name?: string | null;
  /** Per-scheme secret bindings: whole-map replace ({} clears every binding); omit to leave unchanged. */
  credentials?: Record<string, string>;
  /** Per-instance non-secret param values: whole-map replace ({} clears every
   * value); omit to leave unchanged. */
  config?: Record<string, string>;
  url?: string | null;
  use_default_connection?: boolean;
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
  /** Opaque caller-supplied provenance tag (key=value), echoed verbatim. */
  metadata: Record<string, string>;
  created_at: string;
  updated_at: string;
}

/**
 * Body of `PUT /v1/byoc-credentials/{id}` — replaces the client id/secret in
 * place (the credential id and its connection pins survive). Replacing marks
 * every pinned connection `reauth_required`.
 */
export interface UpdateByocCredentialRequest {
  client_id: string;
  client_secret: string;
  metadata?: Record<string, string>;
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
  /**
   * Credential slots the operator binds — one vault secret each. Declared once
   * per template and referenced by the auth entries' templates, so one secret
   * can feed several headers and one header can join several secrets. This is
   * the list the credentials form renders.
   */
  secrets?: SecretSlot[];
  actions: Record<string, ServiceAction>;
}

/** One vault secret an instance binds, keyed by `key` in its `credentials` map. */
export interface SecretSlot {
  key: string;
  /** Display name for the row (e.g. "Mailbox username"). */
  label?: string;
  /** Help text under the picker. */
  description?: string;
  /** Org-vault secret used when `source: 'org'` and nothing is bound. */
  default_secret_name?: string;
  source?: 'instance' | 'org';
  /** When true, an unbound credential is skipped instead of failing the request. */
  optional?: boolean;
}

export type ServiceAuth =
  | { type: 'oauth'; provider: string; scopes?: string[]; token_injection: TokenInjection }
  | {
      type: 'secret';
      /** The securitySchemes key this injection was compiled from (e.g. `gateway`, `mailbox`). */
      scheme?: string;
      /** Short display name from `x-overslash-label` (e.g. "Overfwd API Token"). */
      label?: string;
      /** The OpenAPI securityScheme `description`. */
      description?: string;
      default_secret_name: string;
      injection: TokenInjection;
      /**
       * How the value is built from `slots` — e.g.
       * `'"Basic " + (.mailbox_user + ":" + .mailbox_pass | @base64)'`.
       * Absent means the single slot's secret is injected verbatim. Never
       * rendered to end users.
       */
      template?: CredentialTemplate;
      /** Slot keys this injection reads. */
      slots?: string[];
      /**
       * Fallback when the instance has no explicit `credentials[slot]` binding:
       * `instance` (default) → the legacy scalar `secret_name`; `org` → the fixed
       * `default_secret_name` from the org vault.
       */
      secret_source?: 'instance' | 'org';
      /** When true, an unbound credential is skipped instead of failing the request. */
      optional?: boolean;
    };

export interface CredentialTemplate {
  lang: 'jq';
  expr: string;
}

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
  /** Owner identity (the user the linked account belongs to). The admin
   *  "all users' connections" view resolves this to a display name. */
  owner_identity_id: string;
  provider_key: string;
  account_email: string | null;
  scopes: string[];
  used_by_service_templates: string[];
  is_default: boolean;
  /** When true, this connection is preserved when a service bound to it is
   *  deleted, even if nothing else references it. */
  keep: boolean;
  /** When true, the connection must be re-authorized before use (e.g. its
   *  pinned BYOC client was replaced). Cleared on the next successful reconnect. */
  reauth_required: boolean;
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
 * `integration_managed` is reported for imported token-vault connections that
 * have no shared client — Overslash never refreshes them; the integration
 * refreshes and re-imports.
 */
export type CredentialSource =
  | { kind: 'byoc' }
  | { kind: 'org_secret' }
  | { kind: 'system' }
  | { kind: 'integration_managed' }
  | { kind: 'missing' };

/** Full connection detail from `GET /v1/connections/{id}`. */
export interface ConnectionDetail {
  id: string;
  provider_key: string;
  account_email: string | null;
  scopes: string[];
  is_default: boolean;
  /** When true, this connection is preserved from the service-deletion
   *  auto-cleanup (toggled via `setConnectionKeep`). */
  keep: boolean;
  /**
   * `true` for imported (token-vault) connections whose refresh the
   * integration owns. Overslash injects the stored token until expiry, then
   * signals reauth with no reconnect link (the partner refreshes & re-imports).
   */
  integration_managed: boolean;
  /** When true, the connection must be re-authorized before use (e.g. its
   *  pinned BYOC client was replaced). Cleared on the next successful reconnect. */
  reauth_required: boolean;
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
  | { status: 'denied'; reason: string }
  /** Gateway-level "the target service needs auth" results. Only surfaced
   *  when the caller opts into error-wrapping (`?wrap=true`, used by the
   *  dashboard "try it" surface) — otherwise these come back as a `401`.
   *  Mirrors the `AppError::NeedsAuthentication` / `ReauthRequired` bodies. */
  | {
      status: 'needs_authentication';
      service?: string;
      service_instance_id?: string;
      connection_id?: string;
      auth_url: string;
      short?: string;
      raw?: string;
    }
  | {
      status: 'reauth_required';
      connection_id: string;
      auth_url: string;
      reason: string;
      short?: string;
      raw?: string;
    };

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
  /**
   * `true` for a `user` identity that was pre-created (invited or
   * impersonation-provisioned) but has never completed a sign-in
   * (`external_id IS NULL`). Drives the Members-page "pending" badge.
   */
  pending?: boolean;
  /**
   * How this identity was auto-provisioned, e.g. `"impersonation"`.
   * Absent for identities created through the normal API/UI/SSO paths.
   */
  provisioned_by?: string | null;
  created_at?: string;
  last_active_at?: string;
  archived_at?: string | null;
  archived_reason?: string | null;
}

export interface PermissionRule {
  id: string;
  identity_id: string;
  action_pattern: string;
  /** `action_pattern` as a sentence, rendered server-side by the same describer
   *  that writes an approval's suggested tiers. */
  description: string;
  effect: string;
  expires_at: string | null;
  created_at: string;
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
