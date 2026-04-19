// Mirrors backend Rust types from overslash-core and overslash-api

export interface OrgInfo {
  id: string;
  name: string;
  slug: string;
  subagent_idle_timeout_secs: number;
  subagent_archive_retention_days: number;
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
  path?: string;
  message: string;
}

export interface ActionSummary {
  key: string;
  method: string;
  path: string;
  description: string;
  risk: string;
}

// -- Service instances --

export type ServiceStatus = 'draft' | 'active' | 'archived';

export interface ServiceInstanceSummary {
  id: string;
  name: string;
  template_source: string;
  template_key: string;
  status: ServiceStatus;
  owner_identity_id?: string;
  connection_id?: string;
  secret_name?: string;
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
  status?: ServiceStatus;
  user_level?: boolean;
}

export interface UpdateServiceRequest {
  name?: string;
  connection_id?: string | null;
  secret_name?: string | null;
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

export interface ExecuteRequest {
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
}

export type ExecuteResponse =
  | { status: 'executed'; result: ActionResult; action_description: string | null }
  | {
      status: 'pending_approval';
      approval_id: string;
      approval_url: string;
      action_description: string;
      expires_at: string;
    }
  | { status: 'denied'; reason: string };

export interface Identity {
  id: string;
  org_id: string;
  name: string;
  kind: 'user' | 'agent' | 'sub_agent';
  external_id: string | null;
  parent_id: string | null;
  depth: number;
  owner_id: string | null;
  inherit_permissions: boolean;
}

export interface PermissionRule {
  id: string;
  identity_id: string;
  action_pattern: string;
  effect: string;
}

export interface EnrollmentToken {
  id: string;
  identity_id: string;
  token_prefix: string;
  expires_at: string;
  created_at: string;
}

export interface CreatedEnrollmentToken {
  id: string;
  token: string;
  token_prefix: string;
  identity_id: string;
  expires_at: string;
}

export interface ActionResult {
  status_code: number;
  headers: Record<string, string>;
  body: string;
  duration_ms: number;
}
