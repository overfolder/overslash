// Mirrors backend Rust types from overslash-core and overslash-api

export interface OrgInfo {
  id: string;
  name: string;
  slug: string;
  subagent_idle_timeout_secs: number;
  subagent_archive_retention_days: number;
}

export interface IdpConfig {
  id?: string;
  org_id?: string;
  provider_key: string;
  display_name: string;
  source: 'env' | 'db';
  enabled?: boolean;
  allowed_email_domains?: string[];
  created_at?: string;
  updated_at?: string;
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
  auth: ServiceAuth[];
  actions: Record<string, ServiceAction>;
  tier: TemplateTier;
  id?: string;
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
  | { type: 'oauth'; provider: string; token_injection: TokenInjection }
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
