// Mirrors backend Rust types from overslash-core and overslash-api

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

export interface ActionResult {
  status_code: number;
  headers: Record<string, string>;
  body: string;
  duration_ms: number;
}

// ── Admin types ─────────────────────────────────────────────────────

export interface TemplateSummary {
  key: string;
  display_name: string;
  description: string;
  category: string;
  hosts: string[];
  action_count: number;
  tier: 'global' | 'org' | 'user';
  id: string | null;
}

export interface TemplateDetail extends TemplateSummary {
  auth: ServiceAuth[];
  actions: Record<string, ServiceAction>;
}

export interface ServiceInstanceSummary {
  id: string;
  name: string;
  template_source: string;
  template_key: string;
  status: string;
  owner_identity_id: string | null;
  connection_id: string | null;
  secret_name: string | null;
  created_at: string;
  updated_at: string;
}

export interface WebhookSummary {
  id: string;
  url: string;
  events: string[];
  active: boolean;
}

export interface WebhookDelivery {
  id: string;
  subscription_id: string;
  event: string;
  status_code: number | null;
  response_body: string | null;
  attempts: number;
  delivered_at: string | null;
  created_at: string;
}

export interface GroupResponse {
  id: string;
  org_id: string;
  name: string;
  description: string;
  allow_raw_http: boolean;
  created_at: string;
  updated_at: string;
}

export interface GroupGrantResponse {
  id: string;
  group_id: string;
  service_instance_id: string;
  service_name: string;
  access_level: string;
  auto_approve_reads: boolean;
  created_at: string;
}

export interface GroupMemberResponse {
  identity_id: string;
  group_id: string;
  assigned_at: string;
}

export interface IdpConfigResponse {
  id?: string;
  org_id?: string;
  provider_key: string;
  display_name: string;
  enabled: boolean;
  allowed_email_domains?: string[];
  source: 'env' | 'db';
  created_at?: string;
  updated_at?: string;
}

export interface OrgDetail {
  id: string;
  name: string;
  slug: string;
  allow_user_templates: boolean;
  created_at: string;
}

export interface IdentitySummary {
  id: string;
  org_id: string;
  name: string;
  kind: string;
  email: string | null;
  external_id: string | null;
  created_at: string;
}
