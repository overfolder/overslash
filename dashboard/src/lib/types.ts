// Mirrors backend Rust types from overslash-core and overslash-api

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

export interface ActionResult {
  status_code: number;
  headers: Record<string, string>;
  body: string;
  duration_ms: number;
}
