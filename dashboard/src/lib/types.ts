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
