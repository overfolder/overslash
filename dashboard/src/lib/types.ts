export interface UserInfo {
	identity_id: string;
	org_id: string;
	email: string;
}

export interface Role {
	id: string;
	org_id: string;
	name: string;
	slug: string;
	description: string;
	is_builtin: boolean;
	grants?: Grant[];
	created_at: string;
	updated_at: string;
}

export interface Grant {
	id: string;
	resource_type: string;
	action: string;
}

export interface Assignment {
	id: string;
	org_id: string;
	identity_id: string;
	role_id: string;
	assigned_by: string | null;
	created_at: string;
}

export interface Identity {
	id: string;
	org_id: string;
	name: string;
	kind: string;
	external_id: string | null;
}

export interface MyPermissions {
	identity_id: string;
	permissions: { resource_type: string; action: string }[];
	is_admin: boolean;
}

export interface AclStatus {
	has_admin: boolean;
	admin_count: number;
	admin_identities: { identity_id: string }[];
}

export interface AuditEntry {
	id: string;
	identity_id: string | null;
	action: string;
	resource_type: string | null;
	resource_id: string | null;
	detail: Record<string, unknown>;
	ip_address: string | null;
	created_at: string;
}

export const RESOURCE_TYPES = [
	'services',
	'connections',
	'secrets',
	'agents',
	'approvals',
	'audit_logs',
	'webhooks',
	'org_settings',
	'acl'
] as const;

export const ACTIONS = ['read', 'write', 'delete', 'manage'] as const;

export const RESOURCE_TYPE_LABELS: Record<string, string> = {
	services: 'Services',
	connections: 'Connections',
	secrets: 'Secrets',
	agents: 'Agents',
	approvals: 'Approvals',
	audit_logs: 'Audit Logs',
	webhooks: 'Webhooks',
	org_settings: 'Org Settings',
	acl: 'ACL'
};
