export interface Identity {
	id: string;
	org_id: string;
	name: string;
	kind: 'user' | 'agent';
	external_id: string | null;
	created_at: string;
}

export interface ApiKey {
	id: string;
	key?: string; // Only present on creation
	key_prefix: string;
	name: string;
	identity_id: string | null;
	last_used_at: string | null;
	created_at: string;
}

export interface Secret {
	name: string;
	current_version: number;
	created_at?: string;
}

export interface Permission {
	id: string;
	identity_id: string;
	action_pattern: string;
	effect: 'allow' | 'deny';
	created_at: string;
}

export interface Approval {
	id: string;
	identity_id: string;
	action_summary: string;
	permission_keys: string[];
	status: 'pending' | 'allowed' | 'denied' | 'expired';
	token: string;
	expires_at: string;
	created_at: string;
}

export interface Connection {
	id: string;
	provider_key: string;
	account_email: string | null;
	is_default: boolean;
	created_at: string;
}

export interface ServiceSummary {
	key: string;
	display_name: string;
	hosts: string[];
	action_count: number;
}

export interface ServiceAction {
	key: string;
	method: string;
	path: string;
	description: string;
	risk: string;
}

export interface ServiceDetail {
	key: string;
	display_name: string;
	hosts: string[];
	auth: unknown[];
	actions: Record<string, ServiceAction>;
}

export interface AuditEntry {
	id: string;
	identity_id: string | null;
	action: string;
	resource_type: string | null;
	resource_id: string | null;
	detail: unknown;
	ip_address: string | null;
	created_at: string;
}

export interface Webhook {
	id: string;
	url: string;
	events: string[];
	active: boolean;
	created_at: string;
}

export interface ByocCredential {
	id: string;
	org_id: string;
	identity_id: string | null;
	provider_key: string;
	created_at: string;
	updated_at: string;
}

export interface User {
	identity_id: string;
	org_id: string;
	email: string;
}
