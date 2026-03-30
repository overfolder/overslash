export interface Identity {
	id: string;
	org_id: string;
	name: string;
	kind: 'user' | 'agent';
	parent_id: string | null;
	depth: number;
	external_id: string | null;
	email: string | null;
	created_at: string;
}

export interface Org {
	id: string;
	name: string;
	slug: string;
}

export interface ApiKey {
	id: string;
	name: string;
	key_prefix: string;
	identity_id: string | null;
	last_used_at: string | null;
	created_at: string;
}

export interface CreatedApiKey {
	id: string;
	key: string;
	key_prefix: string;
	name: string;
}

export interface Session {
	identity_id: string;
	org_id: string;
	email: string;
}
