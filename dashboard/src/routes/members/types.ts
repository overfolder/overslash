/** Mirrors crates/overslash-api/src/routes/identities.rs IdentityResponse */
export interface Identity {
	id: string;
	org_id: string;
	name: string;
	kind: 'user' | 'agent' | 'sub_agent';
	external_id: string | null;
	email: string | null;
	provider: string | null;
	picture: string | null;
	parent_id: string | null;
	depth: number;
	owner_id: string | null;
	inherit_permissions: boolean;
	created_at: string;
	last_active_at: string;
	archived_at?: string;
	archived_reason?: string;
}

/** Mirrors crates/overslash-api/src/routes/api_keys.rs ApiKeySummary */
export interface ApiKeySummary {
	id: string;
	identity_id: string | null;
	name: string;
	key_prefix: string;
	created_at: string;
	last_used_at: string | null;
	revoked_at: string | null;
}
