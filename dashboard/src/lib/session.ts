/**
 * Cookie-based API client for authenticated dashboard pages.
 *
 * In dev, requests are proxied by Vite to the Rust backend on :3000.
 * Auth relies on the `oss_session` HttpOnly cookie set by the backend.
 */

export class ApiError extends Error {
	constructor(
		public status: number,
		public body: unknown
	) {
		super(`API error ${status}`);
		this.name = 'ApiError';
	}
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
	const init: RequestInit = {
		method,
		headers: { 'Content-Type': 'application/json' },
		credentials: 'include' // send cookies
	};
	if (body !== undefined) {
		init.body = JSON.stringify(body);
	}

	const res = await fetch(path, init);

	if (!res.ok) {
		let errorBody: unknown;
		try {
			errorBody = await res.json();
		} catch {
			errorBody = await res.text();
		}
		if (res.status === 401 && typeof window !== 'undefined') {
			const here = window.location.pathname + window.location.search;
			if (window.location.pathname !== '/login') {
				window.location.href = `/login?reason=expired&return_to=${encodeURIComponent(here)}`;
			}
		}
		throw new ApiError(res.status, errorBody);
	}

	// Handle 204 No Content
	if (res.status === 204) {
		return undefined as T;
	}

	return res.json();
}

export const session = {
	get: <T>(path: string) => request<T>('GET', path),
	post: <T>(path: string, body?: unknown) => request<T>('POST', path, body),
	put: <T>(path: string, body?: unknown) => request<T>('PUT', path, body),
	delete: <T>(path: string) => request<T>('DELETE', path)
};

/** Response from GET /auth/me/identity — full identity details */
export interface MeIdentity {
	identity_id: string;
	org_id: string;
	org_name?: string | null;
	org_slug?: string | null;
	email: string;
	name: string;
	kind: string;
	external_id: string | null;
	picture?: string | null;
	is_org_admin?: boolean;
}

/** GET /v1/secrets item */
export interface SecretMetadata {
	name: string;
	current_version: number;
}

/** GET /v1/permissions item — remembered approval rule */
export interface PermissionRule {
	id: string;
	identity_id: string;
	action_pattern: string;
	effect: string;
	expires_at: string | null;
	created_at: string;
}

/** GET /v1/enrollment-tokens item */
export interface EnrollmentTokenItem {
	id: string;
	identity_id: string;
	token_prefix: string;
	expires_at: string;
	created_at: string;
}

/** GET/PUT /auth/me/preferences */
export interface UserPreferences {
	time_display?: 'relative' | 'absolute';
	theme?: 'light' | 'dark' | 'system';
}

/** Mirrors overslash_core::permissions::DerivedKey */
export interface DerivedKey {
	service: string;
	action: string;
	arg: string;
}

/** Mirrors overslash_core::permissions::SuggestedTier */
export interface SuggestedTier {
	keys: string[];
	description: string;
}

/** Mirrors crates/overslash-api/src/routes/approvals.rs ApprovalResponse */
export interface ApprovalResponse {
	id: string;
	identity_id: string;
	/** Alias of `identity_id`, named explicitly for clarity in the bubbling model. */
	requesting_identity_id: string;
	/** The identity currently expected to act on this approval. Bubbles upward
	 *  on explicit BubbleUp or via the per-org auto-bubble timer. */
	current_resolver_identity_id: string;
	/** SPIFFE-style hierarchical path of the requesting identity, e.g.
	 *  `spiffe://acme/user/alice/agent/henry`. May be null if the chain
	 *  could not be resolved. */
	identity_path: string | null;
	action_summary: string;
	permission_keys: string[];
	derived_keys: DerivedKey[];
	suggested_tiers: SuggestedTier[];
	status: string;
	token: string;
	expires_at: string;
	created_at: string;
}

export interface ResolveApprovalRequest {
	resolution: 'allow' | 'deny' | 'allow_remember' | 'bubble_up';
	remember_keys?: string[];
	ttl?: string;
}
