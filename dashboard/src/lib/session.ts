/**
 * Cookie-based API client for authenticated dashboard pages.
 *
 * In dev, Vite proxies /v1 and /auth to the Rust backend on :3000.
 * On Vercel, vercel.json rewrites proxy API paths to the backend.
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

async function request<T>(
	method: string,
	path: string,
	body?: unknown,
	signal?: AbortSignal
): Promise<T> {
	const init: RequestInit = {
		method,
		headers: { 'Content-Type': 'application/json' },
		credentials: 'include', // send cookies
		signal
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

/** POST with a raw text body (Content-Type: text/plain). */
async function requestText<T>(path: string, text: string, signal?: AbortSignal): Promise<T> {
	const res = await fetch(path, {
		method: 'POST',
		headers: { 'Content-Type': 'text/plain' },
		credentials: 'include',
		body: text,
		signal
	});

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

	if (res.status === 204) {
		return undefined as T;
	}

	return res.json();
}

export const session = {
	get: <T>(path: string, signal?: AbortSignal) => request<T>('GET', path, undefined, signal),
	post: <T>(path: string, body?: unknown, signal?: AbortSignal) =>
		request<T>('POST', path, body, signal),
	postText: <T>(path: string, text: string, signal?: AbortSignal) =>
		requestText<T>(path, text, signal),
	put: <T>(path: string, body?: unknown, signal?: AbortSignal) =>
		request<T>('PUT', path, body, signal),
	patch: <T>(path: string, body?: unknown, signal?: AbortSignal) =>
		request<T>('PATCH', path, body, signal),
	delete: <T>(path: string, signal?: AbortSignal) => request<T>('DELETE', path, undefined, signal)
};

/** One org the caller belongs to. Mirrors the server's `MembershipSummary`. */
export interface MembershipSummary {
	org_id: string;
	slug: string;
	name: string;
	role: 'admin' | 'member' | string;
	is_personal: boolean;
}

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
	/** Operator-granted instance admin flag (set only via DB). The single
	 *  elevated capability today is creating free-unlimited orgs through
	 *  the Create-Org modal. Drives the small "Instance" badge in the
	 *  layout. */
	is_instance_admin?: boolean;
	/** Multi-org additions. `user_id` + `memberships` are present once a
	 *  post-multi-org-rewire session is minted; legacy tokens leave them
	 *  empty until re-login. */
	user_id?: string | null;
	personal_org_id?: string | null;
	memberships?: MembershipSummary[];
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

/** One entry from approvals.disclosed_fields — a labeled, human-readable
 *  slice of the resolved request extracted via the template's
 *  x-overslash-disclose jq filters. See SPEC §N "Detail disclosure". */
export interface DisclosedField {
	label: string;
	/** Filter output, stringified. Null when the filter produced no value
	 *  (e.g. missing input field) or when `error` is set. */
	value: string | null;
	/** Per-field error message when the filter failed at runtime. Siblings
	 *  still render normally — errors are isolated per-field. */
	error: string | null;
	/** True when the value hit the per-field `max_chars` clamp or a 10 KB
	 *  hard ceiling. The returned `value` is still the prefix. */
	truncated: boolean;
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
	/** Pretty-printed serialization of the stored action_detail JSONB.
	 *  Truncated server-side at MAX_ACTION_DETAIL_BYTES (100 KB) on a
	 *  UTF-8 char boundary. Null when no detail was stored. */
	action_detail: string | null;
	action_detail_truncated: boolean;
	/** Byte length of the full pretty-printed action_detail prior to
	 *  truncation. 0 when no detail was stored. */
	action_detail_size_bytes: number;
	/** Labeled summary of the resolved request, extracted at approval-create
	 *  time via the template's x-overslash-disclose filters. Rendered as the
	 *  "Summary" block above the raw payload. Null when the action template
	 *  declared no disclose entries. */
	disclosed_fields: DisclosedField[] | null;
	status: string;
	token: string;
	expires_at: string;
	created_at: string;
	/** Replay lifecycle state, present once /resolve allow has created the
	 *  pending execution row. Absent on denied / bubbled / pre-replay
	 *  approvals. */
	execution?: ExecutionSummary;
	/** Other pending approvals auto-resolved as a side effect of this call.
	 *  Populated only on the response to POST /v1/approvals/{id}/call when
	 *  an "Allow & Remember" rule was committed and that rule structurally
	 *  satisfied other pending approvals under the same placement identity.
	 *  Empty / omitted in all other contexts. */
	cascaded_approval_ids?: string[];
}

/** Mirrors crates/overslash-api/src/routes/approvals.rs ExecutionSummary. */
export interface ExecutionSummary {
	id: string;
	/** pending | calling | called | failed | cancelled | expired */
	status: string;
	result?: unknown;
	error?: string;
	triggered_by?: 'agent' | 'user';
	started_at?: string;
	completed_at?: string;
	expires_at: string;
	created_at: string;
}

export interface ResolveApprovalRequest {
	resolution: 'allow' | 'deny' | 'allow_remember' | 'bubble_up';
	remember_keys?: string[];
	ttl?: string;
}
