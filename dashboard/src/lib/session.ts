/**
 * Cookie-based API client for authenticated dashboard pages.
 *
 * In dev, Vite proxies /v1 and /auth to the Rust backend on :3000.
 * On Vercel, vercel.json rewrites proxy API paths to the backend.
 * Auth relies on the `oss_session` HttpOnly cookie set by the backend.
 */

// Type-only, so the `$lib/api/account` → `$lib/session` import cycle is erased
// at build time rather than becoming a runtime one.
import type { PendingInvitation } from '$lib/api/account';

export class ApiError extends Error {
	constructor(
		public status: number,
		public body: unknown
	) {
		super(`API error ${status}`);
		this.name = 'ApiError';
	}
}

/**
 * Pull the human-readable reason out of an error response body. The backend's
 * simple errors serialize as `{ "error": "<message>" }` (see AppError
 * IntoResponse), so surface that string when present — lets callers show the
 * server's actual reason (e.g. "admin access required") instead of a bare
 * status code.
 */
export function apiErrorReason(e: unknown): string | undefined {
	if (e instanceof ApiError && e.body && typeof e.body === 'object') {
		const b = e.body as { error?: unknown; message?: unknown };
		if (typeof b.error === 'string') return b.error;
		if (typeof b.message === 'string') return b.message;
	}
	return undefined;
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
		// Read once, parse if it looks like JSON. Calling `.json()` and then
		// falling back to `.text()` blows up on empty 404 bodies because the
		// stream is already consumed.
		const text = await res.text();
		let errorBody: unknown = text;
		if (text) {
			try {
				errorBody = JSON.parse(text);
			} catch {
				/* keep as text */
			}
		}
		if (res.status === 401 && typeof window !== 'undefined') {
			// A 401 carrying the gateway's typed service-auth envelope
			// (needs_authentication / reauth_required) means the *target service*
			// needs auth — the dashboard session itself is fine. Don't bounce to
			// /login; let the caller render it (e.g. the API Explorer "try it"
			// panel, which also opts into ?wrap=true so this is a 200 anyway).
			const code =
				errorBody && typeof errorBody === 'object'
					? (errorBody as { error?: string }).error
					: undefined;
			const isServiceAuth = code === 'needs_authentication' || code === 'reauth_required';
			const here = window.location.pathname + window.location.search;
			if (!isServiceAuth && window.location.pathname !== '/login') {
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
		// Read once, parse if it looks like JSON. Calling `.json()` and then
		// falling back to `.text()` blows up on empty 404 bodies because the
		// stream is already consumed.
		const text = await res.text();
		let errorBody: unknown = text;
		if (text) {
			try {
				errorBody = JSON.parse(text);
			} catch {
				/* keep as text */
			}
		}
		if (res.status === 401 && typeof window !== 'undefined') {
			// A 401 carrying the gateway's typed service-auth envelope
			// (needs_authentication / reauth_required) means the *target service*
			// needs auth — the dashboard session itself is fine. Don't bounce to
			// /login; let the caller render it (e.g. the API Explorer "try it"
			// panel, which also opts into ?wrap=true so this is a 200 anyway).
			const code =
				errorBody && typeof errorBody === 'object'
					? (errorBody as { error?: string }).error
					: undefined;
			const isServiceAuth = code === 'needs_authentication' || code === 'reauth_required';
			const here = window.location.pathname + window.location.search;
			if (!isServiceAuth && window.location.pathname !== '/login') {
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
	/** Pending invitations from orgs the caller has *not* joined yet, keyed
	 *  on their IdP-verified email. Embedded here so the sidebar needs no
	 *  extra round trip; also served on its own by
	 *  `GET /v1/account/invitations`. */
	invitations?: PendingInvitation[];
	/** Instance-admin-managed trial summary for the org-wide banner. `null`
	 *  for non-trial orgs. Enforcement is banner-only — informational. */
	trial?: TrialSummary | null;
}

export interface TrialSummary {
	status: 'active' | 'expired';
	/** Trial window end, unix seconds. */
	ends_at: number;
	/** Whole days left (0 once expired). */
	days_remaining: number;
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
	/** `action_pattern` as a sentence, rendered server-side by the same describer
	 *  that writes an approval's suggested tiers. */
	description: string;
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
	/** Third key segment verbatim, `label=value` included when the action's
	 *  scope carries a label (`recipient=jane@example.com`). */
	arg: string;
	/** The scope label, when `arg` carries one. Absent for a bare arg — keys
	 *  from unlabelled scopes and rules typed by hand. Not a param name: an
	 *  email send files `to`/`cc`/`bcc` alike under `recipient`. */
	label?: string;
	/** `arg` with any `label=` prefix stripped. */
	value: string;
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
	/** True when the template marked this disclose entry `primary`. The detail
	 *  screen renders primary fields as prominent "hero" values (multiple
	 *  primaries render in declaration order); unmarked fields form the table.
	 *  Omitted (falsy) when false — the backend skips serializing it. */
	primary?: boolean;
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
	/** Identity ids for each `(kind, name)` unit in `identity_path`, in the
	 *  same order. Excludes the org slug, so its length matches the unit
	 *  count of `identity_path`. Empty when `identity_path` is null.
	 *  IdentityPath uses these to build `/agents/<id>` links per segment. */
	identity_path_ids: string[];
	action_summary: string;
	/** System-derived metadata tags describing the gated call (`sql:write`,
	 *  `table:wh/orders`, `service:metabase`, …). Shown read-only on the
	 *  approval detail so a reviewer sees what the call actually touches.
	 *  Empty for approvals created before tagging existed. */
	tags: string[];
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
	/** Whether an approved replay runs on the connection that triggers it or is
	 *  queued for the async worker. Stamped from the original call's
	 *  `execution` mode, so a reviewer can be told — before approving — that
	 *  this one will not produce a result on the page. */
	execution_mode: 'sync' | 'async';
	/** Suggested delay before the first poll, ms. Present only on the response
	 *  to POST /v1/approvals/{id}/call that queued the replay. */
	poll_after_ms?: number;
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
	/** Risk class derived from the matching ServiceAction.risk in the live
	 *  service registry. Drives the approval card's risk top bar.
	 *  Read → "low", Write → "med", Delete → "high". Defaults to "med" when
	 *  the lookup misses. */
	risk: 'low' | 'med' | 'high';
	/** Caller↔requester relationship from the *viewing* identity's
	 *  perspective. Populated on identity-bound reads (API key tied to an
	 *  identity); omitted on dashboard-session reads where the relationship
	 *  has no defined viewer. MCP clients use this to pick
	 *  `overslash_approve_self` vs `overslash_approve`. */
	relationship?: 'self' | 'downstream' | 'not_in_your_chain';
}

/** Mirrors crates/overslash-api/src/routes/approvals.rs ExecutionSummary. */
export interface ExecutionSummary {
	id: string;
	/** pending | executing | executed | failed | cancelled | expired —
	 *  authoritative values come from the `executions.status` column;
	 *  the API does no translation. */
	status: string;
	result?: unknown;
	error?: string;
	/** `auto` is set when the resolve handler kicked off the replay because
	 *  the requesting agent's identity has `auto_call_on_approve` enabled
	 *  (default true). Applies uniformly to MCP, REST, and white-label
	 *  agents. */
	triggered_by?: 'agent' | 'user' | 'auto' | 'async';
	/** This execution runs on the async worker, not on a request. It changes
	 *  what `pending` means: "queued, nothing to trigger" rather than
	 *  "approved, waiting for the agent". Absent on every synchronous row. */
	queued?: boolean;
	started_at?: string;
	completed_at?: string;
	expires_at: string;
	created_at: string;
	/** `http` | `mcp` — disambiguates the meaning of `http_status_code`.
	 *  Absent while the execution is still pending. */
	runtime?: string;
	/** Upstream HTTP status for HTTP-runtime executions only. */
	http_status_code?: number;
	/** False until the requesting agent fetches `/v1/approvals/{id}/execution`
	 *  for the first time. Drives the "called but output unread" surface
	 *  on the dashboard's pending-calls list. */
	output_read: boolean;
	/** True when policy hid the body because the viewer is not the requester,
	 *  not in their chain, and not an org admin. `result` and `error` are
	 *  omitted in that case — render "hidden", not "empty", or it reads as a
	 *  bug rather than as policy. */
	result_redacted?: boolean;
}

/**
 * Mirrors crates/overslash-api/src/routes/executions/dto.rs `ExecutionDetail`.
 *
 * The standalone execution resource. `ExecutionSummary` is the shape nested
 * inside an approval and deliberately drops the fields that only matter when
 * an execution is addressed on its own, so this extends rather than replaces
 * it — the Rust side `#[serde(flatten)]`s the same struct, so the two cannot
 * describe a column differently.
 */
export interface ExecutionDetail extends ExecutionSummary {
	/** `approval` when this execution came from a gated call, `async_call`
	 *  when the caller asked for `execution: "async"` directly. Derived from
	 *  whether `approval_id` is set — it is not a stored column. */
	origin: 'approval' | 'async_call';
	/** The identity whose call this is. */
	identity_id: string;
	/** Present only for `origin: "approval"`. */
	approval_id?: string;
	tags: string[];
	service?: string;
	action?: string;
	/** Attempts that ended by losing a worker lease. Non-zero means the job
	 *  was interrupted at least once — usually a Cloud Run scale-in. */
	attempts?: number;
	/** A cancel has been requested but the worker has not yet observed it.
	 *  Cancelling stops Overslash waiting; it does not recall the upstream. */
	cancel_requested?: boolean;
}

/** List rows never carry `result` — fetching the body is also what marks it
 *  read, so a list that inlined it would let a reader scrape results without
 *  ever acknowledging them. The server always sets `result_redacted` on list
 *  rows for the same reason. */
export type ExecutionListItem = Omit<ExecutionDetail, 'result'>;

export interface ResolveApprovalRequest {
	resolution: 'allow' | 'deny' | 'allow_remember' | 'bubble_up';
	remember_keys?: string[];
	ttl?: string;
}
