/**
 * The bits `/secrets/provide/[req_id]` and `/services/setup/[req_id]` share.
 *
 * Both are the same handshake — a signed, single-use capability in the URL, a
 * value the visitor pastes, one `POST /public/secrets/provide/{req_id}` — worn
 * two ways: one leads with the vault key, the other with the service. Keeping
 * the state machine, the error ladder and the countdown here is what stops the
 * two framings from disagreeing about what "expired" means.
 *
 * Deliberately not in a route module: these are pure functions, and a route
 * module drags `./$types` with it and cannot be unit-tested.
 */

/** Populated when the visitor already holds a session for the request's org. */
export interface ViewerInfo {
	identity_id: string;
	email: string;
}

/**
 * The request-level half of either public page's metadata.
 *
 * The backend models the setup page's shape as a superset of this one
 * (`#[serde(flatten)] provide: ProvideMetadata`), so the TS mirror extends it
 * rather than re-declaring nine fields that must then be kept in step by hand.
 */
export interface ProvideMetadata {
	id: string;
	secret_name: string;
	identity_label: string;
	requested_by_label: string;
	reason: string | null;
	expires_at: string;
	created_at: string;
	/**
	 * True iff the request was minted while the org had
	 * `allow_unsigned_secret_provide = false`. When set, submission requires a
	 * same-org session and the page must gate the input accordingly. Captured
	 * at mint time, so flipping the org setting never retroactively breaks an
	 * in-flight URL.
	 */
	require_user_session: boolean;
	/**
	 * Opportunistic session binding: populated iff the visitor already holds a
	 * valid `oss_session` cookie for this request's org. Also what decides
	 * whether a Test button can be offered on the setup page, since the probe
	 * runs through the authenticated call path.
	 */
	viewer: ViewerInfo | null;
}

/** Everything a public request page can be, once its load has run. */
export type PublicRequestState =
	| 'ready'
	| 'expired'
	| 'already_fulfilled'
	| 'invalid'
	| 'missing_token'
	| 'server_error';

/**
 * Map a failed metadata GET onto a page state.
 *
 * Neither GET handler returns 401: `require_user_session` rides on the 200
 * body as a flag, not as a load-time error, so the `ready` branch can render
 * the request and inline a sign-in CTA. A 404 on the setup route also means
 * "this request names no service", which from the visitor's seat is the same
 * dead link as a bad id.
 */
export function mapPublicRequestError(
	status: number,
	body: { error?: string } | null
): PublicRequestState {
	const code = body?.error ?? '';
	if (status === 410 && code.includes('already_fulfilled')) return 'already_fulfilled';
	if (status === 410) return 'expired';
	if (status === 400) return 'invalid';
	if (status >= 500) return 'server_error';
	return 'invalid';
}

/** `59m 04s`, or `expired` once the deadline has passed. */
export function fmtCountdown(expiresAt: string, now: number): string {
	const t = Date.parse(expiresAt);
	if (!Number.isFinite(t)) return expiresAt;
	const ms = t - now;
	if (ms <= 0) return 'expired';
	const s = Math.floor(ms / 1000);
	const m = Math.floor(s / 60);
	return `${m}m ${(s % 60).toString().padStart(2, '0')}s`;
}

/**
 * Round-trip back to the current page after signing in.
 *
 * The visitor's original URL (token and all) is already in their tab history,
 * and after login SvelteKit re-runs the load — so the token survives without
 * being threaded through the redirect layer.
 */
export function loginUrl(): string {
	if (typeof window === 'undefined') return '/login';
	return `/login?next=${encodeURIComponent(window.location.pathname + window.location.search)}`;
}

/**
 * Human-facing copy for a failed submit, by status and error code.
 *
 * One ladder for both pages: a visitor who is told "already fulfilled" on one
 * and something vaguer on the other has no way to tell whether the difference
 * is meaningful.
 */
export function submitErrorMessage(status: number, code: string): string {
	if (status === 410 && code.includes('already_fulfilled')) {
		return 'This request was already fulfilled.';
	}
	if (status === 410) return 'This link has expired.';
	if (status === 401 && code.includes('user_session_required')) {
		return 'This organization requires you to be signed in to provide this credential.';
	}
	if (status === 400) return 'This link is invalid or tampered.';
	return 'Submission failed. Please try again.';
}
