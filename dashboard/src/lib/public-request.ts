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
	/**
	 * The organization this request belongs to.
	 *
	 * Shown as plain, uneditable text: unlike the enrollment consent screen
	 * there is nothing to switch to, because the signed token names one org
	 * and only one.
	 */
	org_name: string;
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
	/**
	 * Version of the vault secret this submission will replace, or absent when
	 * the name is still free.
	 *
	 * Read live at page load rather than recorded when the link was minted:
	 * the mint-time check cannot see a secret created after it, so this page is
	 * the last place the truth is available before the value is written. It
	 * warns rather than blocks, because the person holding the link is the one
	 * who can judge whether replacing the value is what was meant.
	 */
	overwrites_version?: number;
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

/**
 * Whether a verdict means the *upstream* rejected the credential.
 *
 * Narrower than "not ok" on purpose. `pending_approval`, `needs_authentication`
 * and `denied` are all real verdicts in which the upstream was never asked, so
 * reporting them as a rejection is simply untrue — and `TestResult` already
 * tones those amber rather than red, so a page branching on `!== 'ok'`
 * contradicts the component it renders.
 *
 * `null` (no verdict yet, or one still in flight) is not a rejection either.
 */
export function probeRejected(result: { status: string } | null | undefined): boolean {
	return result?.status === 'failed';
}

/** A public request page's load outcome, parameterised on its metadata shape. */
export type PublicRequestLoad<M> =
	| { state: 'ready'; req_id: string; token: string; meta: M }
	| { state: Exclude<PublicRequestState, 'ready'>; req_id: string };

/**
 * Fetch a public request's metadata and map the outcome onto a page state.
 *
 * `path` is the metadata endpoint — the two pages differ only in that and in
 * what shape comes back. `credentials: 'same-origin'` (not `omit`) so the
 * dashboard session cookie travels when the visitor already has one: the URL
 * JWT is still the capability gate, but the session is what records who
 * provided the value, and on the setup page what unlocks the Test button.
 */
export async function loadPublicRequest<M>(
	fetchFn: typeof fetch,
	path: (reqId: string, token: string) => string,
	reqId: string,
	token: string | null
): Promise<PublicRequestLoad<M>> {
	if (!token) return { state: 'missing_token', req_id: reqId };
	const r = await fetchFn(path(reqId, token), {
		method: 'GET',
		credentials: 'same-origin'
	});
	if (!r.ok) {
		const body = await r.json().catch(() => null);
		const state = mapPublicRequestError(r.status, body);
		return { state: state as Exclude<PublicRequestState, 'ready'>, req_id: reqId };
	}
	return { state: 'ready', req_id: reqId, token, meta: (await r.json()) as M };
}

/** What a submit did, as the caller needs to branch on it. */
export type SubmitOutcome<B> =
	| { ok: true; body: B | null }
	/** `message` is ready to render; the page does not re-derive it. */
	| { ok: false; message: string };

/**
 * Submit a value to `POST /public/secrets/provide/{req_id}`.
 *
 * Both pages post here — there is one write path, and the setup page's extra
 * behaviour (binding the credential slot) is the server's, not a second
 * endpoint.
 *
 * A 200 whose body will not parse is still a success: by then the vault write
 * is committed and the single-use row is burned, so reporting failure would
 * send the visitor into a retry that answers `410 already_fulfilled`. The body
 * comes back as `null` in that case, which callers read as "saved, details
 * unknown" rather than as a positive result.
 */
export async function submitPublicRequest<B>(
	reqId: string,
	token: string,
	value: string
): Promise<SubmitOutcome<B>> {
	try {
		const r = await fetch(`/public/secrets/provide/${encodeURIComponent(reqId)}`, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			credentials: 'same-origin',
			body: JSON.stringify({ token, value })
		});
		if (!r.ok) {
			const body = await r.json().catch(() => null);
			const code = (body && (body as { error?: string }).error) || '';
			return { ok: false, message: submitErrorMessage(r.status, code) };
		}
		return { ok: true, body: (await r.json().catch(() => null)) as B | null };
	} catch {
		return { ok: false, message: 'Network error. Please try again.' };
	}
}
