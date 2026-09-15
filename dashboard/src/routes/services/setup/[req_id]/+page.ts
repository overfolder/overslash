import type { PageLoad } from './$types';
import type { TestActionRef } from '$lib/types';

export const ssr = false;
export const prerender = false;

export interface ViewerInfo {
	identity_id: string;
	email: string;
}

export interface SetupSlot {
	key: string;
	label: string;
	description?: string;
	/** True when the instance already has a secret bound to this slot. */
	bound: boolean;
}

export interface SetupService {
	id: string;
	name: string;
	template_key: string;
	display_name: string;
	icon_url?: string;
	/** The slot this link fills. */
	slot: SetupSlot;
	/** Every per-instance slot, so the page can say "1 of 2" honestly. */
	slots: SetupSlot[];
	/** Present when the template declares a credential probe. */
	test_action?: TestActionRef;
}

/**
 * The setup page's metadata: the provide-request half, flattened server-side,
 * plus the service the request is for.
 */
export interface SetupMetadata {
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
	 * same-org session and the page must gate the input accordingly.
	 */
	require_user_session: boolean;
	/**
	 * Opportunistic session binding: populated iff the visitor already holds a
	 * valid `oss_session` cookie for this request's org. Also what decides
	 * whether the Test button can be offered — the probe runs through the
	 * authenticated call path.
	 */
	viewer: ViewerInfo | null;
	service: SetupService;
}

type LoadResult =
	| { state: 'ready'; req_id: string; token: string; meta: SetupMetadata }
	| { state: 'expired'; req_id: string }
	| { state: 'already_fulfilled'; req_id: string }
	| { state: 'invalid'; req_id: string }
	| { state: 'missing_token'; req_id: string }
	| { state: 'server_error'; req_id: string };

// Mirrors `/secrets/provide/[req_id]`: the GET handler never returns 401 —
// `require_user_session` is a flag on the 200 body, not a load-time error — so
// the `ready` branch can render the request and inline a sign-in CTA. A 404
// here also means "this request names no service", which from the visitor's
// seat is the same dead link as a bad id.
function mapError(status: number, body: { error?: string } | null): LoadResult['state'] {
	const code = body?.error ?? '';
	if (status === 410 && code.includes('already_fulfilled')) return 'already_fulfilled';
	if (status === 410) return 'expired';
	if (status === 400) return 'invalid';
	if (status >= 500) return 'server_error';
	return 'invalid';
}

export const load: PageLoad = async ({ params, url, fetch }): Promise<LoadResult> => {
	const req_id = params.req_id;
	const token = url.searchParams.get('token');
	if (!token) return { state: 'missing_token', req_id };

	// `same-origin` (not `omit`) so the dashboard session cookie travels when
	// the visitor already has one. The cookie is purely additive — the URL JWT
	// is still the capability gate — but it is what unlocks the Test button.
	const r = await fetch(
		`/public/services/setup/${encodeURIComponent(req_id)}?token=${encodeURIComponent(token)}`,
		{ method: 'GET', credentials: 'same-origin' }
	);
	if (!r.ok) {
		const body = await r.json().catch(() => null);
		return { state: mapError(r.status, body), req_id } as LoadResult;
	}
	const meta: SetupMetadata = await r.json();
	return { state: 'ready', req_id, token, meta };
};
