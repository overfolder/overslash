import type { PageLoad } from './$types';
import { mapPublicRequestError, type PublicRequestState } from '$lib/public-request';

export const ssr = false;
export const prerender = false;

export type { ViewerInfo } from '$lib/public-request';
import type { ViewerInfo } from '$lib/public-request';

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
	 * `allow_unsigned_secret_provide = false`. When set, submission requires
	 * a same-org session and the page must gate the input accordingly.
	 */
	require_user_session: boolean;
	/**
	 * Opportunistic session binding: populated iff the visitor already
	 * holds a valid `oss_session` cookie for this request's org.
	 */
	viewer: ViewerInfo | null;
}

type LoadResult =
	| { state: 'ready'; req_id: string; token: string; meta: ProvideMetadata }
	| { state: Exclude<PublicRequestState, 'ready'>; req_id: string };

export const load: PageLoad = async ({ params, url, fetch }): Promise<LoadResult> => {
	const req_id = params.req_id;
	const token = url.searchParams.get('token');
	if (!token) return { state: 'missing_token', req_id };

	// `same-origin` (not `omit`) so the dashboard session cookie travels
	// when the visitor already has one. The cookie is purely additive — the
	// URL JWT is still the capability gate. Cross-origin embeds never send
	// the cookie, so this remains safe for the anonymous case.
	const r = await fetch(
		`/public/secrets/provide/${encodeURIComponent(req_id)}?token=${encodeURIComponent(token)}`,
		{ method: 'GET', credentials: 'same-origin' }
	);
	if (!r.ok) {
		const body = await r.json().catch(() => null);
		return { state: mapPublicRequestError(r.status, body), req_id } as LoadResult;
	}
	const meta: ProvideMetadata = await r.json();
	return { state: 'ready', req_id, token, meta };
};
