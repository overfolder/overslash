import type { PageLoad } from './$types';
import { mapPublicRequestError, type PublicRequestState } from '$lib/public-request';
import type { ProvideMetadata } from '$lib/public-request';

export const ssr = false;
export const prerender = false;

// Re-exported: this page's `+page.svelte` and the SDK's `ProvideController`
// both import these from the route module.
export type { ProvideMetadata, ViewerInfo } from '$lib/public-request';

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
