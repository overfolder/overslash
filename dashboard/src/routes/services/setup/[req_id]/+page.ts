import type { PageLoad } from './$types';
import type { TestActionRef } from '$lib/types';
import { mapPublicRequestError, type PublicRequestState } from '$lib/public-request';
import type { ProvideMetadata } from '$lib/public-request';

export const ssr = false;
export const prerender = false;

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
 * plus the service the request is for. Mirrors the backend's
 * `#[serde(flatten)] provide: ProvideMetadata`.
 */
export interface SetupMetadata extends ProvideMetadata {
	service: SetupService;
}

type LoadResult =
	| { state: 'ready'; req_id: string; token: string; meta: SetupMetadata }
	| { state: Exclude<PublicRequestState, 'ready'>; req_id: string };

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
		return { state: mapPublicRequestError(r.status, body), req_id } as LoadResult;
	}
	const meta: SetupMetadata = await r.json();
	return { state: 'ready', req_id, token, meta };
};
