import type { PageLoad } from './$types';
import type { TestActionRef } from '$lib/types';
import { loadPublicRequest } from '$lib/public-request';
import type { ProvideMetadata, PublicRequestLoad } from '$lib/public-request';

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

type LoadResult = PublicRequestLoad<SetupMetadata>;

export const load: PageLoad = ({ params, url, fetch }): Promise<LoadResult> =>
	loadPublicRequest<SetupMetadata>(
		fetch,
		(id, token) =>
			`/public/services/setup/${encodeURIComponent(id)}?token=${encodeURIComponent(token)}`,
		params.req_id,
		url.searchParams.get('token')
	);
