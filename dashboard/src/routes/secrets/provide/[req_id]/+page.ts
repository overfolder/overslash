import type { PageLoad } from './$types';
import { loadPublicRequest } from '$lib/public-request';
import type { ProvideMetadata, PublicRequestLoad } from '$lib/public-request';

export const ssr = false;
export const prerender = false;

type LoadResult = PublicRequestLoad<ProvideMetadata>;

export const load: PageLoad = ({ params, url, fetch }): Promise<LoadResult> =>
	loadPublicRequest<ProvideMetadata>(
		fetch,
		(id, token) =>
			`/public/secrets/provide/${encodeURIComponent(id)}?token=${encodeURIComponent(token)}`,
		params.req_id,
		url.searchParams.get('token')
	);
