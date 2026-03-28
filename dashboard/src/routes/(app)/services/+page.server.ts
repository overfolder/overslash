import * as api from '$lib/server/api';
import type { PageServerLoad } from './$types';
import type { ServiceSummary } from '$lib/types';

export const load: PageServerLoad = async ({ cookies, url }) => {
	const q = url.searchParams.get('q');
	const services = q
		? await api.get<ServiceSummary[]>(`/v1/services/search?q=${encodeURIComponent(q)}`, cookies)
		: await api.get<ServiceSummary[]>('/v1/services', cookies);
	return { services, query: q ?? '' };
};
