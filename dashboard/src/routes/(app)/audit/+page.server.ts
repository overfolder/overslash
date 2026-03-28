import * as api from '$lib/server/api';
import type { PageServerLoad } from './$types';
import type { AuditEntry } from '$lib/types';

export const load: PageServerLoad = async ({ cookies, url }) => {
	const params = new URLSearchParams();
	const limit = url.searchParams.get('limit') ?? '50';
	const offset = url.searchParams.get('offset') ?? '0';
	const action = url.searchParams.get('action');
	const resource_type = url.searchParams.get('resource_type');

	params.set('limit', limit);
	params.set('offset', offset);
	if (action) params.set('action', action);
	if (resource_type) params.set('resource_type', resource_type);

	const entries = await api.get<AuditEntry[]>(`/v1/audit?${params.toString()}`, cookies);
	return {
		entries,
		filters: { action: action ?? '', resource_type: resource_type ?? '' },
		offset: parseInt(offset),
		limit: parseInt(limit),
	};
};
