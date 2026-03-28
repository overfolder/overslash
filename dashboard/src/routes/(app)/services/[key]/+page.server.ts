import * as api from '$lib/server/api';
import type { PageServerLoad } from './$types';
import type { ServiceDetail } from '$lib/types';

export const load: PageServerLoad = async ({ params, cookies }) => {
	const service = await api.get<ServiceDetail>(`/v1/services/${encodeURIComponent(params.key)}`, cookies);
	return { service };
};
