import { session } from '$lib/session';
import type { Identity, ApiKeySummary } from './types';

export const ssr = false;

export const load = async () => {
	const [identities, apiKeys] = await Promise.all([
		session.get<Identity[]>('/v1/identities'),
		session.get<ApiKeySummary[]>('/v1/api-keys')
	]);
	return { identities, apiKeys };
};
