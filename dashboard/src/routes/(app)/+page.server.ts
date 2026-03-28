import * as api from '$lib/server/api';
import type { PageServerLoad } from './$types';
import type { Identity, Approval, Secret } from '$lib/types';

export const load: PageServerLoad = async ({ cookies }) => {
	const [identities, approvals, secrets] = await Promise.all([
		api.get<Identity[]>('/v1/identities', cookies).catch(() => []),
		api.get<Approval[]>('/v1/approvals', cookies).catch(() => []),
		api.get<Secret[]>('/v1/secrets', cookies).catch(() => []),
	]);

	return {
		counts: {
			identities: identities.length,
			approvals: approvals.length,
			secrets: secrets.length,
		},
	};
};
