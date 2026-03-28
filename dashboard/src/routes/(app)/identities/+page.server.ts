import * as api from '$lib/server/api';
import { fail } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import type { Identity } from '$lib/types';

export const load: PageServerLoad = async ({ cookies }) => {
	const identities = await api.get<Identity[]>('/v1/identities', cookies);
	return { identities };
};

export const actions: Actions = {
	create: async ({ request, cookies }) => {
		const form = await request.formData();
		const name = form.get('name') as string;
		const kind = form.get('kind') as string;
		const external_id = form.get('external_id') as string | null;

		if (!name || !kind) {
			return fail(400, { error: 'Name and kind are required' });
		}

		try {
			await api.post('/v1/identities', cookies, {
				name,
				kind,
				...(external_id ? { external_id } : {}),
			});
		} catch (e) {
			const msg = e instanceof api.ApiError ? e.message : 'Failed to create identity';
			return fail(400, { error: msg });
		}
	},
};
