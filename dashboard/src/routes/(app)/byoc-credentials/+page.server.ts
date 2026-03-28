import * as api from '$lib/server/api';
import { fail } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import type { ByocCredential } from '$lib/types';

export const load: PageServerLoad = async ({ cookies }) => {
	const credentials = await api.get<ByocCredential[]>('/v1/byoc-credentials', cookies);
	return { credentials };
};

export const actions: Actions = {
	create: async ({ request, cookies }) => {
		const form = await request.formData();
		const provider = form.get('provider') as string;
		const client_id = form.get('client_id') as string;
		const client_secret = form.get('client_secret') as string;

		if (!provider || !client_id || !client_secret) {
			return fail(400, { error: 'All fields are required' });
		}

		try {
			await api.post('/v1/byoc-credentials', cookies, {
				provider,
				client_id,
				client_secret,
			});
		} catch (e) {
			const msg = e instanceof api.ApiError ? e.message : 'Failed to create credential';
			return fail(400, { error: msg });
		}
	},
	delete: async ({ request, cookies }) => {
		const form = await request.formData();
		const id = form.get('id') as string;

		try {
			await api.del(`/v1/byoc-credentials/${id}`, cookies);
		} catch (e) {
			const msg = e instanceof api.ApiError ? e.message : 'Failed to delete credential';
			return fail(400, { error: msg });
		}
	},
};
