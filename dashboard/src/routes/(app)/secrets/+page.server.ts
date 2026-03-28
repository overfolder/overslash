import * as api from '$lib/server/api';
import { fail } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import type { Secret } from '$lib/types';

export const load: PageServerLoad = async ({ cookies }) => {
	const secrets = await api.get<Secret[]>('/v1/secrets', cookies);
	return { secrets };
};

export const actions: Actions = {
	upsert: async ({ request, cookies }) => {
		const form = await request.formData();
		const name = form.get('name') as string;
		const value = form.get('value') as string;

		if (!name || !value) {
			return fail(400, { error: 'Name and value are required' });
		}

		try {
			await api.put(`/v1/secrets/${encodeURIComponent(name)}`, cookies, { value });
		} catch (e) {
			const msg = e instanceof api.ApiError ? e.message : 'Failed to save secret';
			return fail(400, { error: msg });
		}
	},
	delete: async ({ request, cookies }) => {
		const form = await request.formData();
		const name = form.get('name') as string;

		if (!name) {
			return fail(400, { error: 'Name is required' });
		}

		try {
			await api.del(`/v1/secrets/${encodeURIComponent(name)}`, cookies);
		} catch (e) {
			const msg = e instanceof api.ApiError ? e.message : 'Failed to delete secret';
			return fail(400, { error: msg });
		}
	},
};
