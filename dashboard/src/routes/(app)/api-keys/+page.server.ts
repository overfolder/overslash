import * as api from '$lib/server/api';
import { fail } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import type { ApiKey } from '$lib/types';

export const load: PageServerLoad = async ({ cookies }) => {
	const keys = await api.get<ApiKey[]>('/v1/api-keys', cookies);
	return { keys };
};

export const actions: Actions = {
	create: async ({ request, cookies, locals }) => {
		const form = await request.formData();
		const name = form.get('name') as string;
		const identity_id = form.get('identity_id') as string | null;

		if (!name) {
			return fail(400, { error: 'Name is required' });
		}

		try {
			const result = await api.post<ApiKey>('/v1/api-keys', cookies, {
				org_id: locals.user!.org_id,
				name,
				...(identity_id ? { identity_id } : {}),
			});
			return { created_key: result.key, key_name: result.name };
		} catch (e) {
			const msg = e instanceof api.ApiError ? e.message : 'Failed to create API key';
			return fail(400, { error: msg });
		}
	},
};
