import * as api from '$lib/server/api';
import { fail } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import type { Permission } from '$lib/types';

export const load: PageServerLoad = async ({ cookies }) => {
	const permissions = await api.get<Permission[]>('/v1/permissions', cookies);
	return { permissions };
};

export const actions: Actions = {
	create: async ({ request, cookies }) => {
		const form = await request.formData();
		const identity_id = form.get('identity_id') as string;
		const action_pattern = form.get('action_pattern') as string;
		const effect = form.get('effect') as string;

		if (!identity_id || !action_pattern) {
			return fail(400, { error: 'Identity and action pattern are required' });
		}

		try {
			await api.post('/v1/permissions', cookies, {
				identity_id,
				action_pattern,
				effect: effect || 'allow',
			});
		} catch (e) {
			const msg = e instanceof api.ApiError ? e.message : 'Failed to create permission';
			return fail(400, { error: msg });
		}
	},
	delete: async ({ request, cookies }) => {
		const form = await request.formData();
		const id = form.get('id') as string;

		try {
			await api.del(`/v1/permissions/${id}`, cookies);
		} catch (e) {
			const msg = e instanceof api.ApiError ? e.message : 'Failed to delete permission';
			return fail(400, { error: msg });
		}
	},
};
