import * as api from '$lib/server/api';
import { fail } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import type { Connection } from '$lib/types';

export const load: PageServerLoad = async ({ cookies }) => {
	const connections = await api.get<Connection[]>('/v1/connections', cookies);
	return { connections };
};

export const actions: Actions = {
	connect: async ({ request, cookies }) => {
		const form = await request.formData();
		const provider = form.get('provider') as string;

		if (!provider) {
			return fail(400, { error: 'Provider is required' });
		}

		try {
			const result = await api.post<{ auth_url: string }>('/v1/connections', cookies, {
				provider,
			});
			return { redirect_url: result.auth_url };
		} catch (e) {
			const msg = e instanceof api.ApiError ? e.message : 'Failed to initiate connection';
			return fail(400, { error: msg });
		}
	},
	revoke: async ({ request, cookies }) => {
		const form = await request.formData();
		const id = form.get('id') as string;

		if (!id) {
			return fail(400, { error: 'Connection ID is required' });
		}

		try {
			await api.del(`/v1/connections/${id}`, cookies);
		} catch (e) {
			const msg = e instanceof api.ApiError ? e.message : 'Failed to revoke connection';
			return fail(400, { error: msg });
		}
	},
};
