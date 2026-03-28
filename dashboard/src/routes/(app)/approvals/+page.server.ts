import * as api from '$lib/server/api';
import { fail } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import type { Approval } from '$lib/types';

export const load: PageServerLoad = async ({ cookies }) => {
	const approvals = await api.get<Approval[]>('/v1/approvals', cookies);
	return { approvals };
};

export const actions: Actions = {
	resolve: async ({ request, cookies }) => {
		const form = await request.formData();
		const id = form.get('id') as string;
		const decision = form.get('decision') as string;

		if (!id || !decision) {
			return fail(400, { error: 'Missing id or decision' });
		}

		try {
			await api.post(`/v1/approvals/${id}/resolve`, cookies, { decision });
		} catch (e) {
			const msg = e instanceof api.ApiError ? e.message : 'Failed to resolve approval';
			return fail(400, { error: msg });
		}
	},
};
