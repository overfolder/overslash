import { error } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import type { Approval } from '$lib/types';

const API_URL = process.env.API_URL ?? 'http://localhost:3000';

export const load: PageServerLoad = async ({ url, params }) => {
	const token = url.searchParams.get('token');
	if (!token) {
		error(400, 'Missing token parameter');
	}

	const res = await fetch(`${API_URL}/v1/approvals/by-token/${encodeURIComponent(token)}`);

	if (res.status === 404) {
		error(404, 'Approval not found');
	}
	if (res.status === 410) {
		error(410, 'Approval has expired');
	}
	if (!res.ok) {
		error(res.status, 'Failed to load approval');
	}

	const approval: Approval = await res.json();
	return { approval, token };
};

export const actions: Actions = {
	resolve: async ({ request, url }) => {
		const token = url.searchParams.get('token');
		if (!token) {
			error(400, 'Missing token');
		}

		const form = await request.formData();
		const decision = form.get('decision') as string;

		const res = await fetch(
			`${API_URL}/v1/approvals/by-token/${encodeURIComponent(token)}/resolve`,
			{
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ decision }),
			}
		);

		if (!res.ok) {
			const body = await res.json().catch(() => ({ error: 'Resolution failed' }));
			error(res.status, body.error);
		}

		const resolved: Approval = await res.json();
		return { resolved: true, status: resolved.status };
	},
};
