import { redirect } from '@sveltejs/kit';
import { getMe, ApiError } from '$lib/api';
import type { LayoutLoad } from './$types';

export const ssr = false;

export const load: LayoutLoad = async ({ url }) => {
	if (url.pathname === '/login') {
		return { session: null };
	}

	try {
		const session = await getMe();
		return { session };
	} catch (e) {
		if (e instanceof ApiError && e.status === 401) {
			throw redirect(302, '/login');
		}
		throw e;
	}
};
