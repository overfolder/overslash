import { redirect } from '@sveltejs/kit';
import type { Actions } from './$types';

export const actions: Actions = {
	default: async ({ cookies }) => {
		cookies.delete('oss_session', { path: '/' });
		redirect(303, '/login');
	},
};
