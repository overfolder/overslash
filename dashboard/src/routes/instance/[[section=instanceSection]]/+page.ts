import { redirect } from '@sveltejs/kit';
import type { PageLoad } from './$types';

export const ssr = false;
export const prerender = false;

// Instance admins only. The API refuses everyone else anyway; this keeps a
// non-admin from landing on a panel of 403s.
export const load: PageLoad = async ({ parent, params }) => {
	const { user } = await parent();
	if (user?.is_instance_admin !== true) redirect(307, '/');
	return { section: params.section ?? 'orgs' };
};
