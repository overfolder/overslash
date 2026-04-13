import { redirect } from '@sveltejs/kit';
import type { LayoutLoad } from './$types';
import type { MeIdentity } from '$lib/session';

export const ssr = false;
export const prerender = false;

export const load: LayoutLoad = async ({ url, fetch }) => {
	// Login page is public.
	if (url.pathname === '/login') {
		return { user: null };
	}
	// Standalone "Provide Secret" page is unauthenticated (signed URL).
	if (url.pathname.startsWith('/secrets/provide/')) {
		return { user: null };
	}

	try {
		const res = await fetch('/auth/me/identity', { credentials: 'include' });
		if (res.status === 401) {
			throw redirect(302, `/login?return_to=${encodeURIComponent(url.pathname + url.search)}`);
		}
		if (!res.ok) {
			return { user: null };
		}
		const user = (await res.json()) as MeIdentity;
		return { user };
	} catch (e) {
		// Re-throw SvelteKit redirects
		if (e && typeof e === 'object' && 'status' in e && 'location' in e) throw e;
		throw redirect(302, `/login?return_to=${encodeURIComponent(url.pathname + url.search)}`);
	}
};
