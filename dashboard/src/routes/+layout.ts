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
		// This endpoint *is* the auth check, so any non-OK response means the
		// caller isn't authenticated — send them to /login rather than rendering
		// a userless shell that then 404s on every follow-up call. Covers 401
		// (expired token) and 404 (token valid but identity gone, e.g. dev user
		// after a DB reset).
		if (!res.ok) {
			throw redirect(302, `/login?return_to=${encodeURIComponent(url.pathname + url.search)}`);
		}
		const user = (await res.json()) as MeIdentity;
		return { user };
	} catch (e) {
		// Re-throw SvelteKit redirects
		if (e && typeof e === 'object' && 'status' in e && 'location' in e) throw e;
		throw redirect(302, `/login?return_to=${encodeURIComponent(url.pathname + url.search)}`);
	}
};
