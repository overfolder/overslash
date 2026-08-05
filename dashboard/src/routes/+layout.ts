import { redirect } from '@sveltejs/kit';
import type { LayoutLoad } from './$types';
import type { MeIdentity } from '$lib/session';
import { loadAllowedDomains } from '$lib/orgDomains';

export const ssr = false;
export const prerender = false;

export const load: LayoutLoad = async ({ url, fetch }) => {
	// Login page is public.
	if (url.pathname === '/login') {
		return { user: null, allowedDomains: [] as string[] };
	}
	// Standalone "Provide Secret" page is unauthenticated (signed URL).
	if (url.pathname.startsWith('/secrets/provide/')) {
		return { user: null, allowedDomains: [] as string[] };
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
		// Every page that lists identities needs this to decide whether to strip
		// the email domain off display labels. Memoized per org in
		// `$lib/orgDomains`, so this is one request per session, not per
		// navigation, and it never fails the page.
		const allowedDomains = await loadAllowedDomains(user.org_id, fetch);
		return { user, allowedDomains };
	} catch (e) {
		// Re-throw SvelteKit redirects
		if (e && typeof e === 'object' && 'status' in e && 'location' in e) throw e;
		throw redirect(302, `/login?return_to=${encodeURIComponent(url.pathname + url.search)}`);
	}
};
