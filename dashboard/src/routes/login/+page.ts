import type { PageLoad } from './$types';

export const ssr = false;
export const prerender = false;

interface Provider {
	key: string;
	display_name: string;
	source: string;
	is_default?: boolean;
}

// Same-origin paths only — mirrors the API's `sanitize_next`.
function safePath(raw: string | null): string | null {
	if (!raw || !raw.startsWith('/') || raw.startsWith('//')) return null;
	return raw;
}

export const load: PageLoad = async ({ url, fetch }) => {
	const org = url.searchParams.get('org');
	const qs = org ? `?org=${encodeURIComponent(org)}` : '';
	let providers: Provider[] = [];
	let scope: 'root' | 'org' = 'root';
	try {
		const res = await fetch(`/auth/providers${qs}`);
		if (res.ok) {
			const body = await res.json();
			providers = body.providers ?? [];
			scope = body.scope === 'org' ? 'org' : 'root';
		}
	} catch {}
	// `next` is what `/oauth/authorize` passes when bouncing through login;
	// preserve it on the underlying provider redirect so the AS flow resumes
	// after the IdP round-trip.
	const next = url.searchParams.get('next');
	return {
		providers,
		scope,
		next,
		// Set by the root layout when an unauthenticated visitor hits a deep
		// link (e.g. an approval URL from oversla.sh). Kept null when absent so
		// the IdP callback falls back to the API's `dashboard_url`.
		returnTo: safePath(url.searchParams.get('return_to')),
		reason: url.searchParams.get('reason')
	};
};
