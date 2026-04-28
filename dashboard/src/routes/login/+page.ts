import type { PageLoad } from './$types';

export const ssr = false;
export const prerender = false;

interface Provider {
	key: string;
	display_name: string;
	source: string;
	is_default?: boolean;
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
		returnTo: url.searchParams.get('return_to') ?? '/agents',
		reason: url.searchParams.get('reason')
	};
};
