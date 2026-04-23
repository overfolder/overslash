import type { PageLoad } from './$types';

export const ssr = false;
export const prerender = false;

interface Provider {
	key: string;
	display_name: string;
	source: string;
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
	return {
		providers,
		scope,
		returnTo: url.searchParams.get('return_to') ?? '/agents',
		reason: url.searchParams.get('reason')
	};
};
