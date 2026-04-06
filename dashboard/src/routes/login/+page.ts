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
	try {
		const res = await fetch(`/auth/providers${qs}`);
		if (res.ok) {
			const body = await res.json();
			providers = body.providers ?? [];
		}
	} catch {}
	return {
		providers,
		returnTo: url.searchParams.get('return_to') ?? '/',
		reason: url.searchParams.get('reason')
	};
};
