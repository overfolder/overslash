import { redirect } from '@sveltejs/kit';
import type { PageLoad } from './$types';

export const ssr = false;
export const prerender = false;

// Approval resolution now happens as a modal overlay on top of /agents.
// Keep this route as a stable deep-link target (agent-emitted URLs,
// platform integrations, old bookmarks) by redirecting to the agents
// view with the approval id in the query string.
//
// Preserve the `?org=` hint (minted into the link by the API) so the agents
// page can switch the recipient's session into the approval's org before
// loading it — otherwise an org-scoped fetch 404s and reads as "deleted".
export const load: PageLoad = ({ params, url }) => {
	const org = url.searchParams.get('org');
	const query = org
		? `?approval=${encodeURIComponent(params.id)}&org=${encodeURIComponent(org)}`
		: `?approval=${encodeURIComponent(params.id)}`;
	throw redirect(303, `/agents${query}`);
};
