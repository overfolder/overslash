import { redirect } from '@sveltejs/kit';
import type { PageLoad } from './$types';

export const ssr = false;
export const prerender = false;

// Approval resolution now happens as a modal overlay on top of /agents.
// Keep this route as a stable deep-link target (agent-emitted URLs,
// platform integrations, old bookmarks) by redirecting to the agents
// view with the approval id in the query string.
export const load: PageLoad = ({ params }) => {
	throw redirect(303, `/agents?approval=${encodeURIComponent(params.id)}`);
};
