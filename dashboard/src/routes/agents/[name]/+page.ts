import { session } from '$lib/session';
import type { Identity, McpConnection } from '$lib/types';

export const ssr = false;

export const load = async ({ params }: { params: { name: string } }) => {
	const decoded = decodeURIComponent(params.name);
	// Soft-fail the identity fetch so a transient API error renders as
	// "agent not found" instead of a crashed page. Matches the /users/[name]
	// loader — both pages are recoverable from /members and /agents.
	const identities = await session.get<Identity[]>('/v1/identities').catch(() => [] as Identity[]);
	const identity =
		identities.find(
			(i) => (i.kind === 'agent' || i.kind === 'sub_agent') && i.name === decoded
		) ?? null;

	let mcp: McpConnection | null = null;
	if (identity) {
		// Soft-fail: a missing connection 404s, anything else (transient API
		// hiccup) just renders the empty-state card and the page still works.
		mcp = await session
			.get<{ connection: McpConnection | null }>(
				`/v1/identities/${encodeURIComponent(identity.id)}/mcp-connection`
			)
			.then((r) => r.connection)
			.catch(() => null);
	}

	return { requestedName: decoded, identity, identities, mcp };
};
