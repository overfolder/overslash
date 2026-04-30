import { ApiError, session } from '$lib/session';
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
	let mcpError: string | null = null;
	if (identity) {
		// 404 (no binding) and 403 (caller can't read connections) are normal —
		// render the empty-state card. Anything else surfaces as a banner so a
		// real API/auth regression doesn't masquerade as "not connected".
		try {
			const r = await session.get<{ connection: McpConnection | null }>(
				`/v1/identities/${encodeURIComponent(identity.id)}/mcp-connection`
			);
			mcp = r.connection;
		} catch (e) {
			if (e instanceof ApiError && (e.status === 404 || e.status === 403)) {
				mcp = null;
			} else {
				mcpError = e instanceof ApiError ? `Error ${e.status}` : 'Network error';
			}
		}
	}

	return { requestedName: decoded, identity, identities, mcp, mcpError };
};
