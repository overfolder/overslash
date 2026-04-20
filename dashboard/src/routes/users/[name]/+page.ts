import { session } from '$lib/session';
import type { Identity } from '$lib/types';

export const ssr = false;

export const load = async ({ params }: { params: { name: string } }) => {
	const decoded = decodeURIComponent(params.name);
	// Soft-fail the identity fetch so a transient API error renders as
	// "user not found" instead of a crashed page. The user detail is
	// recoverable via /members; a hard error page is worse UX here.
	const identities = await session.get<Identity[]>('/v1/identities').catch(() => [] as Identity[]);
	const identity = identities.find((i) => i.kind === 'user' && i.name === decoded) ?? null;
	return { requestedName: decoded, identity, identities };
};
