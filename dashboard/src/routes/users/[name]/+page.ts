import { session } from '$lib/session';
import type { Identity } from '$lib/types';

export const ssr = false;

export const load = async ({ params }: { params: { name: string } }) => {
	const decoded = decodeURIComponent(params.name);
	const identities = await session.get<Identity[]>('/v1/identities');
	const identity = identities.find((i) => i.kind === 'user' && i.name === decoded) ?? null;
	return { requestedName: decoded, identity, identities };
};
