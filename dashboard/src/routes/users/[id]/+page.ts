import { session } from '#lib/session.ts';
import type { Identity } from '#lib/types.ts';

export const ssr = false;

// Keyed by identity UUID, or a user's email (matched case-insensitively,
// as the API does). Never by display name: that is the IdP's `name` claim —
// editable and not unique — so a name-keyed URL could land on whoever holds
// the name today.
export const load = async ({ params }: { params: { id: string } }) => {
	const ref = decodeURIComponent(params.id).trim();
	// Soft-fail the identity fetch so a transient API error renders as
	// "user not found" instead of a crashed page. The user detail is
	// recoverable via /members; a hard error page is worse UX here.
	const identities = await session.get<Identity[]>('/v1/identities').catch(() => [] as Identity[]);
	const users = identities.filter((i) => i.kind === 'user');
	const email = ref.includes('@') ? ref.toLowerCase() : null;
	const identity =
		users.find((i) => i.id === ref) ??
		(email ? users.find((i) => i.email?.trim().toLowerCase() === email) : undefined) ??
		null;
	return { requestedRef: ref, identity, identities };
};
